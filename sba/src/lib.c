#include "lib.h"
#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#define MIN_SIZE (sizeof(struct FreeChunk) < 0x40 ? 0x40 : sizeof(struct FreeChunk))
#define DEFAULT_ALIGN 1

// TODO: races etc.
struct SbaLocal sba_new(const char *path, size_t len, void *base_addr_req) {
  // Ensure we have enough space to fit the allocator
  len += sizeof(struct Sba);

  // Open and setup the shared memory block
  int fd = shm_open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    err(EXIT_FAILURE, "%s (%zu)", path, len);
  }

  // log = open("log.txt", O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);

  int res = ftruncate(fd, len);
  if (res != 0) {
    err(EXIT_FAILURE, NULL);
  }

  int flags = MAP_SHARED_VALIDATE;
  if (base_addr_req) flags |= MAP_FIXED;

  struct Sba *sba = mmap(base_addr_req, len, PROT_READ | PROT_WRITE, flags, fd, 0);
  if (sba == MAP_FAILED) {
    err(EXIT_FAILURE, "sba mmap");
  }

  // Create our local handle to the shared memory
  struct SbaLocal self = {
      .path = strdup(path),
      .fd = fd,
      .len = len,
      .sba = sba,
  };

  // Initialize the allocator if we are the first to use it
  // TODO: this races
  if (sba->initialized) return self;
  sba->initialized = true;
  
  sba->top = (struct FreeChunk *) sba->data;
  *sba->top = (struct FreeChunk) {
    .header = (struct FreeChunkHeader) {
      .inuse = false,
      .unsorted = false,
      .prev_size = 0,
      .size = len - sizeof(struct Sba),
    },
    .next = NULL,
    .prev = NULL
  };

  return self;
}

// TODO: races
void sba_drop(struct SbaLocal *self) {
  if (self) {
    assert(munmap(self->sba, self->len) == 0);
    free(self->path);
  }
}

void **sba_metadata(struct SbaLocal *self) {
  return &self->sba->metadata;
}

int sba_lock(struct SbaLocal *self) { return pthread_mutex_lock(&self->sba->lock); }

int sba_unlock(struct SbaLocal *self) { return pthread_mutex_unlock(&self->sba->lock); }



/**** Allocation Functions ****/
size_t smallbin_index_floor(size_t size) {
  return size / SMALLBIN_INCREMENT;
}

size_t smallbin_index_ceil(size_t size) {
  return (size - 1) / SMALLBIN_INCREMENT + 1;
}

uint8_t *free_to_user(struct FreeChunk *free) {
  return (uint8_t *) &free->next;
}

struct FreeChunk *user_to_free(uint8_t *user) {
  return (struct FreeChunk *) (user - offsetof(struct FreeChunk, next));
}

struct FreeChunk *chunk_after(struct FreeChunk *chunk) {
  return (struct FreeChunk *) ((uint8_t *) chunk + chunk->header.size);
}

struct FreeChunk *chunk_before(struct FreeChunk *chunk) {
  return (struct FreeChunk *) ((uint8_t *) chunk - chunk->header.prev_size);
}

void unlink_chunk(struct FreeChunk **freelist, struct FreeChunk *chunk) {
  if (chunk->next) chunk->next->prev = chunk->prev;
  if (chunk->prev) chunk->prev->next = chunk->next;
  else *freelist = chunk->next;
}

struct FreeChunk *alloc_from_freelist_unchecked(struct FreeChunk **freelist) {
  struct FreeChunk *head = *freelist;

  if (head) {
    unlink_chunk(freelist, head);
    head->header.inuse = true;
  };
  return head;
}

struct FreeChunk *alloc_from_freelist_unsorted(struct Sba *sba, size_t size) {
  struct FreeChunk *head = sba->unsorted_bin;

  while (head) {
    // Check if the head is big enough
    if (head->header.size >= size) break;
  
    // Otherwise keep searching
    head = head->next;
  }

  if (!head) return NULL;

  // If the chunk is much bigger than we need, only allocate part of it
  if (head->header.size >= size + MIN_SIZE * 2) {
    struct FreeChunk *after = chunk_after(head);
  
    size_t old_size = head->header.size;
    head->header.size = size;
    
    struct FreeChunk *new_free = chunk_after(head);
    *new_free = (struct FreeChunk) {
      .header = (struct FreeChunkHeader) {
        .inuse = false,
        .unsorted = true,
        .prev_size = size,
        .size = old_size - size,
      },
      .next = head->next,
      .prev = head->prev,
    };

    if (new_free->next) new_free->next->prev = new_free;
    if (new_free->prev) new_free->prev->next = new_free;
    else sba->unsorted_bin = new_free;

    after->header.prev_size = new_free->header.size;
  } else {
    // Otherwise, remove it entirely from the freelist
    unlink_chunk(&sba->unsorted_bin, head);
  }

  // Mark the chunk as allocated and return
  head->header.inuse = true;
  return head;
}

void dealloc_to_freelist(struct FreeChunk **freelist, struct FreeChunk *chunk) {
  struct FreeChunk *head = *freelist;
  if (head) {
    chunk->next = head;
    head->prev = chunk;
  } else {
    chunk->next = NULL;
  }

  chunk->prev = NULL;
  chunk->header.inuse = false;
  *freelist = chunk;
}

uint8_t *sba_alloc(struct SbaLocal *self, size_t size, size_t align) {
  assert(sba_lock(self) == 0);
  struct Sba *sba = self->sba;
  struct FreeChunk *chunk = NULL;
  uint8_t *user = NULL;
  size_t user_size = size;

  // All chunks must have space for their header, trailer, and alignmnet
  if (DEFAULT_ALIGN % align != 0) size += align;
  size += sizeof(struct FreeChunkHeader) + sizeof(FreeChunkTrailer);

  // All chunks will be of at least the minimum size 
  if (size < MIN_SIZE) size = MIN_SIZE;

  // Try to allocate off of the small bins
  if (size <= SMALLBIN_MAXSIZE) {
    size_t index = smallbin_index_ceil(size);
    chunk = alloc_from_freelist_unchecked(&sba->small_bins[index]);
    if (chunk) goto return_chunk;
  }

  // Try to allocate off of the unsorted bin
  chunk = alloc_from_freelist_unsorted(sba, size);
  if (chunk) goto return_chunk;

  // If our freelists do not provide, we allocate from the top chunk
  if (sba->top->header.size < size) goto return_chunk;

  struct FreeChunk *from_top = sba->top;
  sba->top = (struct FreeChunk *) ((uint8_t *) sba->top + size);

  memcpy(sba->top, from_top, sizeof(*sba->top));

  sba->top->header.size -= size;
  sba->top->header.prev_size = size;
  from_top->header.size = size;
  from_top->header.inuse = true;

  chunk = from_top;

return_chunk:
  if (!chunk) goto cleanup;

  // Compensate for alignment by adding the trailer 
  // and shifting the returned pointer correctly
  user = free_to_user(chunk);

  size_t correction = (align - (size_t) user % align) % align;
  user += correction;

  FreeChunkTrailer *trailer = (FreeChunkTrailer *) (user + user_size);
  *trailer = chunk;

  assert(chunk->header.size >= size);
  assert(chunk->header.inuse);

cleanup:
  assert(sba_unlock(self) == 0);

  return user;
}

bool sba_extend(struct SbaLocal *self, uint8_t *user_chunk, size_t old_size, size_t new_size) {
  (void) self;
  (void) old_size;

  assert(sba_lock(self) == 0);
  bool output = false;
  struct Sba *sba = self->sba;

  struct FreeChunk *chunk = user_to_free(user_chunk);
  new_size += sizeof(struct FreeChunkHeader);

  // If we already have the space, we're good
  if (new_size <= chunk->header.size) {
    output = true;
    goto cleanup;
  }

  // Extend into the top chunk if we can 
  struct FreeChunk *after = chunk_after(chunk);
  if (after == sba->top) {
    size_t required = new_size - chunk->header.size;
  
    sba->top -= required;
    chunk->header.size = new_size;

    memmove(sba->top, (uint8_t *) sba->top + required, sizeof(*sba->top));

    output = true;
    goto cleanup;
  }

  // If the next chunk is free, extend into it
  if (!after->header.inuse && after->header.unsorted && new_size <= after->header.size + chunk->header.size) {
    unlink_chunk(&sba->unsorted_bin, after);
  
    chunk->header.size += after->header.size;
    chunk_after(after)->header.prev_size = chunk->header.size;

    output = true;
    goto cleanup;
  }

cleanup:
  assert(sba_unlock(self) == 0);
  return output;
}

void sba_dealloc(struct SbaLocal *self, uint8_t *user_chunk, size_t user_size) {
  assert(sba_lock(self) == 0);
  struct Sba *sba = self->sba;

  struct FreeChunk *free = *(FreeChunkTrailer *) (user_chunk + user_size);
  struct FreeChunk *after = chunk_after(free);
  struct FreeChunk *before = chunk_before(free);

  // If the chunk before is free, consolodiate
  if ((uint8_t *) before != sba->data && !before->header.inuse && before->header.unsorted) {
    before->header.size += free->header.size;
    after->header.prev_size = before->header.size;
    free = before;
  }

  // If the top chunk is the chunk after, consolidate
  if (after == sba->top) {
    if (!free->header.inuse) unlink_chunk(&sba->unsorted_bin, free);

    free->header.size += after->header.size;
    free->header.inuse = false;
    free->next = NULL;
    free->prev = NULL;

    sba->top = free;
    goto cleanup;
  }

  // If the chunk after is free, consolidate
  if (!after->header.inuse && after->header.unsorted) {
    unlink_chunk(&sba->unsorted_bin, after);
  
    free->header.size += after->header.size;
    chunk_after(after)->header.prev_size = free->header.size;
  }

  // If the chunk is already in a freelist (due to consolidation), we're done
  if (!free->header.inuse) goto cleanup;

  // Free it onto the smallbins if possible
  if (free->header.size <= SMALLBIN_MAXSIZE) {
    size_t index = smallbin_index_floor(free->header.size);
  
    free->header.unsorted = false;
    dealloc_to_freelist(&sba->small_bins[index], free);
    goto cleanup;
  }

  // Finally, use the unsorted bin
  free->header.unsorted = true;
  dealloc_to_freelist(&sba->unsorted_bin, free);

cleanup:
  if (free->next) assert(free == free->next->prev);
  if (free->prev) assert(free == free->prev->next);

  assert(sba_unlock(self) == 0);
}
