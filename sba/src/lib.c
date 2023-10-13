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

#define SMALL_SIZE 0x100
#define MIN_SIZE (sizeof(struct FreeChunk) < 0x40 ? 0x40 : sizeof(struct FreeChunk))
#define DEFAULT_ALIGN 1

static int log;

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

uint8_t *free_to_user(struct FreeChunk *free) {
  return (uint8_t *) &free->next;
}

struct FreeChunk *user_to_free(uint8_t *user) {
  return (struct FreeChunk *) (user - offsetof(struct FreeChunk, next));
}

struct FreeChunk *chunk_after(struct FreeChunk *chunk) {
  return (struct FreeChunk *) ((uint8_t *) chunk + chunk->header.size);
}

struct FreeChunk *alloc_from_freelist(struct FreeChunk **freelist, size_t size) {
  struct FreeChunk *head = *freelist;

  // Check if the head is big enough
  if (!head || head->header.size < size) return NULL;

  // Link the freelist correctly
  *freelist = head->next;

  if (head->next) head->next->prev = head->prev;
  if (head->prev) head->prev->next = head->next;

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

  // Try to allocate off of the small bin
  chunk = alloc_from_freelist(&sba->small_bin, size);
  if (chunk) goto return_chunk;

  // Otherwise, try to allocate off of the large bin
  chunk = alloc_from_freelist(&sba->large_bin, size);
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

  assert(chunk->header.inuse);

cleanup:
  assert(sba_unlock(self) == 0);
  // dprintf(log, "A(%p, 0x%lx, 0x%lx)\n", user, size, align);
  // fsync(log);
  return user;
}

bool sba_extend(struct SbaLocal *self, uint8_t *chunk, size_t old_size, size_t new_size) {
  (void) self;
  (void) chunk;
  (void) old_size;
  (void) new_size;
  return false;
}

void sba_dealloc(struct SbaLocal *self, uint8_t *user_chunk, size_t size) {
  assert(sba_lock(self) == 0);
  struct Sba *sba = self->sba;

  struct FreeChunk *free = *(FreeChunkTrailer *) (user_chunk + size);
  struct FreeChunk *after = chunk_after(free);

  // If the top chunk is the chunk after, consolidate
  if (after == sba->top) {
    free->header.size += after->header.size;
    free->header.inuse = false;
    free->next = NULL;
    free->prev = NULL;

    sba->top = free;
    goto cleanup;
  }

  // If the chunk after is free, consolidate
  if (!after->header.inuse) {
    if (after->next) after->next->prev = after->prev;
    if (after->prev) after->prev->next = after->next;
    else if (after->header.size <= SMALL_SIZE) sba->small_bin = after->next;
    else sba->large_bin = after->next;

    free->header.size += after->header.size;
  }

  // If the chunk is small, add it to the small bin
  if (free->header.size <= SMALL_SIZE) {
    dealloc_to_freelist(&sba->small_bin, free); 
    goto cleanup;
  }

  // Otherwise, add it to the large bin
  dealloc_to_freelist(&sba->large_bin, free);

cleanup:
  // dprintf(log, "D(%p, 0x%lx)\n", user_chunk, size);
  // fsync(log);

  if (free->next) assert(free == free->next->prev);
  if (free->prev) assert(free == free->prev->next);

  assert(sba_unlock(self) == 0);
}
