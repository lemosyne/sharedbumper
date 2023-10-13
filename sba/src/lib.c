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

size_t sba_metadata_len(void) { return sizeof(struct Sba); }

// TODO: races etc.
struct SbaLocal sba_new(const char *path, size_t len, void *base_addr_req) {
  len += sba_metadata_len();

  int fd = shm_open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    err(EXIT_FAILURE, "%s (%zu)", path, len);
  }

  int res = ftruncate(fd, len);
  if (res != 0) {
    err(EXIT_FAILURE, NULL);
  }

  struct Sba *sba = mmap(base_addr_req, len, PROT_READ | PROT_WRITE, MAP_SHARED_VALIDATE | MAP_FIXED, fd, 0);
  if (sba == MAP_FAILED) {
    err(EXIT_FAILURE, "mmap");
  }
  sba->cap = len - sizeof(struct Sba);

  struct SbaLocal self = {
      .path = strdup(path),
      .fd = fd,
      .len = len,
      .sba = sba,
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

uint8_t *sba_alloc(struct SbaLocal *self, size_t size, size_t align) {
  assert(sba_lock(self) == 0);
  struct Sba *sba = self->sba;

  // Attempt to use simple alloc:
  uint8_t *sac = sa_alloc(&sba->sa, size, align);
  if (sac) {
    assert(sba_unlock(self) == 0);
    return sac;
  }

  // Otherwise, bump allocate:
  size_t correction = (align - (size_t)(sba->data + sba->idx) % align) % align;
  size_t next_idx = sba->idx + size + correction;

  if (sba->cap < next_idx) {
    assert(sba_unlock(self) == 0);
    return NULL;
  }

  void *data = sba->data + sba->idx + correction;
  sba->idx = next_idx;

  assert(sba_unlock(self) == 0);

  return data;
}

bool sba_extend(struct SbaLocal *self, uint8_t *chunk, size_t old_size, size_t new_size) {
  struct Sba *sba = self->sba;

  // If this is a sa chunk, we cannot extend it
  if (is_sa_chunk(&sba->sa, chunk))
    return false;

  // Extend the chunk if it is adjacent to the top chunk
  assert(new_size >= old_size);
  assert(sba_lock(self) == 0);

  if (sba->data + sba->idx == chunk + old_size) {
    sba->idx += new_size - old_size;

    assert(sba_unlock(self) == 0);
    return true;
  }

  assert(sba_unlock(self) == 0);
  return false;
}

void sba_dealloc(struct SbaLocal *self, uint8_t *chunk, size_t size) {
  assert(sba_lock(self) == 0);
  sa_dealloc(&self->sba->sa, chunk);
  assert(sba_unlock(self) == 0);

  (void) size;
}
