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

size_t sba_metadata_len(void) { return sizeof(uint8_t *); }

struct Sba sba_new(const char *path, size_t cap) {
  cap += sba_metadata_len();

  int fd = shm_open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    err(EXIT_FAILURE, "%s (%zu)", path, cap);
  }

  int res = ftruncate(fd, cap);
  if (res != 0) {
    err(EXIT_FAILURE, NULL);
  }

  uint8_t *data = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (data == MAP_FAILED) {
    err(EXIT_FAILURE, NULL);
  }

  struct Sba self = {
      .lock = PTHREAD_MUTEX_INITIALIZER,
      .path = strdup(path),
      .fd = fd,
      .idx = 0,
      .cap = cap,
      .data = data + sba_metadata_len(),
  };

  return self;
}

void sba_drop(struct Sba *self) {
  if (self) {
    assert(pthread_mutex_destroy(&self->lock) == 0);
    assert(munmap(self->data - sba_metadata_len(), self->cap) == 0);
    assert(shm_unlink(self->path) == 0);
    free(self->path);
  }
}

uint8_t *sba_metadata(struct Sba *self) {
  return self->data - sba_metadata_len();
}

static size_t sba_padding_needed_for(size_t n, size_t align) {
  size_t rounded = (n + align - 1) & ~(align - 1);
  return rounded - n;
}

uint8_t *sba_alloc(struct Sba *self, size_t n, size_t align) {
  assert(pthread_mutex_lock(&self->lock) == 0);

  size_t padding = sba_padding_needed_for(n, align);
  size_t total = n + padding;

  if (self->cap < self->idx + total) {
    return NULL;
  }

  void *data = self->data + self->idx + padding;
  self->idx += total;

  assert(pthread_mutex_unlock(&self->lock) == 0);

  return data;
}

void sba_dealloc(struct Sba *self, uint8_t *data, size_t n) {
  (void)self;
  (void)data;
  (void)n;
}

#ifdef TEST
#include <stdio.h>

int main(void) {
  struct Sba allocator = sba_new("test.mem", 128);

  printf("%zu\n", sba_padding_needed_for(9, 4));

  char *msg = "hello world";
  char *data = (char *)sba_alloc(&allocator, strlen(msg) + 1, 2);
  memcpy(data, msg, strlen(msg));
  data[strlen(msg)] = '\0';
  printf("%s\n", data);

  sba_drop(&allocator);
  return 0;
}
#endif
