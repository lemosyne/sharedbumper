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

  int fd = shm_open(path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
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

int sba_lock(struct Sba *self) { return pthread_mutex_lock(&self->lock); }

int sba_unlock(struct Sba *self) { return pthread_mutex_unlock(&self->lock); }

static size_t sba_padding_needed_for(size_t n, size_t align) {
  size_t rounded = (n + align - 1) & ~(align - 1);
  return rounded - n;
}

uint8_t *sba_alloc(struct Sba *self, size_t n, size_t align) {
  assert(sba_lock(self) == 0);

  size_t padding = sba_padding_needed_for(n, align);
  size_t total = n + padding;

  if (self->cap < self->idx + total) {
    return NULL;
  }

  void *data = self->data + self->idx + padding;
  self->idx += total;

  assert(sba_unlock(self) == 0);

  return data;
}

void sba_dealloc(struct Sba *self, uint8_t *data, size_t n) {
  (void)self;
  (void)data;
  (void)n;
}

#ifdef TEST
#include <stdio.h>

void share_msg(struct Sba *allocator, char *msg) {
  uint8_t *data = sba_alloc(allocator, strlen(msg) + 1, 2);

  sba_lock(allocator);

  memcpy(data, msg, strlen(msg));
  data[strlen(msg)] = '\0';

  uint64_t buf = (uint64_t)data;
  uint8_t *metadata = sba_metadata(allocator);
  memcpy(metadata, &buf, 8);

  sba_unlock(allocator);
}

char *get_msg(struct Sba *allocator) {
  sba_lock(allocator);

  uint8_t *metadata = sba_metadata(allocator);
  uint64_t data;
  memcpy(&data, metadata, 8);

  sba_unlock(allocator);

  return (char *)data;
}

int main(void) {
  char *parent_msg = "hello child";
  char *child_msg = "hello parent";

  struct Sba allocator = sba_new("test.mem", 4096);

  share_msg(&allocator, parent_msg);

  switch (fork()) {
  case 0:
    printf("%s\n", get_msg(&allocator));
    share_msg(&allocator, child_msg);
    return 0;
  default:
    sleep(1);
    printf("%s\n", get_msg(&allocator));
    break;
  }

  sba_drop(&allocator);
  return 0;
}
#endif
