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

size_t sba_metadata_len(void) { return sizeof(void *); }

struct SbaLocal sba_new(const char *path, size_t len) {
  len += sba_metadata_len();

  int fd = shm_open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    err(EXIT_FAILURE, "%s (%zu)", path, len);
  }

  int res = ftruncate(fd, len);
  if (res != 0) {
    err(EXIT_FAILURE, NULL);
  }

  struct Sba *sba = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (sba == MAP_FAILED) {
    err(EXIT_FAILURE, NULL);
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

void sba_drop(struct SbaLocal *self) {
  if (self) {
    assert(munmap(self->sba, self->len) == 0);
    free(self->path);
  }
}

void *sba_metadata(struct SbaLocal *self) {
  return &self->sba->metadata;
}

int sba_lock(struct SbaLocal *self) { return pthread_mutex_lock(&self->sba->lock); }

int sba_unlock(struct SbaLocal *self) { return pthread_mutex_unlock(&self->sba->lock); }

uint8_t *sba_alloc(struct SbaLocal *self, size_t n, size_t align) {
  assert(sba_lock(self) == 0);

  struct Sba *sba = self->sba;

  size_t correction = (align - (size_t)(sba->data + sba->idx) % align) % align;
  size_t total = n + correction;

  if (sba->cap < sba->idx + total) {
    assert(sba_unlock(self) == 0);
    return NULL;
  }

  void *data = sba->data + sba->idx + correction;
  sba->idx += total;

  assert(sba_unlock(self) == 0);

  return data;
}

void sba_dealloc(struct SbaLocal *self, uint8_t *data, size_t n) {
  (void)self;
  (void)data;
  (void)n;
}

// #ifdef TEST
// #include <stdio.h>

// void share_msg(struct Sba *allocator, char *msg) {
//   uint8_t *data = sba_alloc(allocator, strlen(msg) + 1, 2);

//   sba_lock(allocator);

//   memcpy(data, msg, strlen(msg));
//   data[strlen(msg)] = '\0';

//   uint64_t buf = (uint64_t)data;
//   uint8_t *metadata = sba_metadata(allocator);
//   memcpy(metadata, &buf, 8);

//   sba_unlock(allocator);
// }

// char *get_msg(struct Sba *allocator) {
//   sba_lock(allocator);

//   uint8_t *metadata = sba_metadata(allocator);
//   uint64_t data;
//   memcpy(&data, metadata, 8);

//   sba_unlock(allocator);

//   return (char *)data;
// }

// int main(void) {
//   char *parent_msg = "hello child";
//   char *child_msg = "hello parent";

//   struct Sba allocator = sba_new("test.mem", 4096);

//   share_msg(&allocator, parent_msg);

//   switch (fork()) {
//   case 0:
//     printf("%s\n", get_msg(&allocator));
//     share_msg(&allocator, child_msg);
//     return 0;
//   default:
//     sleep(1);
//     printf("%s\n", get_msg(&allocator));
//     break;
//   }

//   sba_drop(&allocator);
//   return 0;
// }
// #endif
