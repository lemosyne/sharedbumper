#pragma once

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

struct SharedBumpAllocator {
  pthread_mutex_t lock;
  char *path;
  int fd;
  size_t idx;
  size_t cap;
  uint8_t *data;
};

struct SharedBumpAllocator sba_new(const char *path, size_t cap);

void sba_drop(struct SharedBumpAllocator *self);

uint8_t *sba_alloc(struct SharedBumpAllocator *self, size_t n);

void sba_dealloc(struct SharedBumpAllocator *self, uint8_t *data, size_t n);
