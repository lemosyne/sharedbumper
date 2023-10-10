#pragma once

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

struct Sba {
  pthread_mutex_t lock;
  char *path;
  int fd;
  size_t idx;
  size_t cap;
  uint8_t *data;
};

struct Sba sba_new(const char *path, size_t cap);

void sba_drop(struct Sba *self);

uint8_t *sba_metadata(struct Sba *self);

int sba_lock(struct Sba *self);

int sba_unlock(struct Sba *self);

uint8_t *sba_alloc(struct Sba *self, size_t n, size_t align);

void sba_dealloc(struct Sba *self, uint8_t *data, size_t n);
