#pragma once

#include "sa.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct SbaLocal {
  char *path;
  int fd;
  size_t len;
  struct Sba *sba;
};

struct Sba {
  pthread_mutex_t lock;
  void *metadata;
  size_t cap;
  size_t idx;
  struct SimpleAlloc sa;
  uint8_t data[];
};

struct SbaLocal sba_new(const char *path, size_t len, void *base_addr_req);

void sba_drop(struct SbaLocal *self);

void **sba_metadata(struct SbaLocal *self);

int sba_lock(struct SbaLocal *self);

int sba_unlock(struct SbaLocal *self);

uint8_t *sba_alloc(struct SbaLocal *self, size_t n, size_t align);

bool sba_extend(struct SbaLocal *self, uint8_t *block, size_t old_size, size_t new_size);

void sba_dealloc(struct SbaLocal *self, uint8_t *data, size_t n);
