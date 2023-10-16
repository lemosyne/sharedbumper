#pragma once

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define SMALLBIN_INCREMENT 0x10
#define SMALLBIN_MAXSIZE 0x1000

struct SbaLocal {
  char *path;
  int fd;
  size_t len;
  struct Sba *sba;
};

struct Sba {
  pthread_mutex_t lock;
  bool initialized;

  void *metadata;

  struct FreeChunk *top;
  
  struct FreeChunk *small_bins[SMALLBIN_MAXSIZE / SMALLBIN_INCREMENT + 1];
  struct FreeChunk *unsorted_bin;

  uint8_t data[];
};

struct FreeChunkHeader {
  bool unsorted;
  bool inuse;
  size_t prev_size;
  size_t size;
};

struct FreeChunk {
  struct FreeChunkHeader header;
  struct FreeChunk *next;
  struct FreeChunk *prev;
};

typedef struct FreeChunk *FreeChunkTrailer;

struct SbaLocal sba_new(const char *path, size_t len, void *base_addr_req);

void sba_drop(struct SbaLocal *self);

void **sba_metadata(struct SbaLocal *self);

int sba_lock(struct SbaLocal *self);

int sba_unlock(struct SbaLocal *self);

uint8_t *sba_alloc(struct SbaLocal *self, size_t size, size_t align);

bool sba_extend(struct SbaLocal *self, uint8_t *chunk, size_t old_size, size_t new_size);

void sba_dealloc(struct SbaLocal *self, uint8_t *chunk, size_t size);
