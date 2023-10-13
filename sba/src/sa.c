#include "sa.h"

#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

bool is_sa_chunk(struct SimpleAlloc *self, uint8_t *chunk) {
  size_t chunk_addr = (size_t) chunk;
  size_t chunks_start = (size_t) self->chunks;
  size_t chunks_end = (size_t) self->chunks + sizeof(self->chunks);

  return chunks_start <= chunk_addr && chunk_addr < chunks_end;
}

ssize_t sa_index(struct SimpleAlloc *self, uint8_t *chunk) {
  if (!is_sa_chunk(self, chunk))
    return -1;

  size_t chunk_addr = (size_t) chunk;
  size_t chunks_start = (size_t) self->chunks;

  assert((chunk_addr - chunks_start) % SA_CHUNKSIZE == 0);
  ssize_t index = (chunk_addr - chunks_start) / SA_CHUNKSIZE;

  return index;
}

uint8_t *sa_alloc(struct SimpleAlloc *self, size_t size, size_t align) {
  if (size > SA_CHUNKSIZE)
    return NULL;

  if ((size_t) self->chunks % align != 0)
    return NULL;

  for (size_t i = 0; i < SA_MAXCHUNKS; ++i)
    if (!self->in_use[i]) {
      self->in_use[i] = true;
      return self->chunks[i];
    }

  return NULL;
}

bool sa_dealloc(struct SimpleAlloc *self, uint8_t *chunk) {
  ssize_t index = sa_index(self, chunk);
  if (index < 0)
    return false;

  assert(self->in_use[index]);
  self->in_use[index] = false;
  return true;
}
