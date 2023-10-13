#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define SA_CHUNKSIZE 0x100
#define SA_MAXCHUNKS 0x10

struct SimpleAlloc {
  bool in_use[SA_MAXCHUNKS]; // todo: should be a bitset but idc rn
  uint8_t chunks[SA_MAXCHUNKS][SA_CHUNKSIZE];
};

bool is_sa_chunk(struct SimpleAlloc *self, uint8_t *chunk);

uint8_t *sa_alloc(struct SimpleAlloc *self, size_t size, size_t align);
bool sa_dealloc(struct SimpleAlloc *self, uint8_t *chunk);
