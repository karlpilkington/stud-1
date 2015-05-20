#include "bud-common.hpp"

#include <string.h>

#define BUD_MURMUR3_C1 0xcc9e2d51
#define BUD_MURMUR3_C2 0x1b873593


static uint32_t bud_murmur3(const char* key, uint32_t len) {
  uint32_t hash;
  const uint32_t* chunks;
  int chunk_count;
  int i;
  uint32_t tail;

  hash = 0;

  /* FIXME(indutny): this leads to unaligned loads for some keys */
  chunks = (const uint32_t*) key;
  chunk_count = len / 4;
  for (i = 0; i < chunk_count; i++) {
    uint32_t k;

    k = chunks[i];
    k *= BUD_MURMUR3_C1;
    k = (k << 15) | (k >> 17);
    k *= BUD_MURMUR3_C2;

    hash ^= k;
    hash = (hash << 13) | (hash >> 19);
    hash *= 5;
    hash += 0xe6546b64;
  }

  tail = 0;
  chunk_count *= 4;
  for (i = len - 1; i >= chunk_count; i--) {
    tail <<= 8;
    tail += key[i];
  }
  if (tail != 0) {
    tail *= BUD_MURMUR3_C1;
    tail = (tail << 15) | (tail >> 17);
    tail *= BUD_MURMUR3_C2;

    hash ^= tail;
  }

  hash ^= len;

  hash ^= hash >> 16;
  hash *= 0x85ebca6b;
  hash ^= hash >> 13;
  hash *= 0xc2b2ae35;
  hash ^= hash >> 16;

  return hash;
}


#undef BUD_MURMUR3_C1
#undef BUD_MURMUR3_C2


int bud_hashmap_init(bud_hashmap_t* hashmap, unsigned int size) {
  hashmap->size = size;
  hashmap->space = (bud_hashmap_item_t*) calloc(size, sizeof(*hashmap->space));
  if (hashmap->space == NULL)
    return -1;

  return 0;
}


void bud_hashmap_destroy(bud_hashmap_t* hashmap) {
  if (hashmap->space == NULL)
    return;

  free(hashmap->space);
  hashmap->space = NULL;
}


/* A bit sparse, but should be fast */
#define BUD_HASHMAP_MAX_ITER 3
#define BUD_HASHMAP_GROW_DELTA 1024


static bud_hashmap_item_t* bud_hashmap_get_int(bud_hashmap_t* hashmap,
                                               const char* key,
                                               unsigned int key_len,
                                               int insert) {
  do {
    uint32_t i;
    uint32_t iter;
    bud_hashmap_item_t* space;
    unsigned int size;
    bud_hashmap_t old_map;

    i = bud_murmur3(key, key_len) % hashmap->size;
    for (iter = 0;
         iter < BUD_HASHMAP_MAX_ITER;
         iter++, i = (i + 1) % hashmap->size) {
      if (hashmap->space[i].key == NULL)
        break;
      if (!insert) {
        if (hashmap->space[i].key_len == key_len &&
            memcmp(hashmap->space[i].key, key, key_len) == 0) {
          break;
        }
      }
    }

    if (!insert && hashmap->space[i].key == NULL)
      return NULL;

    /* Found a spot */
    if (iter != BUD_HASHMAP_MAX_ITER)
      return &hashmap->space[i];

    /* No match */
    if (!insert)
      return NULL;

    /* Grow and retry */
    size = hashmap->size += BUD_HASHMAP_GROW_DELTA;
    space = (bud_hashmap_item_t*) calloc(size, sizeof(*space));
    if (space == NULL)
      return NULL;

    /* Rehash */
    old_map = *hashmap;
    hashmap->space = space;
    hashmap->size = size;
    for (i = 0; i < old_map.size; i++) {
      bud_hashmap_item_t* item;
      int err;

      item = &old_map.space[i];
      err = bud_hashmap_insert(hashmap, item->key, item->key_len, item->value);
      if (err != 0) {
        free(space);
        *hashmap = old_map;
        return NULL;
      }
    }

  /* Retry */
  } while (1);
}


#undef BUD_HASHMAP_GROW_DELTA
#undef BUD_HASHMAP_MAX_ITER


int bud_hashmap_insert(bud_hashmap_t* hashmap,
                       const char* key,
                       unsigned int key_len,
                       void* value) {
  bud_hashmap_item_t* item;

  item = bud_hashmap_get_int(hashmap, key, key_len, 1);
  if (item == NULL)
    return -1;

  item->key = key;
  item->key_len = key_len;
  item->value = value;

  return 0;
}


void* bud_hashmap_get(bud_hashmap_t* hashmap,
                      const char* key,
                      unsigned int key_len) {
  bud_hashmap_item_t* item;

  item = bud_hashmap_get_int(hashmap, key, key_len, 0);
  if (item == NULL)
    return NULL;

  return item->value;
}


int bud_hashmap_iterate(bud_hashmap_t* hashmap,
                        bud_hashmap_iterate_cb cb,
                        void* arg) {
  int err;
  unsigned int i;

  if (hashmap->space == NULL)
    return 0;

  for (i = 0; i < hashmap->size; i++) {
    if (hashmap->space[i].key != NULL) {
      err = cb(&hashmap->space[i], arg);
      if (err != 0)
        return err;
    }
  }

  return 0;
}
