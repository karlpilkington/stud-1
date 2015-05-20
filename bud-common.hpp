#ifndef __BUD_COMMON_HPP
#define __BUD_COMMON_HPP

#include <stdlib.h>
#include <stdio.h>

#define ASSERT__COMMON(expr, desc, ...)                                       \
    do {                                                                      \
      if (!(expr)) {                                                          \
        fprintf(stderr, desc "\n", __VA_ARGS__);                              \
        abort();                                                              \
      }                                                                       \
    } while (0)

#define ASSERT_VA(expr, desc, ...)                                            \
    ASSERT__COMMON(expr,                                                      \
                   "Assertion failed %s:%d\n" desc,                           \
                   __FILE__,                                                  \
                   __LINE__,                                                  \
                   __VA_ARGS__)

#define ASSERT(expr, desc)                                                    \
    ASSERT__COMMON(expr,                                                      \
                   "Assertion failed %s:%d\n" desc,                           \
                   __FILE__,                                                  \
                   __LINE__)

#define UNEXPECTED ASSERT(0, "Unexpected")

/* Hashmap */

typedef struct bud_hashmap_s bud_hashmap_t;
typedef struct bud_hashmap_item_s bud_hashmap_item_t;
typedef void (*bud_hashmap_free_cb)(void*);
typedef int (*bud_hashmap_iterate_cb)(bud_hashmap_item_t* item, void* arg);

struct bud_hashmap_s {
  bud_hashmap_item_t* space;
  unsigned int size;
};

struct bud_hashmap_item_s {
  const char* key;
  unsigned int key_len;
  void* value;
};

int bud_hashmap_init(bud_hashmap_t* hashmap, unsigned int size);
void bud_hashmap_destroy(bud_hashmap_t* hashmap);

int bud_hashmap_insert(bud_hashmap_t* hashmap,
                       const char* key,
                       unsigned int key_len,
                       void* value);
void* bud_hashmap_get(bud_hashmap_t* hashmap,
                      const char* key,
                      unsigned int key_len);
int bud_hashmap_iterate(bud_hashmap_t* hashmap,
                        bud_hashmap_iterate_cb cb,
                        void* arg);

#endif  // __BUD_COMMON_HPP
