/*
 * =====================================================================================
 *
 *       Filename:  ringbuffer.h
 *
 *    Description:  Code to implement a simple ring buffer. This is meant to be fast, 
 *                  but cannot be manipulated by multiple threads at the same time.
 *
 *        Version:  1.0
 *        Created:  08/03/2013 16:44:47
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  George Kola (), georgekola@gmail.com
 *        Company:  
 *
 * =====================================================================================
 */

#ifndef __RINGBUFFER_H
#define __RINGBUFFER_H

#include <string.h>
#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
#define RINGBUFFER_SIZE (16*1024)

typedef struct {
  int head,tail;
  char buf[RINGBUFFER_SIZE];
}ringbuffer_t;

static inline void ringbuffer_init(ringbuffer_t * __restrict r){
    r->head=r->tail=0;
}
static inline bool ringbuffer_is_empty(const ringbuffer_t *r){
  return r->head==r->tail;
}
static inline bool ringbuffer_is_full(const ringbuffer_t *r){
  return ((r->tail+1)&(RINGBUFFER_SIZE-1)) == r->head;
}
static inline int ringbuffer_available_to_write(const ringbuffer_t *r){
  return (r->head + RINGBUFFER_SIZE - r->tail -1)&(RINGBUFFER_SIZE-1);
}
static inline int ringbuffer_available_to_read(const ringbuffer_t *r){
  return (r->tail + RINGBUFFER_SIZE - r->head)&(RINGBUFFER_SIZE-1);
}

int ringbuffer_append(ringbuffer_t *r, const char *buf, int len){
  if(ringbuffer_is_full(r)){
    return 0;
  }
  int max_bytes=ringbuffer_available_to_write(r);
  len=(len > max_bytes)?max_bytes:len;
  if(len > (RINGBUFFER_SIZE-r->tail)){
    int first_chunk=RINGBUFFER_SIZE-r->tail;
    memcpy(r->buf+r->tail,buf,first_chunk);
    memcpy(r->buf,buf+first_chunk,len-first_chunk);
    r->tail=(r->tail+len)&(RINGBUFFER_SIZE-1);
  }else{
    memcpy(r->buf+r->tail,buf,len);
    r->tail+=len;
  }
  return len;
}

char *ringbuffer_get(ringbuffer_t * __restrict r, char * __restrict buf, int *output_len){
    int len=ringbuffer_available_to_read(r);
    *output_len=len;
    if(len > RINGBUFFER_SIZE-r->head){
        int first_chunk=RINGBUFFER_SIZE-r->head;
        memcpy(buf,r->buf+r->head,first_chunk);
        memcpy(buf+first_chunk,r->buf,len-first_chunk);
        return buf;
    }
    return r->buf;
}

void ringbuffer_get2(ringbuffer_t * __restrict r, char * __restrict buf, int len){
    if(len > RINGBUFFER_SIZE-r->head){
        int first_chunk=RINGBUFFER_SIZE-r->head;
        memcpy(buf,r->buf+r->head,first_chunk);
        memcpy(buf+first_chunk,r->buf,len-first_chunk);
    }else{
        memcpy(buf,r->buf+r->head,len);
    }
}

void ringbuffer_advance_read_head(ringbuffer_t * __restrict r, int len){
    r->head=(r->head+len)&(RINGBUFFER_SIZE-1);
    if(r->head==r->tail){
        r->head=r->tail=0;
    }
}
void ringbuffer_advance_write_head(ringbuffer_t * __restrict r, int len){
    r->tail=(r->tail+len)&(RINGBUFFER_SIZE-1);
}
char *ringbuffer_write_ptr(ringbuffer_t * __restrict r){
    return r->buf+r->tail;
}

#endif
