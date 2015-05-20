#include <stdlib.h>
#include <string.h>

#include "rate-limiter.hpp"

#include "bud-common.hpp"

RateLimiter::RateLimiter(struct ev_loop* loop, Callback cb)
    : loop_(loop),
      cb_(cb) {
  ASSERT(0 == bud_hashmap_init(&map_, kDefaultMapSize),
         "Failed to init rate limiter hashmap");

  ev_timer_init(&sweep_timer_, OnSweep, kSweepInterval, kSweepInterval);
  sweep_timer_.data = this;

  ev_timer_start(loop_, &sweep_timer_);
}


RateLimiter::~RateLimiter() {
  ev_timer_stop(loop(), &sweep_timer_);

  ASSERT(0 == bud_hashmap_iterate(&map_, DestroyItems, NULL),
         "Failed to destroy limiter hashmap items");
  bud_hashmap_destroy(&map_);
}


int RateLimiter::DestroyItems(bud_hashmap_item_t* item, void* arg) {
  delete[] const_cast<char*>(item->key);
  item->key = NULL;
  delete reinterpret_cast<Item*>(item->value);

  return 0;
}


// Sweep all items with zero counter
void RateLimiter::OnSweep(struct ev_loop* loop, ev_timer* w, int revents) {
  (void) loop;
  (void) revents;

  RateLimiter* r = reinterpret_cast<RateLimiter*>(w->data);

  struct timeval now;
  ASSERT(0 == gettimeofday(&now, NULL), "Failed to gettimeofday()");

  ASSERT(0 == bud_hashmap_iterate(&r->map_, SweepItems, &now),
         "Failed to sweep limiter hashmap items");
}


int RateLimiter::SweepItems(bud_hashmap_item_t* item, void* arg) {
  Item* i = reinterpret_cast<Item*>(item->value);
  struct timeval* now = reinterpret_cast<struct timeval*>(arg);

  // Update timeout, decrease count
  i->Count(0, now);

  if (!i->empty())
    return 0;

  delete[] const_cast<char*>(item->key);
  delete i;
  memset(item, 0, sizeof(*item));

  return 0;
}


unsigned int RateLimiter::KeySize(struct sockaddr_storage* addr) {
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;

  if (addr->ss_family == AF_INET) {
    return sizeof(addr4->sin_addr);
  } else if (addr->ss_family == AF_INET6) {
    return sizeof(addr6->sin6_addr);
  } else {
    return 0;
  }
}


void RateLimiter::Key(char* out, struct sockaddr_storage* addr) {
  struct sockaddr_in* addr4;
  struct sockaddr_in6* addr6;

  if (addr->ss_family == AF_INET) {
    addr4 = (struct sockaddr_in*) addr;
    memcpy(out, &addr4->sin_addr, sizeof(addr4->sin_addr));
  } else if (addr->ss_family == AF_INET6) {
    addr6 = (struct sockaddr_in6*) addr;
    memcpy(out, &addr6->sin6_addr, sizeof(addr6->sin6_addr));
  }
}


void RateLimiter::Count(struct sockaddr_storage* addr) {
  unsigned int size = KeySize(addr);
  char* key = new char[size];
  Key(key, addr);

  Item* item = reinterpret_cast<Item*>(bud_hashmap_get(&map_, key, size));
  if (item == NULL) {
    item = new Item(this);
    ASSERT(0 == bud_hashmap_insert(&map_, key, size, item),
           "Failed to insert new rate limiter item");
  }

  struct timeval now;
  ASSERT(0 == gettimeofday(&now, NULL), "Failed to gettimeofday()");
  item->Count(1, &now);
}


void RateLimiter::Delay(ev_io* w, int fd, struct sockaddr_storage* addr) {
  unsigned int size = KeySize(addr);
  char key[16];
  Key(key, addr);

  Item* item = reinterpret_cast<Item*>(bud_hashmap_get(&map_, key, size));

  // No counter - immediate callback
  if (item == NULL || !item->triggered()) {
    Socket s;

    s.w = w;
    s.fd = fd;
    s.addr = *addr;
    return InvokeCb(&s);
  }

  Socket* s = new Socket();
  s->w = w;
  s->fd = fd;
  s->addr = *addr;
  item->Delay(s);
}


RateLimiter::Item::Item(RateLimiter* limiter) : limiter_(limiter),
                                                timer_running_(0),
                                                prev_counter_(0),
                                                counter_(0),
                                                list_(NULL) {
  memset(&prev_time_, 0, sizeof(prev_time_));

  // Just to make sure `ev_timer_stop` won't crash
  ev_timer_init(&timer_, OnTimeout, kBackoffTimeout, 0.0);
  timer_.data = this;
}


RateLimiter::Item::~Item() {
  ev_timer_stop(limiter()->loop(), &timer_);
  timer_running_ = 0;
}


void RateLimiter::Item::Count(int delta, struct timeval* now) {
  // Reduce counter after some time
  if (now->tv_sec - prev_time_.tv_sec > kCounterReset) {
    prev_time_ = *now;
    counter_ -= prev_counter_;
    prev_counter_ = counter_;
  }

  counter_ += delta;
  if (counter_ > kCounterTrigger)
    counter_ = kCounterTrigger;
}


void RateLimiter::Item::Delay(Socket* s) {
  if (!timer_running_) {
    ev_timer_init(&timer_, OnTimeout, kBackoffTimeout, 0.0);
    timer_.data = this;

    ev_timer_start(limiter()->loop(), &timer_);
    timer_running_ = 1;
  }

  s->next = list_;
  list_ = s;
}


void RateLimiter::Item::OnTimeout(struct ev_loop* loop,
                                  ev_timer* w,
                                  int revents) {
  (void) loop;
  (void) revents;

  RateLimiter::Item* item = reinterpret_cast<RateLimiter::Item*>(w->data);
  Socket* cur = item->list_;
  item->list_ = NULL;
  item->timer_running_ = 0;

  while (cur != NULL) {
    Socket* next = cur->next;
    item->limiter()->InvokeCb(cur);
    delete cur;

    cur = next;
  }
}
