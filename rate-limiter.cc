#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "rate-limiter.hpp"

#include "bud-common.hpp"

#define LOG(CONFIG, ...)                                    \
    do {                                                    \
      if (!(CONFIG)->QUIET) fprintf(stdout, __VA_ARGS__);   \
      if ((CONFIG)->SYSLOG) syslog(LOG_INFO, __VA_ARGS__);  \
    } while(0)

RateLimiter::RateLimiter(struct ev_loop* loop,
                         Callback cb,
                         stud_config* config)
    : loop_(loop),
      delay_running_(0),
      cb_(cb),
      config_(config),
      first_socket_(NULL),
      last_socket_(NULL) {
  ASSERT(0 == bud_hashmap_init(&map_, kDefaultMapSize),
         "Failed to init rate limiter hashmap");

  double sweep_interval = static_cast<double>(config->RATE_SWEEP_INTERVAL);
  ev_timer_init(&sweep_timer_, OnSweep, sweep_interval, sweep_interval);
  sweep_timer_.data = this;

  ev_timer_start(loop_, &sweep_timer_);
}


RateLimiter::~RateLimiter() {
  ev_timer_stop(loop(), &sweep_timer_);
  if (delay_running_)
    ev_timer_stop(loop(), &delay_timer_);

  ASSERT(0 == bud_hashmap_iterate(&map_, DestroyItems, NULL),
         "Failed to destroy limiter hashmap items");
  bud_hashmap_destroy(&map_);
}


inline double timeval_to_double(struct timeval* tv) {
  return static_cast<double>(tv->tv_sec) +
         static_cast<double>(tv->tv_usec) * 1e-6;
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

  struct timeval now_tv;
  ASSERT(0 == gettimeofday(&now_tv, NULL), "Failed to gettimeofday()");

  double now = timeval_to_double(&now_tv);
  ASSERT(0 == bud_hashmap_iterate(&r->map_, SweepItems, &now),
         "Failed to sweep limiter hashmap items");

  LOG(r->config(), "rate-limiter: sweeping\n");
}


int RateLimiter::SweepItems(bud_hashmap_item_t* item, void* arg) {
  Item* i = reinterpret_cast<Item*>(item->value);
  double* now = reinterpret_cast<double*>(arg);

  // Update timeout, decrease count
  i->Count(0, *now);

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
  item->Count(1, timeval_to_double(&now));
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
    InvokeCb(&s);
    return;
  }

  Socket* s = new Socket();
  s->w = w;
  s->fd = fd;
  s->addr = *addr;

  struct timeval now;
  ASSERT(0 == gettimeofday(&now, NULL), "Failed to gettimeofday()");
  s->time = timeval_to_double(&now);

  // Insert into linked list (sorted by increasing time)
  if (first_socket_ == NULL)
    first_socket_ = s;
  s->next = NULL;
  if (last_socket_ != NULL)
    last_socket_->next = s;
  last_socket_ = s;

  // Start timer if not running
  int delay_interval = config()->RATE_BACKOFF_TIMEOUT;
  StartDelay(static_cast<double>(delay_interval));

  LOG(config(), "rate-limiter: delaying socket\n");
}


RateLimiter::Item::Item(RateLimiter* limiter) : limiter_(limiter),
                                                prev_time_(0.0),
                                                prev_counter_(0),
                                                counter_(0) {
}


void RateLimiter::Item::Count(int delta, double now) {
  stud_config* config = limiter()->config();

  // Reduce counter after some time
  double timeout = static_cast<double>(config->RATE_COUNTER_RESET_TIMEOUT);
  if (now - prev_time_ > timeout) {
    prev_time_ = now;
    counter_ -= prev_counter_;
    prev_counter_ = counter_;
  }

  counter_ += delta;
  if (counter_ > config->RATE_COUNTER_TRIGGER)
    counter_ = config->RATE_COUNTER_TRIGGER;
}


void RateLimiter::OnDelay(struct ev_loop* loop,
                          ev_timer* w,
                          int revents) {
  (void) loop;
  (void) revents;

  RateLimiter* r = reinterpret_cast<RateLimiter*>(w->data);
  r->OnDelay();
}


void RateLimiter::StartDelay(double secs) {
  if (delay_running_)
    return;

  ev_timer_init(&delay_timer_, OnDelay, secs, 0.0);
  delay_timer_.data = this;
  ev_timer_start(loop_, &delay_timer_);

  delay_running_ = 1;

  LOG(config(), "rate-limiter: invoking OnDelay in %f secs\n", secs);
}


void RateLimiter::OnDelay() {
  Socket* cur = first_socket_;

  delay_running_ = 0;
  LOG(config(), "rate-limiter: OnDelay\n");

  int delay_interval = config()->RATE_BACKOFF_TIMEOUT;

  // Figure out maximum socket's time
  struct timeval edge_tv;
  ASSERT(0 == gettimeofday(&edge_tv, NULL), "Failed to gettimeofday()");
  double edge = timeval_to_double(&edge_tv);

  // It should be much greater than delay_interval
  edge -= static_cast<double>(delay_interval);

  while (cur != NULL && cur->time <= edge) {
    Socket* next = cur->next;

    InvokeCb(cur);
    delete cur;

    cur = next;
  }

  // Restart timer if there are more things to run
  if (cur != NULL)
    StartDelay(cur->time - edge);

  first_socket_ = cur;

  // Consumed everything
  if (first_socket_ == NULL)
    last_socket_ = NULL;
}
