#ifndef __RATE_LIMITER_HPP
#define __RATE_LIMITER_HPP

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <ev.h>

#include "bud-common.hpp"

class RateLimiter {
 public:
  class Socket;

  typedef void (*Callback)(Socket* s);

  RateLimiter(struct ev_loop* loop, Callback cb);
  ~RateLimiter();

  unsigned int KeySize(struct sockaddr_storage* addr);
  void Key(char* out, struct sockaddr_storage* addr);

  void Count(struct sockaddr_storage* addr);
  void Delay(ev_io* w, int fd, struct sockaddr_storage* addr);

  inline struct ev_loop* loop() { return loop_; }
  inline void InvokeCb(Socket* s) { cb_(s); }

  class Socket {
   public:
    ev_io* w;
    int fd;
    struct sockaddr_storage addr;

    // Linked list
    Socket* next;
  };

 private:
  class Item {
   public:
    Item(RateLimiter* limiter);
    ~Item();

    void Count(int delta, struct timeval* now);
    void Delay(Socket* s);

    inline RateLimiter* limiter() { return limiter_; }
    inline bool triggered() { return counter_ >= kCounterTrigger; }
    inline bool empty() { return counter_ == 0; }

   protected:
    static void OnTimeout(struct ev_loop* loop, ev_timer* w, int revents);

    static constexpr double kBackoffTimeout = 15.0;  // in seconds
    static const int kCounterReset = 10;  // in seconds
    static const int kCounterTrigger = 50;

    RateLimiter* limiter_;
    struct ev_timer timer_;
    int timer_running_ : 1;

    struct timeval prev_time_;
    int prev_counter_;
    int counter_;

    Socket* list_;
  };

  static const unsigned int kDefaultMapSize = 1024;
  static constexpr double kSweepInterval = 4.0;  // in seconds

  static int DestroyItems(bud_hashmap_item_t* item, void* arg);
  static void OnSweep(struct ev_loop* loop, ev_timer* w, int revents);
  static int SweepItems(bud_hashmap_item_t* item, void* arg);

  struct ev_loop* loop_;
  struct ev_timer sweep_timer_;
  Callback cb_;
  bud_hashmap_t map_;
};

#endif  // __RATE_LIMITER_HPP
