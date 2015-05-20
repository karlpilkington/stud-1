#ifndef __RATE_LIMITER_HPP
#define __RATE_LIMITER_HPP

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <limits.h>

#include <ev.h>

#include "bud-common.hpp"
#include "configuration.h"

class RateLimiter {
 public:
  class Socket;

  typedef void (*Callback)(Socket* s);

  RateLimiter(struct ev_loop* loop, Callback cb, stud_config* config);
  ~RateLimiter();

  unsigned int KeySize(struct sockaddr_storage* addr);
  void Key(char* out, struct sockaddr_storage* addr);

  void Count(struct sockaddr_storage* addr);
  void Delay(ev_io* w, int fd, struct sockaddr_storage* addr);

  inline struct ev_loop* loop() { return loop_; }
  inline stud_config* config() { return config_; }
  inline void InvokeCb(Socket* s) { cb_(s); }

  class Socket {
   public:
    ev_io* w;
    int fd;
    struct sockaddr_storage addr;

    // Linked list
    double time;
    Socket* next;
  };

 private:
  class Item {
   public:
    Item(RateLimiter* limiter);

    void Count(int delta, double now);

    inline RateLimiter* limiter() { return limiter_; }
    inline bool triggered() {
      return counter_ >= limiter()->config()->RATE_COUNTER_TRIGGER;
    }
    inline bool empty() { return counter_ == 0; }

   protected:
    static const int kMaxCounter = INT_MAX;
    RateLimiter* limiter_;

    double prev_time_;
    int prev_counter_;
    int counter_;
  };

  static const unsigned int kDefaultMapSize = 1024;

  static int DestroyItems(bud_hashmap_item_t* item, void* arg);
  static void OnSweep(struct ev_loop* loop, ev_timer* w, int revents);
  static int SweepItems(bud_hashmap_item_t* item, void* arg);
  static void OnDelay(struct ev_loop* loop, ev_timer* w, int revents);

  void OnDelay();
  void StartDelay(double secs);

  struct ev_loop* loop_;
  struct ev_timer sweep_timer_;
  struct ev_timer delay_timer_;
  int delay_running_;

  Callback cb_;
  stud_config* config_;
  bud_hashmap_t map_;

  Socket* first_socket_;
  Socket* last_socket_;
};

#endif  // __RATE_LIMITER_HPP
