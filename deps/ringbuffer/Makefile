CFLAGS ?=
CFLAGS += -g -O3 -Wall

OBJS =
OBJS += ringbuffer.o
OBJS += test.o

all: test

ringbuffer.o: ringbuffer.h

test-ringbuffer: $(OBJS)
	$(CC) $(CFLAGS) $^ -o test-ringbuffer

test: test-ringbuffer
	./test-ringbuffer
