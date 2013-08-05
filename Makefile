# [g]make USE_xxxx=1
#
# USE_SHARED_CACHE   :   enable/disable a shared session cache (disabled by default)

DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man

LDFLAGS=-g -lm -lsocket -lnsl -m64 -L/opt/local/lib -Wl,-R/opt/local/lib
CC=gcc
CFLAGS=-O2 -m64 -Ideps/libev -Ideps/openssl/include -g -march=native -DNDEBUG
OBJS    =stud_provider.o stud.o configuration.o \
				 deps/libev/.libs/libev.a deps/openssl/libssl.a deps/openssl/libcrypto.a

all: realall

# Shared cache feature
ifneq ($(USE_SHARED_CACHE),)
CFLAGS += -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX
OBJS   += shctx.o ebtree/libebtree.a
ALL    += ebtree

ebtree/libebtree.a: $(wildcard ebtree/*.c)
	make -C ebtree
ebtree:
	@[ -d ebtree ] || ( \
		echo "*** Download libebtree at http://1wt.eu/tools/ebtree/" ; \
		echo "*** Untar it and make a link named 'ebtree' to point on it"; \
		exit 1 )
endif

# No config file support?
ifneq ($(NO_CONFIG_FILE),)
CFLAGS += -DNO_CONFIG_FILE
endif

stud_provider.h: stud_provider.d
	dtrace -64 -h -xnolibs -s $^ -o $@

stud_provider.o: stud.o stud_provider.d
	dtrace -64 -G -xnolibs -s stud_provider.d -o $@ stud.o

ALL += stud_provider.h

ALL += stud
realall: $(ALL)

stud: $(OBJS)
	$(CC)  $(CFLAGS) -o $@ $^ $(LDFLAGS)

deps/libev/.libs/libev.a: deps/libev/Makefile
	$(MAKE) $(MAKEFLAGS) -C deps/libev

deps/libev/Makefile:
	cd deps/libev && ./configure

# Forward dependency
deps/openssl/libssl.a: deps/openssl/libcrypto.a

deps/openssl/libcrypto.a:
	cd deps/openssl && ./Configure no-idea no-mdc2 no-rc5 enable-tlsext solaris64-x86_64-gcc
	-$(MAKE) $(MAKEFLAGS) -C deps/openssl depend
	-$(MAKE) $(MAKEFLAGS) -C deps/openssl

install: $(ALL)
	install -d $(DESTDIR)$(BINDIR)
	install stud $(DESTDIR)$(BINDIR)
	install -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 stud.8 $(DESTDIR)$(MANDIR)/man8

clean:
	rm -f stud $(OBJS) stud_provider.h
	make -C deps/openssl clean
	make -C deps/libev clean


.PHONY: all realall
