# [g]make USE_xxxx=1
#
# USE_SHARED_CACHE   :   enable/disable a shared session cache (disabled by default)

DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man
PLATFORM = $(shell sh -c 'uname -s | tr "[A-Z]" "[a-z]"')

LDFLAGS = -g -lm -m64
CC = gcc
CXX = g++
CPPFLAGS = -O2 -m64 -Ideps/libev -g -march=native -DNDEBUG -Wall
CXXFLAGS = -std=c++0x -fpermissive 
OBJS = stud.o configuration.o deps/libev/.libs/libev.a

DTRACE=/usr/sbin/dtrace
all: realall

# Shared cache feature
ifneq ($(USE_SHARED_CACHE),)
CPPFLAGS += -DUSE_SHARED_CACHE -DUSE_SYSCALL_FUTEX
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
CPPFLAGS += -DNO_CONFIG_FILE
endif

ifeq ($(SHARED_OPENSSL),1)
LDFLAGS += -lssl -lcrypto
else
CPPFLAGS += -Ideps/openssl/include
OBJS += deps/openssl/libssl.a deps/openssl/libcrypto.a
endif

ifeq ($(PLATFORM),sunos)
LDFLAGS += -lsocket -L/opt/local/lib -Wl,-R/opt/local/lib -lnsl
CPPFLAGS += -DSTUD_DTRACE=1

OBJS += stud_provider.o

stud_provider.h: stud_provider.d
	$(DTRACE) -64 -h -xnolibs -s $^ -o $@

stud_provider.o: stud.o stud_provider.d
	$(DTRACE) -64 -G -xnolibs -s stud_provider.d -o $@ stud.o

ALL += stud_provider.h
else
LDFLAGS += -ldl
endif

ALL += stud
realall: $(ALL)

stud.o: stud.cc SimpleMemoryPool.hpp

stud: $(OBJS) SimpleMemoryPool.hpp
	$(CXX)  $(CPPFLAGS) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

deps/libev/.libs/libev.a: deps/libev/Makefile
	$(MAKE) $(MAKEFLAGS) -C deps/libev

deps/libev/Makefile:
	cd deps/libev && ./configure

# Forward dependency
deps/openssl/libssl.a: deps/openssl/libcrypto.a

ifeq ($(PLATFORM),darwin)
OPENSSL_PLATFORM = darwin64-x86_64-cc
else ifeq ($(PLATFORM),sunos)
OPENSSL_PLATFORM = solaris64-x86_64-gcc
else
OPENSSL_PLATFORM = linux-x86_64
endif

deps/openssl/libcrypto.a:
	cd deps/openssl && ./Configure no-idea no-mdc2 no-rc5 enable-tlsext $(OPENSSL_PLATFORM)
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
