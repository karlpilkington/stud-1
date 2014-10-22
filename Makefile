# [g]make USE_xxxx=1
#
# USE_SHARED_CACHE   :   enable/disable a shared session cache (disabled by default)

DESTDIR =
PREFIX  = /usr/local
BINDIR  = $(PREFIX)/bin
MANDIR  = $(PREFIX)/share/man
PLATFORM = $(shell sh -c 'uname -s | tr "[A-Z]" "[a-z]"')

CPPFLAGS = -O2 -m64 -Ideps/libev -g -march=native -DNDEBUG -Wall
CXXFLAGS = -std=c++0x -fpermissive 
OBJS = stud.o configuration.o deps/libev/.libs/libev.a
LDFLAGS = -g -lm -m64
STUD_ROOT_DIR := $(shell pwd)

ifeq ($(STUD_FIPS_MODE),1)
	FIPSDIR ?= $(STUD_ROOT_DIR)/deps/fips-build
	FIPSLIBDIR ?= $(FIPSDIR)/lib
	CC = $(FIPSDIR)/bin/fipsld
	CXX = $(FIPSDIR)/bin/fipsld
	CPPFLAGS += -DSTUD_FIPS_MODE=1
else
	CC ?= gcc
	CXX ?= g++
endif

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
endif

ifeq ($(PLATFORM),freebsd)
else
LDFLAGS += -ldl
endif

ALL += stud
realall: $(ALL)

stud.o: stud.cc SimpleMemoryPool.hpp

stud: $(OBJS)
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
else ifeq ($(PLATFORM),freebsd)
OPENSSL_PLATFORM = BSD-x86_64
else
OPENSSL_PLATFORM = linux-x86_64
endif

deps/openssl/libcrypto.a:
ifeq ($(STUD_FIPS_MODE),1)
	cd deps && tar -xzf openssl-fips-2.0.5.tar.gz \
		&& cd openssl-fips-2.0.5/ \
		&& ./config fipscanisterbuild --prefix=$(FIPSDIR)\
		&& make && make install \
		&& cp $(STUD_ROOT_DIR)/deps/backup/fipsld $(FIPSDIR)/bin
	cd deps/openssl && ./Configure no-idea no-mdc2 no-rc5 fips enable-tlsext \
			--with-fipsdir=$(FIPSDIR) $(OPENSSL_PLATFORM)
else
	cd deps/openssl && ./Configure no-idea no-mdc2 no-rc5 enable-tlsext $(OPENSSL_PLATFORM)
endif
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
	rm -rfd deps/openssl-fips-2.0.5/


.PHONY: all realall
