/**
  * Copyright 2011 Bump Technologies, Inc. All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without modification, are
  * permitted provided that the following conditions are met:
  *
  *    1. Redistributions of source code must retain the above copyright notice, this list of
  *       conditions and the following disclaimer.
  *
  *    2. Redistributions in binary form must reproduce the above copyright notice, this list
  *       of conditions and the following disclaimer in the documentation and/or other materials
  *       provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY BUMP TECHNOLOGIES, INC. ``AS IS'' AND ANY EXPRESS OR IMPLIED
  * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
  * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL BUMP TECHNOLOGIES, INC. OR
  * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
  * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
  * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
  *
  * The views and conclusions contained in the software and documentation are those of the
  * authors and should not be interpreted as representing official policies, either expressed
  * or implied, of Bump Technologies, Inc.
  *
  **/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <arpa/inet.h>
char *inet_ntoa_r(const struct in_addr in, char *buffer, socklen_t buflen);
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <limits.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdbool.h>

#ifdef __sun
#include <sys/filio.h>
#include <sys/signal.h>
#endif

#include <ctype.h>
#include <sched.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <ev.h>

#ifdef STUD_DTRACE
# include "stud_provider.h"
#else  /* STUD_DTRACE */
# define STUD_SSL_SESSION_REUSE_ENABLED(a) 0
# define STUD_SSL_SESSION_REUSE(a, b, c) do { } while (0)
# define STUD_SSL_SESSION_NEW(a, b, c) do { } while (0)
#endif  /* STUD_DTRACE */

#include "ringbuffer.h"
#include "shctx.h"
#include "configuration.h"
#include "SimpleMemoryPool.hpp"

#ifndef MSG_NOSIGNAL
# define MSG_NOSIGNAL 0
#endif
#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG 0
#endif

#ifndef SOL_TCP
# define SOL_TCP IPPROTO_TCP
#endif

/* Do we have SNI support? */
#ifndef OPENSSL_NO_TLSEXT
#ifndef SSL_CTRL_SET_TLSEXT_HOSTNAME
#define OPENSSL_NO_TLSEXT
#endif
#endif

/* Globals */
static struct ev_loop *loop;
static struct addrinfo *backaddr;
static pid_t master_pid;
static ev_io listener;
static int listener_socket;
static int child_num;
static pid_t *child_pids;
static SSL_CTX *default_ctx;
static SSL_SESSION *client_session;

#ifdef USE_SHARED_CACHE
static ev_io shcupd_listener;
static int shcupd_socket;
struct addrinfo *shcupd_peers[MAX_SHCUPD_PEERS+1];
static unsigned char shared_secret[SHA_DIGEST_LENGTH];
#endif /*USE_SHARED_CACHE*/

long openssl_version;
int create_workers;
stud_config *CONFIG;

static char tcp_proxy_line[128] = "";

/* What agent/state requests the shutdown--for proper half-closed
 * handling */
typedef enum _SHUTDOWN_REQUESTOR {
    SHUTDOWN_HARD,
    SHUTDOWN_CLEAR,
    SHUTDOWN_SSL
} SHUTDOWN_REQUESTOR;

#ifndef OPENSSL_NO_TLSEXT
/*
 * SSL context linked list. Someday it might be nice to have a more clever data
 * structure here, but assuming the number of SNI certs is small it probably
 * doesn't matter.
 */
typedef struct ctx_list {
    char *servername;
    SSL_CTX *ctx;
    struct ctx_list *next;
} ctx_list;

static ctx_list *sni_ctxs;

#endif /* OPENSSL_NO_TLSEXT */

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)
/*
 * Proxied State
 *
 * All state associated with one proxied connection
 */
typedef struct proxystate {
    //ringbuffer ring_ssl2clear;          /* Pushing bytes from secure to clear stream */
    //ringbuffer ring_clear2ssl;          /* Pushing bytes from clear to secure stream */

    ev_io ev_r_ssl;                     /* Secure stream write event */
    ev_io ev_w_ssl;                     /* Secure stream read event */

    ev_io ev_r_handshake;               /* Secure stream handshake write event */
    ev_io ev_w_handshake;               /* Secure stream handshake read event */

    ev_io ev_w_connect;                 /* Backend connect event */

    ev_io ev_r_clear;                   /* Clear stream write event */
    ev_io ev_w_clear;                   /* Clear stream read event */

    ev_io ev_proxy;                     /* proxy read event */

    int fd_up;                          /* Upstream (client) socket */
    int fd_down;                        /* Downstream (backend) socket */

    int want_shutdown:1;                /* Connection is half-shutdown */
    int handshaked:1;                   /* Initial handshake happened */
    int clear_connected:1;              /* Clear stream is connected  */
    int renegotiation:1;                /* Renegotation is occuring */

    SSL *ssl;                           /* OpenSSL SSL state */

    struct sockaddr_storage remote_ip;  /* Remote ip returned from `accept` */
    ringbuffer_t ring_ssl2clear;
    ringbuffer_t ring_clear2ssl;
    char buf[RINGBUFFER_SIZE*2];
} proxystate;

SimpleMemoryPool <proxystate,8192,sizeof(proxystate)> SPool;
SimpleMemoryPool <char,8192,24*1024> SPool24K;
char *SPool24K_Start;
size_t SPool24K_Size;

#define LOG(...)                                            \
    do {                                                    \
      if (!CONFIG->QUIET) fprintf(stdout, __VA_ARGS__);     \
      if (CONFIG->SYSLOG) syslog(LOG_INFO, __VA_ARGS__);    \
    } while(0)

#define L_ERR(...)                                            \
    do {                                                    \
      fprintf(stderr, __VA_ARGS__);                         \
      if (CONFIG->SYSLOG) syslog(LOG_ERR, __VA_ARGS__);     \
    } while(0)

#define NULL_DEV "/dev/null"

void get_client_info(proxystate* ps, char* host, size_t host_size, int* port) {
    struct sockaddr_in* addr = (struct sockaddr_in*) &ps->remote_ip;

    if (addr->sin_family == AF_INET) {
        inet_ntop(AF_INET, &(addr->sin_addr), host, host_size);
        *port = ntohs(addr->sin_port);
    } else if (addr->sin_family == AF_INET6 ) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*) &ps->remote_ip;
        inet_ntop(AF_INET6, &(addr6->sin6_addr), host, host_size);
        *port = ntohs(addr6->sin6_port);
    }
}

/* Set a file descriptor (socket) to non-blocking mode */
static void setnonblocking(int fd) {
    int flag;
    int r;
#if defined(O_NONBLOCK)
    /* O_NONBLOCK is more portable and POSIX-standard */
    flag = O_NONBLOCK;
    do
        r = fcntl(fd, F_SETFL, flag);
    while (r == -1 && errno == EINTR);
    assert(r == 0);
#elif defined(FIONBIO)
    flag = 1;
    do
        r = ioctl(fd, FIONBIO, &set);
    while (r == -1 && errno == EINTR);
    assert(r == 0);
#else
# error O_NONBLOCK and FIONBIO are both undefined for this platform
#endif
}

/* set a tcp socket to use TCP Keepalive */
static void settcpkeepalive(int fd) {
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    if(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        L_ERR("Error activating SO_KEEPALIVE on client socket: %s", strerror(errno));
    }
/*  #ifdef TCP_KEEPIDLE
    optval = CONFIG->TCP_KEEPALIVE_TIME;
    optlen = sizeof(optval);
    if(setsockopt(fd, SOL_TCP, TCP_KEEPALIVE, &optval, optlen) < 0) {
        L_ERR("Error setting TCP_KEEPALIVE on client socket: %s", strerror(errno));
    }
#endif  */
}

static void fail(const char* s) {
    perror(s);
    exit(1);
}

void die (char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    exit(1);
}

#ifndef OPENSSL_NO_DH
static int init_dh(SSL_CTX *ctx, const char *cert) {
    DH *dh;
    BIO *bio;

    assert(cert);

    bio = BIO_new_file(cert, "r");
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!dh) {
        L_ERR("op=init_no_dh no DH parameters found in %s\n", cert);
        return -1;
    }

    LOG("{core} Using DH parameters from %s\n", cert);
    SSL_CTX_set_tmp_dh(ctx, dh);
    LOG("{core} DH initialized with %d bit key\n", 8*DH_size(dh));
    DH_free(dh);

#ifndef OPENSSL_NO_EC
#ifdef NID_X9_62_prime256v1
    EC_KEY *ecdh = NULL;
    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    LOG("{core} ECDH Initialized with NIST P-256\n");
#endif /* NID_X9_62_prime256v1 */
#endif /* OPENSSL_NO_EC */

    return 0;
}
#endif /* OPENSSL_NO_DH */

/* This callback function is executed while OpenSSL processes the SSL
 * handshake and does SSL record layer stuff.  It's used to trap
 * client-initiated renegotiations.
 */
static void info_callback(const SSL *ssl, int where, int ret) {
    (void)ret;
    if (where & SSL_CB_HANDSHAKE_START) {
        proxystate *ps = (proxystate *)SSL_get_app_data(ssl);
        if (ps->handshaked) {
            ps->renegotiation = 1;
            LOG("{core} SSL renegotiation asked by client\n");
        }
    }
}

#ifdef USE_SHARED_CACHE

/* Handle incoming message updates */
static void handle_shcupd(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    unsigned char msg[SHSESS_MAX_ENCODED_LEN], hash[EVP_MAX_MD_SIZE];
    ssize_t r;
    unsigned int hash_len;
    uint32_t encdate;
    long now = (time_t)ev_now(loop);

    while ( ( r = recv(w->fd, msg, sizeof(msg), 0) ) > 0 ) {

        /* msg len must be greater than 1 Byte of data + sig length */
        if (r < (int)(1+sizeof(shared_secret)))
           continue;

        /* compute sig */
        r -= sizeof(shared_secret);
        HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret), msg, r, hash, &hash_len);

        if (hash_len != sizeof(shared_secret)) /* should never append */
           continue;

        /* check sign */
        if(memcmp(msg+r, hash, hash_len))
           continue;

        /* msg len must be greater than 1 Byte of data + encdate length */
        if (r < (int)(1+sizeof(uint32_t)))
           continue;

        /* drop too unsync updates */
        r -= sizeof(uint32_t);
        encdate = *((uint32_t *)&msg[r]);
        if (!(abs((int)(int32_t)now-ntohl(encdate)) < SSL_CTX_get_timeout(default_ctx)))
           continue;

        shctx_sess_add(msg, r, now);
    }
}

/* Send remote updates messages callback */
void shcupd_session_new(unsigned char *msg, unsigned int len, long cdate) {
    unsigned int hash_len;
    struct addrinfo **pai = shcupd_peers;
    uint32_t ncdate;

    /* add session creation encoded date to footer */
    ncdate = htonl((uint32_t)cdate);
    memcpy(msg+len, &ncdate, sizeof(ncdate));
    len += sizeof(ncdate);

    /* add msg sign */
    HMAC(EVP_sha1(), shared_secret, sizeof(shared_secret),
                     msg, len, msg+len, &hash_len);
    len += hash_len;

    /* send msg to peers */
    while (*pai) {
        sendto(shcupd_socket, msg, len, 0, (*pai)->ai_addr, (*pai)->ai_addrlen);
        pai++;
    }
}

/* Compute a sha1 secret from an ASN1 rsa private key */
static int compute_secret(RSA *rsa, unsigned char *secret) {
    unsigned char *buf,*p;
    unsigned int length;

    length = i2d_RSAPrivateKey(rsa, NULL);
    if (length <= 0)
        return -1;

    p = buf = (unsigned char *)malloc(length*sizeof(unsigned char));
    if (!buf)
        return -1;

    i2d_RSAPrivateKey(rsa,&p);

    SHA1(buf, length, secret);

    free(buf);

    return 0;
}

/* Create udp socket to receive and send updates */
static int create_shcupd_socket() {
    struct addrinfo *ai, hints;
    struct addrinfo **pai = shcupd_peers;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->SHCUPD_IP, CONFIG->SHCUPD_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        L_ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    /* check if peers inet family addresses match */
    while (*pai) {
        if ((*pai)->ai_family != ai->ai_family) {
            L_ERR("Share host and peers inet family differs\n");
            exit(1);
        }
        pai++;
    }

    int s = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);

    if (s == -1)
      fail("{socket: shared cache updates}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif

    setnonblocking(s);

    if (ai->ai_addr->sa_family == AF_INET) {
        struct ip_mreqn mreqn;

        memset(&mreqn, 0, sizeof(mreqn));
        mreqn.imr_multiaddr.s_addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

        if (CONFIG->SHCUPD_MCASTIF) {
            if (isalpha(*CONFIG->SHCUPD_MCASTIF)) { /* appears to be an iface name */
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
                    L_ERR("Error iface name is too long [%s]\n",CONFIG->SHCUPD_MCASTIF);
                    exit(1);
                }

                memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF, strlen(CONFIG->SHCUPD_MCASTIF));
                if (ioctl(s, SIOCGIFINDEX, &ifr)) {
                    fail("{ioctl: SIOCGIFINDEX}");
                }

                mreqn.imr_ifindex = ifr.ifr_ifindex;
            }
            else if (strchr(CONFIG->SHCUPD_MCASTIF,'.')) { /* appears to be an ipv4 address */
                mreqn.imr_address.s_addr = inet_addr(CONFIG->SHCUPD_MCASTIF);
            }
            else { /* appears to be an iface index */
                mreqn.imr_ifindex = atoi(CONFIG->SHCUPD_MCASTIF);
            }
        }

        if (setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn, sizeof(mreqn)) < 0) {
            if (errno != EINVAL) { /* EINVAL if it is not a multicast address,
                                                not an error we consider unicast */
                fail("{setsockopt: IP_ADD_MEMBERSIP}");
            }
        }
        else { /* this is a multicast address */
            unsigned char loop = 0;

            if(setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
               fail("{setsockopt: IP_MULTICAST_LOOP}");
            }
        }

        /* optional set sockopts for sending to multicast msg */
        if (CONFIG->SHCUPD_MCASTIF &&
            setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) < 0) {
            fail("{setsockopt: IP_MULTICAST_IF}");
        }

        if (CONFIG->SHCUPD_MCASTTTL) {
             unsigned char ttl;

             ttl = (unsigned char)atoi(CONFIG->SHCUPD_MCASTTTL);
             if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
                 fail("{setsockopt: IP_MULTICAST_TTL}");
             }
        }

     }
#ifdef IPV6_ADD_MEMBERSHIP
     else if (ai->ai_addr->sa_family == AF_INET6) {
        struct ipv6_mreq mreq;

        memset(&mreq, 0, sizeof(mreq));
        memcpy(&mreq.ipv6mr_multiaddr, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr,
                                       sizeof(mreq.ipv6mr_multiaddr));

        if (CONFIG->SHCUPD_MCASTIF) {
            if (isalpha(*CONFIG->SHCUPD_MCASTIF)) { /* appears to be an iface name */
                struct ifreq ifr;

                memset(&ifr, 0, sizeof(ifr));
                if (strlen(CONFIG->SHCUPD_MCASTIF) > IFNAMSIZ) {
                    L_ERR("Error iface name is too long [%s]\n",CONFIG->SHCUPD_MCASTIF);
                    exit(1);
                }

                memcpy(ifr.ifr_name, CONFIG->SHCUPD_MCASTIF, strlen(CONFIG->SHCUPD_MCASTIF));
                if (ioctl(s, SIOCGIFINDEX, &ifr)) {
                    fail("{ioctl: SIOCGIFINDEX}");
                }

                mreq.ipv6mr_interface = ifr.ifr_ifindex;
            }
            else { /* option appears to be an iface index */
                mreq.ipv6mr_interface = atoi(CONFIG->SHCUPD_MCASTIF);
            }
        }

        if (setsockopt(s, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
            if (errno != EINVAL) { /* EINVAL if it is not a multicast address,
                                                not an error we consider unicast */
                fail("{setsockopt: IPV6_ADD_MEMBERSIP}");
            }
        }
        else { /* this is a multicast address */
            unsigned int loop = 0;

            if(setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof(loop)) < 0) {
               fail("{setsockopt: IPV6_MULTICAST_LOOP}");
            }
        }

        /* optional set sockopts for sending to multicast msg */
        if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF,
                               &mreq.ipv6mr_interface, sizeof(mreq.ipv6mr_interface)) < 0) {
            fail("{setsockopt: IPV6_MULTICAST_IF}");
        }

        if (CONFIG->SHCUPD_MCASTTTL) {
            int hops;

            hops = atoi(CONFIG->SHCUPD_MCASTTTL);
            if (setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0) {
                fail("{setsockopt: IPV6_MULTICAST_HOPS}");
            }
        }
    }
#endif /* IPV6_ADD_MEMBERSHIP */

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

    freeaddrinfo(ai);

    return s;
}

#endif /*USE_SHARED_CACHE */

RSA *load_rsa_privatekey(SSL_CTX *ctx, const char *file) {
    BIO *bio;
    RSA *rsa;

    bio = BIO_new_file(file, "r");
    if (!bio) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    rsa = PEM_read_bio_RSAPrivateKey(bio, NULL,
          ctx->default_passwd_callback, ctx->default_passwd_callback_userdata);
    BIO_free(bio);

    return rsa;
}

#ifndef OPENSSL_NO_TLSEXT
/*
 * Switch the context of the current SSL object to the most appropriate one
 * based on the SNI header
 */
int sni_switch_ctx(SSL *ssl, int *al, void *data) {
    (void)data;
    (void)al;
    const char *servername;
    const ctx_list *cl;

    servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!servername) return SSL_TLSEXT_ERR_NOACK;

    // For now, just compare servernames as case insensitive strings. Someday,
    // it might be nice to Do The Right Thing around star certs.
    for (cl = sni_ctxs; cl != NULL; cl = cl->next) {
        if (strcasecmp(servername, cl->servername) == 0) {
            SSL_set_SSL_CTX(ssl, cl->ctx);
            return SSL_TLSEXT_ERR_NOACK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}
#endif /* OPENSSL_NO_TLSEXT */


/*
 * Initialize an SSL context
 */

SSL_CTX *make_ctx(const char *pemfile) {
    SSL_CTX *ctx;
    RSA *rsa;

    long ssloptions = SSL_OP_NO_SSLv2 | SSL_OP_ALL |
            SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;

#ifdef SSL_OP_NO_COMPRESSION
    ssloptions |= SSL_OP_NO_COMPRESSION;
#endif

    if (CONFIG->ETYPE == ENC_TLS) {
        ctx = SSL_CTX_new((CONFIG->PMODE == SSL_CLIENT) ?
                TLSv1_client_method() : TLSv1_server_method());
    } else if (CONFIG->ETYPE == ENC_SSL) {
        ctx = SSL_CTX_new((CONFIG->PMODE == SSL_CLIENT) ?
                SSLv23_client_method() : SSLv23_server_method());
    } else {
        assert(CONFIG->ETYPE == ENC_TLS || CONFIG->ETYPE == ENC_SSL);
        return NULL; // Won't happen, but gcc was complaining
    }

    SSL_CTX_set_options(ctx, ssloptions);
    SSL_CTX_set_info_callback(ctx, info_callback);

    if (CONFIG->CIPHER_SUITE) {
        if (SSL_CTX_set_cipher_list(ctx, CONFIG->CIPHER_SUITE) != 1) {
            ERR_print_errors_fp(stderr);
        }
    }

    if (CONFIG->PREFER_SERVER_CIPHERS) {
        SSL_CTX_set_options(ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    }

    if (CONFIG->EC_CURVE != NULL) {
      int ecdh_nid;

      ecdh_nid = OBJ_sn2nid(CONFIG->EC_CURVE);
      if (ecdh_nid == NID_undef) {
        fprintf(stderr, "EC curve id '%s' not found\n", CONFIG->EC_CURVE);
      } else {
        EC_KEY* ecdh;

        ecdh = EC_KEY_new_by_curve_name(ecdh_nid);
        if (ecdh == NULL) {
          fprintf(stderr, "EC curve '%s' not found\n", CONFIG->EC_CURVE);
        } else {
          SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
          SSL_CTX_set_tmp_ecdh(ctx, ecdh);
          EC_KEY_free(ecdh);
        }
      }
    }

    if (CONFIG->PMODE == SSL_CLIENT) {
        return ctx;
    }

    /* SSL_SERVER Mode stuff */
    if (SSL_CTX_use_certificate_chain_file(ctx, pemfile) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    rsa = load_rsa_privatekey(ctx, pemfile);
    if (!rsa) {
       L_ERR("Error loading rsa private key\n");
       exit(1);
    }

    if (SSL_CTX_use_RSAPrivateKey(ctx, rsa) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

#ifndef OPENSSL_NO_DH
    init_dh(ctx, pemfile);
#endif /* OPENSSL_NO_DH */

#ifndef OPENSSL_NO_TLSEXT
    if (!SSL_CTX_set_tlsext_servername_callback(ctx, sni_switch_ctx)) {
        L_ERR("Error setting up SNI support\n");
    }
#endif /* OPENSSL_NO_TLSEXT */

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        if (shared_context_init(ctx, CONFIG->SHARED_CACHE) < 0) {
            L_ERR("Unable to alloc memory for shared cache.\n");
            exit(1);
        }
        if (CONFIG->SHCUPD_PORT) {
            if (compute_secret(rsa, shared_secret) < 0) {
                L_ERR("Unable to compute shared secret.\n");
                exit(1);
            }

            /* Force tls tickets cause keys differs */
            SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);

            if (*shcupd_peers) {
                shsess_set_new_cbk(shcupd_session_new);
            }
        }
    }
#endif

    RSA_free(rsa);
    return ctx;
}


static void *stud_malloc(size_t size){
    const uint64_t MAX_SIZE=20*1024;
    void *ptr=NULL;
    // check if the allocation is between 20 & 24 KB 
    if(((uint64_t)size - MAX_SIZE) <=4096){
        ptr=SPool24K.Get();
    }
    return (ptr!=NULL)?ptr:malloc(size);
}

static void *stud_realloc(void *ptr, size_t size){
    uint64_t p=(uint64_t)ptr;
    if(unlikely((p-(uint64_t)SPool24K_Start) < SPool24K_Size)){
        if(((uint64_t)size -1UL) <= (24*1024)){
            return ptr;
        }
        SPool24K.Release((char *)ptr);
        return stud_malloc(size);
    }
    return realloc(ptr,size);
}

static void stud_free(void *ptr){
    if(unlikely(((uint64_t)ptr-(uint64_t)SPool24K_Start) <= SPool24K_Size)){
        SPool24K.Release((char *)ptr);
    }else{
        free(ptr);
    }
}

/* Init library and load specified certificate.
 * Establishes a SSL_ctx, to act as a template for
 * each connection */
void init_openssl() {
    CRYPTO_set_mem_functions(stud_malloc,stud_realloc,stud_free);
    SSL_library_init();
    SSL_load_error_strings();

    assert(CONFIG->CERT_FILES != NULL);

    // The first file (i.e., the last file listed in config) is always the
    // "default" cert
    default_ctx = make_ctx(CONFIG->CERT_FILES->CERT_FILE);

#ifndef OPENSSL_NO_TLSEXT
    {
    struct cert_files *cf;
    int i;
    SSL_CTX *ctx;
    X509 *x509;
    BIO *f;

    STACK_OF(GENERAL_NAME) *names = NULL;
    GENERAL_NAME *name;

#define PUSH_CTX(asn1_str, ctx)                                             \
    do {                                                                    \
        struct ctx_list *cl;                                                \
        cl = (struct ctx_list *)calloc(1, sizeof(*cl));                                        \
        ASN1_STRING_to_UTF8((unsigned char **)&cl->servername, asn1_str);   \
        cl->ctx = ctx;                                                      \
        cl->next = sni_ctxs;                                                \
        sni_ctxs = cl;                                                      \
    } while (0)

    // Go through the list of PEMs and make some SSL contexts for them. We also
    // keep track of the names associated with each cert so we can do SNI on
    // them later
    for (cf = CONFIG->CERT_FILES->NEXT; cf != NULL; cf = cf->NEXT) {
        ctx = make_ctx(cf->CERT_FILE);
        f = BIO_new(BIO_s_file());
        // TODO: error checking
        if (!BIO_read_filename(f, cf->CERT_FILE)) {
            L_ERR("Could not read cert '%s'\n", cf->CERT_FILE);
        }
        x509 = PEM_read_bio_X509_AUX(f, NULL, NULL, NULL);
        BIO_free(f);

        // First, look for Subject Alternative Names
        names = (STACK_OF(GENERAL_NAME) *) X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
        for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
            name = sk_GENERAL_NAME_value(names, i);
            if (name->type == GEN_DNS) {
                PUSH_CTX(name->d.dNSName, ctx);
            }
        }
        if (sk_GENERAL_NAME_num(names) > 0) {
            sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
            // If we actally found some, don't bother looking any further
            continue;
        } else if (names != NULL) {
            sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
        }

        // Now we're left looking at the CN on the cert
        X509_NAME *x509_name = X509_get_subject_name(x509);
        i = X509_NAME_get_index_by_NID(x509_name, NID_commonName, -1);
        if (i < 0) {
            L_ERR("Could not find Subject Alternative Names or a CN on cert %s\n",
                    cf->CERT_FILE);
        }
        X509_NAME_ENTRY *x509_entry = X509_NAME_get_entry(x509_name, i);
        PUSH_CTX(x509_entry->value, ctx);
    }
    }
#undef APPEND_CTX
#endif /* OPENSSL_NO_TLSEXT */

    if (CONFIG->ENGINE) {
        ENGINE *e = NULL;
        ENGINE_load_builtin_engines();
        if (!strcmp(CONFIG->ENGINE, "auto"))
            ENGINE_register_all_complete();
        else {
            if ((e = ENGINE_by_id(CONFIG->ENGINE)) == NULL ||
                !ENGINE_init(e) ||
                !ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            LOG("{core} will use OpenSSL engine %s.\n", ENGINE_get_id(e));
            ENGINE_finish(e);
            ENGINE_free(e);
        }
    }
}

static void prepare_proxy_line(struct sockaddr* ai_addr) {
    tcp_proxy_line[0] = 0;
    char tcp6_address_string[INET6_ADDRSTRLEN];

    if (ai_addr->sa_family == AF_INET) {
        struct sockaddr_in* addr = (struct sockaddr_in*)ai_addr;
        snprintf(tcp_proxy_line, sizeof(tcp_proxy_line), "PROXY %%s %%s %s %%hu %hu\r\n", inet_ntoa(addr->sin_addr), ntohs(addr->sin_port));
    }
    else if (ai_addr->sa_family == AF_INET6 ) {
      struct sockaddr_in6* addr = (struct sockaddr_in6*)ai_addr;
      inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
      snprintf(tcp_proxy_line, sizeof(tcp_proxy_line), "PROXY %%s %%s %s %%hu %hu\r\n", tcp6_address_string, ntohs(addr->sin6_port));
    }
    else {
        L_ERR("The --write-proxy mode is not implemented for this address family.\n");
        exit(1);
    }
}

/* Create the bound socket in the parent process */
static int create_main_socket() {
    struct addrinfo *ai, hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    const int gai_err = getaddrinfo(CONFIG->FRONT_IP, CONFIG->FRONT_PORT,
                                    &hints, &ai);
    if (gai_err != 0) {
        L_ERR("{getaddrinfo}: [%s]\n", gai_strerror(gai_err));
        exit(1);
    }

    int s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);

    if (s == -1)
      fail("{socket: main}");

    int t = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &t, sizeof(int));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &t, sizeof(int));
#endif
    setnonblocking(s);

    if (bind(s, ai->ai_addr, ai->ai_addrlen)) {
        fail("{bind-socket}");
    }

#ifndef NO_DEFER_ACCEPT
#if TCP_DEFER_ACCEPT
    int timeout = 1;
    setsockopt(s, IPPROTO_TCP, TCP_DEFER_ACCEPT, &timeout, sizeof(int) );
#endif /* TCP_DEFER_ACCEPT */
#endif

    prepare_proxy_line(ai->ai_addr);

    freeaddrinfo(ai);
    listen(s, CONFIG->BACKLOG);

    return s;
}

/* Initiate a clear-text nonblocking connect() to the backend IP on behalf
 * of a newly connected upstream (encrypted) client*/
static int create_back_socket() {
    int s = socket(backaddr->ai_family, SOCK_STREAM, IPPROTO_TCP);

    if (s == -1)
      return -1;

    int flag = 1;
    int ret = setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));
    if (ret == -1) {
      perror("Couldn't setsockopt to backend (TCP_NODELAY)\n");
    }
    setnonblocking(s);

    return s;
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static inline void safe_enable_io(proxystate *ps, ev_io *w) {
    if (likely(!ps->want_shutdown))
        ev_io_start(loop, w);
}

/* Only enable a libev ev_io event if the proxied connection still
 * has both up and down connected */
static void shutdown_proxy(proxystate *ps, SHUTDOWN_REQUESTOR req, int backend, char *reason) {
    if (ps->want_shutdown || (req == SHUTDOWN_HARD) || (req == SHUTDOWN_CLEAR && ringbuffer_is_empty(&ps->ring_clear2ssl)) || 
        (req == SHUTDOWN_SSL && ringbuffer_is_empty(&ps->ring_ssl2clear))) {

        ev_io_stop(loop, &ps->ev_w_ssl);
        ev_io_stop(loop, &ps->ev_r_ssl);
        ev_io_stop(loop, &ps->ev_w_handshake);
        ev_io_stop(loop, &ps->ev_r_handshake);
        ev_io_stop(loop, &ps->ev_w_connect);
        ev_io_stop(loop, &ps->ev_w_clear);
        ev_io_stop(loop, &ps->ev_r_clear);
        ev_io_stop(loop, &ps->ev_proxy);
        
        close(ps->fd_up);
        close(ps->fd_down);
        
        SSL_set_shutdown(ps->ssl, SSL_SENT_SHUTDOWN);
        SSL_free(ps->ssl);
        ERR_clear_error();
        
        // Make use-after-free fail immediately
        ps->fd_up = -1;
        ps->fd_down = -1;
        ps->ssl = NULL;
        
        SPool.Release(ps);
        
        char host[INET6_ADDRSTRLEN];
        int port = -1;
        get_client_info(ps, host, sizeof(host), &port);
        LOG("op=\"connection closed\" client=%s:%d direction=%s reason=\"%s\"\n", 
            host, port, backend ? "backend" : "client", reason);
#ifdef STUD_DTRACE
        if (STUD_CLOSE_SIDE_ENABLED() || !CONFIG->QUIET)
            STUD_CLOSE_SIDE(host, port, backend);
#endif
    } else {
        ps->want_shutdown = 1;
    }
}

// Handle various socket errors
static inline void handle_socket_errno(proxystate *ps, int backend) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
        return;

    char *reason;

    if (errno == ECONNRESET)
        reason = (char *)"Connection reset by peer";
    else if (errno == ETIMEDOUT)
        reason = (char *)"Connection to backend timed out";
    else if (errno == EPIPE)
        reason = (char *)"Broken pipe to backend";
    else {
        char reason2[1024];
        strerror_r(errno, reason2, 1024);
        reason = reason2;
    }

    shutdown_proxy(ps, SHUTDOWN_CLEAR, backend, reason);
}

// Start connect to backend
static int start_connect(proxystate *ps) {
    int t = 1;
    t = connect(ps->fd_down, backaddr->ai_addr, backaddr->ai_addrlen);
    if (t == 0 || errno == EINPROGRESS || errno == EINTR) {
        ev_io_start(loop, &ps->ev_w_connect);
        return 0;
    }
    char reason[1024];
    strerror_r(errno, reason, 1024);
    shutdown_proxy(ps, SHUTDOWN_HARD, 1, reason);
    return -1;
}
static void start_handshake(proxystate *ps, int err);
static void handle_fatal_ssl_error(proxystate *ps, int err, int backend);

/* Read some data from the backend when libev says data is available--
 * write it into the upstream buffer and make sure the write event is
 * enabled for the upstream socket */
static void clear_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    proxystate *ps = (proxystate *)w->data;
    if (unlikely(ps->want_shutdown)) {
        ev_io_stop(loop, &ps->ev_r_clear);
        return;
    }
    int fd = w->fd;

    char buf[RINGBUFFER_SIZE-1];
    ringbuffer_t *ring = &ps->ring_clear2ssl;
    bool process_more_data = false;
    do {
        int prev_len = ringbuffer_available_to_read(ring);
        // get previously buffered data 
        if (unlikely(prev_len >= (int)sizeof(buf))){
            // the buffer is full
            ev_io_stop(loop, &ps->ev_r_clear);
            break;
        }
        int offset = prev_len,ret;
        process_more_data=false;
        while(offset < (int)sizeof(buf)){
            ret = recv(fd, buf+offset, sizeof(buf)-offset, MSG_DONTWAIT);
            if(ret <=0){
                break;
            }
            offset += ret;
        }
        int saved_errno = errno;
        if (likely(offset > 0)) {
            bool need_append=true;
            // we check if the other end is connected, we just forward it
            if (likely(ps->handshaked)) {
                //write the data
                //check for other data waiting to be written and append and write it
                if (unlikely(prev_len > 0)) {
                    ringbuffer_get2(ring,buf,prev_len);
                }
                int ret = SSL_write(ps->ssl, buf, offset);
                if (likely(ret > 0)) {
                    ringbuffer_advance_read_head(ring,ret < prev_len?ret:prev_len);
                    if (unlikely(ret < offset)) {
                        ringbuffer_append(ring,buf+ret,offset-ret);
                    }
                    need_append = false;
                } else {
                    int err = SSL_get_error(ps->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ){
                        start_handshake(ps, err);
                    } else if (err == SSL_ERROR_WANT_WRITE) {
                        /*  SSL socket is backed up */
                    } else {
                        //remote end has closed connection
                        //we have to write out anything that client has written 
                        //but we have not sent to backend
                        ringbuffer_t *ring2 = &ps->ring_ssl2clear;
                        int unwritten = ringbuffer_available_to_read(ring2);
                        if (unlikely(unwritten > 0)) {
                            char tmpbuf[unwritten];
                            ringbuffer_get2(ring2,tmpbuf,unwritten);
                            send(ps->fd_down, tmpbuf, unwritten, MSG_NOSIGNAL);
                            ringbuffer_reset(ring2);
                        }
                        return handle_fatal_ssl_error(ps, err, 0);
                    }
                }
            }
            if (unlikely(need_append)) {
                ringbuffer_append(ring,buf+prev_len,offset-prev_len);
            }
            if (unlikely(!ringbuffer_is_empty(ring))) {
                // we stop the read from clear, because SSL_write expects to be retried
                // with the same contents
                // http://www.openssl.org/docs/ssl/SSL_write.html
                ev_io_stop(loop, &ps->ev_r_clear);
                break;
            }
        }
        if (likely(ret==-1)) {
             if (unlikely((saved_errno!= EAGAIN) || (saved_errno!=EWOULDBLOCK) || (saved_errno!=EINTR))) {
                assert(ret == -1);
                errno=saved_errno;
                handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
            }
        } else if(ret > 0) {
            // we filled the buffer, but there may be more data to read
            process_more_data = true;
        } else if (ret  == 0) {
            shutdown_proxy(ps, SHUTDOWN_CLEAR, fd == ps->fd_down, (char *)"connection closed");
        }   
    } while(process_more_data);

    if (unlikely(!ringbuffer_is_empty(ring) && ps->handshaked)) {
        safe_enable_io(ps, &ps->ev_w_ssl);
    }
}

/* Write some data, previously received on the secure upstream socket,
 * out of the downstream buffer and onto the backend socket */
static void clear_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    int fd = w->fd;
    int sz;
    ringbuffer_t *ring=&ps->ring_ssl2clear;

    if(unlikely(ringbuffer_is_empty(ring))){
        ev_io_stop(loop, &ps->ev_w_clear);
        return;
    }
    assert(!ringbuffer_is_empty(ring));
    char buf[RINGBUFFER_SIZE];
    char *next=ringbuffer_get(ring,buf,&sz);
    t = send(fd, next, sz, MSG_NOSIGNAL);

    if (likely(t > 0)) {
        ringbuffer_advance_read_head(ring,t);
        if (t == sz) {
            if (ps->handshaked) {
                safe_enable_io(ps, &ps->ev_r_ssl);
            }
            if (ps->want_shutdown) {
                shutdown_proxy(ps, SHUTDOWN_HARD, 1, (char *)"write failed"); // TODO - what causes this?
                return; // dealloc'd
            }
            ev_io_stop(loop, &ps->ev_w_clear);
        }
    } else {
        assert(t == -1);
        handle_socket_errno(ps, fd == ps->fd_down ? 1 : 0);
    }
}

/* Continue/complete the asynchronous connect() before starting data transmission
 * between front/backend */
static void handle_connect(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;
    t = connect(ps->fd_down, backaddr->ai_addr, backaddr->ai_addrlen);
    if (!t || errno == EISCONN || !errno) {
        ev_io_stop(loop, &ps->ev_w_connect);

        if (!ps->clear_connected) {
            ps->clear_connected = 1;

            /* if incoming buffer is not full */
            if (!ringbuffer_is_full(&ps->ring_clear2ssl))
                safe_enable_io(ps, &ps->ev_r_clear);

            /* if outgoing buffer is not empty */
            if (!ringbuffer_is_empty(&ps->ring_ssl2clear))
                // not safe.. we want to resume stream even during half-closed
                ev_io_start(loop, &ps->ev_w_clear);
        } else {
            /* Clear side already connected so connect is on secure side: perform handshake */
            start_handshake(ps, SSL_ERROR_WANT_WRITE);
        }
    } else if (errno == EINPROGRESS || errno == EINTR || errno == EALREADY) {
        /* do nothing, we'll get phoned home again... */
    } else {
        char reason[1024];
        strerror_r(errno, reason, 1024);
        shutdown_proxy(ps, SHUTDOWN_HARD, 1, reason);
    }
}

/* Upon receiving a signal from OpenSSL that a handshake is required, re-wire
 * the read/write events to hook up to the handshake handlers */
static void start_handshake(proxystate *ps, int err) {
    ev_io_stop(loop, &ps->ev_r_ssl);
    ev_io_stop(loop, &ps->ev_w_ssl);

    ps->handshaked = 0;

    if (err == SSL_ERROR_WANT_READ)
        ev_io_start(loop, &ps->ev_r_handshake);
    else if (err == SSL_ERROR_WANT_WRITE)
        ev_io_start(loop, &ps->ev_w_handshake);
}

/* After OpenSSL is done with a handshake, re-wire standard read/write handlers
 * for data transmission */
static void end_handshake(proxystate *ps) {
    char tcp6_address_string[INET6_ADDRSTRLEN];
    size_t written = 0;
    int port = -1;
    char host[INET6_ADDRSTRLEN];
    ev_io_stop(loop, &ps->ev_r_handshake);
    ev_io_stop(loop, &ps->ev_w_handshake);

    // Disable renegotiation (CVE-2009-3555)
    if (ps->ssl->s3) {
        ps->ssl->s3->flags |= SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS;
    }
    ps->handshaked = 1;

    get_client_info(ps, host, sizeof(host), &port);
    SSL_SESSION* sess = SSL_get_session(ps->ssl);
    long expiry = SSL_SESSION_get_time(sess) + SSL_SESSION_get_timeout(sess) - (time_t) ev_now(loop);

    if (SSL_session_reused(ps->ssl)) {
      LOG("op=\"stud session reuse\" client=\"%s:%d\" expiry=\"%ld\"\n", host, port, expiry);
    } else {
      LOG("op=\"stud session new\" client=\"%s:%d\" expiry=\"%ld\"\n", host, port, expiry);
    }

    {
        int back = create_back_socket();

        if (back == -1) {
            //close(client);
            perror("{backend-socket}");
            abort();
            return;
        } 


        ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);

        ev_io_init(&ps->ev_w_clear, clear_write, back, EV_WRITE);
        ev_io_init(&ps->ev_r_clear, clear_read, back, EV_READ); 
    }

    // DTrace probe
    if (STUD_SSL_SESSION_REUSE_ENABLED()) {
        if (SSL_session_reused(ps->ssl)) {
            STUD_SSL_SESSION_REUSE(host, port, expiry);
        } else {
            STUD_SSL_SESSION_NEW(host, port, expiry);
        }
    }

    /* Check if clear side is connected */
    if (!ps->clear_connected) {
        if (CONFIG->WRITE_PROXY_LINE) {
            char *ring_pnt = ringbuffer_write_ptr(&ps->ring_ssl2clear);
            assert(ps->remote_ip.ss_family == AF_INET ||
                   ps->remote_ip.ss_family == AF_INET6);
            if(likely(ps->remote_ip.ss_family == AF_INET)) {
               struct sockaddr_in* addr = (struct sockaddr_in*)&ps->remote_ip;
               written = snprintf(ring_pnt,
                                  RINGBUFFER_SIZE,
                                  tcp_proxy_line,
                                  "TCP4",
                                  inet_ntoa(addr->sin_addr),
                                  ntohs(addr->sin_port));
               }
               else if (ps->remote_ip.ss_family == AF_INET6) {
                        struct sockaddr_in6* addr = (struct sockaddr_in6*)&ps->remote_ip;
                        inet_ntop(AF_INET6,&(addr->sin6_addr),tcp6_address_string,INET6_ADDRSTRLEN);
                        written = snprintf(ring_pnt,
                                  RINGBUFFER_SIZE,
                                  tcp_proxy_line,
                                  "TCP6",
                                  tcp6_address_string,
                                  ntohs(addr->sin6_port));
            }
            ringbuffer_advance_write_head(&ps->ring_ssl2clear, written);
        }
        else if (CONFIG->WRITE_IP_OCTET) {
            char *ring_pnt = ringbuffer_write_ptr(&ps->ring_ssl2clear);
            assert(ps->remote_ip.ss_family == AF_INET ||
                   ps->remote_ip.ss_family == AF_INET6);
            *ring_pnt++ = (unsigned char) ps->remote_ip.ss_family;
            if (ps->remote_ip.ss_family == AF_INET6) {
                memcpy(ring_pnt, &((struct sockaddr_in6 *) &ps->remote_ip)
                       ->sin6_addr.s6_addr, 16U);
                ringbuffer_advance_write_head(&ps->ring_ssl2clear, 1U + 16U);
            }
            else {
                memcpy(ring_pnt, &((struct sockaddr_in *) &ps->remote_ip)
                       ->sin_addr.s_addr, 4U);
                ringbuffer_advance_write_head(&ps->ring_ssl2clear, 1U + 4U);
            }
        }
        /* start connect now */
        if (start_connect(ps) != 0)
          return;
    }
    else {
        /* stud used in client mode, keep client session ) */
        if (!SSL_session_reused(ps->ssl)) {
            if (client_session)
                SSL_SESSION_free(client_session);
            client_session = SSL_get1_session(ps->ssl);
        }
    }

    /* if incoming buffer is not full */
    if (!ringbuffer_is_full(&ps->ring_ssl2clear))
        safe_enable_io(ps, &ps->ev_r_ssl);

    /* if outgoing buffer is not empty */
    if (!ringbuffer_is_empty(&ps->ring_clear2ssl))
        // not safe.. we want to resume stream even during half-closed
        ev_io_start(loop, &ps->ev_w_ssl);
}

static void client_proxy_proxy(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    char *proxy = tcp_proxy_line, *end = tcp_proxy_line + sizeof(tcp_proxy_line);
    proxystate *ps = (proxystate *)w->data;
    BIO *b = SSL_get_rbio(ps->ssl);

    // Copy characters one-by-one until we hit a \n or an error
    while (proxy != end && (t = BIO_read(b, proxy, 1)) == 1) {
        if (*proxy++ == '\n') break;
    }

    if (proxy == end) {
        shutdown_proxy(ps, SHUTDOWN_SSL, 1, (char *)"Unexpectedly long PROXY line. Perhaps a malformed request?");
    } else if (t == 1) {
        if (ringbuffer_is_full(&ps->ring_ssl2clear)) {
            return shutdown_proxy(ps, SHUTDOWN_SSL, 1, (char *)"Error writing PROXY line");
        }

        char *ring = ringbuffer_write_ptr(&ps->ring_ssl2clear);
        memcpy(ring, tcp_proxy_line, proxy - tcp_proxy_line);
        ringbuffer_advance_write_head(&ps->ring_ssl2clear, proxy - tcp_proxy_line);

        // Finished reading the PROXY header
        if (*(proxy - 1) == '\n') {
            ev_io_stop(loop, &ps->ev_proxy);

            // Start the real handshake
            start_handshake(ps, SSL_ERROR_WANT_READ);
        }
    }
    else if (!BIO_should_retry(b)) {
        shutdown_proxy(ps, SHUTDOWN_SSL, 1, (char *)"Unexpected error reading PROXY line");
    }
}

/* The libev I/O handler during the OpenSSL handshake phase.  Basically, just
 * let OpenSSL do what it likes with the socket and obey its requests for reads
 * or writes */
static void client_handshake(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    proxystate *ps = (proxystate *)w->data;

    t = SSL_do_handshake(ps->ssl);
    if (likely(t == 1)) {
        end_handshake(ps);
    } else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            ev_io_stop(loop, &ps->ev_w_handshake);
            ev_io_start(loop, &ps->ev_r_handshake);
        } else if (err == SSL_ERROR_WANT_WRITE) {
            ev_io_stop(loop, &ps->ev_r_handshake);
            ev_io_start(loop, &ps->ev_w_handshake);
        } else if (err == SSL_ERROR_ZERO_RETURN) {
            shutdown_proxy(ps, SHUTDOWN_SSL, w->fd == ps->fd_down, (char *)"Connection closed in handshake");
        } else {
            shutdown_proxy(ps, SHUTDOWN_SSL, w->fd == ps->fd_down, (char *)"Unexpected SSL error in handshake");
        }
    }
}

/* Handle a socket error condition passed to us from OpenSSL */
static void handle_fatal_ssl_error(proxystate *ps, int err, int backend) {
    char *reason;
    char reason2[1024];
    if (err == SSL_ERROR_ZERO_RETURN) {
        reason = (char *)"Connection closed (SSL_ERROR_ZERO_RETURN)";
    } else if (err == SSL_ERROR_SYSCALL) {
        if (errno == 0)
            reason = (char *)"Connection closed (SSL_ERROR_SYSCALL)";
        else {
            strerror_r(errno, reason2, 1024);
            reason = reason2;
        }
    } else {
        snprintf(reason2, 1024, "Unexpected SSL_read error: %d", err);
        reason = reason2;
    }

    shutdown_proxy(ps, SHUTDOWN_SSL, backend, reason);
}

/* Read some data from the upstream secure socket via OpenSSL,
 * and buffer anything we get for writing to the backend */
static void ssl_read(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    proxystate *ps = (proxystate *)w->data;
    if (unlikely(ps->want_shutdown)) {
        ev_io_stop(loop, &ps->ev_r_ssl);
        return;
    }
    char buf[RINGBUFFER_SIZE-1];
    ringbuffer_t *ring=&ps->ring_ssl2clear;
    int prev_len=ringbuffer_available_to_read(ring);
    // get previously buffered data 
    int offset=prev_len,ret=0;
    while(offset < (int)sizeof(buf)){
        ret = SSL_read(ps->ssl, buf+offset, sizeof(buf)-offset);
        if(ret <=0){
            break;
        }
        offset+=ret;
    }

    // Fix CVE-2009-3555. Disable reneg if started by client.
    if (ps->renegotiation) {
        shutdown_proxy(ps, SHUTDOWN_SSL, 0, (char *)"server rejects client renegotiation request, closing connection");
        return;
    }

    bool need_append=true;
    if(likely(ps->clear_connected  && (offset > 0))){
        if(unlikely(prev_len > 0)){
            ringbuffer_get2(ring,buf,prev_len);
        }
        int ret = send(ps->fd_down, buf, offset, MSG_NOSIGNAL);
        //write(STDOUT_FILENO,buf,offset);
        if(likely(ret > 0)){
            ringbuffer_advance_read_head(ring,ret < prev_len?ret:prev_len);
            if(unlikely(ret < offset)){
                //append data to ring
                ringbuffer_append(ring,buf+ret,offset-ret);
            }
            need_append=false;
        }else if (unlikely(!(errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))){
            //George: backend is gone, we need to flush any backend data to client
            //for simplicity we just reset the ring 
            //we should probably flush the data first
            //but ssl_write may itself fail and we are keeping it simple
            ringbuffer_reset(&ps->ring_clear2ssl);
            return handle_socket_errno(ps,1);
        }
    }
    if (unlikely(need_append)) {
        ringbuffer_append(ring,buf+prev_len,offset-prev_len);
        if (ringbuffer_is_full(ring)){
            ev_io_stop(loop, &ps->ev_r_ssl);
        }
    }
    if(ret <= 0){
        int err = SSL_get_error(ps->ssl, ret);
        if (err == SSL_ERROR_WANT_WRITE) {
            start_handshake(ps, err);
        }
        else if (err == SSL_ERROR_WANT_READ) { } /* incomplete SSL data */
        else
            handle_fatal_ssl_error(ps, err, w->fd == ps->fd_up ? 0 : 1);
    }
    if (unlikely(!(ringbuffer_is_empty(ring)) && (ps->clear_connected))){
        safe_enable_io(ps, &ps->ev_w_clear);
    }
    //fprintf(stdout,"offset:%d avail_to_read:%d\n",offset,ringbuffer_available_to_read(ring));
    //fflush(stdout);
}

/* Write some previously-buffered backend data upstream on the
 * secure socket using OpenSSL */
static void ssl_write(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    int t;
    int sz;
    proxystate *ps = (proxystate *)w->data;
    ringbuffer_t *ring=&ps->ring_clear2ssl;
    if(unlikely(ringbuffer_is_empty(ring))){
        ev_io_stop(loop, &ps->ev_w_ssl);
        return;
    }
    assert(!ringbuffer_is_empty(ring));
    char buf[RINGBUFFER_SIZE];
    char * next = ringbuffer_get(ring, buf, &sz);
    t = SSL_write(ps->ssl, next, sz);
    if (t > 0) {
        ringbuffer_advance_read_head(ring,sz);
        if (ps->clear_connected){
            safe_enable_io(ps, &ps->ev_r_clear); // can be re-enabled b/c we've popped
        }
        if (t == sz) {
            if (ps->want_shutdown) {
                shutdown_proxy(ps, SHUTDOWN_HARD, 1, (char *)"close after write"); // TODO - what causes this?
                return;
            }
            ev_io_stop(loop, &ps->ev_w_ssl);
        }
    } else {
        int err = SSL_get_error(ps->ssl, t);
        if (err == SSL_ERROR_WANT_READ) {
            start_handshake(ps, err);
        } else if (err == SSL_ERROR_WANT_WRITE) {} // incomplete SSL data
        else {
            handle_fatal_ssl_error(ps, err,  w->fd == ps->fd_up ? 0 : 1);
        }
    }
}

#ifdef OPENSSL_NPN_NEGOTIATED
static int ssl_advertise_spdy(SSL* ssl,
                              const unsigned char** data,
                              unsigned int *len,
                              void* arg) {
    if (CONFIG->NPN_RAW == NULL) {
      *data = reinterpret_cast<const unsigned char*>("");
      *len = 0;
    } else {
      *data = CONFIG->NPN_RAW;
      *len = static_cast<unsigned int>(CONFIG->NPN_RAW_LEN);
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif

/* libev read handler for the bound socket.  Socket is accepted,
 * the proxystate is allocated and initalized, and we're off the races
 * connecting to the backend */
static void handle_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct sockaddr_storage addr;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            L_ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            L_ERR("{client} accept() failed; too many open files for this system\n");
            break;

    case ECONNABORTED:
      L_ERR("{client} accept() failed; client went away while negotiating TCP with Solaris ECONNABORTED\n");
      break;

        default:
      fprintf(stderr, "server socket accept returned -1, errno is: %d\n", errno);
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    int flag = 1;
    int ret ;
    ret=setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_NODELAY)\n");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_CWND)\n");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    /*   int back = create_back_socket();

    if (back == -1) {
        close(client);
        perror("{backend-socket}");
        return;
    } */

    SSL_CTX * ctx = (SSL_CTX *)w->data;
    SSL *ssl = SSL_new(ctx);
    long mode = SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
#ifdef SSL_MODE_RELEASE_BUFFERS
    mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
    SSL_set_mode(ssl, mode);
    SSL_set_accept_state(ssl);
    SSL_set_fd(ssl, client);

#ifdef OPENSSL_NPN_NEGOTIATED
    // Advertise SPDY support
    SSL_CTX_set_next_protos_advertised_cb(ctx, ssl_advertise_spdy, NULL);
#endif

    //proxystate *ps = (proxystate *)malloc(sizeof(proxystate));
    proxystate *ps = SPool.Get();
    if(unlikely(ps==NULL)){
        fprintf(stderr,"Ran out of memory in the memory pool -- recompile with a larger memory pool");
        close(client);
        //close(back);
        SSL_set_shutdown(ps->ssl, SSL_SENT_SHUTDOWN);
        SSL_free(ps->ssl);
        ERR_clear_error();
        return;
    }

    ps->fd_up = client;
    //ps->fd_down = back;
    ps->fd_down = -1;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->clear_connected = 0;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    ringbuffer_init(&ps->ring_ssl2clear,ps->buf);
    ringbuffer_init(&ps->ring_clear2ssl,ps->buf+RINGBUFFER_SIZE);

    /* set up events */
    ev_io_init(
           &ps->ev_r_ssl,
           ssl_read,
           client,
           EV_READ
           );
    ev_io_init(&ps->ev_w_ssl, ssl_write, client, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, client, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, client, EV_WRITE);

    ev_io_init(&ps->ev_proxy, client_proxy_proxy, client, EV_READ);

    /*  ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);

    ev_io_init(&ps->ev_w_clear, clear_write, back, EV_WRITE);
    ev_io_init(&ps->ev_r_clear, clear_read, back, EV_READ); */

    ps->ev_r_ssl.data = ps;
    ps->ev_w_ssl.data = ps;
    ps->ev_r_clear.data = ps;
    ps->ev_w_clear.data = ps;
    ps->ev_proxy.data = ps;
    ps->ev_w_connect.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;

    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);

    if (CONFIG->PROXY_PROXY_LINE) {
        ev_io_start(loop, &ps->ev_proxy);
    }
    else {
        start_handshake(ps, SSL_ERROR_WANT_READ); /* for client-first handshake */
    }
}


static void check_ppid(struct ev_loop *loop, ev_timer *w, int revents) {
    (void) revents;
    pid_t ppid = getppid();
    if (ppid != master_pid) {
        L_ERR("{core} Process %d detected parent death, closing listener socket.\n", child_num);
        ev_timer_stop(loop, w);
        ev_io_stop(loop, &listener);
        close(listener_socket);
    }

}

static void handle_clear_accept(struct ev_loop *loop, ev_io *w, int revents) {
    (void) revents;
    (void) loop;
    struct sockaddr_storage addr;
    socklen_t sl = sizeof(addr);
    int client = accept(w->fd, (struct sockaddr *) &addr, &sl);
    if (client == -1) {
        switch (errno) {
        case EMFILE:
            L_ERR("{client} accept() failed; too many open files for this process\n");
            break;

        case ENFILE:
            L_ERR("{client} accept() failed; too many open files for this system\n");
            break;

        default:
            assert(errno == EINTR || errno == EWOULDBLOCK || errno == EAGAIN);
            break;
        }
        return;
    }

    int flag = 1;
    int ret = setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag) );
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_NODELAY)\n");
    }
#ifdef TCP_CWND
    int cwnd = 10;
    ret = setsockopt(client, IPPROTO_TCP, TCP_CWND, &cwnd, sizeof(cwnd));
    if (ret == -1) {
      perror("Couldn't setsockopt on client (TCP_CWND)\n");
    }
#endif

    setnonblocking(client);
    settcpkeepalive(client);

    int back = create_back_socket();

    if (back == -1) {
        close(client);
        perror("{backend-socket}");
        return;
    }

    SSL_CTX * ctx = (SSL_CTX *)w->data;
    SSL *ssl = SSL_new(ctx);
    long mode = SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
#ifdef SSL_MODE_RELEASE_BUFFERS
    mode |= SSL_MODE_RELEASE_BUFFERS;
#endif
    SSL_set_mode(ssl, mode);
    SSL_set_connect_state(ssl);
    SSL_set_fd(ssl, back);
    if (client_session)
        SSL_set_session(ssl, client_session);

    proxystate *ps = (proxystate *)malloc(sizeof(proxystate));

    ps->fd_up = client;
    ps->fd_down = back;
    ps->ssl = ssl;
    ps->want_shutdown = 0;
    ps->clear_connected = 1;
    ps->handshaked = 0;
    ps->renegotiation = 0;
    ps->remote_ip = addr;
    ringbuffer_init(&ps->ring_clear2ssl,ps->buf+RINGBUFFER_SIZE);
    ringbuffer_init(&ps->ring_ssl2clear,ps->buf);

    /* set up events */
    ev_io_init(&ps->ev_r_clear, clear_read, client, EV_READ);
    ev_io_init(&ps->ev_w_clear, clear_write, client, EV_WRITE);

    ev_io_init(&ps->ev_w_connect, handle_connect, back, EV_WRITE);

    ev_io_init(&ps->ev_r_handshake, client_handshake, back, EV_READ);
    ev_io_init(&ps->ev_w_handshake, client_handshake, back, EV_WRITE);


    ev_io_init(&ps->ev_w_ssl, ssl_write, back, EV_WRITE);
    ev_io_init(&ps->ev_r_ssl, ssl_read, back, EV_READ);

    ps->ev_r_ssl.data = ps;
    ps->ev_w_ssl.data = ps;
    ps->ev_r_clear.data = ps;
    ps->ev_w_clear.data = ps;
    ps->ev_w_connect.data = ps;
    ps->ev_r_handshake.data = ps;
    ps->ev_w_handshake.data = ps;

    /* Link back proxystate to SSL state */
    SSL_set_app_data(ssl, ps);

    ev_io_start(loop, &ps->ev_r_clear);
    start_connect(ps); /* start connect */
}

/* Set up the child (worker) process including libev event loop, read event
 * on the bound socket, etc */
static void handle_connections() {
    LOG("op=process_online child_num=%d\n", child_num);

    /* child cannot create new children... */
    create_workers = 0;

#if defined(CPU_ZERO) && defined(CPU_SET)
    cpu_set_t cpus;

    CPU_ZERO(&cpus);
    CPU_SET(child_num, &cpus);

    int res = sched_setaffinity(0, sizeof(cpus), &cpus);
    if (!res)
        LOG("{core} Successfully attached to CPU #%d\n", child_num);
    else
        L_ERR("{core-warning} Unable to attach to CPU #%d; do you have that many cores?\n", child_num);
#endif

    loop = ev_default_loop(EVFLAG_AUTO);

    ev_timer timer_ppid_check;
    ev_timer_init(&timer_ppid_check, check_ppid, 1.0, 1.0);
    ev_timer_start(loop, &timer_ppid_check);

    ev_io_init(&listener, (CONFIG->PMODE == SSL_CLIENT) ? handle_clear_accept : handle_accept, listener_socket, EV_READ);
    listener.data = default_ctx;
    ev_io_start(loop, &listener);

    ev_loop(loop, 0);
    L_ERR("{core} Child %d exiting.\n", child_num);
    exit(1);
}

void change_root() {
    if (chroot(CONFIG->CHROOT) == -1)
        fail("chroot");
    if (chdir("/"))
        fail("chdir");
}

void drop_privileges() {
    if (setgid(CONFIG->GID))
        fail("setgid failed");
    if (setuid(CONFIG->UID))
        fail("setuid failed");
}


void init_globals() {
    /* backaddr */
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    const int gai_err = getaddrinfo(CONFIG->BACK_IP, CONFIG->BACK_PORT,
                                    &hints, &backaddr);
    if (gai_err != 0) {
        L_ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
        exit(1);
    }

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHARED_CACHE) {
        /* cache update peers addresses */
        shcupd_peer_opt *spo = CONFIG->SHCUPD_PEERS;
        struct addrinfo **pai = shcupd_peers;

        while (spo->ip) {
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = 0;
            const int gai_err = getaddrinfo(spo->ip,
                                spo->port ? spo->port : CONFIG->SHCUPD_PORT, &hints, pai);
            if (gai_err != 0) {
                L_ERR("{getaddrinfo}: [%s]", gai_strerror(gai_err));
                exit(1);
            }
            spo++;
            pai++;
        }
    }
#endif
    /* child_pids */
    if ((child_pids = (pid_t *)calloc(CONFIG->NCORES, sizeof(pid_t))) == NULL)
        fail("calloc");

    if (CONFIG->SYSLOG)
        openlog("stud", LOG_CONS | LOG_PID | LOG_NDELAY, CONFIG->SYSLOG_FACILITY);

    SPool24K_Start=SPool24K.Info(SPool24K_Size);
}

/* Forks COUNT children starting with START_INDEX.
 * Each child's index is stored in child_num and its pid is stored in child_pids[child_num]
 * so the parent can manage it later. */
void start_children(int start_index, int count) {
    /* don't do anything if we're not allowed to create new children */
    if (!create_workers) return;

    for (child_num = start_index; child_num < start_index + count; child_num++) {
        int pid = fork();
        if (pid == -1) {
            L_ERR("{core} fork() failed: %s; Goodbye cruel world!\n", strerror(errno));
            exit(1);
        }
        else if (pid == 0) { /* child */
            handle_connections();
            exit(0);
        }
        else { /* parent. Track new child. */
            child_pids[child_num] = pid;
        }
    }
}

/* Forks a new child to replace the old, dead, one with the given PID.*/
void replace_child_with_pid(pid_t pid) {
    int i;

    /* find old child's slot and put a new child there */
    for (i = 0; i < CONFIG->NCORES; i++) {
        if (child_pids[i] == pid) {
            start_children(i, 1);
            return;
        }
    }

    L_ERR("Cannot find index for child pid %d", pid);
}

/* Manage status changes in child processes */
static void do_wait(int __attribute__ ((unused)) signo) {

    int status;
    int pid = wait(&status);

    if (pid == -1) {
        if (errno == ECHILD) {
            L_ERR("{core} All children have exited! Restarting...\n");
            start_children(0, CONFIG->NCORES);
        }
        else if (errno == EINTR) {
            L_ERR("{core} Interrupted wait\n");
        }
        else {
            fail("wait");
        }
    }
    else {
        if (WIFEXITED(status)) {
            L_ERR("{core} Child %d exited with status %d. Replacing...\n", pid, WEXITSTATUS(status));
            replace_child_with_pid(pid);
        }
        else if (WIFSIGNALED(status)) {
            L_ERR("{core} Child %d was terminated by signal %d. Replacing...\n", pid, WTERMSIG(status));
            replace_child_with_pid(pid);
        }
    }
}

static void sigh_terminate (int __attribute__ ((unused)) signo) {
    /* don't create any more children */
    create_workers = 0;

    /* are we the master? */
    if (getpid() == master_pid) {
        LOG("{core} Received signal %d, shutting down.\n", signo);

        /* kill all children */
        int i;
        for (i = 0; i < CONFIG->NCORES; i++) {
            /* LOG("Stopping worker pid %d.\n", child_pids[i]); */
            if (child_pids[i] > 1 && kill(child_pids[i], SIGTERM) != 0) {
                L_ERR("{core} Unable to send SIGTERM to worker pid %d: %s\n", child_pids[i], strerror(errno));
            }
        }
        /* LOG("Shutdown complete.\n"); */
    }

    /* this is it, we're done... */
    exit(0);
}

void init_signals() {
    struct sigaction act;

    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = SIG_IGN;

    /* Avoid getting PIPE signal when writing to a closed file descriptor */
    if (sigaction(SIGPIPE, &act, NULL) < 0)
        fail("sigaction - sigpipe");

    /* We don't care if someone stops and starts a child process with kill (1) */
    act.sa_flags = SA_NOCLDSTOP;

    act.sa_handler = do_wait;

    /* We do care when child processes change status */
    if (sigaction(SIGCHLD, &act, NULL) < 0)
        fail("sigaction - sigchld");

    /* catch INT and TERM signals */
    act.sa_flags = 0;
    act.sa_handler = sigh_terminate;
    if (sigaction(SIGINT, &act, NULL) < 0) {
        L_ERR("Unable to register SIGINT signal handler: %s\n", strerror(errno));
        exit(1);
    }
    if (sigaction(SIGTERM, &act, NULL) < 0) {
        L_ERR("Unable to register SIGTERM signal handler: %s\n", strerror(errno));
        exit(1);
    }
}

void daemonize () {
    /* go to root directory */
    if (chdir("/") != 0) {
        L_ERR("Unable change directory to /: %s\n", strerror(errno));
        exit(1);
    }

    /* let's make some children, baby :) */
    pid_t pid = fork();
    if (pid < 0) {
        L_ERR("Unable to daemonize: fork failed: %s\n", strerror(errno));
        exit(1);
    }

    /* am i the parent? */
    if (pid != 0) {
        printf("{core} Daemonized as pid %d.\n", pid);
        exit(0);
    }

    /* reopen standard streams to null device */
    freopen(NULL_DEV, "r", stdin);
    if (stdin == NULL) {
        L_ERR("Unable to reopen stdin to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    freopen(NULL_DEV, "w", stdout);
    if (stdout == NULL) {
        L_ERR("Unable to reopen stdout to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }
    freopen(NULL_DEV, "w", stderr);
    if (stderr == NULL) {
        L_ERR("Unable to reopen stderr to %s: %s\n", NULL_DEV, strerror(errno));
        exit(1);
    }

    /* this is child, the new master */
    pid_t s = setsid();
    if (s < 0) {
        L_ERR("Unable to create new session, setsid(2) failed: %s :: %d\n", strerror(errno), s);
        exit(1);
    }

    LOG("Successfully daemonized as pid %d.\n", getpid());
}

void openssl_check_version() {
    /* detect OpenSSL version in runtime */
    openssl_version = SSLeay();

    /* check if we're running the same openssl that we were */
    /* compiled with */
    if ((openssl_version ^ OPENSSL_VERSION_NUMBER) & ~0xff0L) {
        L_ERR(
            "WARNING: {core} OpenSSL version mismatch; stud was compiled with %lx, now using %lx.\n",
            (unsigned long int) OPENSSL_VERSION_NUMBER,
            (unsigned long int) openssl_version
        );
    // might want to exit now, but then again, maybe everything is just fine
    }

    LOG("op=init ssl_version=\"%s\" %s %s %s %s\n",
    SSLeay_version(SSLEAY_VERSION),
    SSLeay_version(SSLEAY_BUILT_ON),
    SSLeay_version(SSLEAY_PLATFORM),
    SSLeay_version(SSLEAY_DIR),
    SSLeay_version(SSLEAY_CFLAGS)
    );
}

/* Process command line args, create the bound socket,
 * spawn child (worker) processes, and respawn if any die */
int main(int argc, char **argv) {
#if STUD_FIPS_MODE
    if (!FIPS_mode_set(1)) {
        int err = ERR_get_error();
        fprintf(stdout, "openssl fips failed: %s\n", ERR_error_string(err, NULL));
        fail("FIPS failed");
    }
#endif

    // initialize configuration
    CONFIG = config_new();

    // parse command line
    config_parse_cli(argc, argv, CONFIG);

    create_workers = 1;

    openssl_check_version();

    init_signals();

    init_globals();

    listener_socket = create_main_socket();

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHCUPD_PORT) {
        /* create socket to send(children) and
               receive(parent) cache updates */
        shcupd_socket = create_shcupd_socket();
    }
#endif /* USE_SHARED_CACHE */

    /* load certificates, pass to handle_connections */
    init_openssl();

    if (CONFIG->CHROOT && CONFIG->CHROOT[0])
        change_root();

    if (CONFIG->UID || CONFIG->GID)
        drop_privileges();

    /* should we daemonize ?*/
    if (CONFIG->DAEMONIZE) {
        /* disable logging to stderr */
        CONFIG->QUIET = 1;
        CONFIG->SYSLOG = 1;

        /* become a daemon */
        daemonize();
    }

    master_pid = getpid();

    start_children(0, CONFIG->NCORES);

#ifdef USE_SHARED_CACHE
    if (CONFIG->SHCUPD_PORT) {
        /* start event loop to receive cache updates */

        loop = ev_default_loop(EVFLAG_AUTO);

        ev_io_init(&shcupd_listener, handle_shcupd, shcupd_socket, EV_READ);
        ev_io_start(loop, &shcupd_listener);

        ev_loop(loop, 0);
    }
#endif /* USE_SHARED_CACHE */

    for (;;) {
        /* Sleep and let the children work.
         * Parent will be woken up if a signal arrives */
        pause();
    }

    exit(0); /* just a formality; we never get here */
}
