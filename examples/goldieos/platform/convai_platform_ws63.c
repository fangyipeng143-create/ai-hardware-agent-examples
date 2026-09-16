/**
 * @file convai_platform_ws63.c
 * @brief WS63 platform abstraction implementation.
 *
 * 基于goldieos项目架构实现:
 *  - OSAL: goldie_osal (LiteOS API封装)
 *  - NetAL: lwIP sockets
 *  - TLSAL: mbedTLS
 */

#include "convai_platform_ws63.h"
#include "goldie_osal.h"
#include "services/ntp/ntp_service.h"
#include "core/service_manager.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "certs/convai_aia_chain.h"

/* Forward-declare poll_table for lwip/sockets.h (WS63 lwip header uses it
 * in a function prototype without including poll.h). */
typedef struct poll_table poll_table;

#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "lwip/arch/sys_arch.h"  /* sys_now() — monotonic ms systick */

#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#define NTP_SERVICE_INDEX 7

static int g_hal_initialized = 0;
static uint64_t g_start_time_ms = 0;

/* ===== Opaque type definitions (must match SDK internal layout) ===== */
struct convai_mutex_s {
    goldie_mutex mutex;
};

struct convai_thread_s {
    void *handle;
    goldie_sem exit_sem;  /* notify when thread exits */
    int exited;           /* exit flag */
};

struct convai_socket_s {
    mbedtls_net_context net;
};

struct convai_tls_s {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;
    convai_socket_t *sock;  /* 持有 socket 引用 */
    int connected;
};

/* Manual implementation of timegm for platforms that don't have it (like WS63) */
static time_t my_timegm(const struct tm *tm) {
    static const int mon_lengths[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    
    int year = tm->tm_year + 1900 - 1970;
    if (year < 0) return (time_t)-1;
    
    time_t days = 0;
    
    for (int y = 1970; y < tm->tm_year + 1900; y++) {
        days += 365;
        if ((y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)) {
            days++;
        }
    }
    
    for (int m = 0; m < tm->tm_mon; m++) {
        days += mon_lengths[m];
        if (m == 1 && ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0))) {
            days++;
        }
    }
    
    days += tm->tm_mday - 1;
    
    time_t seconds = days * 24 * 3600;
    seconds += tm->tm_hour * 3600;
    seconds += tm->tm_min * 60;
    seconds += tm->tm_sec;
    
    return seconds;
}

/* ===== OSAL – Memory ===== */
static void *ws63_malloc(size_t size) {
    return goldie_malloc(size);
}

static void ws63_free(void *ptr) {
    goldie_free(ptr);
}

/* ===== OSAL – Time ===== */

extern void* get_service(int service_index);
NTPService* ntp_service = NULL;
uint64_t ws63_get_time_ms(void) {
    uint64_t timestamp_s = 0;
    
    struct tm tm_now;
    if (!ntp_service) {
        ntp_service = get_service(NTP_SERVICE_INDEX);
    }

    if (ntp_service && ntp_service->get_time(&tm_now) == 0) {
        time_t t = my_timegm(&tm_now);
        
        timestamp_s = (uint64_t)t - 86400;
    }
    return timestamp_s * 1000;
}

static void ws63_sleep_ms(uint32_t ms) {
    goldie_msleep((int)ms);
}

/* Monotonic millisecond tick for interval/timeout math (PING/reconnect/stop).
 * ws63_get_time_ms is NTP wall-clock with only SECOND resolution and it jumps on
 * NTP sync — unusable for sub-second PING timing (a 30s PING would actually fire
 * at ~31s, racing a ~30s server idle timeout, and NTP jumps corrupt the math).
 * sys_now() is lwIP's systick-based monotonic ms counter — millisecond-accurate
 * and non-jumping. */
static uint64_t ws63_tick_ms(void) {
    return (uint64_t)sys_now();
}

/* ===== OSAL – Mutex ===== */
static int ws63_mutex_create(convai_mutex_t **mutex) {
    if (mutex == NULL) return -1;
    convai_mutex_t *m = (convai_mutex_t*)goldie_malloc(sizeof(*m));
    if (m == NULL) return -1;
    goldie_mutex_init(&m->mutex);
    *mutex = m;
    return 0;
}

static void ws63_mutex_destroy(convai_mutex_t *mutex) {
    if (mutex == NULL) return;
    goldie_mutex_destroy(&mutex->mutex);
    goldie_free(mutex);
}

static void ws63_mutex_lock(convai_mutex_t *mutex) {
    if (mutex == NULL) return;
    goldie_mutex_lock(&mutex->mutex);
}

static void ws63_mutex_unlock(convai_mutex_t *mutex) {
    if (mutex == NULL) return;
    goldie_mutex_unlock(&mutex->mutex);
}

/* ===== OSAL – Thread ===== */
static int ws63_thread_wrapper(void *data) {
    void **args = (void **)data;
    convai_thread_func_t func = (convai_thread_func_t)args[0];
    void *arg = args[1];
    convai_thread_t *thread = (convai_thread_t *)args[2];
    goldie_free(args);
    if (func) func(arg);
    /* notify thread exit for join/destroy */
    if (thread) {
        thread->exited = 1;
        goldie_sem_post(&thread->exit_sem);
    }
    return 0;
}

static int ws63_thread_create(convai_thread_t **thread,
                              convai_thread_func_t func, void *arg,
                              const char *name, size_t stack_size, int priority) {
    if (thread == NULL || func == NULL) return -1;

    convai_thread_t *t = (convai_thread_t*)goldie_malloc(sizeof(*t));
    if (t == NULL) return -1;
    memset(t, 0, sizeof(*t));

    void **args = (void**)goldie_malloc(3 * sizeof(void*));
    if (args == NULL) {
        goldie_free(t);
        return -1;
    }
    args[0] = (void*)func;
    args[1] = arg;
    args[2] = (void*)t;

    unsigned int ss = stack_size > 0 ? stack_size : 4096;
    const char *n = name ? name : "convai";

    goldie_sem_init(&t->exit_sem);

    t->handle = goldie_thread_create(
        (goldie_thread_handler)ws63_thread_wrapper, args, n, ss);
    if (t->handle == NULL) {
        goldie_sem_destroy(&t->exit_sem);
        goldie_free(args);
        goldie_free(t);
        return -1;
    }

    /* Forward an explicit priority only when the caller set one (priority != 0).
     * LiteOS uses higher-number = higher-priority (playback=21, audio=22,
     * sys_init=24). goldie_thread_create has no priority param, so a non-zero
     * request is applied post-create via goldie_thread_set_priority. A priority
     * of 0 means "use goldie's default" — leave it untouched so the SDK's IO
     * thread (which passes 0) keeps its default scheduling. */
    if (priority != 0) {
        goldie_thread_set_priority(t->handle, (unsigned int)priority);
    }

    *thread = t;
    return 0;
}

/* wait for thread to call exit_sem_post */
static void ws63_thread_join(convai_thread_t *thread) {
    if (thread == NULL) return;
    goldie_sem_wait(&thread->exit_sem);
}

/* safe destroy: wait if thread not exited, then release resources */
static void ws63_thread_destroy(convai_thread_t *thread) {
    if (thread == NULL) return;
    if (!thread->exited) {
        goldie_sem_wait(&thread->exit_sem);
    }
    /* Destroy the underlying goldie/LiteOS thread so its task stack is returned
     * to the LiteOS task pool. Without this the convai_thread_t struct is freed
     * (heap) but the LiteOS task (e.g. the 16KB convai_io stack) leaks in the
     * task pool — repeated start/stop (or reconnect cycles) exhaust the pool and
     * subsequent LOS_TaskCreate fails with 0x3000200 (LOS_ERRNO_TSK_TSKMEMOUT),
     * taking down convai_audio / convai_playback. */
    if (thread->handle) {
        goldie_thread_destroy(thread->handle);
        thread->handle = NULL;
    }
    goldie_sem_destroy(&thread->exit_sem);
    goldie_free(thread);
}

/* ===== OSAL – Misc ===== */
static int ws63_fill_random(uint8_t *buf, size_t len) {
    if (buf == NULL) return -1;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}

static char *ws63_strdup(const char *s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = (char*)goldie_malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

/* ===== NetAL – Socket ===== */
static int ws63_socket_create(convai_socket_t **sock) {
    if (sock == NULL) return -1;
    *sock = (convai_socket_t*)goldie_malloc(sizeof(**sock));
    if (*sock == NULL) return -1;
    memset(*sock, 0, sizeof(**sock));
    mbedtls_net_init(&(*sock)->net);
    return 0;
}

static int ws63_socket_destroy(convai_socket_t *sock) {
    if (sock == NULL) return 0;
    printf("[sock] destroy: BEGIN sock=%p fd=%d\n", (void*)sock, sock->net.fd);
    /* Explicitly close the lwIP fd. mbedtls_net_free() in the prebuilt mbedtls
     * lib may call musl close() (not lwip_close), which does NOT release the
     * lwIP socket — the fd then leaks (observed fd 0→1→... across reconnects),
     * and each leaked socket keeps its send/recv buffers (~tens of KB), driving
     * the heap toward exhaustion over reconnect cycles. lwip_close is the
     * authoritative close for an fd created by lwip_socket. */
    if (sock->net.fd >= 0) {
        lwip_close(sock->net.fd);
        sock->net.fd = -1;
    }
    mbedtls_net_free(&sock->net);
    printf("[sock] destroy: before goldie_free(sock) sock=%p\n", (void*)sock);
    goldie_free(sock);
    printf("[sock] destroy: END\n");
    return 0;
}

/* Non-blocking TCP connect: resolve host, create a socket, set it non-blocking,
 * and initiate connect (returns immediately; EINPROGRESS is the expected "in
 * progress" result). The fd is stored in sock->net.fd so the SDK poll loop can
 * drive it (poll WRITE + getsockopt SO_ERROR) and the TLS BIO can use it.
 * Returns 0 if connect was initiated (including EINPROGRESS), <0 on error. */
static int ws63_socket_connect(convai_socket_t *sock, const char *host, uint16_t port) {
    if (sock == NULL || host == NULL) return -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    printf("[I] ws63_net: resolving %s:%s ...\n", host, port_str);
    struct addrinfo *res = NULL;
    int gai = lwip_getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || res == NULL) {
        printf("[E] ws63_net: DNS resolve failed for %s (gai=%d)\n", host, gai);
        return -1;
    }

    /* Log the resolved address so we can confirm the address conversion worked. */
    {
        char addr_str[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        const char *s = lwip_inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        printf("[I] ws63_net: resolved %s -> %s (port=%u)\n", host,
               s ? addr_str : "?", port);
    }

    int fd = lwip_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) {
        printf("[E] ws63_net: lwip_socket failed (errno=%d)\n", errno);
        lwip_freeaddrinfo(res);
        return -1;
    }
    printf("[I] ws63_net: socket created fd=%d\n", fd);

    /* Non-blocking mode before connect so lwip_connect returns EINPROGRESS. */
    unsigned long nb = 1UL;
    lwip_ioctl(fd, FIONBIO, &nb);

    int cr = lwip_connect(fd, res->ai_addr, res->ai_addrlen);
    int saved_errno = errno;
    lwip_freeaddrinfo(res);

    if (cr != 0 && saved_errno != EINPROGRESS) {
        printf("[E] ws63_net: lwip_connect failed (errno=%d)\n", saved_errno);
        lwip_close(fd);
        return -1;
    }

    printf("[I] ws63_net: connect initiated (fd=%d, %s)\n", fd,
           (cr == 0) ? "connected" : "EINPROGRESS");

    /* Connect initiated (cr == 0 already connected, or EINPROGRESS pending).
     * Store the lwIP fd in the mbedtls_net_context so the TLS BIO (which calls
     * mbedtls_net_send/recv -> lwip_send/recv) and socket_poll both use it. */
    sock->net.fd = fd;
    return 0;
}

static int ws63_socket_send(convai_socket_t *sock, const uint8_t *buf, size_t len, size_t *sent) {
    if (sent) *sent = 0;
    if (sock == NULL || buf == NULL) return -1;
    int ret = mbedtls_net_send(&sock->net, buf, len);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return 0;  /* would-block: 0 bytes transferred, ret 0 */
        return -1;
    }
    if (sent) *sent = (size_t)ret;
    return 0;
}

static int ws63_socket_recv(convai_socket_t *sock, uint8_t *buf, size_t len, size_t *recvd) {
    if (recvd) *recvd = 0;
    if (sock == NULL || buf == NULL) return -1;
    int ret = mbedtls_net_recv(&sock->net, buf, len);
    if (ret == 0)
        return -1;  /* peer closed */
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            return 0;  /* would-block: 0 bytes transferred, ret 0 */
        return -1;  /* error */
    }
    if (recvd) *recvd = (size_t)ret;
    return 0;
}

static int ws63_socket_set_nonblock(convai_socket_t *sock, int non_block) {
    if (sock == NULL) return -1;
    if (sock->net.fd < 0) return -1;
    /* Use lwip_ioctl(FIONBIO) directly because mbedtls_net_set_nonblock
     * depends on fcntl() which is unavailable in the WS63 LiteOS build. */
    unsigned long nonblock = non_block ? 1UL : 0UL;

    return lwip_ioctl(sock->net.fd, FIONBIO, &nonblock);
}

static int ws63_socket_is_connected(convai_socket_t *sock) {
    if (sock == NULL) return 0;
    return sock->net.fd >= 0 ? 1 : 0;
}

static int ws63_socket_get_fd(convai_socket_t *sock) {
    if (sock == NULL) return -1;
    return sock->net.fd;
}

static int ws63_socket_get_error(convai_socket_t *sock) {
    if (sock == NULL || sock->net.fd < 0) return -1;
    int so_error = 0;
    socklen_t optlen = sizeof(so_error);
    if (lwip_getsockopt(sock->net.fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) < 0)
        return -1;
    return so_error;  /* 0 = no error, positive = errno */
}

/* ===== TLSAL – mbedTLS implementation (platform layer; SDK is mbedtls-free) ===== */

/* BIO callbacks for mbedTLS (internal). Call mbedtls_net_* directly so that on a
 * non-blocking socket a would-block surfaces as MBEDTLS_ERR_SSL_WANT_WRITE/WANT_READ
 * (the ws63_socket_* wrappers collapse it to -1, which would be a fatal error). */
static int ws63_tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    convai_socket_t *sock = (convai_socket_t *)ctx;
    if (sock == NULL) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return mbedtls_net_send(&sock->net, buf, len);
}

static int ws63_tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    convai_socket_t *sock = (convai_socket_t *)ctx;
    if (sock == NULL) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    return mbedtls_net_recv(&sock->net, buf, len);
}

/* ===== HTTPS fetch callback for AIA certificate chasing (WS63) ===== */

/**
 * @brief Platform-specific HTTPS fetch for AIA certificates (WS63).
 *
 * Creates a temporary TLS connection to fetch DER-encoded certificates from
 * HTTPS URLs. Uses VERIFY_NONE to avoid recursive AIA chasing.
 *
 * @param url         [in]  HTTPS URL (e.g., "https://example.com/ca.der").
 * @param out_der     [out] Buffer for DER certificate data.
 * @param out_buf_len [in]  Size of out_der buffer.
 * @param out_der_len [out] Actual bytes received.
 *
 * @return 0 on success, negative on error.
 */
static int ws63_https_fetch_ca_der(const char *url,
                                   uint8_t *out_der,
                                   size_t out_buf_len,
                                   size_t *out_der_len)
{
    if (url == NULL || out_der == NULL || out_der_len == NULL) {
        return -1;
    }
    *out_der_len = 0;

    /* Parse HTTPS URL: https://host[:port]/path */
    if (strncmp(url, "https://", 8) != 0) {
        printf("[W] AIA fetch: non-HTTPS URL rejected: %s\n", url);
        return -2;
    }
    const char *host_start = url + 8;
    const char *path_start = strchr(host_start, '/');
    if (path_start == NULL) {
        path_start = "/";
    }

    char host[256];
    uint16_t port = 443;
    const char *colon = strchr(host_start, ':');
    const char *host_end = path_start;

    if (colon != NULL && colon < path_start) {
        /* host:port format */
        size_t hlen = colon - host_start;
        if (hlen >= sizeof(host)) return -2;
        memcpy(host, host_start, hlen);
        host[hlen] = '\0';
        port = (uint16_t)atoi(colon + 1);
    } else {
        size_t hlen = host_end - host_start;
        if (hlen >= sizeof(host)) return -2;
        memcpy(host, host_start, hlen);
        host[hlen] = '\0';
    }

    printf("[I] AIA fetch: connecting to %s:%d%s\n", host, port, path_start);

    /* Create temporary socket */
    mbedtls_net_context net_ctx;
    mbedtls_net_init(&net_ctx);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int ret = mbedtls_net_connect(&net_ctx, host, port_str, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) {
        printf("[W] AIA fetch: connect failed: -0x%x\n", (unsigned int)(-ret));
        mbedtls_net_free(&net_ctx);
        return -3;
    }

    /* Create temporary TLS context */
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                 (const unsigned char *)"aia_fetch", 9);
    if (ret != 0) {
        printf("[E] AIA fetch: CTR_DRBG seed failed: -0x%x\n", (unsigned int)(-ret));
        ret = -4;
        goto cleanup;
    }

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                       MBEDTLS_SSL_TRANSPORT_STREAM,
                                       MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        printf("[E] AIA fetch: SSL config defaults failed: -0x%x\n", (unsigned int)(-ret));
        ret = -4;
        goto cleanup;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);  /* Avoid recursion */
    mbedtls_ssl_conf_dbg(&conf, NULL, NULL);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) {
        printf("[E] AIA fetch: SSL setup failed: -0x%x\n", (unsigned int)(-ret));
        ret = -4;
        goto cleanup;
    }

    mbedtls_ssl_set_bio(&ssl, &net_ctx, mbedtls_net_send, mbedtls_net_recv, NULL);
    mbedtls_ssl_set_hostname(&ssl, host);

    /* Perform TLS handshake */
    ret = mbedtls_ssl_handshake(&ssl);
    if (ret != 0) {
        printf("[W] AIA fetch: TLS handshake failed: -0x%x\n", (unsigned int)(-ret));
        ret = -5;
        goto cleanup;
    }

    /* Send HTTP GET request */
    char http_req[512];
    int req_len = snprintf(http_req, sizeof(http_req),
                           "GET %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Connection: close\r\n"
                           "User-Agent: ConvAI-SDK/1.0\r\n"
                           "\r\n",
                           path_start, host);
    if (req_len <= 0 || req_len >= (int)sizeof(http_req)) {
        ret = -5;
        goto cleanup;
    }

    ret = mbedtls_ssl_write(&ssl, (const unsigned char *)http_req, req_len);
    if (ret < 0) {
        printf("[W] AIA fetch: write failed: -0x%x\n", (unsigned int)(-ret));
        ret = -5;
        goto cleanup;
    }

    /* Receive HTTP response */
    uint8_t resp_buf[4096 + 512];  /* Cert + headers */
    size_t total_recv = 0;

    while (total_recv < sizeof(resp_buf)) {
        ret = mbedtls_ssl_read(&ssl, resp_buf + total_recv,
                               sizeof(resp_buf) - total_recv);
        if (ret < 0) {
            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }
            break;  /* EOF or error */
        }
        if (ret == 0) {
            break;  /* Connection closed */
        }
        total_recv += ret;
    }

    if (total_recv == 0) {
        printf("[W] AIA fetch: no response from %s\n", host);
        ret = -6;
        goto cleanup;
    }

    /* Parse HTTP response: find status line */
    const char *resp_str = (const char *)resp_buf;
    if (strncmp(resp_str, "HTTP/", 5) != 0) {
        printf("[W] AIA fetch: invalid HTTP response\n");
        ret = -6;
        goto cleanup;
    }

    /* Find status code */
    const char *status_start = strchr(resp_str, ' ');
    if (status_start == NULL) {
        ret = -6;
        goto cleanup;
    }
    int status_code = atoi(status_start + 1);
    if (status_code != 200) {
        printf("[W] AIA fetch: HTTP %d from %s\n", status_code, url);
        ret = -6;
        goto cleanup;
    }

    /* Find body (after \r\n\r\n) */
    const char *body_start = strstr(resp_str, "\r\n\r\n");
    if (body_start == NULL) {
        printf("[W] AIA fetch: no body delimiter in response\n");
        ret = -6;
        goto cleanup;
    }
    body_start += 4;

    size_t body_len = total_recv - (body_start - resp_str);
    if (body_len > out_buf_len) {
        printf("[W] AIA fetch: response too large (%zu bytes)\n", body_len);
        ret = -7;
        goto cleanup;
    }

    /* Copy DER certificate to output buffer */
    memcpy(out_der, body_start, body_len);
    *out_der_len = body_len;
    ret = 0;

    printf("[I] AIA fetch: got %zu bytes from %s\n", body_len, url);

cleanup:
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_net_free(&net_ctx);
    return ret;
}

static int ws63_tls_create(convai_tls_t **tls)
{
    if (tls == NULL) return -1;

    convai_tls_t *t = (convai_tls_t *)goldie_malloc(sizeof(*t));
    if (t == NULL) return -1;
    memset(t, 0, sizeof(*t));

    mbedtls_ssl_init(&t->ssl);
    mbedtls_ssl_config_init(&t->conf);
    mbedtls_ctr_drbg_init(&t->ctr_drbg);
    mbedtls_entropy_init(&t->entropy);
    mbedtls_x509_crt_init(&t->cacert);

    // Seed RNG
    int ret = mbedtls_ctr_drbg_seed(&t->ctr_drbg, mbedtls_entropy_func,
                                     &t->entropy,
                                     (const unsigned char *)"convai_tls", 10);
    if (ret != 0) goto tls_create_fail;

    // Config SSL defaults
    ret = mbedtls_ssl_config_defaults(&t->conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) goto tls_create_fail;

    mbedtls_ssl_conf_rng(&t->conf, mbedtls_ctr_drbg_random, &t->ctr_drbg);
    mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
    /* Silence mbedTLS debug output (e.g. "mbedtls_ssl_read_record ..." prints) which
     * floods the log and burns CPU during non-blocking reads. */
    mbedtls_ssl_conf_dbg(&t->conf, NULL, NULL);

    ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
    if (ret != 0) goto tls_create_fail;

    /* Register HTTPS fetch callback for AIA certificate chasing */
    convai_aia_chain_set_https_fetch(ws63_https_fetch_ca_der);

    *tls = t;
    return 0;

tls_create_fail:
    /* Release every mbedTLS sub-object that was init'd, in reverse order, so a
     * setup failure doesn't leak the entropy/drbg/ssl internals already allocated.
     * mbedtls_*_free are safe on a context that was init'd but not fully set up. */
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    mbedtls_ctr_drbg_free(&t->ctr_drbg);
    mbedtls_entropy_free(&t->entropy);
    mbedtls_x509_crt_free(&t->cacert);
    goldie_free(t);
    return -1;
}

static int ws63_tls_destroy(convai_tls_t *tls)
{
    if (tls == NULL) return 0;
    /* Alignment check: a corrupted tls pointer (garbage from heap/UAF) is likely
     * unaligned. LiteOS allocates 16B-aligned, so any valid tls is aligned.
     * Skip all mbedtls free on a bad pointer — better to leak than to feed a
     * corrupted struct into mbedtls_ssl_free (which may memset wild ptr via
     * mpi_free with a corrupted n field). */
    if (((unsigned int)(uintptr_t)tls & 0x3) != 0) {
        printf("[tls] destroy: BAD ALIGN tls=%p — skip free\n", (void*)tls);
        return -1;
    }
    /* Diagnostic probe: log tls state before each mbedtls free. If a crash
     * happens during stop teardown, these lines reveal which mbedtls_*_free
     * was executing and whether the tls struct was already corrupted
     * (connected/ssl_state out of range). Zero extra RAM — reads existing
     * fields only. Runs only on the stop/destroy path, not in the hot loop.
     *
     * NOTE: ssl_state is logged for diagnosis only — it is NOT range-checked
     * to skip ssl_free. The legal range depends on mbedTLS compile config
     * (TLS1.2/1.3, extensions) and cannot be safely bounded without reading
     * the exact enum. A corrupted ssl context may still have a state value
     * inside any plausible range, so range-checking gives false security. */
    printf("[tls] destroy: BEGIN tls=%p connected=%d ssl_state=%d\n",
           (void*)tls, tls->connected, (int)tls->ssl.MBEDTLS_PRIVATE(state));
    mbedtls_ssl_free(&tls->ssl);
    printf("[tls] destroy: after ssl_free tls=%p\n", (void*)tls);
    mbedtls_ssl_config_free(&tls->conf);
    printf("[tls] destroy: after config_free tls=%p\n", (void*)tls);
    mbedtls_ctr_drbg_free(&tls->ctr_drbg);
    mbedtls_entropy_free(&tls->entropy);
    mbedtls_x509_crt_free(&tls->cacert);
    printf("[tls] destroy: before goldie_free(tls) tls=%p\n", (void*)tls);
    goldie_free(tls);
    printf("[tls] destroy: END\n");
    return 0;
}

/* Setup only: bind the socket + set hostname + load CA cert (if provided).
 * The handshake itself is driven incrementally by ws63_tls_handshake_step
 * (called from the SDK poll loop) so the SDK's IO thread is never blocked.
 * @param ca_cert  PEM CA cert; non-NULL → parse + VERIFY_REQUIRED,
 *                  NULL → VERIFY_NONE (skip verification). */
static int ws63_tls_connect(convai_tls_t *tls, void *sock, const char *host,
                            const char *ca_cert)
{
    if (tls == NULL || sock == NULL || host == NULL) return -1;

    convai_socket_t *socket = (convai_socket_t *)sock;
    tls->sock = socket;

    mbedtls_ssl_set_hostname(&tls->ssl, host);
    mbedtls_ssl_set_bio(&tls->ssl, socket,
                        ws63_tls_bio_send, ws63_tls_bio_recv, NULL);

    if (ca_cert != NULL) {
        /* Load the CA cert and require server certificate verification. */
        int ret = mbedtls_x509_crt_parse(&tls->cacert,
                                          (const unsigned char *)ca_cert,
                                          strlen(ca_cert) + 1);
        if (ret < 0) {
            printf("[E] ws63_tls: CA cert parse failed: -0x%x\n", (unsigned int)(-ret));
            return -1;
        }
        mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->cacert, NULL);
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_verify(&tls->conf, convai_aia_verify_callback, &tls->cacert);
        printf("[I] VERIFY_REQUIRED (CA cert loaded, %d bytes)\n",
               (int)strlen(ca_cert));
    } else {
        /* No CA cert — skip verification (test/custom environments). */
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
        printf("[W] VERIFY_NONE (no CA cert provided)\n");
    }

    return 0;
}

/* One non-blocking step of the TLS handshake.
 *   *done=1            : handshake complete
 *   *want_flags=POLL_* : need to poll socket in that direction, then re-call
 *   return <0           : fatal handshake error */
static int ws63_tls_handshake_step(convai_tls_t *tls, int *want_flags, int *done)
{
    if (tls == NULL || want_flags == NULL || done == NULL) return -1;
    *want_flags = 0;
    *done = 0;

    int ret = mbedtls_ssl_handshake(&tls->ssl);
    if (ret == 0) {
        tls->connected = 1;
        *done = 1;
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        *want_flags = CONVAI_POLL_READ;
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        *want_flags = CONVAI_POLL_WRITE;
        return 0;
    }
    printf("[E] ws63_tls: handshake failed: -0x%x\n", (unsigned int)(-ret));
    return -1;
}

static int ws63_tls_read(convai_tls_t *tls, uint8_t *buf, size_t len, size_t *nread)
{
    if (nread) *nread = 0;
    if (tls == NULL || buf == NULL) return -1;

    int ret = mbedtls_ssl_read(&tls->ssl, (unsigned char *)buf, (int)len);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return 0;  /* would-block: 0 bytes, ret 0 */
        }
        return -1;  /* error or peer-closed */
    }
    if (ret == 0) {
        return -1;  /* peer closed the connection */
    }
    if (nread) *nread = (size_t)ret;
    return 0;
}

static int ws63_tls_write(convai_tls_t *tls, const uint8_t *buf, size_t len, size_t *nwrite)
{
    if (nwrite) *nwrite = 0;
    if (tls == NULL || buf == NULL) return -1;

    int ret = mbedtls_ssl_write(&tls->ssl, (const unsigned char *)buf, (int)len);
    if (ret < 0) {
        if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
            ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            return 0;
        }
        return -1;
    }
    if (nwrite) *nwrite = (size_t)ret;
    return 0;
}

static int ws63_tls_close(convai_tls_t *tls)
{
    if (tls == NULL) return -1;
    /* Skip close_notify on an already-disconnected TLS session — calling it on a
     * peer-closed / dead socket can re-enter mbedtls internal read paths on an
     * inconsistent ssl context (observed crash signature: memset wild ptr with
     * ra inside mbedtls_mpi_mul_mpi). connected==0 means we never handshaked or
     * already closed; close_notify is pointless and risky in that state. */
    if (!tls->connected) {
        printf("[tls] close: skip close_notify (already disconnected, tls=%p)\n", (void*)tls);
        return 0;
    }
    printf("[tls] close: close_notify tls=%p ssl_state=%d\n",
           (void*)tls, (int)tls->ssl.MBEDTLS_PRIVATE(state));
    mbedtls_ssl_close_notify(&tls->ssl);
    tls->connected = 0;
    return 0;
}

/* ===== NetAL: socket_poll (required by the poll architecture) =====
 *
 * WS63 lwip_select() does NOT honour a non-zero timeout when there are no ready
 * fds: it returns ret=0 immediately (confirmed by tracing select ret=0 printed
 * very fast). This busy-loops the IO thread (CPU 100%, mbedtls debug flood) and
 * eventually overflows the stack on the 401 path. musl poll() is not linked on
 * this target (undefined reference to `poll`).
 *
 * Workaround: poll with a zero-timeout select (non-blocking readiness check) and
 * sleep in small slices when nothing is ready, retrying up to timeout_ms/slice.
 * Event latency is bounded by the slice (10ms). No time-of-day measurement is
 * used (ws63_get_time_ms has only second resolution), just a slice counter. */
static int ws63_socket_poll(convai_socket_t *sock, int events, int *revents, int timeout_ms) {
    if (sock == NULL || revents == NULL) return -1;
    *revents = 0;

    int fd = sock->net.fd;
    if (fd < 0) return -1;

    #define WS63_POLL_SLICE_MS 10
    int slices = (timeout_ms > 0) ? (timeout_ms / WS63_POLL_SLICE_MS) : 0;

    for (int i = 0; i <= slices; i++) {
        fd_set rfds, wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        if (events & CONVAI_POLL_READ)  FD_SET(fd, &rfds);
        if (events & CONVAI_POLL_WRITE) FD_SET(fd, &wfds);

        struct timeval ztv;
        ztv.tv_sec = 0;
        ztv.tv_usec = 0;
        int ret = select(fd + 1, &rfds, &wfds, NULL, &ztv);
        if (ret < 0) {
            printf("[E] ws63_net: select failed fd=%d errno=%d\n", fd, errno);
            return -1;
        }
        if (FD_ISSET(fd, &rfds)) *revents |= CONVAI_POLL_READ;
        if (FD_ISSET(fd, &wfds)) *revents |= CONVAI_POLL_WRITE;
        if (*revents != 0) {
            return 0;  /* event ready */
        }
        if (i < slices) {
            goldie_msleep(WS63_POLL_SLICE_MS);  /* wait a slice, then re-check */
        }
    }
    return 0;  /* timed out, no event */
}

/* ===== Misc ===== */
static void ws63_log(int level, const char *file, int line, const char *fmt, ...) {
    char buf[256];
    va_list args;
    uint64_t now_ms = ws63_get_time_ms();
    uint32_t sec = (uint32_t)(now_ms / 1000);
    uint32_t ms = (uint32_t)(now_ms % 1000);
    int pos = snprintf(buf, sizeof(buf), "[%u.%03u] [%c] [%s:%d] ",
                       sec, ms,
                       level == 0 ? 'E' : level == 1 ? 'W' : level == 2 ? 'I' : 'D',
                       file ? file : "???", line);
    va_start(args, fmt);
    vsnprintf(buf + pos, sizeof(buf) - pos - 2, fmt, args);
    va_end(args);
    int len = strlen(buf);
    if (len < (int)sizeof(buf) - 1) {
        buf[len] = '\n';
        buf[len + 1] = '\0';
    }
    printf("%s", buf);
}

int ws63_device_id(char *buf, size_t len) {
    if (buf == NULL || len < 18) return -1;

    WifiService *wifi_svc = (WifiService *)get_service(WIFI_SERVICE_INDEX);
    if (wifi_svc != NULL && wifi_svc->svr_get_hwddr != NULL) {
        uint8_t hw_addr[6] = {0};
        if (wifi_svc->svr_get_hwddr(hw_addr, 6) == 0) {
            int is_valid = 0;
            for (int i = 0; i < 6; i++) {
                if (hw_addr[i] != 0x00 && hw_addr[i] != 0xFF) {
                    is_valid = 1;
                    break;
                }
            }
            if (is_valid) {
                snprintf(buf, len, "%02X%02X%02X%02X%02X%02X",
                         hw_addr[0], hw_addr[1], hw_addr[2],
                         hw_addr[3], hw_addr[4], hw_addr[5]);
                return (int)strlen(buf);
            }
        }
    }

    snprintf(buf, len, "ws63-device");
    return (int)strlen(buf);
}

static int ws63_random(uint8_t *buf, size_t len) {
    return ws63_fill_random(buf, len);
}

static int ws63_uuid(char *buf, size_t size) {
    if (buf == NULL || size == 0) return -1;
    snprintf(buf, size, "00000000-0000-0000-0000-000000000000");
    return (int)strlen(buf);
}

static int ws63_info(char *buf, size_t size) {
    if (buf == NULL || size == 0) return -1;
    snprintf(buf, size, "ws63-liteos");
    return (int)strlen(buf);
}

static int ws63_network_available(void) {
    return 1;
}

static int ws63_network_get_type(char *buf, size_t size) {
    if (buf == NULL || size == 0) return -1;
    snprintf(buf, size, "wifi");
    return (int)strlen(buf);
}

/* ===== Platform structure instance ===== */
const convai_platform_t g_convai_platform = {
    .abi_version = CONVAI_ABI_VERSION,
    ._reserved = 0,
    .osal = {
        .malloc = ws63_malloc,
        .free = ws63_free,
        .get_time_ms = ws63_get_time_ms,
        .sleep_ms = ws63_sleep_ms,
        .get_tick_ms = ws63_tick_ms,
        .mutex_create = ws63_mutex_create,
        .mutex_destroy = ws63_mutex_destroy,
        .mutex_lock = ws63_mutex_lock,
        .mutex_unlock = ws63_mutex_unlock,
        .thread_create = ws63_thread_create,
        .thread_join = ws63_thread_join,
        .thread_destroy = ws63_thread_destroy,
        .fill_random = ws63_fill_random,
        .strdup = ws63_strdup,
    },
    .netal = {
        .socket_create = ws63_socket_create,
        .socket_destroy = ws63_socket_destroy,
        .socket_connect = ws63_socket_connect,
        .socket_send = ws63_socket_send,
        .socket_recv = ws63_socket_recv,
        .socket_set_nonblock = ws63_socket_set_nonblock,
        .socket_is_connected = ws63_socket_is_connected,
        .socket_get_fd = ws63_socket_get_fd,
        .socket_poll = ws63_socket_poll,
        .socket_get_error = ws63_socket_get_error,
    },
    .tlsal = {
        .tls_create = ws63_tls_create,
        .tls_destroy = ws63_tls_destroy,
        .tls_connect = ws63_tls_connect,
        .tls_handshake_step = ws63_tls_handshake_step,
        .tls_read = ws63_tls_read,
        .tls_write = ws63_tls_write,
        .tls_close = ws63_tls_close,
    },
    .misc = {
        .log = ws63_log,
        .device_id = ws63_device_id,
        .random = ws63_random,
        .uuid = ws63_uuid,
        .info = ws63_info,
        .network_available = ws63_network_available,
        .network_get_type = ws63_network_get_type,
    },
};

int convai_platform_ws63_init(void) {
    /* Initialize AIA chain completion subsystem */
    convai_aia_chain_init();

    /* Configure volatile-only trust store (WS63 has no writable FS) */
    convai_aia_chain_set_truststore(NULL);

    return convai_platform_init(&g_convai_platform);
}
