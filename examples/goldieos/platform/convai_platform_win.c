/**
 * @file convai_platform_win.c
 * @brief Windows simulator platform abstraction implementation.
 *
 * 与 convai_platform_ws63.c 同构:
 *  - OSAL: goldie_osal (由 libwinvm.a 提供的 Windows 实现)
 *  - NetAL: Winsock2 (非阻塞 connect + select poll)
 *  - TLSAL: mbedTLS (libs/win10 预编译库)
 */

#include "convai_platform_win.h"
#include "goldie_osal.h"

/* winsock2.h 必须先于 windows.h 包含，避免旧版 winsock.h 被拉入导致符号冲突。 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600  /* Vista+: GetTickCount64、inet_ntop 需要 */
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "certs/convai_aia_chain.h"
#include "certs/convai_aia_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

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
    mbedtls_net_context net;  /* 持有 winsock fd, TLS BIO 复用 */
};

struct convai_tls_s {
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt cacert;
    convai_socket_t *sock;  /* 持有 socket 引用 */
    int connected;
    int aia_attempted;      /* AIA chain completion already attempted */
    /* Saved peer cert raw data for post-handshake AIA retry */
    uint8_t saved_peer_cert[8192];
    size_t saved_peer_cert_len;
};

/* ===== Winsock 惰性初始化 (WSAStartup 只需调用一次) ===== */
static int win_wsa_init(void)
{
    static int wsa_started = 0;
    WSADATA wsa_data;

    if (wsa_started) {
        return 0;
    }
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("[E] win_net: WSAStartup failed\n");
        return -1;
    }
    wsa_started = 1;
    return 0;
}

/* ===== HTTPS fetch callback for AIA certificate chasing ===== */

/**
 * @brief Platform-specific HTTPS fetch for AIA certificates (Windows).
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
static int win_https_fetch_ca_der(const char *url,
                                  uint8_t *out_der,
                                  size_t out_buf_len,
                                  size_t *out_der_len)
{
    if (url == NULL || out_der == NULL || out_der_len == NULL) {
        return -1;
    }
    *out_der_len = 0;

    /* Parse URL: support both http:// and https:// */
    int use_tls = 0;
    const char *host_start = NULL;
    uint16_t default_port = 80;

    if (strncmp(url, "https://", 8) == 0) {
        use_tls = 1;
        host_start = url + 8;
        default_port = 443;
    } else if (strncmp(url, "http://", 7) == 0) {
        use_tls = 0;
        host_start = url + 7;
        default_port = 80;
    } else {
        printf("[W] AIA fetch: unsupported URL scheme: %s\n", url);
        return -2;
    }

    const char *path_start = strchr(host_start, '/');
    if (path_start == NULL) {
        path_start = "/";
    }

    char host[256];
    uint16_t port = default_port;
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

    printf("[I] AIA fetch: connecting to %s:%d%s (TLS=%d)\n", host, port, path_start, use_tls);

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

    /* Set socket timeout to 3 seconds to prevent blocking */
    DWORD timeout_ms = 3000;
    setsockopt(net_ctx.fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));
    setsockopt(net_ctx.fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout_ms, sizeof(timeout_ms));

    /* TLS context (only used when use_tls == 1) */
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    int tls_initialized = 0;

    if (use_tls) {
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        tls_initialized = 1;

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

    if (use_tls) {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char *)http_req, req_len);
    } else {
        ret = mbedtls_net_send(&net_ctx, (const unsigned char *)http_req, req_len);
    }
    if (ret < 0) {
        printf("[W] AIA fetch: write failed: -0x%x\n", (unsigned int)(-ret));
        ret = -5;
        goto cleanup;
    }
    printf("[D] AIA fetch: sent %d bytes\n", ret);

    /* Receive HTTP response */
    uint8_t resp_buf[4096 + 512];  /* Cert + headers */
    size_t total_recv = 0;

    while (total_recv < sizeof(resp_buf)) {
        if (use_tls) {
            ret = mbedtls_ssl_read(&ssl, resp_buf + total_recv,
                                   sizeof(resp_buf) - total_recv);
            if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }
        } else {
            ret = mbedtls_net_recv(&net_ctx, resp_buf + total_recv,
                                   sizeof(resp_buf) - total_recv);
            if (ret < 0) {
                printf("[D] AIA fetch: recv error: -0x%x (total_recv=%zu)\n",
                       (unsigned int)(-ret), total_recv);
            }
        }
        if (ret < 0) {
            break;  /* EOF or error */
        }
        if (ret == 0) {
            printf("[D] AIA fetch: connection closed by server (total_recv=%zu)\n", total_recv);
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
    if (tls_initialized) {
        mbedtls_ssl_free(&ssl);
        mbedtls_ssl_config_free(&conf);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
    }
    mbedtls_net_free(&net_ctx);
    return ret;
}

/* ===== OSAL – Memory ===== */
static void *win_malloc(size_t size) {
    return goldie_malloc(size);
}

static void win_free(void *ptr) {
    goldie_free(ptr);
}

/* ===== OSAL – Time ===== */

/* Wall-clock epoch ms (winvm 的 goldie_gettimeofday 映射到系统实时时钟). */
uint64_t win_get_time_ms(void) {
    goldie_timeval tv;
    goldie_gettimeofday(&tv);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)tv.tv_usec / 1000ULL;
}

static void win_sleep_ms(uint32_t ms) {
    goldie_msleep((int)ms);
}

/* Monotonic millisecond tick for interval/timeout math (PING/reconnect/stop).
 * GetTickCount64 单调递增、不受系统校时影响 — 对应 ws63 用 sys_now() 的设计意图. */
static uint64_t win_tick_ms(void) {
    return (uint64_t)GetTickCount64();
}

/* ===== OSAL – Mutex ===== */
static int win_mutex_create(convai_mutex_t **mutex) {
    if (mutex == NULL) return -1;
    convai_mutex_t *m = (convai_mutex_t*)goldie_malloc(sizeof(*m));
    if (m == NULL) return -1;
    goldie_mutex_init(&m->mutex);
    *mutex = m;
    return 0;
}

static void win_mutex_destroy(convai_mutex_t *mutex) {
    if (mutex == NULL) return;
    goldie_mutex_destroy(&mutex->mutex);
    goldie_free(mutex);
}

static void win_mutex_lock(convai_mutex_t *mutex) {
    if (mutex == NULL) return;
    goldie_mutex_lock(&mutex->mutex);
}

static void win_mutex_unlock(convai_mutex_t *mutex) {
    if (mutex == NULL) return;
    goldie_mutex_unlock(&mutex->mutex);
}

/* ===== OSAL – Thread ===== */
static int win_thread_wrapper(void *data) {
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

static int win_thread_create(convai_thread_t **thread,
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

    unsigned int ss = stack_size > 0 ? (unsigned int)stack_size : 4096U;

    if (ss < 128U * 1024U) {
        ss = 128U * 1024U;
    }
    const char *n = name ? name : "convai";

    goldie_sem_init(&t->exit_sem);

    t->handle = goldie_thread_create(
        (goldie_thread_handler)win_thread_wrapper, args, n, ss);
    if (t->handle == NULL) {
        goldie_sem_destroy(&t->exit_sem);
        goldie_free(args);
        goldie_free(t);
        return -1;
    }

    /* 仅当调用方显式指定优先级时才转发 (priority != 0);
     * 0 表示使用 goldie 默认调度, 与 ws63 行为一致. */
    if (priority != 0) {
        goldie_thread_set_priority(t->handle, (unsigned int)priority);
    }

    *thread = t;
    return 0;
}

/* wait for thread to call exit_sem_post */
static void win_thread_join(convai_thread_t *thread) {
    if (thread == NULL) return;
    goldie_sem_wait(&thread->exit_sem);
}

/* safe destroy: wait if thread not exited, then release resources */
static void win_thread_destroy(convai_thread_t *thread) {
    if (thread == NULL) return;
    if (!thread->exited) {
        goldie_sem_wait(&thread->exit_sem);
    }
    if (thread->handle) {
        goldie_thread_destroy(thread->handle);
        thread->handle = NULL;
    }
    goldie_sem_destroy(&thread->exit_sem);
    goldie_free(thread);
}

/* ===== OSAL – Misc ===== */
static int win_fill_random(uint8_t *buf, size_t len) {
    if (buf == NULL) return -1;
    for (size_t i = 0; i < len; i++) {
        buf[i] = (uint8_t)(rand() & 0xFF);
    }
    return 0;
}

static char *win_strdup(const char *s) {
    if (s == NULL) return NULL;
    size_t len = strlen(s) + 1;
    char *dup = (char*)goldie_malloc(len);
    if (dup) memcpy(dup, s, len);
    return dup;
}

/* ===== OSAL – File I/O (for persistent trust store) ===== */
static int win_file_write(const char *path, const uint8_t *data, size_t len) {
    if (path == NULL || data == NULL) return -1;
    FILE *fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    return (written == len) ? 0 : -1;
}

static int win_file_read(const char *path, uint8_t *buf, size_t buf_len, size_t *out_len) {
    if (path == NULL || buf == NULL || out_len == NULL) return -1;
    *out_len = 0;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    size_t nread = fread(buf, 1, buf_len, fp);
    fclose(fp);
    *out_len = nread;
    return 0;
}

static int win_file_exists(const char *path) {
    if (path == NULL) return -1;
    FILE *fp = fopen(path, "rb");
    if (fp == NULL) return -1;
    fclose(fp);
    return 0;
}

static int win_file_remove(const char *path) {
    if (path == NULL) return -1;
    return remove(path) == 0 ? 0 : -1;
}

/* ===== NetAL – Socket ===== */
static int win_socket_create(convai_socket_t **sock) {
    if (sock == NULL) return -1;
    if (win_wsa_init() != 0) return -1;
    *sock = (convai_socket_t*)goldie_malloc(sizeof(**sock));
    if (*sock == NULL) return -1;
    memset(*sock, 0, sizeof(**sock));
    mbedtls_net_init(&(*sock)->net);
    return 0;
}

static int win_socket_destroy(convai_socket_t *sock) {
    if (sock == NULL) return 0;
    /* 显式关闭 winsock fd, 与 ws63 显式 lwip_close 同理:
     * 确保 fd 及其收发缓冲及时释放, 重连场景不泄漏. */
    if (sock->net.fd >= 0) {
        closesocket((SOCKET)sock->net.fd);
        sock->net.fd = -1;
    }
    mbedtls_net_free(&sock->net);
    goldie_free(sock);
    return 0;
}

/* Non-blocking TCP connect: resolve host, create a socket, set it non-blocking,
 * and initiate connect (returns immediately; WSAEWOULDBLOCK is the expected "in
 * progress" result). The fd is stored in sock->net.fd so the SDK poll loop can
 * drive it (poll WRITE + getsockopt SO_ERROR) and the TLS BIO can use it.
 * Returns 0 if connect was initiated, <0 on error. */
static int win_socket_connect(convai_socket_t *sock, const char *host, uint16_t port) {
    if (sock == NULL || host == NULL) return -1;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    printf("[I] win_net: resolving %s:%s ...\n", host, port_str);
    struct addrinfo *res = NULL;
    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || res == NULL) {
        printf("[E] win_net: DNS resolve failed for %s (gai=%d)\n", host, gai);
        return -1;
    }

    {
        char addr_str[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        const char *s = inet_ntop(AF_INET, &sin->sin_addr, addr_str, sizeof(addr_str));
        printf("[I] win_net: resolved %s -> %s (port=%u)\n", host,
               s ? addr_str : "?", port);
    }

    SOCKET fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == INVALID_SOCKET) {
        printf("[E] win_net: socket failed (WSA error=%d)\n", WSAGetLastError());
        freeaddrinfo(res);
        return -1;
    }
    printf("[I] win_net: socket created fd=%d\n", (int)fd);

    /* Non-blocking mode before connect so connect returns WSAEWOULDBLOCK. */
    u_long nb = 1UL;
    ioctlsocket(fd, FIONBIO, &nb);

    int cr = connect(fd, res->ai_addr, (int)res->ai_addrlen);
    int wsa_err = WSAGetLastError();
    freeaddrinfo(res);

    if (cr == SOCKET_ERROR && wsa_err != WSAEWOULDBLOCK && wsa_err != WSAEINPROGRESS) {
        printf("[E] win_net: connect failed (WSA error=%d)\n", wsa_err);
        closesocket(fd);
        return -1;
    }

    printf("[I] win_net: connect initiated (fd=%d, %s)\n", (int)fd,
           (cr == 0) ? "connected" : "WSAEWOULDBLOCK");

    /* Connect initiated (cr == 0 already connected, or WSAEWOULDBLOCK pending).
     * Store the fd in the mbedtls_net_context so the TLS BIO (which calls
     * mbedtls_net_send/recv) and socket_poll both use it. */
    sock->net.fd = (int)fd;
    return 0;
}

static int win_socket_send(convai_socket_t *sock, const uint8_t *buf, size_t len, size_t *sent) {
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

static int win_socket_recv(convai_socket_t *sock, uint8_t *buf, size_t len, size_t *recvd) {
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

static int win_socket_set_nonblock(convai_socket_t *sock, int non_block) {
    if (sock == NULL) return -1;
    if (sock->net.fd < 0) return -1;
    u_long mode = non_block ? 1UL : 0UL;
    return ioctlsocket((SOCKET)sock->net.fd, FIONBIO, &mode) == 0 ? 0 : -1;
}

static int win_socket_is_connected(convai_socket_t *sock) {
    if (sock == NULL) return 0;
    return sock->net.fd >= 0 ? 1 : 0;
}

static int win_socket_get_fd(convai_socket_t *sock) {
    if (sock == NULL) return -1;
    return sock->net.fd;
}

static int win_socket_get_error(convai_socket_t *sock) {
    if (sock == NULL || sock->net.fd < 0) return -1;
    int so_error = 0;
    int optlen = sizeof(so_error);
    if (getsockopt((SOCKET)sock->net.fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &optlen) != 0)
        return -1;
    return so_error;  /* 0 = no error, positive = WSA error code */
}

/* ===== TLSAL – mbedTLS implementation (platform layer; SDK is mbedtls-free) ===== */

/* BIO callbacks for mbedTLS (internal). Call mbedtls_net_* directly so that on a
 * non-blocking socket a would-block surfaces as MBEDTLS_ERR_SSL_WANT_WRITE/WANT_READ
 * (the win_socket_* wrappers collapse it to -1, which would be a fatal error). */
static int win_tls_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
    convai_socket_t *sock = (convai_socket_t *)ctx;
    if (sock == NULL) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    int ret = mbedtls_net_send(&sock->net, buf, len);
    printf("[D] win_tls_bio_send: len=%zu ret=%d\n", len, ret);
    return ret;
}

static int win_tls_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
    convai_socket_t *sock = (convai_socket_t *)ctx;
    if (sock == NULL) return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
    int ret = mbedtls_net_recv(&sock->net, buf, len);
    printf("[D] win_tls_bio_recv: len=%zu ret=%d\n", len, ret);
    return ret;
}

/* Diagnostic wrapper for AIA verify callback. Logs every invocation with
 * certificate details, delegates to AIA callback, logs result. */
static int win_tls_verify_callback(void *ctx, mbedtls_x509_crt *crt,
                                   int depth, uint32_t *flags)
{
    convai_tls_t *tls = (convai_tls_t *)ctx;

    /* Extract subject and issuer CN */
    char subject[256] = {0}, issuer[256] = {0};
    mbedtls_x509_dn_gets(subject, sizeof(subject), &crt->subject);
    mbedtls_x509_dn_gets(issuer, sizeof(issuer), &crt->issuer);

    printf("[D] ===== verify callback: depth=%d flags=0x%08x =====\n",
           depth, flags ? *flags : 0);
    printf("[D]   subject: %s\n", subject);
    printf("[D]   issuer:  %s\n", issuer);
    printf("[D]   valid:   %04d-%02d-%02d ~ %04d-%02d-%02d\n",
           crt->valid_from.year, crt->valid_from.mon, crt->valid_from.day,
           crt->valid_to.year, crt->valid_to.mon, crt->valid_to.day);

    if (flags && *flags) {
        printf("[D]   verify FAIL flags: ");
        if (*flags & 0x01) printf("EXPIRED ");
        if (*flags & 0x02) printf("REVOKED ");
        if (*flags & 0x04) printf("CN_MISMATCH ");
        if (*flags & 0x08) printf("NOT_TRUSTED ");
        if (*flags & 0x40) printf("MISSING ");
        if (*flags & 0x0200) printf("FUTURE ");
        printf("\n");
    } else {
        printf("[D]   verify OK (flags=0)\n");
    }

    if (tls == NULL) {
        printf("[E] win_tls: verify callback has NULL context\n");
        return 1;
    }

    /* Save peer cert raw data at depth=0 for post-handshake AIA retry */
    if (depth == 0 && crt->raw.p != NULL && crt->raw.len <= sizeof(tls->saved_peer_cert)) {
        memcpy(tls->saved_peer_cert, crt->raw.p, crt->raw.len);
        tls->saved_peer_cert_len = crt->raw.len;
        printf("[D]   saved peer cert (%zu bytes) for AIA retry\n", crt->raw.len);
    }

    /* Delegate to AIA callback with the CA chain */
    uint32_t flags_before = flags ? *flags : 0;
    int ret = convai_aia_verify_callback(&tls->cacert, crt, depth, flags);
    uint32_t flags_after = flags ? *flags : 0;

    if (flags_before != flags_after) {
        printf("[D]   AIA callback changed flags: 0x%08x -> 0x%08x\n",
               flags_before, flags_after);
    } else {
        printf("[D]   AIA callback: flags unchanged (0x%08x), ret=%d\n",
               flags_after, ret);
    }
    printf("[D] ===== end verify callback =====\n");
    return ret;
}

static int win_tls_create(convai_tls_t **tls)
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
    /* Silence mbedTLS debug output which floods the log and burns CPU
     * during non-blocking reads. */
    mbedtls_ssl_conf_dbg(&t->conf, NULL, NULL);

    ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
    if (ret != 0) goto tls_create_fail;

    /* Register HTTPS fetch callback for AIA certificate chasing */
    convai_aia_chain_set_https_fetch(win_https_fetch_ca_der);

    *tls = t;
    return 0;

tls_create_fail:
    /* Release every mbedTLS sub-object that was init'd, in reverse order.
     * mbedtls_*_free are safe on a context that was init'd but not fully set up. */
    mbedtls_ssl_free(&t->ssl);
    mbedtls_ssl_config_free(&t->conf);
    mbedtls_ctr_drbg_free(&t->ctr_drbg);
    mbedtls_entropy_free(&t->entropy);
    mbedtls_x509_crt_free(&t->cacert);
    goldie_free(t);
    return -1;
}

static int win_tls_destroy(convai_tls_t *tls)
{
    if (tls == NULL) return 0;
    mbedtls_ssl_free(&tls->ssl);
    mbedtls_ssl_config_free(&tls->conf);
    mbedtls_ctr_drbg_free(&tls->ctr_drbg);
    mbedtls_entropy_free(&tls->entropy);
    mbedtls_x509_crt_free(&tls->cacert);
    goldie_free(tls);
    return 0;
}

/* Setup only: bind the socket + set hostname + load CA cert (if provided).
 * The handshake itself is driven incrementally by win_tls_handshake_step
 * (called from the SDK poll loop) so the SDK's IO thread is never blocked.
 * @param ca_cert  PEM CA cert; non-NULL → parse + VERIFY_REQUIRED,
 *                  NULL → VERIFY_NONE (skip verification). */
static int win_tls_connect(convai_tls_t *tls, void *sock, const char *host,
                           const char *ca_cert)
{
    if (tls == NULL || sock == NULL || host == NULL) return -1;

    convai_socket_t *socket = (convai_socket_t *)sock;
    tls->sock = socket;

    mbedtls_ssl_set_hostname(&tls->ssl, host);
    mbedtls_ssl_set_bio(&tls->ssl, socket,
                        win_tls_bio_send, win_tls_bio_recv, NULL);

    if (ca_cert != NULL) {
        /* Load the CA cert and require server certificate verification. */
        int ret = mbedtls_x509_crt_parse(&tls->cacert,
                                          (const unsigned char *)ca_cert,
                                          strlen(ca_cert) + 1);
        if (ret < 0) {
            printf("[E] win_tls: CA cert parse failed: -0x%x\n", (unsigned int)(-ret));
            return -1;
        }
        /* Log CA cert info */
        char ca_info[512] = {0};
        mbedtls_x509_crt_info(ca_info, sizeof(ca_info), "", &tls->cacert);
        printf("[I] CA cert loaded (%d bytes):\n%s", (int)strlen(ca_cert), ca_info);

        mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->cacert, NULL);
        mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        /* Diagnostic wrapper: log every verify callback invocation, then
         * delegate to the AIA callback which does chain auto-completion. */
        mbedtls_ssl_conf_verify(&tls->conf, win_tls_verify_callback, tls);
        printf("[I] VERIFY_REQUIRED enabled, hostname=%s\n", host);
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
static int win_tls_handshake_step(convai_tls_t *tls, int *want_flags, int *done)
{
    if (tls == NULL || want_flags == NULL || done == NULL) return -1;
    *want_flags = 0;
    *done = 0;

    printf("[D] win_tls: handshake_step called, connected=%d\n", tls->connected);

    int ret = mbedtls_ssl_handshake(&tls->ssl);
    printf("[D] win_tls: mbedtls_ssl_handshake returned -0x%x\n", ret ? (unsigned int)(-ret) : 0);

    if (ret == 0) {
        tls->connected = 1;
        *done = 1;
        printf("[I] win_tls: handshake complete, %s / %s\n",
               mbedtls_ssl_get_version(&tls->ssl),
               mbedtls_ssl_get_ciphersuite(&tls->ssl));
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
        *want_flags = CONVAI_POLL_READ;
        printf("[D] win_tls: handshake wants READ\n");
        return 0;
    }
    if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
        *want_flags = CONVAI_POLL_WRITE;
        printf("[D] win_tls: handshake wants WRITE\n");
        return 0;
    }

    /* Log all other errors */
    printf("[E] win_tls: handshake error -0x%x\n", (unsigned int)(-ret));

    /* Check if this is a certificate verification failure that we can fix with AIA */
    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        uint32_t flags = mbedtls_ssl_get_verify_result(&tls->ssl);
        printf("[I] win_tls: certificate verify failed, flags=0x%08x\n", flags);

        /* If NOT_TRUSTED and we haven't tried AIA yet, try to fetch intermediate cert */
        if ((flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED) && !tls->aia_attempted) {
            tls->aia_attempted = 1;
            printf("[I] win_tls: attempting AIA chain completion...\n");

            /* Get peer certificate - try saved cert first, then SSL context */
            const uint8_t *peer_cert_data = NULL;
            size_t peer_cert_len = 0;

            if (tls->saved_peer_cert_len > 0) {
                peer_cert_data = tls->saved_peer_cert;
                peer_cert_len = tls->saved_peer_cert_len;
                printf("[I] win_tls: using saved peer cert (%zu bytes)\n", peer_cert_len);
            } else {
                const mbedtls_x509_crt *peer_crt = mbedtls_ssl_get_peer_cert(&tls->ssl);
                if (peer_crt != NULL) {
                    peer_cert_data = peer_crt->raw.p;
                    peer_cert_len = peer_crt->raw.len;
                    printf("[I] win_tls: got peer cert from SSL context (%zu bytes)\n", peer_cert_len);
                }
            }

            if (peer_cert_data != NULL && peer_cert_len > 0) {
                printf("[I] win_tls: parsing AIA URLs from peer cert...\n");

                /* Parse AIA URLs from peer certificate */
                convai_aia_info_t aia_info;
                int parse_ret = convai_aia_parse_cert(peer_cert_data, peer_cert_len,
                                                       0, &aia_info);
                if (parse_ret == 0 && aia_info.url_count > 0) {
                    printf("[I] win_tls: found %d AIA URL(s)\n", aia_info.url_count);

                    /* Try to fetch intermediate certificate from any URL */
                    for (int i = 0; i < aia_info.url_count; i++) {
                        const char *url = aia_info.urls[i];

                        printf("[I] win_tls: fetching intermediate from %s\n", url);

                        uint8_t fetched_der[4096];
                        size_t fetched_len = 0;
                        int fetch_ret = win_https_fetch_ca_der(url, fetched_der,
                                                               sizeof(fetched_der),
                                                               &fetched_len);
                        if (fetch_ret == 0 && fetched_len > 0) {
                            printf("[I] win_tls: fetched %zu bytes, adding to CA chain\n",
                                   fetched_len);

                            /* Parse and add to CA chain */
                            mbedtls_x509_crt *intermediate = calloc(1, sizeof(mbedtls_x509_crt));
                            if (intermediate != NULL) {
                                mbedtls_x509_crt_init(intermediate);
                                int cert_ret = mbedtls_x509_crt_parse_der(intermediate,
                                                                           fetched_der,
                                                                           fetched_len);
                                if (cert_ret == 0) {
                                    /* Add to CA chain */
                                    mbedtls_x509_crt *cur = &tls->cacert;
                                    while (cur->next != NULL) cur = cur->next;
                                    cur->next = intermediate;

                                    printf("[I] win_tls: intermediate cert added, retrying handshake\n");

                                    /* Reset SSL state for retry */
                                    mbedtls_ssl_session_reset(&tls->ssl);

                                    /* Continue handshake (will be called again) */
                                    return 0;
                                } else {
                                    printf("[E] win_tls: failed to parse intermediate cert: -0x%x\n",
                                           (unsigned int)(-cert_ret));
                                    mbedtls_x509_crt_free(intermediate);
                                    free(intermediate);
                                }
                            }
                        } else {
                            printf("[W] win_tls: failed to fetch from %s (ret=%d)\n", url, fetch_ret);
                        }
                    }
                } else {
                    printf("[W] win_tls: no AIA URLs found in peer certificate\n");
                }
            } else {
                printf("[W] win_tls: no peer certificate available (saved=%zu, ssl=%p)\n",
                       tls->saved_peer_cert_len, (void*)mbedtls_ssl_get_peer_cert(&tls->ssl));
            }
        }
    }

    printf("[E] win_tls: handshake failed: -0x%x\n", (unsigned int)(-ret));

    /* Human-readable error string */
    char errbuf[256] = {0};
    mbedtls_strerror(ret, errbuf, sizeof(errbuf));
    printf("[E]   error: %s\n", errbuf);

    if (ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
        uint32_t flags = mbedtls_ssl_get_verify_result(&tls->ssl);
        printf("[E] win_tls: certificate verify failed, flags=0x%08x\n", flags);
        if (flags & MBEDTLS_X509_BADCERT_EXPIRED)
            printf("[E]   - certificate expired\n");
        if (flags & MBEDTLS_X509_BADCERT_REVOKED)
            printf("[E]   - certificate revoked\n");
        if (flags & MBEDTLS_X509_BADCERT_CN_MISMATCH)
            printf("[E]   - CN mismatch\n");
        if (flags & MBEDTLS_X509_BADCERT_NOT_TRUSTED)
            printf("[E]   - certificate not trusted (CA chain incomplete?)\n");
        if (flags & MBEDTLS_X509_BADCERT_MISSING)
            printf("[E]   - certificate missing\n");
        if (flags & MBEDTLS_X509_BADCERT_SKIP_VERIFY)
            printf("[E]   - verification skipped\n");
        if (flags & MBEDTLS_X509_BADCERT_FUTURE)
            printf("[E]   - certificate from future\n");

        /* Dump peer certificate info */
        const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&tls->ssl);
        if (peer != NULL) {
            char peer_info[1024] = {0};
            mbedtls_x509_crt_info(peer_info, sizeof(peer_info), "    ", peer);
            printf("[E] Peer certificate:\n%s\n", peer_info);
        } else {
            printf("[E] No peer certificate available\n");
        }
    }
    return -1;
}

static int win_tls_read(convai_tls_t *tls, uint8_t *buf, size_t len, size_t *nread)
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

static int win_tls_write(convai_tls_t *tls, const uint8_t *buf, size_t len, size_t *nwrite)
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

static int win_tls_close(convai_tls_t *tls)
{
    if (tls == NULL) return -1;
    mbedtls_ssl_close_notify(&tls->ssl);
    tls->connected = 0;
    return 0;
}

/* ===== NetAL: socket_poll (required by the poll architecture) =====
 *
 * Windows select() honours a real timeout (unlike WS63 lwip_select), so a single
 * select call suffices — no slice-polling workaround needed, zero CPU spin.
 * exceptfds is mapped to POLL_WRITE so a failed non-blocking connect still
 * wakes the SDK loop, which then reads SO_ERROR via socket_get_error. */
static int win_socket_poll(convai_socket_t *sock, int events, int *revents, int timeout_ms) {
    if (sock == NULL || revents == NULL) return -1;
    *revents = 0;

    int fd = sock->net.fd;
    if (fd < 0) return -1;

    fd_set rfds, wfds, efds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);
    FD_ZERO(&efds);
    if (events & CONVAI_POLL_READ)  FD_SET((SOCKET)fd, &rfds);
    if (events & CONVAI_POLL_WRITE) FD_SET((SOCKET)fd, &wfds);
    FD_SET((SOCKET)fd, &efds);

    struct timeval tv;
    struct timeval *ptv = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (long)(timeout_ms % 1000) * 1000L;
        ptv = &tv;
    }

    /* Windows select() ignores the nfds argument; pass 0. */
    int ret = select(0, &rfds, &wfds, &efds, ptv);
    printf("[D] win_net: poll fd=%d events=0x%x timeout=%dms ret=%d\n", fd, events, timeout_ms, ret);
    if (ret == SOCKET_ERROR) {
        printf("[E] win_net: select failed fd=%d WSA error=%d\n", fd, WSAGetLastError());
        return -1;
    }
    if (FD_ISSET((SOCKET)fd, &rfds)) *revents |= CONVAI_POLL_READ;
    if (FD_ISSET((SOCKET)fd, &wfds)) *revents |= CONVAI_POLL_WRITE;
    if (FD_ISSET((SOCKET)fd, &efds)) *revents |= CONVAI_POLL_WRITE;
    printf("[D] win_net: poll revents=0x%x\n", *revents);
    return 0;  /* ret==0: timed out, no event */
}

/* ===== Misc ===== */
static void win_log(int level, const char *file, int line, const char *fmt, ...) {
    char buf[256];
    va_list args;
    uint64_t now_ms = win_tick_ms();
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

int win_device_id(char *buf, size_t len) {
    if (buf == NULL || len < 16) return -1;

    /* 取 NetBIOS 主机名 (Windows 10+ 装机随机生成 15 字符名, 如
     * "DESKTOP-ABC1234")。比固定串 "goldieos-sim" 更有区分度, 且语义上
     * 接近 ws63 用 WiFi MAC 做设备标识的意图。GetComputerNameA 由 kernel32
     * 导出, Windows 恒链接, 无需在 CMake 加库。 */
    DWORD name_len = (DWORD)len;
    if (GetComputerNameA(buf, &name_len)) {
        return (int)strlen(buf);
    }

    /* 兜底: 取名失败时退回原固定串行为。 */
    snprintf(buf, len, "goldieos-sim");
    return (int)strlen(buf);
}

static int win_random(uint8_t *buf, size_t len) {
    return win_fill_random(buf, len);
}

static int win_uuid(char *buf, size_t size) {
    if (buf == NULL || size == 0) return -1;
    snprintf(buf, size, "00000000-0000-0000-0000-000000000000");
    return (int)strlen(buf);
}

static int win_info(char *buf, size_t size) {
    if (buf == NULL || size == 0) return -1;
    snprintf(buf, size, "win-simulator");
    return (int)strlen(buf);
}

static int win_network_available(void) {
    return 1;
}

static int win_network_get_type(char *buf, size_t size) {
    if (buf == NULL || size == 0) return -1;
    snprintf(buf, size, "ethernet");
    return (int)strlen(buf);
}

/* ===== Platform structure instance ===== */
static const convai_platform_t g_convai_platform = {
    .abi_version = CONVAI_ABI_VERSION,
    ._reserved = 0,
    .osal = {
        .malloc = win_malloc,
        .free = win_free,
        .get_time_ms = win_get_time_ms,
        .sleep_ms = win_sleep_ms,
        .get_tick_ms = win_tick_ms,
        .mutex_create = win_mutex_create,
        .mutex_destroy = win_mutex_destroy,
        .mutex_lock = win_mutex_lock,
        .mutex_unlock = win_mutex_unlock,
        .thread_create = win_thread_create,
        .thread_join = win_thread_join,
        .thread_destroy = win_thread_destroy,
        .fill_random = win_fill_random,
        .strdup = win_strdup,
        .file_write = win_file_write,
        .file_read = win_file_read,
        .file_exists = win_file_exists,
        .file_remove = win_file_remove,
    },
    .netal = {
        .socket_create = win_socket_create,
        .socket_destroy = win_socket_destroy,
        .socket_connect = win_socket_connect,
        .socket_send = win_socket_send,
        .socket_recv = win_socket_recv,
        .socket_set_nonblock = win_socket_set_nonblock,
        .socket_is_connected = win_socket_is_connected,
        .socket_get_fd = win_socket_get_fd,
        .socket_poll = win_socket_poll,
        .socket_get_error = win_socket_get_error,
    },
    .tlsal = {
        .tls_create = win_tls_create,
        .tls_destroy = win_tls_destroy,
        .tls_connect = win_tls_connect,
        .tls_handshake_step = win_tls_handshake_step,
        .tls_read = win_tls_read,
        .tls_write = win_tls_write,
        .tls_close = win_tls_close,
    },
    .misc = {
        .log = win_log,
        .device_id = win_device_id,
        .random = win_random,
        .uuid = win_uuid,
        .info = win_info,
        .network_available = win_network_available,
        .network_get_type = win_network_get_type,
    },
};

int convai_platform_win_init(void) {
    /* SDK 内部 convai_tick_ms() 调用 convai_platform_get_osal() 后用 cltq 将返回
     * 的指针截断为 32 位（SDK ABI bug，在 32 位 ws63 上无害，在 64 位 Windows 上
     * 丢失高 32 位导致 SIGSEGV）。若 g_convai_platform 被链接器放在高地址（如
     * 0x7ff6_156933e0），截断后的 0x156933e0 是无效地址。
     *
     * 规避方法：用 VirtualAlloc 在低 4GB 地址空间分配一份 platform 结构体副本，
     * 传给 convai_platform_init。低 4GB 地址截断为 32 位后仍有效，bug 被绕过。
     * 内存永久存活（与进程同生命周期），无需释放。
     */
    static convai_platform_t *p = NULL;
    if (p == NULL) {
        /* VirtualAlloc(NULL,...) 在 64 位 Windows 上可能返回高 4GB 外的地址
         * (如 0x1_5fc80000)，cltq 截断后仍无效。必须在低 4GB 内显式占位：
         * 从 0x10000000 起，每次跳 4MB 向上扫描，直至成功 reserve+commit。 */
        const uintptr_t kLowCeiling = 0x100000000ULL; /* 4GB 边界 */
        const uintptr_t kStep       = 0x400000;       /* 4MB 步进 */
        for (uintptr_t base = 0x10000000; base + sizeof(convai_platform_t) <= kLowCeiling; base += kStep) {
            p = (convai_platform_t *)VirtualAlloc((void *)base, sizeof(convai_platform_t),
                                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (p != NULL) {
                break; /* 命中低 4GB 内的空闲区域 */
            }
        }
        if (p == NULL) {
            return -1;
        }
        memcpy(p, &g_convai_platform, sizeof(convai_platform_t));
    }

    /* Initialize AIA chain completion subsystem */
    convai_aia_chain_init();

    /* Configure persistent trust store for AIA certificate caching */
    convai_aia_chain_set_truststore("./trust_store");

    return convai_platform_init(p);
}

