/**
 * @file platform/esp32_tlsal.c
 * @brief TLSAL layer of the ESP32-S3 ConvAI platform HAL (mbedTLS client).
 *
 * The BIO callbacks talk to the raw socket fd directly instead of using
 * mbedtls_net_*, so the non-blocking socket owned by NetAL keeps its
 * semantics: a would-block turns into MBEDTLS_ERR_SSL_WANT_READ/WRITE and the
 * SDK re-drives the handshake from socket_poll().
 *
 * mbedTLS 4.x is used through the PSA Crypto backend, which owns the RNG
 * (hardware TRNG); no ctr_drbg/entropy contexts are needed here.
 */

#include "convai_platform_esp32_internal.h"

#include "esp_log.h"
#include "lwip/sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "psa/crypto.h"
#include "certs/convai_aia_chain.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

static const char *TAG = CONVAI_HAL_TAG;

/* ===================================================================
 *  BIO callbacks (raw socket fd)
 * =================================================================== */

static int esp32_tls_bio_send(void *ctx, const unsigned char *buf,
                              size_t len) {
  convai_socket_t *sock = (convai_socket_t *)ctx;
  if (sock == NULL || sock->fd < 0) {
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
  }
  int ret = send(sock->fd, buf, len, 0);
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return MBEDTLS_ERR_SSL_WANT_WRITE;
    }
    return MBEDTLS_ERR_NET_SEND_FAILED;
  }
  return ret;
}

static int esp32_tls_bio_recv(void *ctx, unsigned char *buf, size_t len) {
  convai_socket_t *sock = (convai_socket_t *)ctx;
  if (sock == NULL || sock->fd < 0) {
    return MBEDTLS_ERR_SSL_BAD_INPUT_DATA;
  }
  int ret = recv(sock->fd, buf, len, 0);
  if (ret == 0) {
    return MBEDTLS_ERR_SSL_CONN_EOF;
  }
  if (ret < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return MBEDTLS_ERR_SSL_WANT_READ;
    }
    return MBEDTLS_ERR_NET_RECV_FAILED;
  }
  return ret;
}

/* ===================================================================
 *  HTTPS fetch callback for AIA certificate chasing (ESP32)
 * =================================================================== */

/**
 * @brief Platform-specific HTTPS fetch for AIA certificates (ESP32).
 *
 * Creates a temporary TLS connection to fetch DER-encoded certificates from
 * HTTPS URLs. Uses VERIFY_NONE to avoid recursive AIA chasing.
 * Uses PSA crypto (hardware TRNG) and raw lwip sockets.
 *
 * @param url         [in]  HTTPS URL (e.g., "https://example.com/ca.der").
 * @param out_der     [out] Buffer for DER certificate data.
 * @param out_buf_len [in]  Size of out_der buffer.
 * @param out_der_len [out] Actual bytes received.
 *
 * @return 0 on success, negative on error.
 */
static int esp32_https_fetch_ca_der(const char *url,
                                    uint8_t *out_der,
                                    size_t out_buf_len,
                                    size_t *out_der_len) {
  if (url == NULL || out_der == NULL || out_der_len == NULL) {
    return -1;
  }
  *out_der_len = 0;

  /* Parse HTTPS URL: https://host[:port]/path */
  if (strncmp(url, "https://", 8) != 0) {
    ESP_LOGW(TAG, "AIA fetch: non-HTTPS URL rejected: %s", url);
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

  ESP_LOGI(TAG, "AIA fetch: connecting to %s:%d%s", host, port, path_start);

  /* Resolve hostname */
  struct addrinfo hints = {0};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  char port_str[8];
  snprintf(port_str, sizeof(port_str), "%d", port);

  struct addrinfo *res = NULL;
  int ret = getaddrinfo(host, port_str, &hints, &res);
  if (ret != 0 || res == NULL) {
    ESP_LOGW(TAG, "AIA fetch: DNS resolution failed for %s", host);
    if (res) freeaddrinfo(res);
    return -3;
  }

  /* Create socket */
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd < 0) {
    ESP_LOGW(TAG, "AIA fetch: socket creation failed");
    freeaddrinfo(res);
    return -3;
  }

  /* Connect */
  ret = connect(fd, res->ai_addr, res->ai_addrlen);
  freeaddrinfo(res);
  if (ret != 0) {
    ESP_LOGW(TAG, "AIA fetch: connect failed");
    close(fd);
    return -3;
  }

  /* Create temporary TLS context */
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;

  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);

  ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    ESP_LOGE(TAG, "AIA fetch: SSL config defaults failed: -0x%x", (unsigned int)(-ret));
    ret = -4;
    goto cleanup;
  }

  mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);  /* Avoid recursion */
  mbedtls_ssl_conf_dbg(&conf, NULL, NULL);

  ret = mbedtls_ssl_setup(&ssl, &conf);
  if (ret != 0) {
    ESP_LOGE(TAG, "AIA fetch: SSL setup failed: -0x%x", (unsigned int)(-ret));
    ret = -4;
    goto cleanup;
  }

  /* BIO callbacks for temporary socket */
  int temp_fd = fd;
  mbedtls_ssl_set_bio(&ssl, &temp_fd,
                      (mbedtls_ssl_send_t *)send,
                      (mbedtls_ssl_recv_t *)recv,
                      NULL);
  mbedtls_ssl_set_hostname(&ssl, host);

  /* Perform TLS handshake */
  ret = mbedtls_ssl_handshake(&ssl);
  if (ret != 0) {
    ESP_LOGW(TAG, "AIA fetch: TLS handshake failed: -0x%x", (unsigned int)(-ret));
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
    ESP_LOGW(TAG, "AIA fetch: write failed: -0x%x", (unsigned int)(-ret));
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
    ESP_LOGW(TAG, "AIA fetch: no response from %s", host);
    ret = -6;
    goto cleanup;
  }

  /* Parse HTTP response: find status line */
  const char *resp_str = (const char *)resp_buf;
  if (strncmp(resp_str, "HTTP/", 5) != 0) {
    ESP_LOGW(TAG, "AIA fetch: invalid HTTP response");
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
    ESP_LOGW(TAG, "AIA fetch: HTTP %d from %s", status_code, url);
    ret = -6;
    goto cleanup;
  }

  /* Find body (after \r\n\r\n) */
  const char *body_start = strstr(resp_str, "\r\n\r\n");
  if (body_start == NULL) {
    ESP_LOGW(TAG, "AIA fetch: no body delimiter in response");
    ret = -6;
    goto cleanup;
  }
  body_start += 4;

  size_t body_len = total_recv - (body_start - resp_str);
  if (body_len > out_buf_len) {
    ESP_LOGW(TAG, "AIA fetch: response too large (%zu bytes)", body_len);
    ret = -7;
    goto cleanup;
  }

  /* Copy DER certificate to output buffer */
  memcpy(out_der, body_start, body_len);
  *out_der_len = body_len;
  ret = 0;

  ESP_LOGI(TAG, "AIA fetch: got %zu bytes from %s", body_len, url);

cleanup:
  mbedtls_ssl_free(&ssl);
  mbedtls_ssl_config_free(&conf);
  close(fd);
  return ret;
}

/* ===================================================================
 *  Lifecycle
 * =================================================================== */

int esp32_tls_create(convai_tls_t **tls) {
  if (tls == NULL) {
    return -1;
  }

  convai_tls_t *t = (convai_tls_t *)calloc(1, sizeof(*t));
  if (t == NULL) {
    return -1;
  }

  psa_crypto_init();

  mbedtls_ssl_init(&t->ssl);
  mbedtls_ssl_config_init(&t->conf);
  mbedtls_x509_crt_init(&t->cacert);

  int ret = mbedtls_ssl_config_defaults(&t->conf, MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
  if (ret != 0) {
    ESP_LOGE(TAG, "ssl_config_defaults failed: -0x%x", (unsigned int)(-ret));
    goto fail;
  }

  /* Verification mode is finalized in esp32_tls_connect() once we know
   * whether a CA certificate was supplied. */
  mbedtls_ssl_conf_authmode(&t->conf, MBEDTLS_SSL_VERIFY_NONE);
  mbedtls_ssl_conf_dbg(&t->conf, NULL, NULL);

  ret = mbedtls_ssl_setup(&t->ssl, &t->conf);
  if (ret != 0) {
    ESP_LOGE(TAG, "ssl_setup failed: -0x%x", (unsigned int)(-ret));
    goto fail;
  }

  convai_aia_chain_set_https_fetch(esp32_https_fetch_ca_der);

  *tls = t;
  return 0;

fail:
  mbedtls_ssl_free(&t->ssl);
  mbedtls_ssl_config_free(&t->conf);
  mbedtls_x509_crt_free(&t->cacert);
  free(t);
  return -1;
}

int esp32_tls_destroy(convai_tls_t *tls) {
  if (tls == NULL) {
    return 0;
  }
  mbedtls_ssl_free(&tls->ssl);
  mbedtls_ssl_config_free(&tls->conf);
  mbedtls_x509_crt_free(&tls->cacert);
  free(tls);
  return 0;
}

int esp32_tls_connect(convai_tls_t *tls, void *sock, const char *host,
                      const char *ca_cert) {
  if (tls == NULL || sock == NULL || host == NULL) {
    return -1;
  }

  convai_socket_t *socket_handle = (convai_socket_t *)sock;
  tls->sock = socket_handle;

  mbedtls_ssl_set_hostname(&tls->ssl, host); /* SNI */
  mbedtls_ssl_set_bio(&tls->ssl, socket_handle, esp32_tls_bio_send,
                      esp32_tls_bio_recv, NULL);

  if (ca_cert != NULL) {
    int ret = mbedtls_x509_crt_parse(&tls->cacert,
                                     (const unsigned char *)ca_cert,
                                     strlen(ca_cert) + 1);
    if (ret < 0) {
      ESP_LOGE(TAG, "CA cert parse failed: -0x%x", (unsigned int)(-ret));
      return -1;
    }
    mbedtls_ssl_conf_ca_chain(&tls->conf, &tls->cacert, NULL);
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_verify(&tls->conf, convai_aia_verify_callback, &tls->cacert);
    ESP_LOGI(TAG, "TLS VERIFY_REQUIRED (CA cert loaded, %d bytes)",
             (int)strlen(ca_cert));
  } else {
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE);
    ESP_LOGW(TAG, "TLS VERIFY_NONE (no CA cert)");
  }

  return 0;
}

/* ===================================================================
 *  Handshake / IO
 * =================================================================== */

int esp32_tls_handshake_step(convai_tls_t *tls, int *want_flags, int *done) {
  if (tls == NULL || want_flags == NULL || done == NULL) {
    return -1;
  }
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
  ESP_LOGE(TAG, "TLS handshake failed: -0x%x", (unsigned int)(-ret));
  return -1;
}

int esp32_tls_read(convai_tls_t *tls, uint8_t *buf, size_t len,
                   size_t *nread) {
  if (nread != NULL) {
    *nread = 0;
  }
  if (tls == NULL || buf == NULL) {
    return -1;
  }

  int ret = mbedtls_ssl_read(&tls->ssl, buf, len);
  if (ret < 0) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      return 0; /* would-block */
    }
    return -1;
  }
  if (ret == 0) {
    return -1; /* peer closed */
  }
  if (nread != NULL) {
    *nread = (size_t)ret;
  }
  return 0;
}

int esp32_tls_write(convai_tls_t *tls, const uint8_t *buf, size_t len,
                    size_t *nwrite) {
  if (nwrite != NULL) {
    *nwrite = 0;
  }
  if (tls == NULL || buf == NULL) {
    return -1;
  }

  int ret = mbedtls_ssl_write(&tls->ssl, buf, len);
  if (ret < 0) {
    if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
        ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
      return 0; /* would-block */
    }
    return -1;
  }
  if (nwrite != NULL) {
    *nwrite = (size_t)ret;
  }
  return 0;
}

int esp32_tls_close(convai_tls_t *tls) {
  if (tls == NULL) {
    return -1;
  }
  mbedtls_ssl_close_notify(&tls->ssl);
  tls->connected = 0;
  return 0;
}

