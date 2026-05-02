#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>
#include <stddef.h>

int http_init(void);
void http_cleanup(void);
int http_request(const char *method, const char *path,
                 const uint8_t *body, size_t body_len,
                 uint8_t *resp_buf, size_t resp_max);

#endif
