#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <wchar.h>

void *b_memcpy(void *dst, const void *src, size_t n);
void *b_memset(void *dst, int c, size_t n);
void b_memzero(void *dst, size_t n);

size_t b_strlen(const char *s);
size_t b_wcslen(const wchar_t *s);
int b_wcsnicmp(const wchar_t *a, const wchar_t *b, size_t n);
int b_strncmp(const char *a, const char *b, size_t n);
char *b_strchr(const char *s, int c);
char *b_strrchr(const char *s, int c);
unsigned long b_strtoul10(const char *s);

int b_vsnprintf(char *out, size_t out_len, const char *fmt, va_list ap);
int b_snprintf(char *out, size_t out_len, const char *fmt, ...);

#define memcpy      b_memcpy
#define memset      b_memset
#define strlen      b_strlen
#define wcslen      b_wcslen
#define _wcsnicmp   b_wcsnicmp
#define strncmp     b_strncmp
#define strchr      b_strchr
#define strrchr     b_strrchr
#define strtoul(s, endp, base) b_strtoul10((s))
#define _snprintf   b_snprintf
#define snprintf    b_snprintf
