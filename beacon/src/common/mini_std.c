#include "mini_std.h"

#undef memcpy
#undef memset
#undef strlen
#undef wcslen
#undef _wcsnicmp
#undef strncmp
#undef strchr
#undef strrchr
#undef strtoul
#undef _snprintf
#undef snprintf

void *b_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    size_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

void *b_memset(void *dst, int c, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    size_t i;
    for (i = 0; i < n; i++) d[i] = (unsigned char)c;
    return dst;
}

void b_memzero(void *dst, size_t n) {
    b_memset(dst, 0, n);
}

size_t b_strlen(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

size_t b_wcslen(const wchar_t *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static wchar_t lower_wchar(wchar_t c) {
    if (c >= L'A' && c <= L'Z') return (wchar_t)(c + 32);
    return c;
}

int b_wcsnicmp(const wchar_t *a, const wchar_t *b, size_t n) {
    size_t i;
    if (!a || !b) return a == b ? 0 : 1;
    for (i = 0; i < n; i++) {
        wchar_t ca = lower_wchar(a[i]);
        wchar_t cb = lower_wchar(b[i]);
        if (ca != cb) return (int)(ca - cb);
        if (ca == 0) return 0;
    }
    return 0;
}

int b_strncmp(const char *a, const char *b, size_t n) {
    size_t i;
    if (!a || !b) return a == b ? 0 : 1;
    for (i = 0; i < n; i++) {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca != cb) return (int)ca - (int)cb;
        if (ca == 0) return 0;
    }
    return 0;
}

char *b_strchr(const char *s, int c) {
    char needle = (char)c;
    if (!s) return NULL;
    while (*s) {
        if (*s == needle) return (char *)s;
        s++;
    }
    return needle == 0 ? (char *)s : NULL;
}

char *b_strrchr(const char *s, int c) {
    const char *last = NULL;
    char needle = (char)c;
    if (!s) return NULL;
    while (*s) {
        if (*s == needle) last = s;
        s++;
    }
    if (needle == 0) return (char *)s;
    return (char *)last;
}

unsigned long b_strtoul10(const char *s) {
    unsigned long v = 0;
    if (!s) return 0;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n') s++;
    while (*s >= '0' && *s <= '9') {
        v = (v * 10UL) + (unsigned long)(*s - '0');
        s++;
    }
    return v;
}

typedef struct {
    char *buf;
    size_t cap;
    size_t pos;
    size_t total;
} fmt_ctx_t;

static void fmt_putc(fmt_ctx_t *ctx, char c) {
    if (ctx->buf && ctx->cap > 0 && ctx->pos + 1 < ctx->cap) {
        ctx->buf[ctx->pos++] = c;
    }
    ctx->total++;
}

static void fmt_puts_len(fmt_ctx_t *ctx, const char *s, size_t len) {
    size_t i;
    if (!s) s = "";
    for (i = 0; i < len; i++) fmt_putc(ctx, s[i]);
}

static void fmt_pad(fmt_ctx_t *ctx, int count, char c) {
    int i;
    for (i = 0; i < count; i++) fmt_putc(ctx, c);
}

static void fmt_padded(fmt_ctx_t *ctx, const char *s, size_t len,
                       int width, int left_align, char pad) {
    int room = width - (int)len;
    if (room < 0) room = 0;
    if (!left_align) fmt_pad(ctx, room, pad);
    fmt_puts_len(ctx, s, len);
    if (left_align) fmt_pad(ctx, room, ' ');
}

static void fmt_uint(fmt_ctx_t *ctx, unsigned long long v,
                     unsigned int base, int uppercase,
                     int width, int zero_pad, int left_align) {
    char rev[32];
    char out[32];
    int rev_pos = 0;
    int out_pos = 0;
    char digit;

    if (base < 2 || base > 16) return;
    if (v == 0) rev[rev_pos++] = '0';
    while (v && rev_pos < (int)sizeof(rev)) {
        digit = (char)(v % base);
        if (digit < 10) digit = (char)('0' + digit);
        else digit = (char)((uppercase ? 'A' : 'a') + digit - 10);
        rev[rev_pos++] = digit;
        v /= base;
    }
    while (rev_pos > 0 && out_pos < (int)sizeof(out)) out[out_pos++] = rev[--rev_pos];
    fmt_padded(ctx, out, (size_t)out_pos, width, left_align, zero_pad && !left_align ? '0' : ' ');
}

static void fmt_int(fmt_ctx_t *ctx, long long v, int width, int zero_pad, int left_align) {
    char rev[32];
    char out[40];
    unsigned long long u;
    int rev_pos = 0;
    int out_pos = 0;
    if (v < 0) {
        out[out_pos++] = '-';
        u = (unsigned long long)(-v);
    } else {
        u = (unsigned long long)v;
    }
    if (u == 0) rev[rev_pos++] = '0';
    while (u && rev_pos < (int)sizeof(rev)) {
        rev[rev_pos++] = (char)('0' + (u % 10));
        u /= 10;
    }
    while (rev_pos > 0 && out_pos < (int)sizeof(out)) out[out_pos++] = rev[--rev_pos];
    if (zero_pad && !left_align && out[0] == '-' && width > out_pos) {
        fmt_putc(ctx, '-');
        fmt_pad(ctx, width - out_pos, '0');
        fmt_puts_len(ctx, out + 1, (size_t)(out_pos - 1));
        return;
    }
    fmt_padded(ctx, out, (size_t)out_pos, width, left_align, zero_pad && !left_align ? '0' : ' ');
}

int b_vsnprintf(char *out, size_t out_len, const char *fmt, va_list ap) {
    fmt_ctx_t ctx;
    const char *p = fmt;

    ctx.buf = out;
    ctx.cap = out_len;
    ctx.pos = 0;
    ctx.total = 0;

    if (out && out_len > 0) out[0] = 0;
    if (!fmt) return 0;

    while (*p) {
        int zero_pad = 0;
        int left_align = 0;
        int width = 0;
        int long_flag = 0;
        int long_long_flag = 0;
        char spec;

        if (*p != '%') {
            fmt_putc(&ctx, *p++);
            continue;
        }
        p++;
        if (*p == '%') {
            fmt_putc(&ctx, '%');
            p++;
            continue;
        }
        if (*p == '-') {
            left_align = 1;
            p++;
        }
        if (*p == '0') {
            zero_pad = 1;
            p++;
        }
        while (*p >= '0' && *p <= '9') {
            width = (width * 10) + (*p - '0');
            p++;
        }
        if (*p == 'l') {
            long_flag = 1;
            p++;
            if (*p == 'l') {
                long_long_flag = 1;
                p++;
            }
        } else if (*p == 'z') {
            long_long_flag = 1;
            p++;
        }

        spec = *p;
        if (!spec) break;
        p++;

        switch (spec) {
        case 's':
            {
                const char *s = va_arg(ap, char *);
                if (!s) s = "";
                fmt_padded(&ctx, s, b_strlen(s), width, left_align, ' ');
            }
            break;
        case 'c':
            fmt_putc(&ctx, (char)va_arg(ap, int));
            break;
        case 'd':
        case 'i':
            if (long_long_flag) fmt_int(&ctx, va_arg(ap, long long), width, zero_pad, left_align);
            else if (long_flag) fmt_int(&ctx, (long long)va_arg(ap, long), width, zero_pad, left_align);
            else fmt_int(&ctx, (long long)va_arg(ap, int), width, zero_pad, left_align);
            break;
        case 'u':
            if (long_long_flag) fmt_uint(&ctx, va_arg(ap, unsigned long long), 10, 0, width, zero_pad, left_align);
            else if (long_flag) fmt_uint(&ctx, (unsigned long long)va_arg(ap, unsigned long), 10, 0, width, zero_pad, left_align);
            else fmt_uint(&ctx, (unsigned long long)va_arg(ap, unsigned int), 10, 0, width, zero_pad, left_align);
            break;
        case 'x':
        case 'X':
            if (long_long_flag) fmt_uint(&ctx, va_arg(ap, unsigned long long), 16, spec == 'X', width, zero_pad, left_align);
            else if (long_flag) fmt_uint(&ctx, (unsigned long long)va_arg(ap, unsigned long), 16, spec == 'X', width, zero_pad, left_align);
            else fmt_uint(&ctx, (unsigned long long)va_arg(ap, unsigned int), 16, spec == 'X', width, zero_pad, left_align);
            break;
        case 'p':
            fmt_puts_len(&ctx, "0x", 2);
            fmt_uint(&ctx, (unsigned long long)(uintptr_t)va_arg(ap, void *), 16, 0, width, zero_pad, left_align);
            break;
        default:
            fmt_putc(&ctx, spec);
            break;
        }
    }

    if (out && out_len > 0) {
        if (ctx.pos >= out_len) ctx.pos = out_len - 1;
        out[ctx.pos] = 0;
    }
    return (int)ctx.total;
}

int b_snprintf(char *out, size_t out_len, const char *fmt, ...) {
    int n;
    va_list ap;
    va_start(ap, fmt);
    n = b_vsnprintf(out, out_len, fmt, ap);
    va_end(ap);
    return n;
}

void *memcpy(void *dst, const void *src, size_t n) {
    return b_memcpy(dst, src, n);
}

void *memset(void *dst, int c, size_t n) {
    return b_memset(dst, c, n);
}

size_t strlen(const char *s) {
    return b_strlen(s);
}

int strncmp(const char *a, const char *b, size_t n) {
    return b_strncmp(a, b, n);
}
