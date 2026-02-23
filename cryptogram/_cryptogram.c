/*
 * cryptogram — Ultra-Fast AES Cryptography for Telegram MTProto
 * Copyright (C) 2024 Ankit Chaubey <ankitchaubey.dev@gmail.com>
 * https://github.com/ankit-chaubey/cryptogram
 *
 * Strategy:
 *   Uses OpenSSL (loaded at runtime via dlopen — no build-time headers
 *   needed) for provably-correct, hardware-accelerated AES-NI block ops.
 *   Implements IGE-256, CTR-256, CBC-256 modes in tight C loops.
 *
 * API surface:
 *   tgcrypto-compatible: ige256_encrypt, ige256_decrypt,
 *                        ctr256_encrypt, ctr256_decrypt,
 *                        cbc256_encrypt, cbc256_decrypt
 *   cryptg-compatible:   encrypt_ige, decrypt_ige, factorize_pq_pair
 *   extra:               has_aesni
 *
 * SPDX-License-Identifier: MIT
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# include <windows.h>
# define dl_open(n)   ((void*)LoadLibrary(n))
# define dl_sym(h,n)  ((void*)GetProcAddress((HMODULE)(h),(n)))
# define dl_close(h)  FreeLibrary((HMODULE)(h))
#else
# include <dlfcn.h>
# define dl_open(n)   dlopen((n), RTLD_LAZY|RTLD_GLOBAL)
# define dl_sym(h,n)  dlsym((h),(n))
# define dl_close(h)  dlclose(h)
#endif

/* ──────────────────────────────────────────────────────────────────
 * Minimal OpenSSL AES_KEY struct — same layout across 1.x and 3.x
 * ────────────────────────────────────────────────────────────────── */
typedef struct { uint32_t rd_key[60]; int rounds; } AES_KEY_T;

typedef int  (*fn_set_enc)(const unsigned char *key, int bits, AES_KEY_T *ks);
typedef int  (*fn_set_dec)(const unsigned char *key, int bits, AES_KEY_T *ks);
typedef void (*fn_aes)    (const unsigned char *in, unsigned char *out, const AES_KEY_T *ks);

/* EVP for bulk CBC */
typedef void* EVP_CIPHER_CTX;
typedef void* EVP_CIPHER;
typedef EVP_CIPHER_CTX* (*fn_ctx_new) (void);
typedef void            (*fn_ctx_free)(EVP_CIPHER_CTX*);
typedef int             (*fn_cipher_init)(EVP_CIPHER_CTX*, const EVP_CIPHER*,
                                          void*, const unsigned char*,
                                          const unsigned char*, int);
typedef int             (*fn_cipher_update)(EVP_CIPHER_CTX*, unsigned char*, int*,
                                            const unsigned char*, int);
typedef int             (*fn_cipher_final)(EVP_CIPHER_CTX*, unsigned char*, int*);
typedef int             (*fn_ctx_set_pad)(EVP_CIPHER_CTX*, int);
typedef const EVP_CIPHER* (*fn_aes_cbc)(void);

static struct {
    void           *lib;
    fn_set_enc      set_enc;
    fn_set_dec      set_dec;
    fn_aes          aes_enc;
    fn_aes          aes_dec;
    fn_ctx_new      ctx_new;
    fn_ctx_free     ctx_free;
    fn_cipher_init  c_init;
    fn_cipher_update c_update;
    fn_cipher_final  c_final;
    fn_ctx_set_pad   c_pad;
    fn_aes_cbc       aes_256_cbc;
    fn_aes_cbc       aes_256_ecb;
    int              ok;           /* 0=uninit, 1=loaded, -1=failed */
} G;

static void ssl_load(void) {
    if (G.ok) return;
    static const char *libs[] = {
        /* Linux */
        "libcrypto.so.3","libcrypto.so.1.1","libcrypto.so",
        "libssl.so.3",   "libssl.so.1.1",   "libssl.so",
        /* Windows */
        "libcrypto-3-x64.dll","libcrypto-1_1-x64.dll",
        /* macOS — bare dylib names (found if on DYLD_LIBRARY_PATH) */
        "libcrypto.3.dylib","libcrypto.1.1.dylib","libcrypto.dylib",
        /* macOS — Homebrew arm64 (Apple Silicon, prefix /opt/homebrew) */
        "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
        "/opt/homebrew/opt/openssl@3/lib/libcrypto.dylib",
        "/opt/homebrew/opt/openssl@1.1/lib/libcrypto.1.1.dylib",
        "/opt/homebrew/lib/libcrypto.3.dylib",
        /* macOS — Homebrew x86_64 (Intel, prefix /usr/local) */
        "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
        "/usr/local/opt/openssl@3/lib/libcrypto.dylib",
        "/usr/local/opt/openssl@1.1/lib/libcrypto.1.1.dylib",
        "/usr/local/lib/libcrypto.3.dylib",
        /* NOTE: /usr/lib/libcrypto.dylib is intentionally omitted.
         * On macOS 12+ that path is Apple's security stub: dlopen-ing it
         * triggers a SIGABRT ("loading libcrypto in an unsafe way").
         * If none of the Homebrew paths above match, ssl_load() sets
         * G.ok=-1 and PyInit__cryptogram raises ImportError so that
         * __init__.py falls back cleanly to the pure-Python backend. */
        NULL
    };
    for (int i = 0; libs[i]; i++) {
        G.lib = dl_open(libs[i]);
        if (G.lib) break;
    }
    if (!G.lib) { G.ok = -1; return; }

#define LD(field, sym, T) G.field = (T)dl_sym(G.lib, sym); if(!G.field){G.ok=-1;return;}
    LD(set_enc,    "AES_set_encrypt_key",      fn_set_enc)
    LD(set_dec,    "AES_set_decrypt_key",      fn_set_dec)
    LD(aes_enc,    "AES_encrypt",              fn_aes)
    LD(aes_dec,    "AES_decrypt",              fn_aes)
    LD(ctx_new,    "EVP_CIPHER_CTX_new",       fn_ctx_new)
    LD(ctx_free,   "EVP_CIPHER_CTX_free",      fn_ctx_free)
    LD(c_init,     "EVP_CipherInit_ex",        fn_cipher_init)
    LD(c_update,   "EVP_CipherUpdate",         fn_cipher_update)
    LD(c_final,    "EVP_CipherFinal_ex",       fn_cipher_final)
    LD(c_pad,      "EVP_CIPHER_CTX_set_padding", fn_ctx_set_pad)
    LD(aes_256_cbc,"EVP_aes_256_cbc",          fn_aes_cbc)
    LD(aes_256_ecb,"EVP_aes_256_ecb",          fn_aes_cbc)
#undef LD
    G.ok = 1;
}

/* ──────────────────────────────────────────────────────────────────
 * Core mode implementations
 * ────────────────────────────────────────────────────────────────── */

/* IGE-256: sequential, one block at a time */
static void do_ige(const uint8_t *in, uint8_t *out, uint32_t len,
                   const uint8_t *key, const uint8_t *iv, int encrypt) {
    AES_KEY_T k;
    if (encrypt) G.set_enc(key, 256, &k);
    else         G.set_dec(key, 256, &k);

    uint8_t iv1[16], iv2[16], saved[16], buf[16];
    if (encrypt) { memcpy(iv1, iv, 16);    memcpy(iv2, iv+16, 16); }
    else         { memcpy(iv2, iv, 16);    memcpy(iv1, iv+16, 16); }

    for (uint32_t i = 0; i < len; i += 16) {
        const uint8_t *src = in  + i;
        uint8_t       *dst = out + i;

        memcpy(saved, src, 16);
        for (int j = 0; j < 16; j++) buf[j] = src[j] ^ iv1[j];
        if (encrypt) G.aes_enc(buf, dst, &k);
        else         G.aes_dec(buf, dst, &k);
        for (int j = 0; j < 16; j++) dst[j] ^= iv2[j];

        memcpy(iv1, dst,   16);
        memcpy(iv2, saved, 16);
    }
}

/* CTR-256: symmetric. Batches counter encryption via EVP ECB for high throughput. */
#define CTR_BATCH 64
static void ctr_inc_be(uint8_t iv[16]) {
    for (int j=15; j>=0 && ++iv[j]==0; j--);
}
static void do_ctr(const uint8_t *in, uint8_t *out, uint32_t len,
                   const uint8_t *key, uint8_t iv[16], uint8_t *sp) {
    uint8_t state = *sp;
    if (state != 0) {
        uint8_t ks[16];
        EVP_CIPHER_CTX *ctx = G.ctx_new();
        G.c_init(ctx,G.aes_256_ecb(),NULL,key,NULL,1); G.c_pad(ctx,0);
        int ol=0,tmp=0; G.c_update(ctx,ks,&ol,iv,16); G.c_final(ctx,ks+ol,&tmp);
        G.ctx_free(ctx);
        while (state<16 && len>0) { *out++=*in++^ks[state++]; len--; }
        if (state==16) { state=0; ctr_inc_be(iv); }
        if (!len) { *sp=state; return; }
    }
    uint8_t ctr_buf[CTR_BATCH*16], ks_buf[CTR_BATCH*16];
    while (len >= 16) {
        int batch=(int)(len/16); if(batch>CTR_BATCH) batch=CTR_BATCH;
        for (int b=0;b<batch;b++) { memcpy(ctr_buf+b*16,iv,16); ctr_inc_be(iv); }
        EVP_CIPHER_CTX *ctx=G.ctx_new();
        G.c_init(ctx,G.aes_256_ecb(),NULL,key,NULL,1); G.c_pad(ctx,0);
        int ol=0,tmp=0;
        G.c_update(ctx,ks_buf,&ol,ctr_buf,batch*16); G.c_final(ctx,ks_buf+ol,&tmp);
        G.ctx_free(ctx);
        for (int i=0;i<batch*16;i++,len--) *out++=*in++^ks_buf[i];
    }
    if (len>0) {
        uint8_t ks[16];
        EVP_CIPHER_CTX *ctx=G.ctx_new();
        G.c_init(ctx,G.aes_256_ecb(),NULL,key,NULL,1); G.c_pad(ctx,0);
        int ol=0,tmp=0; G.c_update(ctx,ks,&ol,iv,16); G.c_final(ctx,ks+ol,&tmp);
        G.ctx_free(ctx);
        for (uint32_t i=0;i<len;i++) { *out++=*in++^ks[state++]; }
        if (state==16) { state=0; ctr_inc_be(iv); }
    }
    *sp=state;
}

/* CBC-256 via EVP (OpenSSL handles AES-NI parallelism internally) */
static void do_cbc(const uint8_t *in, uint8_t *out, uint32_t len,
                   const uint8_t *key, const uint8_t *iv, int enc) {
    EVP_CIPHER_CTX *ctx = G.ctx_new();
    G.c_init(ctx, G.aes_256_cbc(), NULL, key, iv, enc);
    G.c_pad(ctx, 0);
    int outl = 0, tmp = 0;
    G.c_update(ctx, out, &outl, in, (int)len);
    G.c_final(ctx, out + outl, &tmp);
    G.ctx_free(ctx);
}

/* ──────────────────────────────────────────────────────────────────
 * PQ Factorisation — deterministic Brent-Pollard ρ
 * ────────────────────────────────────────────────────────────────── */
#if defined(__SIZEOF_INT128__)
/* GCC / Clang 64-bit: native 128-bit type is available */
typedef unsigned __int128 u128;
static uint64_t mulmod(uint64_t a,uint64_t b,uint64_t m){return(uint64_t)(((u128)a*b)%m);}
#elif defined(_MSC_VER) && defined(_M_X64)
/* MSVC x64: __int128 doesn't exist, but _umul128 / _udiv128 intrinsics do
 * (_udiv128 available since VS 2019 16.8 / MSVC 19.28) */
#include <intrin.h>
static uint64_t mulmod(uint64_t a,uint64_t b,uint64_t m){
    uint64_t hi,r;
    uint64_t lo=_umul128(a,b,&hi);
    _udiv128(hi,lo,m,&r);
    return r;
}
#else
/* Portable fallback for MSVC x86 (win32) and any other platform without
 * 128-bit support.  Uses binary long-multiplication — correct for all
 * 64-bit inputs even though it is slower than the intrinsic path. */
static uint64_t mulmod(uint64_t a,uint64_t b,uint64_t m){
    uint64_t r=0;
    a%=m;
    while(b){
        if(b&1){r+=a;if(r>=m)r-=m;}
        a<<=1;if(a>=m)a-=m;
        b>>=1;
    }
    return r;
}
#endif
static uint64_t powmod(uint64_t b,uint64_t e,uint64_t m){uint64_t r=1;b%=m;for(;e;e>>=1){if(e&1)r=mulmod(r,b,m);b=mulmod(b,b,m);}return r;}
static int mr_test(uint64_t n,uint64_t a){if(n%a==0)return n==a;uint64_t d=n-1;int r=0;while(!(d&1)){d>>=1;r++;}uint64_t x=powmod(a,d,n);if(x==1||x==n-1)return 1;for(int i=0;i<r-1;i++){x=mulmod(x,x,n);if(x==n-1)return 1;}return 0;}
static int is_prime(uint64_t n){if(n<2)return 0;static const uint64_t W[]={2,3,5,7,11,13,17,19,23,29,31,37,0};for(int i=0;W[i];i++){if(n==W[i])return 1;if(!mr_test(n,W[i]))return 0;}return 1;}
static uint64_t gcd64(uint64_t a,uint64_t b){while(b){uint64_t t=b;b=a%b;a=t;}return a;}
static uint64_t absd(uint64_t a,uint64_t b){return a>b?a-b:b-a;}
static uint64_t brent(uint64_t n,uint64_t c){uint64_t y=2,r=1,q=1,x,ys,d;do{x=y;for(uint64_t i=0;i<r;i++)y=(mulmod(y,y,n)+c)%n;uint64_t k=0;do{ys=y;uint64_t lim=r-k<128?r-k:128;for(uint64_t i=0;i<lim;i++){y=(mulmod(y,y,n)+c)%n;q=mulmod(q,absd(x,y),n);}d=gcd64(q,n);k+=128;}while(k<r&&d==1);r*=2;}while(d==1);if(d==n){do{ys=(mulmod(ys,ys,n)+c)%n;d=gcd64(absd(x,ys),n);}while(d==1);}return d;}
static uint64_t factor1(uint64_t n){if(n<=1||is_prime(n))return n;if(!(n&1))return 2;uint64_t d=n;for(uint64_t c=1;d==n;c++)d=brent(n,c);return is_prime(d)?d:factor1(d);}

/* ──────────────────────────────────────────────────────────────────
 * has_aesni
 * ────────────────────────────────────────────────────────────────── */
#if defined(__x86_64__)||defined(__i386__)
# include <cpuid.h>
static int _has_aesni(void){unsigned a,b,c,d;if(!__get_cpuid(1,&a,&b,&c,&d))return 0;return(c>>25)&1;}
#else
static int _has_aesni(void){return 0;}
#endif

/* ──────────────────────────────────────────────────────────────────
 * Python bindings
 * ────────────────────────────────────────────────────────────────── */
#define CHK(cond,msg) do{if(!(cond)){PyErr_SetString(PyExc_ValueError,(msg));goto err;}}while(0)
#define NEEDSSL() do{if(G.ok!=1){PyErr_SetString(PyExc_RuntimeError,"OpenSSL unavailable");return NULL;}}while(0)

#define IGE_BIND(name, enc_flag)                                                 \
static PyObject *name(PyObject *self, PyObject *args) {                          \
    NEEDSSL();                                                                   \
    Py_buffer d, k, iv;                                                          \
    if (!PyArg_ParseTuple(args,"y*y*y*",&d,&k,&iv)) return NULL;                \
    CHK(d.len>0,       "data must not be empty");                                \
    CHK(d.len%16==0,   "data size must be a multiple of 16 bytes");              \
    CHK(k.len==32,     (enc_flag) ? "key size must be exactly 32 bytes"         \
                                  : "key size must be exactly 32 bytes");        \
    CHK(iv.len==32,    "IV size must be exactly 32 bytes");                      \
    uint8_t *out = (uint8_t*)malloc(d.len);                                      \
    if (!out) { PyErr_NoMemory(); goto err; }                                    \
    Py_BEGIN_ALLOW_THREADS                                                       \
        do_ige(d.buf, out, (uint32_t)d.len, k.buf, iv.buf, (enc_flag));         \
    Py_END_ALLOW_THREADS                                                         \
    PyObject *r = PyBytes_FromStringAndSize((char*)out, d.len);                  \
    free(out);                                                                   \
    PyBuffer_Release(&d); PyBuffer_Release(&k); PyBuffer_Release(&iv);          \
    return r;                                                                    \
err: PyBuffer_Release(&d); PyBuffer_Release(&k); PyBuffer_Release(&iv);         \
    return NULL;                                                                 \
}

IGE_BIND(py_ige256_encrypt, 1)
IGE_BIND(py_ige256_decrypt, 0)
IGE_BIND(py_encrypt_ige,    1)
IGE_BIND(py_decrypt_ige,    0)

static PyObject *py_ctr256_encrypt(PyObject *self, PyObject *args) {
    NEEDSSL();
    Py_buffer d, k, iv, st;
    if (!PyArg_ParseTuple(args,"y*y*y*y*",&d,&k,&iv,&st)) return NULL;
    CHK(d.len>0,             "data must not be empty");
    CHK(k.len==32,           "key size must be exactly 32 bytes");
    CHK(iv.len==16,          "IV size must be exactly 16 bytes");
    CHK(st.len==1,           "state size must be exactly 1 byte");
    CHK(*(uint8_t*)st.buf<=15,"state must be in range [0, 15]");
    uint8_t *out = (uint8_t*)malloc(d.len);
    uint8_t iv_cp[16], s = *(uint8_t*)st.buf;
    memcpy(iv_cp, iv.buf, 16);
    if (!out) { PyErr_NoMemory(); goto err; }
    Py_BEGIN_ALLOW_THREADS
        do_ctr(d.buf, out, (uint32_t)d.len, k.buf, iv_cp, &s);
    Py_END_ALLOW_THREADS
    memcpy(iv.buf, iv_cp, 16);
    *(uint8_t*)st.buf = s;
    PyObject *r = PyBytes_FromStringAndSize((char*)out, d.len);
    free(out);
    PyBuffer_Release(&d); PyBuffer_Release(&k); PyBuffer_Release(&iv); PyBuffer_Release(&st);
    return r;
err: PyBuffer_Release(&d); PyBuffer_Release(&k); PyBuffer_Release(&iv); PyBuffer_Release(&st);
    return NULL;
}

static PyObject *py_ctr256_decrypt(PyObject *s, PyObject *a){return py_ctr256_encrypt(s,a);}

#define CBC_BIND(name, enc_flag)                                                 \
static PyObject *name(PyObject *self, PyObject *args) {                          \
    NEEDSSL();                                                                   \
    Py_buffer d, k, iv;                                                          \
    if (!PyArg_ParseTuple(args,"y*y*y*",&d,&k,&iv)) return NULL;                \
    CHK(d.len>0,     "data must not be empty");                                  \
    CHK(d.len%16==0, "data size must be a multiple of 16 bytes");                \
    CHK(k.len==32,   "key size must be exactly 32 bytes");                       \
    CHK(iv.len==16,  "IV size must be exactly 16 bytes");                        \
    uint8_t *out = (uint8_t*)malloc(d.len);                                      \
    if (!out) { PyErr_NoMemory(); goto err; }                                    \
    Py_BEGIN_ALLOW_THREADS                                                       \
        do_cbc(d.buf, out, (uint32_t)d.len, k.buf, iv.buf, (enc_flag));         \
    Py_END_ALLOW_THREADS                                                         \
    PyObject *r = PyBytes_FromStringAndSize((char*)out, d.len);                  \
    free(out);                                                                   \
    PyBuffer_Release(&d); PyBuffer_Release(&k); PyBuffer_Release(&iv);          \
    return r;                                                                    \
err: PyBuffer_Release(&d); PyBuffer_Release(&k); PyBuffer_Release(&iv);         \
    return NULL;                                                                 \
}

CBC_BIND(py_cbc256_encrypt, 1)
CBC_BIND(py_cbc256_decrypt, 0)

static PyObject *py_factorize(PyObject *self, PyObject *args) {
    unsigned long long pq;
    if (!PyArg_ParseTuple(args,"K",&pq)) return NULL;
    uint64_t p = factor1((uint64_t)pq);
    uint64_t q = (uint64_t)pq / p;
    if (p > q) { uint64_t t=p; p=q; q=t; }
    return Py_BuildValue("(KK)",(unsigned long long)p,(unsigned long long)q);
}

static PyObject *py_has_aesni(PyObject *self, PyObject *args){
    return PyBool_FromLong(_has_aesni());
}

static PyMethodDef methods[] = {
    {"ige256_encrypt",    py_ige256_encrypt, METH_VARARGS, "AES-256-IGE encrypt (tgcrypto API)"},
    {"ige256_decrypt",    py_ige256_decrypt, METH_VARARGS, "AES-256-IGE decrypt (tgcrypto API)"},
    {"ctr256_encrypt",    py_ctr256_encrypt, METH_VARARGS, "AES-256-CTR encrypt (tgcrypto API)"},
    {"ctr256_decrypt",    py_ctr256_decrypt, METH_VARARGS, "AES-256-CTR decrypt (tgcrypto API)"},
    {"cbc256_encrypt",    py_cbc256_encrypt, METH_VARARGS, "AES-256-CBC encrypt (tgcrypto API)"},
    {"cbc256_decrypt",    py_cbc256_decrypt, METH_VARARGS, "AES-256-CBC decrypt (tgcrypto API)"},
    {"encrypt_ige",       py_encrypt_ige,    METH_VARARGS, "AES-256-IGE encrypt (cryptg API)"},
    {"decrypt_ige",       py_decrypt_ige,    METH_VARARGS, "AES-256-IGE decrypt (cryptg API)"},
    {"factorize_pq_pair", py_factorize,      METH_VARARGS, "Factorise pq into (p, q)"},
    {"has_aesni",         py_has_aesni,      METH_NOARGS,  "True if CPU has AES-NI"},
    {NULL,NULL,0,NULL}
};

static struct PyModuleDef moddef = {
    PyModuleDef_HEAD_INIT, "_cryptogram",
    "cryptogram — AES-NI-accelerated Telegram MTProto crypto (OpenSSL backend)",
    -1, methods
};

PyMODINIT_FUNC PyInit__cryptogram(void) {
    ssl_load();
    if (G.ok != 1) {
        /* OpenSSL could not be loaded at runtime.  Raising ImportError here
         * lets cryptogram/__init__.py catch it and fall back to the pure-
         * Python _fallback.py backend instead of importing successfully and
         * then crashing with RuntimeError (or SIGABRT) on first use. */
        PyErr_SetString(PyExc_ImportError,
            "cryptogram: OpenSSL shared library not found â "
            "falling back to pure-Python backend");
        return NULL;
    }
    return PyModule_Create(&moddef);
}
