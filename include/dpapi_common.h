/*
 * dpapi_common.h — Core DPAPI parsing and masterkey decryption
 * Ported from SharpDPAPI/lib/Dpapi.cs
 */
#ifndef _DPAPI_COMMON_H_
#define _DPAPI_COMMON_H_

#include "bofdefs.h"
#include "crypto.h"
#include "helpers.h"

/* ---- Known DPAPI Algorithm IDs (from Interop.cs) ---- */
#ifndef CALG_MD5
#define CALG_MD5        0x00008003
#endif
#ifndef CALG_SHA1
#define CALG_SHA1       0x00008004
#endif
#ifndef CALG_SHA
#define CALG_SHA        0x00008004
#endif
#ifndef CALG_3DES
#define CALG_3DES       0x00006603
#endif
#ifndef CALG_3DES_112
#define CALG_3DES_112   0x00006609
#endif
#ifndef CALG_DES
#define CALG_DES        0x00006601
#endif
#ifndef CALG_AES_128
#define CALG_AES_128    0x0000660e
#endif
#ifndef CALG_AES_192
#define CALG_AES_192    0x0000660f
#endif
#ifndef CALG_AES_256
#define CALG_AES_256    0x00006610
#endif
#ifndef CALG_SHA_256
#define CALG_SHA_256    0x0000800c
#endif
#ifndef CALG_SHA_384
#define CALG_SHA_384    0x0000800d
#endif
#ifndef CALG_SHA_512
#define CALG_SHA_512    0x0000800e
#endif
#ifndef CALG_HMAC
#define CALG_HMAC       0x00008009
#endif
#ifndef CALG_RSA_KEYX
#define CALG_RSA_KEYX   0x0000a400
#endif

/* ---- DPAPI Blob Flags ---- */
#define CRYPTPROTECT_SYSTEM 0x20000000

/* ---- Kerberos etype ---- */
#define KERB_ETYPE_RC4_HMAC             23
#define KERB_ETYPE_AES128_CTS_HMAC     17
#define KERB_ETYPE_AES256_CTS_HMAC     18

/* ---- Masterkey structures ---- */
typedef struct _MASTERKEY_CACHE_ENTRY {
    GUID  guid;
    BYTE  sha1[20];
    struct _MASTERKEY_CACHE_ENTRY* next;
} MASTERKEY_CACHE_ENTRY;

typedef struct _MASTERKEY_CACHE {
    MASTERKEY_CACHE_ENTRY* head;
    int count;
} MASTERKEY_CACHE;

/* Masterkey cache operations */
void     mk_cache_init(MASTERKEY_CACHE* cache);
void     mk_cache_free(MASTERKEY_CACHE* cache);
BOOL     mk_cache_add(MASTERKEY_CACHE* cache, const GUID* guid, const BYTE* sha1);
BYTE*    mk_cache_lookup(MASTERKEY_CACHE* cache, const GUID* guid);
void     mk_cache_print(MASTERKEY_CACHE* cache);

/* ---- DPAPI Blob Parsing ---- */
typedef struct _DPAPI_BLOB {
    DWORD version;
    GUID  provider;
    GUID  masterkey_guid;
    DWORD flags;
    DWORD description_len;
    wchar_t* description;
    DWORD alg_crypt;
    DWORD alg_crypt_len;
    DWORD alg_hash;
    DWORD alg_hash_len;
    BYTE* salt;
    DWORD salt_len;
    BYTE* hmac_key;
    DWORD hmac_key_len;
    BYTE* hmac;
    DWORD hmac_len;
    BYTE* data;
    DWORD data_len;
    BYTE* sign;
    DWORD sign_len;
} DPAPI_BLOB;

BOOL parse_dpapi_blob(const BYTE* raw, int raw_len, DPAPI_BLOB* blob);
void free_dpapi_blob(DPAPI_BLOB* blob);
BOOL describe_dpapi_blob(const BYTE* raw, int raw_len,
                         MASTERKEY_CACHE* cache,
                         BOOL unprotect,
                         char** output);

/* ---- Masterkey File Decryption ---- */
BOOL decrypt_masterkey(const BYTE* mk_bytes, int mk_len,
                       const BYTE* key, int key_len,
                       BYTE* out_sha1);

BOOL decrypt_masterkey_with_sha(const BYTE* mk_bytes, int mk_len,
                                const BYTE* sha_key, int key_len,
                                BYTE* out_sha1);

BOOL derive_pre_key(const char* password, const char* sid,
                    BOOL is_domain, int hash_type,
                    BYTE** out_key, int* key_len);

BOOL calculate_keys(const BYTE* mk_bytes, int mk_len,
                    const BYTE* key, int key_len,
                    BYTE* out_derived_key, BYTE* out_hmac_key);

BYTE* get_masterkey(const BYTE* mk_file_bytes, int file_len);
BYTE* get_domain_key(const BYTE* mk_file_bytes, int file_len, int* dk_len);
GUID  get_preferred_key(const BYTE* preferred_bytes, int pref_len);
char* get_sid_from_bkfile(const BYTE* bk_bytes, int bk_len);

/* ---- Credential Parsing ---- */
BOOL describe_credential(const BYTE* data, int data_len,
                         MASTERKEY_CACHE* cache,
                         BOOL unprotect,
                         char** output);

BOOL parse_dec_cred_blob(const BYTE* data, int data_len, char** output);

/* ---- Vault Parsing ---- */
BOOL describe_vault_policy(const BYTE* data, int data_len,
                           MASTERKEY_CACHE* cache,
                           BYTE** aes128_key, BYTE** aes256_key,
                           char** output);

BOOL describe_vault_cred(const BYTE* data, int data_len,
                         const BYTE* aes128_key, const BYTE* aes256_key,
                         char** output);

BOOL describe_vault_item(const BYTE* data, int data_len, char** output);

/* ---- Certificate Parsing ---- */
BOOL describe_dpapi_cert_private_key(const BYTE* data, int data_len,
                                     MASTERKEY_CACHE* cache,
                                     BOOL is_machine,
                                     char** output,
                                     BYTE** private_key, int* pk_len);

BOOL describe_certificate(const BYTE* cert_data, int cert_len,
                          const BYTE* private_key, int pk_len,
                          char** output);

BOOL describe_cng_cert_blob(const BYTE* data, int data_len,
                            MASTERKEY_CACHE* cache,
                            char** output);

BOOL describe_capi_cert_blob(const BYTE* data, int data_len,
                             MASTERKEY_CACHE* cache,
                             char** output);

/* ---- PVK Triage ---- */
BOOL pvk_triage(const BYTE* pvk_data, int pvk_len,
                MASTERKEY_CACHE* cache,
                char** output);

/* ---- Hash output (JTR/Hashcat) ---- */
char* format_hash(const BYTE* mk_bytes, int mk_len, const char* sid);

/* ---- Backup key parsing ---- */
BOOL parse_dec_policy_blob(const BYTE* data, int data_len, char** output);

#endif /* _DPAPI_COMMON_H_ */
