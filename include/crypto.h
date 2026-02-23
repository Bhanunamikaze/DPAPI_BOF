/*
 * crypto.h — Cryptographic functions for DPAPI BOFs
 * Ported from SharpDPAPI/lib/Crypto.cs
 */
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include "bofdefs.h"

/* ---- Kerberos password hashing ---- */
BOOL kerberos_password_hash(DWORD etype, const wchar_t* password, const wchar_t* salt, BYTE* out_key, int* key_len);

/* ---- DPAPI blob decryption ---- */
BOOL decrypt_blob(const BYTE* encrypted, int enc_len,
                  const BYTE* key, int key_len,
                  DWORD alg_crypt, DWORD alg_hash,
                  BYTE** decrypted, int* dec_len);

/* ---- Key derivation ---- */
BOOL derive_key(const BYTE* key_material, int km_len,
                DWORD alg_hash,
                BYTE* derived_key, int dk_len);

BOOL derive_key_raw(const BYTE* key_material, int km_len,
                    DWORD alg_hash,
                    BYTE* derived_key, int dk_len);

/* ---- Hash functions (via BCrypt) ---- */
BOOL hmac_sha512(const BYTE* key, int key_len, const BYTE* data, int data_len, BYTE* out_hash);
BOOL hmac_sha256(const BYTE* key, int key_len, const BYTE* data, int data_len, BYTE* out_hash);
BOOL hmac_sha1(const BYTE* key, int key_len, const BYTE* data, int data_len, BYTE* out_hash);
BOOL sha1_hash(const BYTE* data, int data_len, BYTE* out_hash);
BOOL sha256_hash(const BYTE* data, int data_len, BYTE* out_hash);
BOOL sha512_hash(const BYTE* data, int data_len, BYTE* out_hash);
BOOL md4_hash(const BYTE* data, int data_len, BYTE* out_hash);

/* ---- PBKDF2 ---- */
BOOL pbkdf2_hmac_sha1(const BYTE* password, int pw_len,
                      const BYTE* salt, int salt_len,
                      int iterations,
                      BYTE* out_key, int key_len);

BOOL pbkdf2_hmac_sha256(const BYTE* password, int pw_len,
                        const BYTE* salt, int salt_len,
                        int iterations,
                        BYTE* out_key, int key_len);

BOOL pbkdf2_hmac_sha512(const BYTE* password, int pw_len,
                        const BYTE* salt, int salt_len,
                        int iterations,
                        BYTE* out_key, int key_len);

/* ---- Symmetric encryption/decryption ---- */
BOOL aes_decrypt(const BYTE* key, int key_len,
                 const BYTE* iv, int iv_len,
                 const BYTE* data, int data_len,
                 BYTE** decrypted, int* dec_len);

BOOL triple_des_decrypt(const BYTE* key, int key_len,
                        const BYTE* iv, int iv_len,
                        const BYTE* data, int data_len,
                        BYTE** decrypted, int* dec_len);

BOOL lsa_aes_decrypt(const BYTE* key, int key_len,
                     const BYTE* data, int data_len,
                     BYTE** decrypted, int* dec_len);

BOOL lsa_sha256_hash(const BYTE* key, int key_len,
                     const BYTE* data, int data_len,
                     BYTE* out_hash);

/* ---- RSA ---- */
BOOL rsa_decrypt(const BYTE* private_key, int pk_len,
                 const BYTE* encrypted, int enc_len,
                 BYTE** decrypted, int* dec_len);

BOOL export_private_key(const BYTE* capi_blob, int blob_len,
                        BYTE** pkcs8, int* pkcs8_len);

/* ---- DPAPI-specific crypto ---- */
BOOL decrypt_aes256_hmac_sha512(const BYTE* key, int key_len,
                                const BYTE* data, int data_len,
                                BYTE** decrypted, int* dec_len);

BOOL decrypt_triple_des_hmac(const BYTE* key, int key_len,
                             const BYTE* data, int data_len,
                             BYTE** decrypted, int* dec_len);

BOOL is_valid_hmac(const BYTE* key, int key_len,
                   const BYTE* hash_data, int hash_len,
                   const BYTE* computed_hash, int ch_len,
                   DWORD alg_hash);

/* ---- AES-GCM (for Chrome v80+) ---- */
BOOL aes_gcm_decrypt(const BYTE* key, int key_len,
                     const BYTE* nonce, int nonce_len,
                     const BYTE* data, int data_len,
                     const BYTE* tag, int tag_len,
                     BYTE** decrypted, int* dec_len);

#endif /* _CRYPTO_H_ */
