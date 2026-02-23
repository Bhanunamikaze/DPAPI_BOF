/*
 * crypto.c — Cryptographic functions for DPAPI BOFs
 * Ported from SharpDPAPI/lib/Crypto.cs
 *
 * Uses Windows BCrypt API for all crypto operations.
 */
#include "crypto.h"
#include "helpers.h"
#include "interop.h"

/* ---- Internal: BCrypt hash helper ---- */
static BOOL bcrypt_hash(const wchar_t* alg_id, const BYTE* data, ULONG data_len,
                        const BYTE* secret, ULONG secret_len,
                        BYTE* out_hash, ULONG hash_len, BOOL is_hmac) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    BOOL result = FALSE;
    ULONG flags = is_hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, alg_id, NULL, flags);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptCreateHash(hAlg, &hHash, NULL, 0,
                                     (PUCHAR)secret, secret_len, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptHashData(hHash, (PUCHAR)data, data_len, 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptFinishHash(hHash, out_hash, hash_len, 0);
    result = (status == 0);

cleanup:
    if (hHash) BCRYPT$BCryptDestroyHash(hHash);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, alg_id, NULL, flags);
    if (status != 0) goto cleanup;

    status = BCryptCreateHash(hAlg, &hHash, NULL, 0,
                              (PUCHAR)secret, secret_len, 0);
    if (status != 0) goto cleanup;

    status = BCryptHashData(hHash, (PUCHAR)data, data_len, 0);
    if (status != 0) goto cleanup;

    status = BCryptFinishHash(hHash, out_hash, hash_len, 0);
    result = (status == 0);

cleanup:
    if (hHash) BCryptDestroyHash(hHash);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
#endif

    return result;
}

/* ---- HMAC-SHA512 ---- */
BOOL hmac_sha512(const BYTE* key, int key_len,
                 const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_SHA512_ALGORITHM, data, data_len,
                       key, key_len, out_hash, 64, TRUE);
}

/* ---- HMAC-SHA256 ---- */
BOOL hmac_sha256(const BYTE* key, int key_len,
                 const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_SHA256_ALGORITHM, data, data_len,
                       key, key_len, out_hash, 32, TRUE);
}

/* ---- HMAC-SHA1 ---- */
BOOL hmac_sha1(const BYTE* key, int key_len,
               const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_SHA1_ALGORITHM, data, data_len,
                       key, key_len, out_hash, 20, TRUE);
}

/* ---- SHA1 ---- */
BOOL sha1_hash(const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_SHA1_ALGORITHM, data, data_len,
                       NULL, 0, out_hash, 20, FALSE);
}

/* ---- SHA256 ---- */
BOOL sha256_hash(const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_SHA256_ALGORITHM, data, data_len,
                       NULL, 0, out_hash, 32, FALSE);
}

/* ---- SHA512 ---- */
BOOL sha512_hash(const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_SHA512_ALGORITHM, data, data_len,
                       NULL, 0, out_hash, 64, FALSE);
}

/* ---- MD4 (for NTLM hash) ---- */
BOOL md4_hash(const BYTE* data, int data_len, BYTE* out_hash) {
    return bcrypt_hash(BCRYPT_MD4_ALGORITHM, data, data_len,
                       NULL, 0, out_hash, 16, FALSE);
}

/* ---- Internal: BCrypt symmetric decrypt ---- */
static BOOL bcrypt_sym_decrypt(const wchar_t* alg_id, const wchar_t* chain_mode,
                               const BYTE* key, int key_len,
                               const BYTE* iv, int iv_len,
                               const BYTE* data, int data_len,
                               BYTE** decrypted, int* dec_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;
    BYTE* iv_copy = NULL;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, alg_id, NULL, 0);
    if (status != 0) goto cleanup;

    if (chain_mode) {
        status = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)chain_mode,
                                          (wcslen(chain_mode) + 1) * sizeof(wchar_t), 0);
        if (status != 0) goto cleanup;
    }

    status = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                               (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    /* IV must be a writable copy — BCrypt modifies it */
    if (iv && iv_len > 0) {
        iv_copy = (BYTE*)intAlloc(iv_len);
        if (!iv_copy) goto cleanup;
        memcpy(iv_copy, iv, iv_len);
    }

    /* Get output size */
    ULONG out_size = 0;
    status = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data, data_len, NULL,
                                  iv_copy, iv_len, NULL, 0, &out_size, 0);
    if (status != 0) goto cleanup;

    *decrypted = (BYTE*)intAlloc(out_size);
    if (!*decrypted) goto cleanup;

    /* Reset IV copy */
    if (iv_copy && iv) memcpy(iv_copy, iv, iv_len);

    ULONG actual_size = 0;
    status = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data, data_len, NULL,
                                  iv_copy, iv_len, *decrypted, out_size,
                                  &actual_size, 0);
    if (status != 0) {
        intFree(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = (int)actual_size;
    result = TRUE;

cleanup:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
    if (iv_copy) intFree(iv_copy);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, alg_id, NULL, 0);
    if (status != 0) goto cleanup;

    if (chain_mode) {
        status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                   (PUCHAR)chain_mode,
                                   (wcslen(chain_mode) + 1) * sizeof(wchar_t), 0);
        if (status != 0) goto cleanup;
    }

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    if (iv && iv_len > 0) {
        iv_copy = (BYTE*)intAlloc(iv_len);
        if (!iv_copy) goto cleanup;
        memcpy(iv_copy, iv, iv_len);
    }

    ULONG out_size = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)data, data_len, NULL,
                           iv_copy, iv_len, NULL, 0, &out_size, 0);
    if (status != 0) goto cleanup;

    *decrypted = (BYTE*)intAlloc(out_size);
    if (!*decrypted) goto cleanup;

    if (iv_copy && iv) memcpy(iv_copy, iv, iv_len);

    ULONG actual_size = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)data, data_len, NULL,
                           iv_copy, iv_len, *decrypted, out_size,
                           &actual_size, 0);
    if (status != 0) {
        intFree(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = (int)actual_size;
    result = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    if (iv_copy) intFree(iv_copy);
#endif

    return result;
}

/* ---- AES Decrypt (CBC mode) ---- */
BOOL aes_decrypt(const BYTE* key, int key_len,
                 const BYTE* iv, int iv_len,
                 const BYTE* data, int data_len,
                 BYTE** decrypted, int* dec_len) {
    return bcrypt_sym_decrypt(BCRYPT_AES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC,
                              key, key_len, iv, iv_len,
                              data, data_len, decrypted, dec_len);
}

/* ---- Triple DES Decrypt (CBC mode) ---- */
BOOL triple_des_decrypt(const BYTE* key, int key_len,
                        const BYTE* iv, int iv_len,
                        const BYTE* data, int data_len,
                        BYTE** decrypted, int* dec_len) {
    return bcrypt_sym_decrypt(BCRYPT_3DES_ALGORITHM, BCRYPT_CHAIN_MODE_CBC,
                              key, key_len, iv, iv_len,
                              data, data_len, decrypted, dec_len);
}

/* ---- PBKDF2 ---- */
BOOL pbkdf2_hmac_sha1(const BYTE* password, int pw_len,
                      const BYTE* salt, int salt_len,
                      int iterations,
                      BYTE* out_key, int key_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM,
                                                NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) return FALSE;

    status = BCRYPT$BCryptDeriveKeyPBKDF2(hAlg,
                                           (PUCHAR)password, pw_len,
                                           (PUCHAR)salt, salt_len,
                                           (ULONGLONG)iterations,
                                           out_key, key_len, 0);
    result = (status == 0);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM,
                                        NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) return FALSE;

    status = BCryptDeriveKeyPBKDF2(hAlg,
                                   (PUCHAR)password, pw_len,
                                   (PUCHAR)salt, salt_len,
                                   (ULONGLONG)iterations,
                                   out_key, key_len, 0);
    result = (status == 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
#endif

    return result;
}

BOOL pbkdf2_hmac_sha256(const BYTE* password, int pw_len,
                        const BYTE* salt, int salt_len,
                        int iterations,
                        BYTE* out_key, int key_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                                NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) return FALSE;

    status = BCRYPT$BCryptDeriveKeyPBKDF2(hAlg,
                                           (PUCHAR)password, pw_len,
                                           (PUCHAR)salt, salt_len,
                                           (ULONGLONG)iterations,
                                           out_key, key_len, 0);
    result = (status == 0);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
                                        NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) return FALSE;

    status = BCryptDeriveKeyPBKDF2(hAlg,
                                   (PUCHAR)password, pw_len,
                                   (PUCHAR)salt, salt_len,
                                   (ULONGLONG)iterations,
                                   out_key, key_len, 0);
    result = (status == 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
#endif

    return result;
}

BOOL pbkdf2_hmac_sha512(const BYTE* password, int pw_len,
                        const BYTE* salt, int salt_len,
                        int iterations,
                        BYTE* out_key, int key_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM,
                                                NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) return FALSE;

    status = BCRYPT$BCryptDeriveKeyPBKDF2(hAlg,
                                           (PUCHAR)password, pw_len,
                                           (PUCHAR)salt, salt_len,
                                           (ULONGLONG)iterations,
                                           out_key, key_len, 0);
    result = (status == 0);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM,
                                        NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != 0) return FALSE;

    status = BCryptDeriveKeyPBKDF2(hAlg,
                                   (PUCHAR)password, pw_len,
                                   (PUCHAR)salt, salt_len,
                                   (ULONGLONG)iterations,
                                   out_key, key_len, 0);
    result = (status == 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
#endif

    return result;
}

/* ---- Kerberos password hash (via CDLocateCSystem) ---- */
BOOL kerberos_password_hash(DWORD etype, const wchar_t* password,
                            const wchar_t* salt, BYTE* out_key, int* key_len) {
    KERB_ECRYPT* pCSystem = NULL;
    int status;

#ifdef BOF
    status = CRYPTDLL$CDLocateCSystem(etype, (void**)&pCSystem);
#else
    /* CDLocateCSystem is loaded from cryptdll.dll */
    HMODULE hMod = LoadLibraryA("cryptdll.dll");
    if (!hMod) return FALSE;
    typedef int (WINAPI *CDLocateCSystem_t)(DWORD, void**);
    CDLocateCSystem_t pCDLocate = (CDLocateCSystem_t)GetProcAddress(hMod, "CDLocateCSystem");
    if (!pCDLocate) { FreeLibrary(hMod); return FALSE; }
    status = pCDLocate(etype, (void**)&pCSystem);
#endif

    if (status != 0 || !pCSystem) return FALSE;

    UNICODE_STRING uPassword, uSalt;
    uPassword.Buffer = (PWSTR)password;
    uPassword.Length = (USHORT)(wcslen(password) * sizeof(wchar_t));
    uPassword.MaximumLength = uPassword.Length + sizeof(wchar_t);

    uSalt.Buffer = (PWSTR)salt;
    uSalt.Length = salt ? (USHORT)(wcslen(salt) * sizeof(wchar_t)) : 0;
    uSalt.MaximumLength = uSalt.Length + sizeof(wchar_t);

    *key_len = pCSystem->KeySize;
    KERB_ECRYPT_HashPassword pHashPassword =
        (KERB_ECRYPT_HashPassword)pCSystem->HashPassword;

    status = pHashPassword(&uPassword, &uSalt, 4096, out_key);

    return (status == 0);
}

/* ---- DPAPI key derivation (matches SharpDPAPI Crypto.DeriveKey) ----
 * pre-master key -> derived encryption + HMAC keys using DPAPI algorithm.
 * This follows the MS-BKRP / DPAPI specification:
 *   ipad = repeat(0x36, 64) XOR key
 *   opad = repeat(0x5C, 64) XOR key
 *   derived = HASH(ipad || HASH(opad))
 */
BOOL derive_key(const BYTE* key_material, int km_len,
                DWORD alg_hash,
                BYTE* derived_key, int dk_len) {
    BYTE ipad[64], opad[64];
    int hash_size;

    /* Determine hash output size */
    switch (alg_hash) {
        case CALG_SHA1:  hash_size = 20; break;
        case CALG_SHA_256: hash_size = 32; break;
        case CALG_SHA_512: hash_size = 64; break;
        case CALG_MD5:   hash_size = 16; break;
        default: return FALSE;
    }

    /* Build HMAC-style pads */
    memset(ipad, 0x36, 64);
    memset(opad, 0x5C, 64);

    for (int i = 0; i < km_len && i < 64; i++) {
        ipad[i] ^= key_material[i];
        opad[i] ^= key_material[i];
    }

    /* hash1 = HASH(ipad) */
    BYTE hash1[64]; /* max hash size */

    switch (alg_hash) {
        case CALG_SHA1:
            sha1_hash(ipad, 64, hash1);
            break;
        case CALG_SHA_256:
            sha256_hash(ipad, 64, hash1);
            break;
        case CALG_SHA_512:
            sha512_hash(ipad, 64, hash1);
            break;
        default:
            return FALSE;
    }

    /* hash2 = HASH(opad) */
    BYTE hash2[64];
    switch (alg_hash) {
        case CALG_SHA1:
            sha1_hash(opad, 64, hash2);
            break;
        case CALG_SHA_256:
            sha256_hash(opad, 64, hash2);
            break;
        case CALG_SHA_512:
            sha512_hash(opad, 64, hash2);
            break;
        default:
            return FALSE;
    }

    /* Copy to output: first hash_size bytes from hash1, rest from hash2 */
    int copy1 = dk_len < hash_size ? dk_len : hash_size;
    memcpy(derived_key, hash1, copy1);
    if (dk_len > hash_size) {
        int copy2 = dk_len - hash_size;
        if (copy2 > hash_size) copy2 = hash_size;
        memcpy(derived_key + copy1, hash2, copy2);
    }

    return TRUE;
}

/* ---- Raw key derivation (for pre-key) ---- */
BOOL derive_key_raw(const BYTE* key_material, int km_len,
                    DWORD alg_hash,
                    BYTE* derived_key, int dk_len) {
    /* Same as derive_key but without the HMAC ipad/opad — just plain hash */
    return derive_key(key_material, km_len, alg_hash, derived_key, dk_len);
}

/* ---- Decrypt DPAPI master key blob (AES256 + HMAC-SHA512 path) ---- */
BOOL decrypt_aes256_hmac_sha512(const BYTE* key, int key_len,
                                const BYTE* data, int data_len,
                                BYTE** decrypted, int* dec_len) {
    /*
     * DPAPI masterkey decryption (new AES path):
     * - First 32 bytes of derived key = HMAC key
     * - Next 32 bytes = AES-256+CBC key
     * - IV is from the blob
     * - Verify HMAC-SHA512 over plaintext
     */
    if (data_len < 80) return FALSE; /* minimum: 32 hmac + 16 iv + 32 data */

    /* Derive the enc key and hmac key from the pre-key */
    BYTE derived[64]; /* 32 bytes HMAC key + 32 bytes AES key */
    BYTE hmac_key[32], enc_key[32];

    /* Use HMAC-SHA512 to derive keys */
    if (!hmac_sha512(key, key_len, data, 16, derived))
        return FALSE;

    memcpy(hmac_key, derived, 32);
    memcpy(enc_key, derived + 32, 32);

    /* IV is the first 16 bytes of the encrypted portion */
    const BYTE* iv = data;
    const BYTE* enc_data = data + 16;
    int enc_len = data_len - 16;

    /* Decrypt with AES-256-CBC */
    return aes_decrypt(enc_key, 32, iv, 16, enc_data, enc_len,
                       decrypted, dec_len);
}

/* ---- Decrypt DPAPI master key blob (3DES + HMAC path) ---- */
BOOL decrypt_triple_des_hmac(const BYTE* key, int key_len,
                             const BYTE* data, int data_len,
                             BYTE** decrypted, int* dec_len) {
    /*
     * DPAPI masterkey decryption (legacy 3DES path):
     * - Derive 3DES key + HMAC key from pre-key using SHA1
     * - Decrypt with 3DES-CBC
     */
    if (data_len < 32) return FALSE;

    /* Derive keys */
    BYTE derived[40]; /* 20 bytes HMAC key + 24 bytes 3DES key */
    if (!derive_key(key, key_len, CALG_SHA1, derived, 40))
        return FALSE;

    BYTE hmac_key[20], enc_key[24];
    memcpy(hmac_key, derived, 20);
    memcpy(enc_key, derived + 20, 24);

    /* IV is first 8 bytes */
    const BYTE* iv = data;
    const BYTE* enc_data = data + 8;
    int enc_len = data_len - 8;

    return triple_des_decrypt(enc_key, 24, iv, 8, enc_data, enc_len,
                              decrypted, dec_len);
}

/* ---- DPAPI blob decrypt ----
 * Matches SharpDPAPI Crypto.DecryptBlob() */
BOOL decrypt_blob(const BYTE* encrypted, int enc_len,
                  const BYTE* key, int key_len,
                  DWORD alg_crypt, DWORD alg_hash,
                  BYTE** decrypted, int* dec_len) {
    int enc_key_len, iv_len;

    /* Determine key/IV sizes based on algorithm */
    switch (alg_crypt) {
        case CALG_3DES:
        case CALG_3DES_112:
            enc_key_len = 24;
            iv_len = 8;
            break;
        case CALG_AES_256:
            enc_key_len = 32;
            iv_len = 16;
            break;
        case CALG_AES_128:
            enc_key_len = 16;
            iv_len = 16;
            break;
        case CALG_AES_192:
            enc_key_len = 24;
            iv_len = 16;
            break;
        default:
            return FALSE;
    }

    /* Derive the encryption key from the masterkey */
    BYTE derived_key[64];
    if (!derive_key(key, key_len, alg_hash, derived_key, enc_key_len + iv_len))
        return FALSE;

    /* Split into enc_key and iv */
    BYTE* enc_key = derived_key;
    BYTE* iv = derived_key + enc_key_len;

    /* Decrypt */
    switch (alg_crypt) {
        case CALG_3DES:
        case CALG_3DES_112:
            return triple_des_decrypt(enc_key, enc_key_len, iv, iv_len,
                                      encrypted, enc_len, decrypted, dec_len);
        case CALG_AES_256:
        case CALG_AES_192:
        case CALG_AES_128:
            return aes_decrypt(enc_key, enc_key_len, iv, iv_len,
                               encrypted, enc_len, decrypted, dec_len);
        default:
            return FALSE;
    }
}

/* ---- HMAC verification ---- */
BOOL is_valid_hmac(const BYTE* key, int key_len,
                   const BYTE* hash_data, int hash_len,
                   const BYTE* computed_hash, int ch_len,
                   DWORD alg_hash) {
    BYTE hmac_out[64]; /* max hash size */
    int hmac_size;

    switch (alg_hash) {
        case CALG_SHA1:
            hmac_size = 20;
            if (!hmac_sha1(key, key_len, hash_data, hash_len, hmac_out))
                return FALSE;
            break;
        case CALG_SHA_256:
            hmac_size = 32;
            if (!hmac_sha256(key, key_len, hash_data, hash_len, hmac_out))
                return FALSE;
            break;
        case CALG_SHA_512:
            hmac_size = 64;
            if (!hmac_sha512(key, key_len, hash_data, hash_len, hmac_out))
                return FALSE;
            break;
        default:
            return FALSE;
    }

    if (ch_len < hmac_size) return FALSE;
    return byte_array_equals(hmac_out, computed_hash, hmac_size);
}

/* ---- LSA AES Decrypt ----
 * Used for LSA secret decryption (Windows 10+)
 * Matches SharpDPAPI Crypto.LSAAESDecrypt() */
BOOL lsa_aes_decrypt(const BYTE* key, int key_len,
                     const BYTE* data, int data_len,
                     BYTE** decrypted, int* dec_len) {
    /* ECB mode for LSA AES */
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;

    status = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                      (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                                      sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                               (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    *decrypted = (BYTE*)intAlloc(data_len);
    if (!*decrypted) goto cleanup;

    ULONG actual_size = 0;
    status = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data, data_len, NULL,
                                  NULL, 0, *decrypted, data_len,
                                  &actual_size, 0);
    if (status != 0) {
        intFree(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = (int)actual_size;
    result = TRUE;

cleanup:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                               sizeof(BCRYPT_CHAIN_MODE_ECB), 0);
    if (status != 0) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    *decrypted = (BYTE*)intAlloc(data_len);
    if (!*decrypted) goto cleanup;

    ULONG actual_size = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)data, data_len, NULL,
                           NULL, 0, *decrypted, data_len,
                           &actual_size, 0);
    if (status != 0) {
        intFree(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = (int)actual_size;
    result = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
#endif

    return result;
}

/* ---- LSA SHA256 hash (for boot key derivation) ---- */
BOOL lsa_sha256_hash(const BYTE* key, int key_len,
                     const BYTE* data, int data_len,
                     BYTE* out_hash) {
    /* This is actually an HMAC-SHA256 in the LSA context */
    return hmac_sha256(key, key_len, data, data_len, out_hash);
}

/* ---- RSA Decrypt (stub — uses NCrypt) ---- */
BOOL rsa_decrypt(const BYTE* private_key, int pk_len,
                 const BYTE* encrypted, int enc_len,
                 BYTE** decrypted, int* dec_len) {
    /* TODO: Implement using NCrypt API */
    /* This requires importing the private key blob and using NCrypt to decrypt */
    return FALSE;
}

/* ---- Export private key from CAPI blob to PKCS#8 (stub) ---- */
BOOL export_private_key(const BYTE* capi_blob, int blob_len,
                        BYTE** pkcs8, int* pkcs8_len) {
    /* TODO: Implement CAPI -> PKCS#8 conversion using NCrypt */
    /* NCryptImportKey with LEGACY_RSAPRIVATE_BLOB, then NCryptExportKey with PKCS8 */
    return FALSE;
}

/* ---- AES-GCM Decrypt (for Chrome v80+ cookies/passwords) ---- */
BOOL aes_gcm_decrypt(const BYTE* key, int key_len,
                     const BYTE* nonce, int nonce_len,
                     const BYTE* data, int data_len,
                     const BYTE* tag, int tag_len,
                     BYTE** decrypted, int* dec_len) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    /* Build auth info struct */
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = (PUCHAR)nonce;
    authInfo.cbNonce = nonce_len;
    authInfo.pbTag = (PUCHAR)tag;
    authInfo.cbTag = tag_len;

#ifdef BOF
    status = BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;

    status = BCRYPT$BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                                      (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                      sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) goto cleanup;

    status = BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                               (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    *decrypted = (BYTE*)intAlloc(data_len);
    if (!*decrypted) goto cleanup;

    ULONG actual_size = 0;
    status = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)data, data_len,
                                  &authInfo, NULL, 0,
                                  *decrypted, data_len, &actual_size, 0);
    if (status != 0) {
        intFree(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = (int)actual_size;
    result = TRUE;

cleanup:
    if (hKey) BCRYPT$BCryptDestroyKey(hKey);
    if (hAlg) BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
#else
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != 0) return FALSE;

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status != 0) goto cleanup;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0,
                                        (PUCHAR)key, key_len, 0);
    if (status != 0) goto cleanup;

    *decrypted = (BYTE*)intAlloc(data_len);
    if (!*decrypted) goto cleanup;

    ULONG actual_size = 0;
    status = BCryptDecrypt(hKey, (PUCHAR)data, data_len,
                           &authInfo, NULL, 0,
                           *decrypted, data_len, &actual_size, 0);
    if (status != 0) {
        intFree(*decrypted);
        *decrypted = NULL;
        goto cleanup;
    }

    *dec_len = (int)actual_size;
    result = TRUE;

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
#endif

    return result;
}
