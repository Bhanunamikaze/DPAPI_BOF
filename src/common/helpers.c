/*
 * helpers.c — Utility functions for DPAPI BOFs
 * Ported from SharpDPAPI/lib/Helpers.cs
 */
#include "helpers.h"

/* ---- Hex string to byte array ---- */
BYTE* hex_to_bytes(const char* hex, int* out_len) {
    if (!hex || !out_len) return NULL;
    int slen = strlen(hex);
    if (slen % 2 != 0) return NULL;

    int blen = slen / 2;
    BYTE* bytes = (BYTE*)intAlloc(blen);
    if (!bytes) return NULL;

    for (int i = 0; i < blen; i++) {
        unsigned int val = 0;
        char tmp[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        for (int j = 0; j < 2; j++) {
            val <<= 4;
            char c = tmp[j];
            if (c >= '0' && c <= '9') val |= (c - '0');
            else if (c >= 'a' && c <= 'f') val |= (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') val |= (c - 'A' + 10);
            else { intFree(bytes); return NULL; }
        }
        bytes[i] = (BYTE)val;
    }
    *out_len = blen;
    return bytes;
}

/* ---- Byte array to hex string ---- */
char* bytes_to_hex(const BYTE* data, int len) {
    if (!data || len <= 0) return NULL;
    char* hex = (char*)intAlloc(len * 2 + 1);
    if (!hex) return NULL;
    for (int i = 0; i < len; i++) {
        sprintf(hex + i * 2, "%02X", data[i]);
    }
    hex[len * 2] = 0;
    return hex;
}

/* ---- Byte array comparison ---- */
BOOL byte_array_equals(const BYTE* a, const BYTE* b, int len) {
    if (!a || !b) return FALSE;
    return memcmp(a, b, len) == 0;
}

/* ---- Find needle in haystack ---- */
int array_index_of(const BYTE* haystack, int haystack_len,
                   const BYTE* needle, int needle_len) {
    if (!haystack || !needle || needle_len > haystack_len) return -1;
    for (int i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0)
            return i;
    }
    return -1;
}

/* ---- Wide string to UTF-8 ---- */
char* wide_to_utf8(const wchar_t* wstr) {
    if (!wstr) return NULL;
#ifdef BOF
    int len = KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* str = (char*)intAlloc(len);
    if (!str) return NULL;
    KERNEL32$WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
#else
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* str = (char*)intAlloc(len);
    if (!str) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, str, len, NULL, NULL);
#endif
    return str;
}

/* ---- UTF-8 to wide string ---- */
wchar_t* utf8_to_wide(const char* str) {
    if (!str) return NULL;
#ifdef BOF
    int len = KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t* wstr = (wchar_t*)intAlloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    KERNEL32$MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
#else
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (len <= 0) return NULL;
    wchar_t* wstr = (wchar_t*)intAlloc(len * sizeof(wchar_t));
    if (!wstr) return NULL;
    MultiByteToWideChar(CP_UTF8, 0, str, -1, wstr, len);
#endif
    return wstr;
}

/* ---- String case conversion ---- */
void str_to_upper(char* str) {
    if (!str) return;
    for (; *str; str++) *str = (char)toupper((unsigned char)*str);
}

void str_to_lower(char* str) {
    if (!str) return;
    for (; *str; str++) *str = (char)tolower((unsigned char)*str);
}

/* ---- Check if running as high integrity ---- */
BOOL is_high_integrity(void) {
    HANDLE hToken = NULL;
    BOOL result = FALSE;

#ifdef BOF
    if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD dwSize = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { KERNEL32$CloseHandle(hToken); return FALSE; }

    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)intAlloc(dwSize);
    if (!tml) { KERNEL32$CloseHandle(hToken); return FALSE; }

    if (ADVAPI32$GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize)) {
        DWORD* pCount = GetSidSubAuthorityCount(tml->Label.Sid);
        DWORD integrity = *GetSidSubAuthority(tml->Label.Sid, *pCount - 1);
        result = (integrity >= SECURITY_MANDATORY_HIGH_RID);
    }

    intFree(tml);
    KERNEL32$CloseHandle(hToken);
#else
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return FALSE;

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    if (dwSize == 0) { CloseHandle(hToken); return FALSE; }

    TOKEN_MANDATORY_LABEL* tml = (TOKEN_MANDATORY_LABEL*)intAlloc(dwSize);
    if (!tml) { CloseHandle(hToken); return FALSE; }

    if (GetTokenInformation(hToken, TokenIntegrityLevel, tml, dwSize, &dwSize)) {
        DWORD* pCount = GetSidSubAuthorityCount(tml->Label.Sid);
        DWORD integrity = *GetSidSubAuthority(tml->Label.Sid, *pCount - 1);
        result = (integrity >= SECURITY_MANDATORY_HIGH_RID);
    }

    intFree(tml);
    CloseHandle(hToken);
#endif

    return result;
}

/* ---- Elevate to SYSTEM via token impersonation ---- */
BOOL get_system(void) {
    /* Find winlogon.exe and steal its token */
    /* This is a simplified version — in the full port we use
       CreateToolhelp32Snapshot to find winlogon PID */
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    HANDLE hProcess = NULL;
    BOOL result = FALSE;

    /* Try well-known PID approach: enumerate processes for winlogon */
    /* For BOF simplicity, we look for PID passed or enumerate */
    /* This will be fleshed out in Phase 4 when machine triage needs it */

    return result;
}

/* ---- Revert to original token ---- */
BOOL revert_to_self_helper(void) {
#ifdef BOF
    return ADVAPI32$RevertToSelf();
#else
    return RevertToSelf();
#endif
}

/* ---- Get user profile folders ---- */
wchar_t** get_user_folders(int* count) {
    /* Enumerate C:\Users\* directories */
    wchar_t search_path[] = L"C:\\Users\\*";
    WIN32_FIND_DATAW ffd;
    HANDLE hFind;
    wchar_t** folders = NULL;
    int n = 0;
    int capacity = 16;

    folders = (wchar_t**)intAlloc(capacity * sizeof(wchar_t*));
    if (!folders) { *count = 0; return NULL; }

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search_path, &ffd);
#else
    hFind = FindFirstFileW(search_path, &ffd);
#endif
    if (hFind == INVALID_HANDLE_VALUE) { *count = 0; return folders; }

    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"Public") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"Default") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"Default User") == 0) continue;
        if (_wcsicmp(ffd.cFileName, L"All Users") == 0) continue;

        if (n >= capacity) {
            capacity *= 2;
            folders = (wchar_t**)intRealloc(folders, capacity * sizeof(wchar_t*));
        }

        /* Build full path */
        int plen = 9 + wcslen(ffd.cFileName) + 1; /* "C:\\Users\\" + name + null */
        wchar_t* path = (wchar_t*)intAlloc(plen * sizeof(wchar_t));
        if (path) {
            swprintf(path, L"C:\\Users\\%s", ffd.cFileName);
            folders[n++] = path;
        }

#ifdef BOF
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif

    *count = n;
    return folders;
}

/* ---- Read registry key value ---- */
BOOL get_reg_key_value(HKEY root, const wchar_t* path, const wchar_t* name,
                       BYTE** out_data, DWORD* out_len) {
    HKEY hKey = NULL;
    LONG status;
    DWORD type = 0, size = 0;

#ifdef BOF
    status = ADVAPI32$RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
#else
    status = RegOpenKeyExW(root, path, 0, KEY_READ, &hKey);
#endif
    if (status != ERROR_SUCCESS) return FALSE;

#ifdef BOF
    status = ADVAPI32$RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
#else
    status = RegQueryValueExW(hKey, name, NULL, &type, NULL, &size);
#endif
    if (status != ERROR_SUCCESS || size == 0) {
#ifdef BOF
        ADVAPI32$RegCloseKey(hKey);
#else
        RegCloseKey(hKey);
#endif
        return FALSE;
    }

    BYTE* data = (BYTE*)intAlloc(size);
    if (!data) {
#ifdef BOF
        ADVAPI32$RegCloseKey(hKey);
#else
        RegCloseKey(hKey);
#endif
        return FALSE;
    }

#ifdef BOF
    status = ADVAPI32$RegQueryValueExW(hKey, name, NULL, &type, data, &size);
    ADVAPI32$RegCloseKey(hKey);
#else
    status = RegQueryValueExW(hKey, name, NULL, &type, data, &size);
    RegCloseKey(hKey);
#endif

    if (status != ERROR_SUCCESS) {
        intFree(data);
        return FALSE;
    }

    *out_data = data;
    *out_len = size;
    return TRUE;
}

/* ---- Parse masterkey file structure ---- */
BOOL parse_masterkey_file(const BYTE* data, int data_len,
                          BYTE** masterkey_bytes, int* mk_len,
                          BYTE** backup_bytes, int* bk_len,
                          BYTE** domain_key_bytes, int* dk_len,
                          GUID* master_key_guid) {
    /*
     * Masterkey file layout:
     * [0-3]   version (2)
     * [4-7]   reserved
     * [8-11]  reserved
     * [12-75] GUID string (64 bytes, wide)
     * [76-79] reserved
     * [80-83] policy flags
     * [84-91] masterkey len
     * [92-99] backupkey len
     * [100-107] credhistory len
     * [108-115] domainkey len
     * [116+]  masterkey blob, then backup, then credhistory, then domainkey
     */
    if (data_len < 116) return FALSE;

    /* Extract GUID from bytes 12..75 (64 bytes of wide chars) */
    wchar_t guid_str[33];
    memcpy(guid_str, data + 12, 64);
    guid_str[32] = L'\0';

    /* Parse GUID — this is the file's GUID name, not the struct */
    /* CLSIDFromString equivalent */
    /* We'll parse from the wide string */

    /* Extract lengths */
    DWORD mk_size = *(DWORD*)(data + 84);
    DWORD bk_size = *(DWORD*)(data + 92);
    DWORD ch_size = *(DWORD*)(data + 100);
    DWORD dk_size = *(DWORD*)(data + 108);

    int offset = 116;

    /* Masterkey blob */
    if (mk_size > 0 && offset + (int)mk_size <= data_len) {
        *masterkey_bytes = (BYTE*)intAlloc(mk_size);
        if (*masterkey_bytes) {
            memcpy(*masterkey_bytes, data + offset, mk_size);
            *mk_len = mk_size;
        }
    }
    offset += mk_size;

    /* Backup key blob */
    if (bk_size > 0 && offset + (int)bk_size <= data_len) {
        *backup_bytes = (BYTE*)intAlloc(bk_size);
        if (*backup_bytes) {
            memcpy(*backup_bytes, data + offset, bk_size);
            *bk_len = bk_size;
        }
    }
    offset += bk_size;

    /* Skip credential history */
    offset += ch_size;

    /* Domain key blob */
    if (dk_size > 0 && offset + (int)dk_size <= data_len) {
        *domain_key_bytes = (BYTE*)intAlloc(dk_size);
        if (*domain_key_bytes) {
            memcpy(*domain_key_bytes, data + offset, dk_size);
            *dk_len = dk_size;
        }
    }

    return TRUE;
}

/* ---- Base64 decode using CryptStringToBinaryA ---- */
BYTE* base64_decode(const char* input, int* out_len) {
    if (!input || !out_len) return NULL;
    DWORD size = 0;

#ifdef BOF
    if (!CRYPT32$CryptStringToBinaryA(input, 0, 0x00000001 /* CRYPT_STRING_BASE64 */, NULL, &size, NULL, NULL))
        return NULL;

    BYTE* output = (BYTE*)intAlloc(size);
    if (!output) return NULL;

    if (!CRYPT32$CryptStringToBinaryA(input, 0, 0x00000001, output, &size, NULL, NULL)) {
        intFree(output);
        return NULL;
    }
#else
    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL))
        return NULL;

    BYTE* output = (BYTE*)intAlloc(size);
    if (!output) return NULL;

    if (!CryptStringToBinaryA(input, 0, CRYPT_STRING_BASE64, output, &size, NULL, NULL)) {
        intFree(output);
        return NULL;
    }
#endif

    *out_len = (int)size;
    return output;
}

/* ---- Base64 encode using CryptBinaryToStringA ---- */
char* base64_encode(const BYTE* data, int len) {
    if (!data || len <= 0) return NULL;
    DWORD size = 0;

#ifdef BOF
    if (!CRYPT32$CryptBinaryToStringA(data, len, 0x00000001 | 0x40000000 /* BASE64 | NOCRLF */, NULL, &size))
        return NULL;

    char* output = (char*)intAlloc(size + 1);
    if (!output) return NULL;

    if (!CRYPT32$CryptBinaryToStringA(data, len, 0x00000001 | 0x40000000, output, &size)) {
        intFree(output);
        return NULL;
    }
#else
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size))
        return NULL;

    char* output = (char*)intAlloc(size + 1);
    if (!output) return NULL;

    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, output, &size)) {
        intFree(output);
        return NULL;
    }
#endif

    return output;
}

/* ---- GUID string check ---- */
BOOL is_guid(const char* str) {
    if (!str) return FALSE;
    int len = strlen(str);
    /* GUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars) */
    /* or {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx} (38 chars) */
    if (len != 36 && len != 38) return FALSE;
    return TRUE;  /* Simplified check */
}

/* ---- GUID to string ---- */
char* guid_to_string(const GUID* guid) {
    if (!guid) return NULL;
    char* str = (char*)intAlloc(40);
    if (!str) return NULL;
    sprintf(str, "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
            guid->Data1, guid->Data2, guid->Data3,
            guid->Data4[0], guid->Data4[1],
            guid->Data4[2], guid->Data4[3],
            guid->Data4[4], guid->Data4[5],
            guid->Data4[6], guid->Data4[7]);
    return str;
}

/* ---- String to GUID ---- */
BOOL string_to_guid(const char* str, GUID* out) {
    if (!str || !out) return FALSE;
    memset(out, 0, sizeof(GUID));

    /* Skip leading { if present */
    const char* p = str;
    if (*p == '{') p++;

    unsigned int d1, d2, d3;
    unsigned int d4[8];
    int n = sscanf(p, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                   &d1, &d2, &d3,
                   &d4[0], &d4[1], &d4[2], &d4[3],
                   &d4[4], &d4[5], &d4[6], &d4[7]);
    if (n != 11) return FALSE;

    out->Data1 = (DWORD)d1;
    out->Data2 = (unsigned short)d2;
    out->Data3 = (unsigned short)d3;
    for (int i = 0; i < 8; i++) out->Data4[i] = (BYTE)d4[i];
    return TRUE;
}

/* ---- Extract SID from file path ---- */
char* extract_sid_from_path(const wchar_t* path) {
    /* Look for S-1-5-21-... pattern in the path */
    if (!path) return NULL;

    const wchar_t* sid_start = wcsstr(path, L"S-1-5-21-");
    if (!sid_start) return NULL;

    /* Find end of SID */
    const wchar_t* ep = sid_start;
    while (*ep && *ep != L'\\' && *ep != L'/') ep++;

    int sid_len = (int)(ep - sid_start);
    char* sid = (char*)intAlloc(sid_len + 1);
    if (!sid) return NULL;

    for (int i = 0; i < sid_len; i++) {
        sid[i] = (char)sid_start[i];
    }
    sid[sid_len] = 0;
    return sid;
}
