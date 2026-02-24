/*
 * triage.h — File system triage operations for DPAPI artifacts
 * Ported from SharpDPAPI/lib/Triage.cs
 */
#ifndef _TRIAGE_H_
#define _TRIAGE_H_

#include "bofdefs.h"
#include "dpapi_common.h"

/* ---- Masterkey Triage ---- */
BOOL triage_user_masterkeys(MASTERKEY_CACHE* cache,
                            const BYTE* pvk, int pvk_len,
                            const char* password,
                            const char* ntlm,
                            const char* credkey,
                            BOOL use_rpc,
                            const wchar_t* target,
                            const wchar_t* server,
                            BOOL hashes_only,
                            const char* sid);

BOOL triage_system_masterkeys(MASTERKEY_CACHE* cache);

/* ---- Credential Triage ---- */
BOOL triage_user_creds(MASTERKEY_CACHE* cache,
                       const wchar_t* target,
                       const wchar_t* server,
                       BOOL unprotect);

BOOL triage_system_creds(MASTERKEY_CACHE* cache,
                         BOOL unprotect);

BOOL triage_cred_folder(MASTERKEY_CACHE* cache,
                        const wchar_t* folder,
                        BOOL unprotect);

BOOL triage_cred_file(MASTERKEY_CACHE* cache,
                      const wchar_t* file_path,
                      BOOL unprotect);

/* ---- Vault Triage ---- */
BOOL triage_user_vaults(MASTERKEY_CACHE* cache,
                        const wchar_t* target,
                        const wchar_t* server);

BOOL triage_system_vaults(MASTERKEY_CACHE* cache);

BOOL triage_vault_folder(MASTERKEY_CACHE* cache,
                         const wchar_t* folder);

/* ---- Certificate Triage ---- */
BOOL triage_user_certs(MASTERKEY_CACHE* cache,
                       const wchar_t* target,
                       const wchar_t* server,
                       BOOL show_all);

BOOL triage_system_certs(MASTERKEY_CACHE* cache,
                         const wchar_t* target,
                         BOOL show_all);

BOOL triage_cert_folder(MASTERKEY_CACHE* cache,
                        const wchar_t* folder,
                        BOOL show_all);

BOOL triage_cert_file(MASTERKEY_CACHE* cache,
                      const wchar_t* file_path,
                      BOOL show_all);

/* ---- KeePass Triage ---- */
BOOL triage_keepass(MASTERKEY_CACHE* cache,
                    const wchar_t* target,
                    BOOL unprotect);

BOOL triage_keepass_key_file(MASTERKEY_CACHE* cache,
                             const wchar_t* file_path,
                             BOOL unprotect);

/* ---- RDCMan Triage ---- */
BOOL triage_rdcman(MASTERKEY_CACHE* cache,
                   const wchar_t* target,
                   BOOL unprotect);

BOOL triage_rdcman_file(MASTERKEY_CACHE* cache,
                        const wchar_t* file_path,
                        BOOL unprotect);

BOOL triage_rdg_folder(MASTERKEY_CACHE* cache,
                       const wchar_t* folder,
                       BOOL unprotect);

BOOL triage_rdg_file(MASTERKEY_CACHE* cache,
                     const wchar_t* file_path,
                     BOOL unprotect);

/* ---- PSCredential Triage ---- */
BOOL triage_ps_cred_file(MASTERKEY_CACHE* cache,
                         const wchar_t* file_path,
                         BOOL unprotect);

/* ---- Chrome Triage ---- */
BOOL triage_chrome_logins(MASTERKEY_CACHE* cache,
                          const wchar_t* target,
                          const wchar_t* server,
                          BOOL unprotect,
                          const BYTE* state_key, int state_key_len);

BOOL triage_chrome_cookies(MASTERKEY_CACHE* cache,
                           const wchar_t* target,
                           const wchar_t* server,
                           BOOL unprotect,
                           const BYTE* state_key, int state_key_len,
                           const char* cookie_regex,
                           const char* url_regex);

BOOL triage_chrome_statekeys(MASTERKEY_CACHE* cache,
                             const wchar_t* target,
                             const wchar_t* server,
                             BOOL unprotect);

/* ---- Search / SCCM ---- */
BOOL triage_search(MASTERKEY_CACHE* cache,
                   const wchar_t* target,
                   const wchar_t* server,
                   const char* pattern);

BOOL triage_sccm(MASTERKEY_CACHE* cache,
                 const wchar_t* target);

/* ---- Full user triage ---- */
BOOL triage_user_full(MASTERKEY_CACHE* cache,
                      const BYTE* pvk, int pvk_len,
                      const char* password,
                      const char* ntlm,
                      const char* credkey,
                      BOOL use_rpc,
                      const wchar_t* target,
                      const wchar_t* server,
                      BOOL show_all);

/* ---- Cred Profile Display ---- */
BOOL display_cred_profile(const wchar_t* file_path,
                          const char* username,
                          const char* password_enc);

#endif /* _TRIAGE_H_ */
