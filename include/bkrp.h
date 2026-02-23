/*
 * bkrp.h — MS-BKRP (BackupKey Remote Protocol) client
 *
 * Implements the RPC client for MS-BKRP, allowing masterkey
 * decryption by requesting the domain controller to decrypt
 * the domain key portion of a DPAPI masterkey file.
 *
 * Ref: SharpDPAPI/lib/Bkrp.cs
 * Ref: Mimikatz kull_m_rpc_ms-bkrp_c.c
 */
#ifndef BKRP_H
#define BKRP_H

#include "bofdefs.h"

/* ---- DFR for NdrClientCall2 (only declared here, not in bofdefs.h) ---- */
#ifndef BKRP_NDRCLIENTCALL2_DECLARED
#define BKRP_NDRCLIENTCALL2_DECLARED
DECLSPEC_IMPORT void* CDECL RPCRT4$NdrClientCall2(
    void* pStubDescriptor, void* pFormat, ...);
#endif

/* ---- Public API ---- */

/*
 * bkrp_decrypt_masterkey — Decrypt a masterkey's domain key via MS-BKRP RPC
 *
 * @param dc_name      Domain controller hostname or IP (e.g. "dc01.corp.local")
 * @param domain_key   Raw domain key bytes extracted from masterkey blob
 * @param dk_len       Length of domain_key
 * @param out_key      Output buffer (caller allocates, min 64 bytes)
 * @param out_key_len  On return, length of decrypted key (should be 64)
 *
 * Returns TRUE on success, FALSE on failure.
 */
BOOL bkrp_decrypt_masterkey(const wchar_t* dc_name,
                            const BYTE* domain_key, int dk_len,
                            BYTE* out_key, int* out_key_len);

/*
 * dpapi_get_domain_key — Extract the domain key portion from a masterkey blob
 *
 * The masterkey file format has a header at offset 0, then at offset 96:
 *   QWORD masterKeyLen
 *   QWORD backupKeyLen
 *   QWORD credHistLen
 *   QWORD domainKeyLen
 *   [masterKeyLen bytes]
 *   [backupKeyLen bytes]
 *   [credHistLen bytes]
 *   [domainKeyLen bytes]  <-- this is what we extract
 *
 * @param mk_bytes     Raw masterkey file bytes
 * @param mk_len       Length of masterkey file
 * @param out_dk       Output pointer to domain key bytes (caller frees with intFree)
 * @param out_dk_len   Length of domain key bytes
 *
 * Returns TRUE on success.
 */
BOOL dpapi_get_domain_key(const BYTE* mk_bytes, int mk_len,
                          BYTE** out_dk, int* out_dk_len);

/*
 * dpapi_get_masterkey_guid — Extract the GUID string from a masterkey blob
 *
 * The GUID is stored as a Unicode string at offset 12, length 72 bytes (36 wchars).
 *
 * @param mk_bytes     Raw masterkey file bytes
 * @param mk_len       Length of masterkey file
 * @param guid_str     Output buffer (min 40 chars) for "{GUID}" string
 *
 * Returns TRUE on success.
 */
BOOL dpapi_get_masterkey_guid(const BYTE* mk_bytes, int mk_len, char* guid_str);

#endif /* BKRP_H */
