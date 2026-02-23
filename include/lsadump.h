/*
 * lsadump.h — LSA secret and boot key extraction
 * Ported from SharpDPAPI/lib/LSADump.cs
 */
#ifndef _LSADUMP_H_
#define _LSADUMP_H_

#include "bofdefs.h"

/* ---- LSA DPAPI Keys ---- */
BOOL get_dpapi_keys(BYTE** dpapi_system_key, int* key_len);

/* ---- LSA Secrets ---- */
BOOL get_lsa_secret(const wchar_t* secret_name, BYTE** out_data, int* out_len);
BOOL get_lsa_key(BYTE** out_key, int* out_len);
BOOL get_boot_key(BYTE** out_key, int* out_len);

#endif /* _LSADUMP_H_ */
