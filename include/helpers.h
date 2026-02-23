/*
 * helpers.h — Utility functions for DPAPI BOFs
 * Ported from SharpDPAPI/lib/Helpers.cs
 */
#ifndef _HELPERS_H_
#define _HELPERS_H_

#include "bofdefs.h"
#include "beacon.h"

/* ---- Memory helpers ---- */
BYTE* hex_to_bytes(const char* hex, int* out_len);
char* bytes_to_hex(const BYTE* data, int len);
BOOL byte_array_equals(const BYTE* a, const BYTE* b, int len);
int  array_index_of(const BYTE* haystack, int haystack_len, const BYTE* needle, int needle_len);

/* ---- String helpers ---- */
char* wide_to_utf8(const wchar_t* wstr);
wchar_t* utf8_to_wide(const char* str);
void str_to_upper(char* str);
void str_to_lower(char* str);

/* ---- Path / system helpers ---- */
BOOL is_high_integrity(void);
BOOL get_system(void);
BOOL revert_to_self_helper(void);
wchar_t** get_user_folders(int* count);
BOOL get_reg_key_value(HKEY root, const wchar_t* path, const wchar_t* name, BYTE** out_data, DWORD* out_len);

/* ---- DPAPI file helpers ---- */
BOOL parse_masterkey_file(const BYTE* data, int data_len,
                          BYTE** masterkey_bytes, int* mk_len,
                          BYTE** backup_bytes, int* bk_len,
                          BYTE** domain_key_bytes, int* dk_len,
                          GUID* master_key_guid);

/* ---- SID helpers ---- */
char* get_sid_from_bk_file(const BYTE* data, int data_len);
char* extract_sid_from_path(const wchar_t* path);

/* ---- Encoding helpers ---- */
int encode_length(BYTE* output, int length);
int encode_integer_big_endian(BYTE* output, const BYTE* value, int value_len);
wchar_t* convert_local_path_to_unc(const wchar_t* local_path, const wchar_t* server);

/* ---- Base64 ---- */
BYTE* base64_decode(const char* input, int* out_len);
char* base64_encode(const BYTE* data, int len);

/* ---- GUID helpers ---- */
BOOL is_guid(const char* str);
char* guid_to_string(const GUID* guid);
BOOL  string_to_guid(const char* str, GUID* out);

#endif /* _HELPERS_H_ */
