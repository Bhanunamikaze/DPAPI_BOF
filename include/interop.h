/*
 * interop.h — Win32 interop structures and wrapper functions
 * Ported from SharpDPAPI/lib/Interop.cs
 */
#ifndef _INTEROP_H_
#define _INTEROP_H_

#include "bofdefs.h"

/* ---- KERB_ECRYPT structure (for CDLocateCSystem) ---- */
typedef struct _KERB_ECRYPT {
    DWORD Type0;
    DWORD BlockSize;
    DWORD Type1;
    DWORD KeySize;
    DWORD Size;
    DWORD unk2;
    DWORD unk3;
    wchar_t* AlgName;
    void* Initialize;
    void* Encrypt;
    void* Decrypt;
    void* Finish;
    void* HashPassword;
    void* RandomKey;
    void* Control;
    void* unk0_null;
    void* unk1_null;
    void* unk2_null;
} KERB_ECRYPT;

typedef int (WINAPI *KERB_ECRYPT_HashPassword)(
    UNICODE_STRING* Password,
    UNICODE_STRING* Salt,
    int count,
    BYTE* output
);

/* ---- DC discovery ---- */
char* get_dc_name(void);
wchar_t* get_dc_name_w(void);

#endif /* _INTEROP_H_ */
