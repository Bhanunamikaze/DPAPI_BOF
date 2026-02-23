/*
 * interop.c — Win32 interop wrappers
 * Ported from SharpDPAPI/lib/Interop.cs
 */
#include "interop.h"
#include "helpers.h"

/* ---- Get Domain Controller name ---- */
wchar_t* get_dc_name_w(void) {
    PDOMAIN_CONTROLLER_INFOW pDCI = NULL;
    wchar_t* dc_name = NULL;

#ifdef BOF
    DWORD ret = NETAPI32$DsGetDcNameW(NULL, NULL, NULL, NULL,
                                       DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
                                       &pDCI);
    if (ret != ERROR_SUCCESS || !pDCI) return NULL;

    int len = wcslen(pDCI->DomainControllerName);
    dc_name = (wchar_t*)intAlloc((len + 1) * sizeof(wchar_t));
    if (dc_name) {
        wcscpy(dc_name, pDCI->DomainControllerName);
        /* Strip leading \\ */
        if (dc_name[0] == L'\\' && dc_name[1] == L'\\') {
            memmove(dc_name, dc_name + 2, (len - 1) * sizeof(wchar_t));
        }
    }
    NETAPI32$NetApiBufferFree(pDCI);
#else
    DWORD ret = DsGetDcNameW(NULL, NULL, NULL, NULL,
                             DS_DIRECTORY_SERVICE_REQUIRED | DS_RETURN_DNS_NAME,
                             &pDCI);
    if (ret != ERROR_SUCCESS || !pDCI) return NULL;

    int len = wcslen(pDCI->DomainControllerName);
    dc_name = (wchar_t*)intAlloc((len + 1) * sizeof(wchar_t));
    if (dc_name) {
        wcscpy(dc_name, pDCI->DomainControllerName);
        if (dc_name[0] == L'\\' && dc_name[1] == L'\\') {
            memmove(dc_name, dc_name + 2, (len - 1) * sizeof(wchar_t));
        }
    }
    NetApiBufferFree(pDCI);
#endif

    return dc_name;
}

char* get_dc_name(void) {
    wchar_t* wdc = get_dc_name_w();
    if (!wdc) return NULL;
    char* dc = wide_to_utf8(wdc);
    intFree(wdc);
    return dc;
}
