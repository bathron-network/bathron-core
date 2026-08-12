// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_KILLSWITCH_H
#define BATHRON_KILLSWITCH_H

#include <atomic>
#include <cstdint>

/**
 * BP12 - BTC Burns Emergency Control (Kill Switch)
 *
 * This is a soft consensus rule enforced by all validating nodes.
 * When the kill switch is OFF, all nodes reject burn claims —
 * not just mempool policy, but block validation itself.
 *
 * The kill switch is controlled via:
 * - Config file: btcburnsenabled=0/1 (default: 1)
 * - RPC: setbtcburnsenabled true/false (requires special auth)
 *
 * IMPORTANT: This does NOT affect the M0/M1 rail. Only BTC entry is paused.
 * - M0 → lock → M1 ✅ (still works)
 * - M1 → unlock → M0 ✅ (still works)
 * - M1 → transfer → M1' ✅ (still works)
 */

// Global kill switch state (atomic for thread safety)
extern std::atomic<bool> g_btc_burns_enabled;

/**
 * Initialize kill switch from config.
 * Called at daemon startup.
 */
void InitKillSwitch();

/**
 * Check if BTC burns are currently enabled.
 *
 * NODE-LOCAL POLICY, NOT CONSENSUS (the old comment claiming "CONSENSUS FUNCTION —
 * used in CheckBurnClaim() and CheckMintM0BTC()" was FALSE and is the exact class
 * of confusion behind AUD-003). This flag is read in exactly three places, none of
 * them a validation path:
 *   1. AcceptToMemoryPool — refuse to accept/relay/mine NEW TX_BURN_CLAIM;
 *   2. MintPolicyAllowsProduction (producer side) — refuse to BUILD a mint;
 *   3. the getburnstatus/setbtcburnsenabled RPCs — display only.
 * It is NEVER read on a block-validation path: CheckBurnClaim, CheckMintM0BTC and
 * the consensus oracle CreateExpectedMintM0BTC are all flag-blind (LOT 2), so
 * differing kill-switch states across operators can never fork the chain.
 *
 * ⚠ CONSEQUENCE OF LOT 2, know it before flipping this in production: consensus now
 * always requires the due mint, so a FLEET-WIDE kill switch does not "pause minting"
 * — every producer refuses to assemble and block production STOPS until the flag is
 * restored. Partial activation is survivable (other operators keep producing).
 *
 * @return true if burns are enabled, false if kill switch is active
 */
bool AreBtcBurnsEnabled();

/**
 * Set the kill switch state.
 *
 * @param enabled true to enable burns, false to disable
 * @return true if state changed, false if already in requested state
 */
bool SetBtcBurnsEnabled(bool enabled);

/**
 * Get kill switch status information.
 */
struct KillSwitchStatus {
    bool enabled;           // Current state
    int64_t lastChanged;    // Timestamp of last state change (0 if never changed)
    bool configDefault;     // Default from config file
};

KillSwitchStatus GetKillSwitchStatus();

#endif // BATHRON_KILLSWITCH_H
