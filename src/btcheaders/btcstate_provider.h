// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCHEADERS_BTCSTATE_PROVIDER_H
#define BATHRON_BTCHEADERS_BTCSTATE_PROVIDER_H

#include "script/btcstate.h"

#include <stdint.h>
#include <vector>

class uint256;

/**
 * Node-side evaluator for OP_BTCSTATEVERIFY queries (A1), backed by the
 * consensus btcheadersdb. See script/btcstate.h for the model; the two
 * consensus anchors implemented here:
 *
 *  - SNAPSHOT: queries answer against the headers tip AS OF THE PREVIOUS
 *    BATHRON block. validation.cpp calls BtcStateCaptureSnapshot() at
 *    ConnectBlock start (before any tx of the block applies) and at mempool
 *    acceptance. Deterministic per block, order- and thread-independent.
 *
 *  - MARGIN: only heights h with h + BTCSTATE_REORG_MARGIN <= snapshotTip
 *    are readable. Together with the btcheaders max-reorg-depth rule (R7,
 *    btcheaders.cpp) that region is immutable, so a query answer can never
 *    flip from true to false (monotone validity).
 */

/** Capture the current btcheadersdb tip as the evaluation snapshot.
 *  Call under cs_main, before applying any tx of the context. */
void BtcStateCaptureSnapshot();

/** Install the real evaluator into the script-lib seam (node init). */
void InstallBtcStateProvider();

/** The evaluator itself (exposed for tests). */
bool BtcStateEvaluate(const BtcStateQuery& query);

/** TX_CONFIRMED proof check against a known Merkle root (exposed for tests).
 *  Burn-claim pattern: strict-parse the BTC tx, compute its txid, verify the
 *  Merkle branch, then sum the outputs paying exactly q.targetScript and
 *  require >= q.amountOperand. Pure given the root (uses g_btc_spv only for
 *  the branch verification, itself a pure function of its arguments). */
bool BtcTxConfirmedProofCheck(const BtcStateQuery& q, const uint256& merkleRoot);

// ── Pure helpers (unit-testable without a DB) ────────────────────────────

/** difficulty(a) >= difficulty(b), i.e. target(a) <= target(b).
 *  Invalid/zero/overflowing compacts compare as "no" (fail closed). */
bool CompactDifficultyGte(uint32_t nBitsA, uint32_t nBitsB);

/** Bitcoin-style median-time-past over the last up-to-11 timestamps
 *  (input ordered by ascending height, last element = subject height). */
int64_t MedianTimePast(std::vector<int64_t> times);

#endif // BATHRON_BTCHEADERS_BTCSTATE_PROVIDER_H
