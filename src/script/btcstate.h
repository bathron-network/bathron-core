// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_SCRIPT_BTCSTATE_H
#define BATHRON_SCRIPT_BTCSTATE_H

#include <stddef.h>
#include <stdint.h>
#include <vector>

/**
 * A1 — OP_BTCSTATEVERIFY (doc/PREMAINNET-CONSENSUS-ADDITIONS.md §1)
 *
 * Lets a script assert a fact about the Bitcoin chain that BATHRON already
 * carries in consensus (btcheadersdb): header-field queries (difficulty /
 * height / median-time-past) and TX_CONFIRMED (SPV inclusion of a BTC tx,
 * Merkle proof supplied by the spender — the burn-claim pattern opened to
 * script). No oracle: the facts are internal to the BTC chain and
 * SPV-verified by every node.
 *
 * Determinism anchor: queries are answered against the btcheaders state AS
 * OF THE PREVIOUS BATHRON BLOCK (snapshot captured at ConnectBlock start),
 * so the answer is independent of intra-block tx ordering and of script-
 * check thread scheduling. Reads are restricted to heights buried at least
 * BTCSTATE_REORG_MARGIN under that snapshot tip; combined with the
 * btcheaders max-reorg-depth consensus rule (R7) this region is immutable,
 * making script validity monotone (CLTV-style: not-yet-valid can become
 * valid, never the reverse).
 *
 * This header lives in the script (common) lib and carries NO chain
 * dependency: the evaluator is injected by the node at init
 * (btcheaders/btcstate_provider), and by unit tests as a mock. When no
 * provider is installed (e.g. tx-tool contexts) every query evaluates
 * false — fail closed.
 */

// Query types (stack byte)
static const uint8_t BTCSTATE_DIFF_GTE   = 0x01;  // difficulty(h) >= difficulty(operand nBits)
static const uint8_t BTCSTATE_DIFF_LT    = 0x02;  // difficulty(h) <  difficulty(operand nBits)
static const uint8_t BTCSTATE_HEIGHT_GTE = 0x03;  // buried BTC height >= h (no operand)
static const uint8_t BTCSTATE_MTP_GTE    = 0x04;  // median-time-past(h) >= operand time
static const uint8_t BTCSTATE_TX_CONFIRMED = 0x05; // a BTC tx paying >= amount to script, buried & confirmed (Merkle proof in witness)

/** Reads must be buried at least this deep under the snapshot tip.
 *  MUST equal the btcheaders max-reorg-depth (R7) so the readable region is
 *  consensus-immutable. 144 BTC blocks ≈ 1 day. */
static const uint32_t BTCSTATE_REORG_MARGIN = 144;

/** TX_CONFIRMED: max Merkle proof depth. The proof is one stack element of
 *  concatenated 32-byte hashes, so MAX_SCRIPT_ELEMENT_SIZE (520) already caps
 *  it at 16 levels = blocks of up to 65536 txs (real BTC blocks are < 2^14). */
static const size_t BTCSTATE_MAX_MERKLE_DEPTH = 16;

struct BtcStateQuery {
    uint8_t qtype;
    uint32_t btcHeight;   // subject height (DIFF_*, MTP_GTE, TX_CONFIRMED) or threshold (HEIGHT_GTE)
    uint32_t nBitsOperand; // DIFF_*: compact target to compare against
    int64_t timeOperand;   // MTP_GTE: unix time threshold

    // TX_CONFIRMED (0x05) — "a BTC tx paying >= amountOperand to targetScript,
    // included at btcHeight (Merkle-proved) with >= minDepth confirmations".
    // targetScript/amountOperand/minDepth are committed in the covenant script;
    // rawBtcTx/merkleProof/txIndex/btcHeight come from the spender's witness.
    std::vector<uint8_t> targetScript;  // exact BTC scriptPubKey to be paid
    int64_t amountOperand;              // min total satoshis paid to targetScript (>= 1)
    uint32_t minDepth;                  // min confirmations (>= 1)
    uint32_t txIndex;                   // position of the tx in its BTC block
    std::vector<uint8_t> merkleProof;   // concatenated 32-byte sibling hashes, leaf -> root
    std::vector<uint8_t> rawBtcTx;      // the BTC tx, strict Bitcoin serialization

    BtcStateQuery() : qtype(0), btcHeight(0), nBitsOperand(0), timeOperand(0),
                      amountOperand(0), minDepth(0), txIndex(0) {}
};

/** Evaluator signature: return true iff the fact holds (fail closed). */
typedef bool (*BtcStateProviderFn)(const BtcStateQuery& query);

/** Install the evaluator (node init: real provider; tests: mock).
 *  Passing nullptr uninstalls (queries then evaluate false). */
void SetBtcStateProvider(BtcStateProviderFn fn);

/** Evaluate a query through the installed provider (false if none). */
bool EvalBtcStateQuery(const BtcStateQuery& query);

#endif // BATHRON_SCRIPT_BTCSTATE_H
