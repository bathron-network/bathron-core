// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCHEADERS_H
#define BATHRON_BTCHEADERS_H

#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "hash.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "serialize.h"
#include "uint256.h"

#include <string>
#include <vector>

class CBlockIndex;
class CValidationState;

/**
 * BP-SPVMNPUB: On-chain BTC Header Publication
 *
 * This module implements TX_BTC_HEADERS, which allows masternodes to publish
 * Bitcoin headers on-chain, making BTC header availability a consensus property.
 *
 * CRITICAL: Validation order must check R7 (count/size) BEFORE accessing headers[0].
 */

// Limits (from BP-SPVMNPUB spec)
// NOTE: Validation limit is 1000 for backwards compatibility with existing chain.
// However, publishing should use BTCHEADERS_DEFAULT_COUNT (100) because
// MAX_SPECIALTX_EXTRAPAYLOAD is 10KB and 1000*80=80KB exceeds that.
static const uint16_t BTCHEADERS_MAX_COUNT = 1000;          // Max headers per TX (validation limit)
static const uint16_t BTCHEADERS_DEFAULT_COUNT = 100;       // Default for publishing (fits 10KB)
static const size_t BTCHEADERS_MAX_PAYLOAD_SIZE = 500000;   // Max payload bytes (~500KB, covers genesis with up to ~6000 headers)
static const uint8_t BTCHEADERS_VERSION = 1;                // Current payload version

// Anti-spam: Publisher cooldown (blocks)
// Same MN cannot publish twice within this many blocks, UNLESS sync is behind
// This prevents monopolization while allowing rapid catch-up when needed
static const int BTCHEADERS_PUBLISHER_COOLDOWN = 3;

// Signet-default FALLBACK genesis checkpoint only. The authoritative, NETWORK-AWARE
// value comes from g_btc_spv->GetGenesisCheckpoint() (mainnet 800000 / signet 286000) —
// callers must use that, not this const. Kept as a compile-time default for the rare
// path where btcspv is unavailable. (Signet: BEFORE first burn 286326 for clean discovery.)
static const uint32_t BTCHEADERS_GENESIS_CHECKPOINT = 286000;

// Max headers per genesis/bootstrap TX_BTC_HEADERS chunk.
// Capped so the serialized payload (count*80 + ~40) stays under
// BTCHEADERS_MAX_PAYLOAD_SIZE (500000) — 8000*80=640KB exceeded it and was
// rejected "bad-txns-payload-oversize". 6000*80=480KB fits with margin.
static const uint16_t BTCHEADERS_GENESIS_MAX_COUNT = 6000;

// Max headers seeded into a SINGLE bootstrap block (across several chunk txs).
// The genesis seed (checkpoint -> BTC tip) grows unbounded; one block is capped
// at MAX_BLOCK_SIZE (2MB). Seed at most this many headers per block (~1.44MB of
// header data) and let the catch-up blocks stream the rest from btcheadersdb.tip.
static const uint32_t MAX_GENESIS_HEADERS_PER_BLOCK = 18000;

// ============================================================================
// BtcHeadersPayload - Payload for TX_BTC_HEADERS (type 33)
// ============================================================================

/**
 * BtcHeadersPayload - Payload for TX_BTC_HEADERS transactions.
 *
 * Allows registered masternodes to publish BTC headers on-chain.
 * Headers become consensus data, eliminating manual SPV sync.
 *
 * Anti-spam: MN-only + signature + extend-tip-only + max-1-per-block + mempool policy
 */
struct BtcHeadersPayload
{
    static const uint8_t CURRENT_VERSION = BTCHEADERS_VERSION;
    static constexpr int16_t SPECIALTX_TYPE = CTransaction::TxType::TX_BTC_HEADERS;

    uint8_t nVersion{CURRENT_VERSION};

    // Publisher identity (must be registered MN)
    uint256 publisherProTxHash;

    // First header height (must be tipHeight + 1)
    uint32_t startHeight{0};

    // Number of headers (1-1000)
    uint16_t count{0};

    // BTC headers (80 bytes each)
    std::vector<BtcBlockHeader> headers;

    // ECDSA signature over payload (operator key + BTCHDR domain sep)
    // Excludes sig itself from the signed message
    std::vector<uint8_t> sig;

    SERIALIZE_METHODS(BtcHeadersPayload, obj)
    {
        READWRITE(obj.nVersion);
        READWRITE(obj.publisherProTxHash);
        READWRITE(obj.startHeight);
        READWRITE(obj.count);
        READWRITE(obj.headers);
        if (!(s.GetType() & SER_GETHASH)) {
            READWRITE(obj.sig);
        }
    }

    /**
     * Get the hash to be signed by the MN operator.
     * Uses "BTCHDR" domain separation tag to prevent cross-protocol replay.
     */
    uint256 GetSignatureHash() const;

    /**
     * Verify the ECDSA signature using the MN's operator key.
     * CRITICAL: The key must match publisherProTxHash (anti-spoof).
     */
    bool VerifySignature() const;

    /**
     * Basic validation (version, count, size, count matches headers.size()).
     * Does NOT check MN validity, signature, or chain state.
     */
    bool IsTriviallyValid(std::string& strError) const;

    /**
     * Get the canonical serialized size of this payload.
     * Used for the 2048 byte limit check.
     */
    size_t GetSerializedSize() const;

    std::string ToString() const;
};

// ============================================================================
// Validation Functions
// ============================================================================

/**
 * Extract BtcHeadersPayload from a transaction.
 * Returns false if extraction fails.
 */
bool GetBtcHeadersPayload(const CTransaction& tx, BtcHeadersPayload& payload);

/**
 * Check TX_BTC_HEADERS consensus rules (R1-R7).
 *
 * CRITICAL: R7 (count/size) is checked FIRST before accessing headers[0].
 *
 * @param tx          The transaction to validate
 * @param pindexPrev  The previous block index (nullptr for no-context check)
 * @param state       Validation state for error reporting
 * @return true if valid, false otherwise with state set to error
 */
bool CheckBtcHeadersTx(const CTransaction& tx,
                       const CBlockIndex* pindexPrev,
                       CValidationState& state);

// ============================================================================
// Block Processing Functions
// ============================================================================

/**
 * Process TX_BTC_HEADERS in a block (called from ProcessSpecialTxsInBlock).
 * Writes headers to the batch for atomic commit.
 * Also tracks the publisher for anti-spam cooldown.
 *
 * @param tx              The TX_BTC_HEADERS transaction
 * @param batch           The btcheadersdb batch to write to
 * @param bathronBlockHeight The BATHRON block height (for publisher tracking)
 * @return true on success
 */
bool ProcessBtcHeadersTxInBlock(const CTransaction& tx,
                                btcheadersdb::CBtcHeadersDB::Batch& batch,
                                int bathronBlockHeight);

/**
 * Disconnect TX_BTC_HEADERS during BATHRON reorg.
 * Erases headers and restores previous tip.
 *
 * @param tx                 The TX_BTC_HEADERS transaction
 * @param batch              The btcheadersdb batch to write to
 * @param bathronBlockHeight The BATHRON block height being disconnected
 * @return true on success
 */
bool DisconnectBtcHeadersTx(const CTransaction& tx,
                            btcheadersdb::CBtcHeadersDB::Batch& batch,
                            int bathronBlockHeight);

/**
 * P1 mempool policy decision: may a candidate TX_BTC_HEADERS replace the
 * incumbent in the single-slot mempool? Returns true iff the candidate reaches
 * a STRICTLY higher resulting BTC tip (startHeight + count - 1).
 *
 * Both payloads are assumed to have already passed CheckBtcHeadersTx (a valid
 * tip-extension or a heavier work-based reorg) — that check runs before P1 in
 * AcceptToMemoryPool, so anything reaching here connects to the chain.
 *
 * Comparing on the resulting tip rather than raw header `count` correctly
 * prefers the furthest-reaching publication even when publishers start at
 * different heights (notably reorg publications that start below the tip), and
 * not replacing on an equal tip removes the old equal-count/smaller-txid
 * tie-break that let an attacker grind a txid to evict + re-relay an
 * equal-progress publication (relay churn).
 */
bool BtcHeadersCandidateReplaces(uint32_t candStartHeight, uint16_t candCount,
                                 uint32_t incumbentStartHeight, uint16_t incumbentCount);

#endif // BATHRON_BTCHEADERS_H
