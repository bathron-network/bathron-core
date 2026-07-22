// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "burnclaim/burnclaim.h"   // R2: GetHighestFinalizedBtcHeight()
#include "script/btcstate.h"     // R7: BTCSTATE_REORG_MARGIN (A1)

#include <algorithm>
#include <vector>

#include "chainparams.h"
#include "consensus/validation.h"
#include "masternode/deterministicmns.h"
#include "hash.h"
#include "logging.h"
#include "primitives/transaction.h"
#include "tinyformat.h"
#include "util/system.h"
#include "validation.h"

// ============================================================================
// BtcHeadersPayload Implementation
// ============================================================================

// Static member definition (required for ODR-use in C++11/14)
const uint8_t BtcHeadersPayload::CURRENT_VERSION;

uint256 BtcHeadersPayload::GetSignatureHash() const
{
    // Domain separation: "BTCHDR" prevents cross-protocol replay
    // Message format: "BTCHDR" || version || publisherProTxHash || startHeight || count || headers
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("BTCHDR");  // 6 bytes domain tag
    ss << nVersion;
    ss << publisherProTxHash;
    ss << startHeight;
    ss << count;
    for (const auto& h : headers) {
        ss << h;
    }
    return ss.GetHash();
}

bool BtcHeadersPayload::VerifySignature() const
{
    // Get MN from DMN manager (use GetListAtChainTip().GetMN())
    auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(publisherProTxHash);
    if (!dmn) {
        return false;
    }

    // Verify signature using operator public key
    // CRITICAL: Key must match publisherProTxHash (anti-spoof)
    uint256 hash = GetSignatureHash();
    return dmn->pdmnState->pubKeyOperator.Verify(hash, sig);
}

bool BtcHeadersPayload::IsTriviallyValid(std::string& strError) const
{
    // Version check
    if (nVersion != CURRENT_VERSION) {
        strError = strprintf("invalid version %d (expected %d)", nVersion, CURRENT_VERSION);
        return false;
    }

    // R7: Count range check (1..BTCHEADERS_MAX_COUNT)
    if (count < 1 || count > BTCHEADERS_MAX_COUNT) {
        strError = strprintf("invalid count %d (must be 1-%d)", count, BTCHEADERS_MAX_COUNT);
        return false;
    }

    // R7: Count must match headers vector size
    if (headers.size() != count) {
        strError = strprintf("count %d != headers.size() %zu", count, headers.size());
        return false;
    }

    // R7: Payload size check
    if (GetSerializedSize() > BTCHEADERS_MAX_PAYLOAD_SIZE) {
        strError = strprintf("payload size %zu exceeds max %zu",
                             GetSerializedSize(), BTCHEADERS_MAX_PAYLOAD_SIZE);
        return false;
    }

    // Publisher proTxHash must not be null
    if (publisherProTxHash.IsNull()) {
        strError = "publisherProTxHash is null";
        return false;
    }

    // Signature must not be empty
    if (sig.empty()) {
        strError = "signature is empty";
        return false;
    }

    return true;
}

size_t BtcHeadersPayload::GetSerializedSize() const
{
    // 1 (version) + 32 (proTxHash) + 4 (startHeight) + 1 (count) +
    // count * 80 (headers) + sig.size() + varint overhead
    size_t baseSize = 1 + 32 + 4 + 1 + (headers.size() * 80);
    // Add signature size + varint for sig length
    baseSize += sig.size() + GetSizeOfCompactSize(sig.size());
    return baseSize;
}

std::string BtcHeadersPayload::ToString() const
{
    return strprintf("BtcHeadersPayload(version=%d, publisher=%s, start=%u, count=%d)",
                     nVersion,
                     publisherProTxHash.ToString().substr(0, 16),
                     startHeight,
                     count);
}

// ============================================================================
// Payload Extraction
// ============================================================================

bool GetBtcHeadersPayload(const CTransaction& tx, BtcHeadersPayload& payload)
{
    if (tx.nType != CTransaction::TxType::TX_BTC_HEADERS) {
        return false;
    }
    if (!tx.IsSpecialTx() || !tx.hasExtraPayload()) {
        return false;
    }
    try {
        CDataStream ds(*tx.extraPayload, SER_NETWORK, PROTOCOL_VERSION);
        ds >> payload;
        return ds.empty();  // Must consume all bytes
    } catch (const std::exception& e) {
        return false;
    }
}

// ============================================================================
// Consensus Validation (R1-R7)
// ============================================================================

// F3 (BP-BTCHEADERS-REORG): median-time-past of the 11 BTC headers preceding the
// payload header at `idx`, mixing in-payload headers and consensus btcheadersdb
// ancestors. Deterministic (no wall clock). Returns false if no ancestor exists.
static bool BtcMtpBefore(const BtcHeadersPayload& payload, size_t idx, uint32_t& mtpOut)
{
    std::vector<int64_t> t;
    for (long j = (long)idx - 1; j >= 0 && t.size() < 11; j--) {
        t.push_back(payload.headers[j].nTime);
    }
    if (payload.startHeight > 0) {
        uint32_t h = payload.startHeight - 1;
        while (t.size() < 11) {
            BtcBlockHeader hdr;
            if (!g_btcheadersdb || !g_btcheadersdb->GetHeaderByHeight(h, hdr)) break;
            t.push_back(hdr.nTime);
            if (h == 0) break;
            h--;
        }
    }
    if (t.empty()) return false;
    std::sort(t.begin(), t.end());
    mtpOut = (uint32_t)t[t.size() / 2];
    return true;
}

bool CheckBtcHeadersTx(const CTransaction& tx,
                       const CBlockIndex* pindexPrev,
                       CValidationState& state)
{
    // Extract payload
    BtcHeadersPayload payload;
    if (!GetBtcHeadersPayload(tx, payload)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-payload");
    }

    // Genesis/Bootstrap: TX_BTC_HEADERS carries BTC headers from checkpoint.
    // No MNs registered yet, so skip R1 (MN check), R2 (signature), anti-spam.
    // pindexPrev==nullptr when called from CheckBlock (non-contextual)
    // pindexPrev->nHeight==0 when called contextually for block 1
    // Bootstrap heights (1..nDMMBootstrapHeight): also allow unsigned headers
    // (needed when btcspv backup is incomplete and requires multi-block catch-up)
    bool isGenesisBlock = (!pindexPrev || pindexPrev->nHeight == 0);
    bool isBootstrapBlock = (pindexPrev &&
                             (uint32_t)(pindexPrev->nHeight + 1) <= (uint32_t)Params().GetConsensus().nDMMBootstrapHeight);
    bool skipMNChecks = isGenesisBlock || isBootstrapBlock;

    // R7: Trivial validation FIRST (count, size, count==headers.size())
    // Genesis/Bootstrap allows higher count (BTCHEADERS_GENESIS_MAX_COUNT)
    {
        if (payload.nVersion != BTCHEADERS_VERSION) {
            return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-version");
        }
        uint16_t maxCount = skipMNChecks ? BTCHEADERS_GENESIS_MAX_COUNT : BTCHEADERS_MAX_COUNT;
        if (payload.count < 1 || payload.count > maxCount) {
            LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS invalid count %d (max=%d, skipMN=%d)\n",
                     payload.count, maxCount, skipMNChecks);
            return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-count");
        }
        if (payload.headers.size() != payload.count) {
            return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-count-mismatch");
        }
        if (payload.GetSerializedSize() > BTCHEADERS_MAX_PAYLOAD_SIZE) {
            return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-size");
        }
        // Genesis/Bootstrap: allow null publisher and empty sig (no MNs yet)
        if (!skipMNChecks) {
            if (payload.publisherProTxHash.IsNull()) {
                return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-null-publisher");
            }
            if (payload.sig.empty()) {
                return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-empty-sig");
            }
        }
    }

    if (!skipMNChecks) {
        // R1: Publisher must be registered MN
        auto dmn = deterministicMNManager->GetListAtChainTip().GetMN(payload.publisherProTxHash);
        if (!dmn) {
            LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS unknown MN: %s\n",
                     payload.publisherProTxHash.ToString());
            return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-unknown-mn");
        }

        // R2: Valid signature (operator key + BTCHDR domain sep)
        if (!payload.VerifySignature()) {
            LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS invalid signature from %s\n",
                     payload.publisherProTxHash.ToString());
            return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-sig");
        }
    } else {
        LogPrintf("TX_BTC_HEADERS: Genesis/bootstrap block - skipping R1/R2 (no MNs yet)\n");
    }

    // Anti-spam: Publisher cooldown check (skip for genesis/bootstrap)
    // Same MN cannot publish twice within BTCHEADERS_PUBLISHER_COOLDOWN blocks
    // EXCEPTION: If sync is behind (btcspv > btcheadersdb), allow rapid catch-up
    if (!skipMNChecks && pindexPrev && g_btcheadersdb) {
        uint256 lastPublisher;
        int lastPublishHeight = 0;
        if (g_btcheadersdb->GetLastPublisher(lastPublisher, lastPublishHeight)) {
            int currentHeight = pindexPrev->nHeight + 1;  // Block being validated
            int blocksSinceLastPublish = currentHeight - lastPublishHeight;

            if (lastPublisher == payload.publisherProTxHash &&
                blocksSinceLastPublish < BTCHEADERS_PUBLISHER_COOLDOWN) {
                // Same publisher within cooldown - check if sync is behind
                // Two ways to determine this:
                // 1. If we have SPV: check if spvTip > headersTip
                // 2. Without SPV: if TX's startHeight == tipHeight+1, we need these headers
                uint32_t headersTip = g_btcheadersdb->GetTipHeight();
                bool syncBehind = false;

                // Method 1: SPV-based check (if available)
                if (g_btc_spv) {
                    uint32_t spvTip = g_btc_spv->GetTipHeight();
                    syncBehind = (spvTip > headersTip + payload.count);
                }

                // Method 2: TX-based check (always works)
                // If this TX starts right after our tip, we clearly need it for catch-up
                if (!syncBehind && payload.startHeight == headersTip + 1) {
                    syncBehind = true;
                    LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS: cooldown bypassed (startHeight=%u == tipHeight+1=%u)\n",
                             payload.startHeight, headersTip + 1);
                }

                if (!syncBehind) {
                    // Not catching up - enforce cooldown
                    LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS publisher %s in cooldown (%d blocks since last)\n",
                             payload.publisherProTxHash.ToString().substr(0, 16), blocksSinceLastPublish);
                    return state.DoS(10, false, REJECT_INVALID, "btcheaders-publisher-cooldown");
                }
            }
        }
    }

    // Context-dependent checks (R3-R6)
    // Only if we have pindexPrev and btcheadersdb is initialized
    if (pindexPrev && g_btcheadersdb) {
        uint32_t tipHeight;
        uint256 tipHash;

        if (g_btcheadersdb->GetTip(tipHeight, tipHash)) {
            // BP-BTCHEADERS-HARDENING (#3/#5): reindex now wipes+rebuilds
            // btcheadersdb in block order, so a block being (re)validated never
            // finds its OWN headers already stored. Therefore headers already
            // present at these heights with IDENTICAL hashes (a full match) means a
            // DUPLICATE TX_BTC_HEADERS re-stating applied headers on the active
            // chain — reject it. Re-applying would clobber the reorg-undo record
            // and move the active tip backward (#3). A match on headers[0] only
            // (partial) is NOT a replay: it must run R3' so a non-heavier branch
            // can't overwrite the tail via the old headers[0]-keyed shortcut (#5).
            uint256 existingHash;
            bool fullMatch = g_btcheadersdb->GetHashAtHeight(payload.startHeight, existingHash);
            for (size_t i = 0; fullMatch && i < payload.headers.size(); i++) {
                uint256 hAt;
                if (!g_btcheadersdb->GetHashAtHeight(payload.startHeight + (uint32_t)i, hAt) ||
                    hAt != payload.headers[i].GetHash()) {
                    fullMatch = false;
                }
            }

            if (fullMatch) {
                LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS: duplicate (headers already on active chain) at %u\n",
                         payload.startHeight);
                return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-duplicate");
            } else {
                // Either an empty slot (new headers) OR a DIFFERING header at an
                // existing height — which is a REORG (BP-BTCHEADERS-REORG), not a
                // replay-mismatch. Run R3/R3': the V2 work-based path decides if the
                // heavier branch wins; the V1 path rejects a non-extend as before.
                // (The old unconditional replay-mismatch rejection here made reorgs
                // — and reindex of reorg blocks, audit F4 — impossible.)
                // R3': BP-BTCHEADERS-REORG. Before activation: extend-tip-only (V1).
                // After: also accept a branch that connects to a known active
                // ancestor AND has strictly more cumulative work (work-based reorg).
                int nHeight = pindexPrev->nHeight + 1;
                bool reorgActive = Params().GetConsensus().IsBtcHeadersReorg(nHeight);

                // Fast path (V1 and V2): a clean extend of the current tip.
                bool isExtend = (payload.startHeight == tipHeight + 1 &&
                                 payload.headers[0].hashPrevBlock == tipHash);

                if (!isExtend && !reorgActive) {
                    // V1: extend-tip-only (no BTC reorg support before activation).
                    if (payload.startHeight != tipHeight + 1) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS startHeight %u != tipHeight+1 (%u)\n",
                                 payload.startHeight, tipHeight + 1);
                        return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-startheight");
                    }
                    if (payload.headers[0].hashPrevBlock != tipHash) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS headers[0].prevBlock != tipHash\n");
                        return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-not-extending-tip");
                    }
                } else if (!isExtend && reorgActive) {
                    // R3' reorg case: must fork from a known ancestor on the active
                    // chain and be strictly heavier than the current tip.
                    if (payload.startHeight == 0) {
                        return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-startheight");
                    }
                    uint256 parentHash;
                    if (!g_btcheadersdb->GetHashAtHeight(payload.startHeight - 1, parentHash) ||
                        parentHash != payload.headers[0].hashPrevBlock) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS reorg: prevBlock not a known active ancestor at %u\n",
                                 payload.startHeight - 1);
                        return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-not-extending-tip");
                    }
                    if (!g_btc_spv) {
                        return state.DoS(0, false, REJECT_INVALID, "btcheaders-no-spv");
                    }
                    // F5: a reorg may not fork at/below a finalized checkpoint.
                    if (payload.startHeight <= g_btc_spv->HighestCheckpointHeight()) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS reorg forks at/below checkpoint (start=%u, cp=%u)\n",
                                 payload.startHeight, g_btc_spv->HighestCheckpointHeight());
                        return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-reorg-below-checkpoint");
                    }
                    // R2: a reorg may not fork at/below the BTC anchor of any
                    // FINALIZED (minted) burn — that would orphan an already-minted
                    // M0 (A4 break). This makes the K-confirmation finalization real:
                    // once a burn is minted, BATHRON refuses to reorg its BTC anchor
                    // away. (PENDING burns are protected separately by re-validation
                    // at finalization.)
                    uint32_t finalFloor = GetHighestFinalizedBtcHeight();
                    if (finalFloor > 0 && payload.startHeight <= finalFloor) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS reorg forks at/below finalized burn (start=%u, floor=%u)\n",
                                 payload.startHeight, finalFloor);
                        return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-reorg-below-finalized-burn");
                    }
                    // R7 (A1, gate UPGRADE_BTCSTATE): bound reorg depth so the
                    // region at tip - BTCSTATE_REORG_MARGIN and below is
                    // consensus-IMMUTABLE — OP_BTCSTATEVERIFY reads only under
                    // that floor, which makes script validity monotone.
                    // Trade-off (same family as R2, cf. mainnet checklist §3b):
                    // a genuine BTC reorg deeper than the margin (never observed
                    // on mainnet; 144 blocks ≈ 1 day) wedges the header chain
                    // pending manual intervention, rather than silently
                    // invalidating settled contracts.
                    if (Params().GetConsensus().IsBtcState(nHeight) &&
                        tipHeight >= BTCSTATE_REORG_MARGIN &&
                        payload.startHeight <= tipHeight - BTCSTATE_REORG_MARGIN) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS reorg too deep (start=%u, tip=%u, margin=%u)\n",
                                 payload.startHeight, tipHeight, BTCSTATE_REORG_MARGIN);
                        return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-reorg-too-deep");
                    }
                    arith_uint256 parentWork, tipWork;
                    if (!g_btcheadersdb->GetOrComputeChainWork(payload.startHeight - 1, parentWork) ||
                        !g_btcheadersdb->GetOrComputeChainWork(tipHeight, tipWork)) {
                        return state.DoS(0, false, REJECT_INVALID, "btcheaders-work-unavailable");
                    }
                    arith_uint256 branchWork = parentWork;
                    for (const auto& hdr : payload.headers) {
                        branchWork += g_btc_spv->GetBlockProof(hdr);
                    }
                    // Strictly heavier only (anti-grief: stale/sidechain can't move the tip).
                    if (!(branchWork > tipWork)) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS reorg not heavier: branch=%s tip=%s\n",
                                 branchWork.GetHex(), tipWork.GetHex());
                        return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-not-heavier");
                    }
                    LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS reorg accepted at start=%u (heavier branch)\n",
                             payload.startHeight);
                }
            }
        } else {
            // Empty DB - first headers submission.
            // F6: the ANCHOR chunk (startHeight == genesisCheckpoint+1) must build
            // on the genesis checkpoint hash, pinning the seed to the real BTC
            // chain and preventing a malicious bootstrap from injecting an
            // arbitrary chain. The genesis seed is split into several chunk txs,
            // ALL validated against the still-empty btcheadersdb (processing runs
            // after validation), so continuation chunks (startHeight > checkpoint+1)
            // also reach this branch — they are NOT the anchor and skip F6 here;
            // they remain subject to R4 internal chaining + R5 PoW + R6 difficulty
            // below. (Only block-1 genesis ever hits this empty-DB branch.)
            uint32_t gHeight = 0;
            uint256 gHash;
            if (g_btc_spv && g_btc_spv->GetGenesisCheckpoint(gHeight, gHash) &&
                payload.startHeight == gHeight + 1) {
                if (payload.headers[0].hashPrevBlock != gHash) {
                    LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS empty-DB: anchor headers[0] does not build on genesis checkpoint %u\n", gHeight);
                    return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-genesis-binding");
                }
            }
            LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS: btcheadersdb empty, startHeight=%u (anchor=%u)\n",
                     payload.startHeight, gHeight + 1);
        }

        // R4: Internal chaining
        for (size_t i = 1; i < payload.headers.size(); i++) {
            if (payload.headers[i].hashPrevBlock != payload.headers[i-1].GetHash()) {
                LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS broken chain at index %zu\n", i);
                return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-broken-chain");
            }
        }

        // F5: any header landing on a checkpoint height must match the
        // checkpoint hash (prevents a chain diverging at/before a checkpoint).
        if (g_btc_spv) {
            for (size_t i = 0; i < payload.headers.size(); i++) {
                uint32_t hH = payload.startHeight + (uint32_t)i;
                uint256 cpHash;
                if (g_btc_spv->GetCheckpointHash(hH, cpHash) &&
                    payload.headers[i].GetHash() != cpHash) {
                    LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS checkpoint mismatch at h=%u\n", hH);
                    return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-checkpoint");
                }
            }
        }

        // R5: Valid PoW for each header
        // Reuse btcspv CheckProofOfWork (need to make it accessible)
        if (g_btc_spv) {
            for (size_t i = 0; i < payload.headers.size(); i++) {
                const auto& header = payload.headers[i];
                if (!g_btc_spv->CheckProofOfWork(header)) {
                    LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS invalid PoW at index %zu\n", i);
                    return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-pow");
                }
            }

            // R6: Correct difficulty per header (BP-BTCHEADERS-REORG F1).
            // Validates nBits against the expected retarget schedule, reading
            // ancestors from the CONSENSUS btcheadersdb (not local btcspv state).
            // Without this, a malicious MN can publish a difficulty-1 (CPU-mined)
            // fake BTC header committing a fake burn -> forge M0 (breaks A4/A5).
            //
            // BP-BTCHEADERS-HARDENING: difficulty is OBJECTIVE (needs no MN/signature),
            // so it is now enforced even during genesis/bootstrap WHEN the hardcoded
            // genesis checkpoint header is available (it is the difficulty parent for
            // the first seeded header — anchoring it to the real BTC checkpoint instead
            // of trusting the seeder). R1/R2 stay skipped at bootstrap; only R6 is
            // decoupled. Networks with no BTC checkpoint header (regtest) keep the skip.
            //
            // Residual (documented): the genesis seed is split across several
            // TX_BTC_HEADERS, validated before any is processed, so a header whose
            // difficulty parent / retarget period-first lives in an EARLIER seed tx
            // is not yet in btcheadersdb. During bootstrap such cross-tx ancestors are
            // skipped (not rejected) to keep the multi-tx seed valid; the per-tx anchor
            // + intra-tx nBits==parent enforcement still pin difficulty, and any drift
            // is bounded by the 4x/period retarget clamp + the SPV checkpoints. Outside
            // bootstrap the strict (reject-on-missing) behaviour is unchanged.
            bool reorgRuleset = pindexPrev &&
                Params().GetConsensus().IsBtcHeadersReorg(pindexPrev->nHeight + 1);
            bool haveGenesisHeader = g_btc_spv->HasGenesisCheckpointHeader();
            bool enforceDifficulty = reorgRuleset && (!skipMNChecks || haveGenesisHeader);
            if (enforceDifficulty) {
                const bool btcTestnet = Params().IsTestnet();
                const bool bootstrapMode = skipMNChecks;  // skip (don't reject) cross-tx gaps here
                uint32_t gcpHeight = 0; uint256 gcpHash; BtcBlockHeader genesisHdr;
                bool haveGcpHdr = g_btc_spv->GetGenesisCheckpoint(gcpHeight, gcpHash) &&
                                  g_btc_spv->GetGenesisCheckpointHeader(genesisHdr);
                for (size_t i = 0; i < payload.headers.size(); i++) {
                    uint32_t hHeight = payload.startHeight + (uint32_t)i;
                    BtcBlockHeader parent;
                    if (i == 0) {
                        if (!g_btcheadersdb->GetHeaderByHeight(payload.startHeight - 1, parent)) {
                            // Genesis anchor: parent is the hardcoded checkpoint header.
                            if (haveGcpHdr && payload.startHeight == gcpHeight + 1) {
                                parent = genesisHdr;
                            } else if (bootstrapMode || btcTestnet) {
                                continue; // cross-tx seed gap / signet mid-chain: rely on checkpoints
                            } else {
                                return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-difficulty-noparent");
                            }
                        }
                    } else {
                        parent = payload.headers[i - 1];
                    }
                    // Retarget period-first (height-2016): look in THIS payload first
                    // (a large seed isn't in btcheadersdb yet), then btcheadersdb, then
                    // the genesis checkpoint header.
                    const BtcBlockHeader* pFirst = nullptr;
                    BtcBlockHeader firstHdr;
                    if (hHeight % 2016 == 0) {
                        uint32_t fHeight = hHeight - 2016;
                        if (fHeight >= payload.startHeight && (size_t)(fHeight - payload.startHeight) < i) {
                            pFirst = &payload.headers[fHeight - payload.startHeight];
                        } else if (g_btcheadersdb->GetHeaderByHeight(fHeight, firstHdr)) {
                            pFirst = &firstHdr;
                        } else if (haveGcpHdr && fHeight == gcpHeight) {
                            firstHdr = genesisHdr; pFirst = &firstHdr;
                        }
                    }
                    uint32_t expected = g_btc_spv->ExpectedNextBits(hHeight, parent, pFirst);
                    if (expected == 0) {
                        if (bootstrapMode || btcTestnet) continue; // cross-tx period-first gap
                        return state.DoS(50, false, REJECT_INVALID, "bad-btcheaders-difficulty-unverifiable");
                    }
                    if (payload.headers[i].nBits != expected) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS bad difficulty at h=%u: got %08x expected %08x\n",
                                 hHeight, payload.headers[i].nBits, expected);
                        return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-bad-difficulty");
                    }
                    // F3: timestamp must exceed median-time-past (anti-timewarp).
                    // Past-bound only (deterministic); no wall-clock future bound.
                    uint32_t mtp = 0;
                    if (BtcMtpBefore(payload, i, mtp) && payload.headers[i].nTime <= mtp) {
                        LogPrint(BCLog::MASTERNODE, "TX_BTC_HEADERS nTime <= MTP at h=%u\n", hHeight);
                        return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-time");
                    }
                }
            }
        } else {
            // No btcspv - cannot verify PoW/difficulty
            // In production this should fail, but for testing we allow it
            LogPrintf("WARNING: TX_BTC_HEADERS PoW/difficulty not verified (no btcspv)\n");
        }
    }

    return true;
}

// ============================================================================
// Block Processing
// ============================================================================

bool ProcessBtcHeadersTxInBlock(const CTransaction& tx,
                                btcheadersdb::CBtcHeadersDB::Batch& batch,
                                int bathronBlockHeight)
{
    BtcHeadersPayload payload;
    if (!GetBtcHeadersPayload(tx, payload)) {
        return false;
    }

    LogPrint(BCLog::MASTERNODE, "ProcessBtcHeadersTxInBlock: %s start=%u count=%d publisher=%s\n",
             tx.GetHash().ToString().substr(0, 16), payload.startHeight, payload.count,
             payload.publisherProTxHash.ToString().substr(0, 16));

    bool reorgActive = Params().GetConsensus().IsBtcHeadersReorg(bathronBlockHeight);

    if (!reorgActive) {
        // V1 (pre-activation): append-only. Disconnect reconstructs from payload.
        uint32_t h = payload.startHeight;
        for (const auto& header : payload.headers) {
            batch.WriteHeader(h, header);
            h++;
        }
        batch.WriteTip(h - 1, payload.headers.back().GetHash());
        batch.WriteLastPublisher(payload.publisherProTxHash, bathronBlockHeight);
        return true;
    }

    // ── V2 (BP-BTCHEADERS-REORG): reorg-aware connect with chainwork + undo ──
    if (!g_btc_spv || !g_btcheadersdb) {
        return error("ProcessBtcHeadersTxInBlock: SPV/headersdb unavailable for V2 connect");
    }

    const uint32_t startHeight = payload.startHeight;
    const uint32_t newTipHeight = startHeight + payload.count - 1;

    // Prefer the tip pending in THIS batch (an earlier same-block chunk) over the
    // committed DB, so a multi-chunk genesis block accumulates correctly instead of
    // each chunk re-reading the stale committed tip (spv-headers-0).
    uint32_t oldTipHeight = 0;
    uint256 oldTipHash;
    arith_uint256 oldTipWork;
    bool hasTip = batch.GetPendingTip(oldTipHeight, oldTipHash);
    if (hasTip) {
        batch.GetPendingTipWork(oldTipWork); // 0 if unavailable
    } else {
        hasTip = g_btcheadersdb->GetTip(oldTipHeight, oldTipHash);
        if (hasTip) {
            g_btcheadersdb->GetOrComputeChainWork(oldTipHeight, oldTipWork); // 0 if unavailable
        }
    }

    // spv-headers-1: cross-chunk continuity at connect time. A chunk that strictly
    // extends the tip (including an earlier same-block chunk's pending tip) must
    // build header[0] on that tip. At genesis CheckBtcHeadersTx cannot enforce this
    // — continuation chunks are validated against the still-empty committed DB — so
    // a forged/disconnected continuation chunk would otherwise connect. (Reorg/
    // overwrite chunks have startHeight <= oldTipHeight and are validated by R3'.)
    if (hasTip && startHeight == oldTipHeight + 1 &&
        payload.headers[0].hashPrevBlock != oldTipHash) {
        return error("ProcessBtcHeadersTxInBlock: chunk at height %u does not build on "
                     "tip %s (cross-chunk continuity)", startHeight, oldTipHash.ToString());
    }

    // Build undo: capture overwritten active entries [startHeight..oldTipHeight].
    btcheadersdb::CBtcHeadersReorgUndo undo;
    undo.oldTipHeight = oldTipHeight;
    undo.oldTipHash = oldTipHash;
    undo.oldTipWork = ArithToUint256(oldTipWork);
    undo.newTipHeight = newTipHeight;
    if (hasTip && startHeight <= oldTipHeight) {
        for (uint32_t hh = startHeight; hh <= oldTipHeight; hh++) {
            uint256 oh;
            if (!g_btcheadersdb->GetHashAtHeight(hh, oh)) continue;
            arith_uint256 ow;
            g_btcheadersdb->GetOrComputeChainWork(hh, ow); // real work even if 'w' unset
            btcheadersdb::ReplacedHeaderEntry e;
            e.height = hh;
            e.oldHash = oh;
            e.oldWork = ArithToUint256(ow);
            undo.replaced.push_back(e);
        }
    }

    // Parent cumulative work (base for the new branch): prefer the value pending in
    // this batch (an earlier same-block chunk), else the committed DB (spv-headers-0).
    arith_uint256 work;
    if (startHeight > 0 && !batch.GetPendingChainWork(startHeight - 1, work)) {
        g_btcheadersdb->GetOrComputeChainWork(startHeight - 1, work); // 0 if genesis/empty
    }

    // Write the new branch headers + per-height chainwork (overwrites active 'h').
    uint32_t h = startHeight;
    for (const auto& header : payload.headers) {
        batch.WriteHeader(h, header);
        work += g_btc_spv->GetBlockProof(header);
        batch.WriteChainWork(h, work);
        h++;
    }
    // `work` is now chainwork(newTipHeight).

    // Shorter-but-heavier branch: drop active entries above the new tip
    // (keep the append-only 'H' data for undo).
    if (hasTip && oldTipHeight > newTipHeight) {
        for (uint32_t hh = newTipHeight + 1; hh <= oldTipHeight; hh++) {
            batch.EraseHeightIndex(hh);
        }
    }

    batch.WriteTip(newTipHeight, payload.headers.back().GetHash());
    batch.WriteTipWork(work);
    batch.WriteReorgUndo(tx.GetHash(), undo);
    batch.WriteLastPublisher(payload.publisherProTxHash, bathronBlockHeight);

    return true;
}

bool BtcHeadersCandidateReplaces(uint32_t candStartHeight, uint16_t candCount,
                                 uint32_t incumbentStartHeight, uint16_t incumbentCount)
{
    // count is >= 1 for any CheckBtcHeadersTx-valid payload; guard against 0 anyway.
    const uint64_t candTip =
        static_cast<uint64_t>(candStartHeight) + (candCount ? candCount - 1u : 0u);
    const uint64_t incumbentTip =
        static_cast<uint64_t>(incumbentStartHeight) + (incumbentCount ? incumbentCount - 1u : 0u);
    return candTip > incumbentTip;
}

bool DisconnectBtcHeadersTx(const CTransaction& tx,
                            btcheadersdb::CBtcHeadersDB::Batch& batch,
                            int bathronBlockHeight)
{
    BtcHeadersPayload payload;
    if (!GetBtcHeadersPayload(tx, payload)) {
        return false;
    }

    LogPrint(BCLog::MASTERNODE, "DisconnectBtcHeadersTx: %s start=%u count=%d height=%d\n",
             tx.GetHash().ToString().substr(0, 16), payload.startHeight, payload.count,
             bathronBlockHeight);

    // V2 (BP-BTCHEADERS-REORG): if reorg undo was recorded at connect, restore
    // the prior active-chain index + tip exactly (handles reorgs, not just appends).
    btcheadersdb::CBtcHeadersReorgUndo undo;
    if (g_btcheadersdb && g_btcheadersdb->ReadReorgUndo(tx.GetHash(), undo)) {
        // 1. Erase the purely-new active heights (oldTip+1 .. newTip).
        for (uint32_t hh = undo.oldTipHeight + 1; hh <= undo.newTipHeight; hh++) {
            batch.EraseHeightIndex(hh);
        }
        // 2. Restore overwritten active entries (pointer + chainwork).
        for (const auto& e : undo.replaced) {
            batch.WriteHeightIndex(e.height, e.oldHash);
            batch.WriteChainWork(e.height, UintToArith256(e.oldWork));
        }
        // 3. Restore tip + tip chainwork.
        batch.WriteTip(undo.oldTipHeight, undo.oldTipHash);
        batch.WriteTipWork(UintToArith256(undo.oldTipWork));
        // 4. Drop the undo record.
        batch.EraseReorgUndo(tx.GetHash());
        return true;
    }

    // No undo record. For a block at/after the V2 reorg activation, the connect
    // path (ProcessBtcHeadersTxInBlock) always writes a reorg-undo record, so its
    // absence here means DB corruption or a logic bug — the V1 truncate below would
    // silently mangle the active index. Hard-error instead (R5). The legacy truncate
    // remains valid ONLY for genuinely pre-activation (append-only) blocks.
    if (Params().GetConsensus().IsBtcHeadersReorg(bathronBlockHeight)) {
        return error("DisconnectBtcHeadersTx: missing reorg-undo for post-activation "
                     "tx %s at height %d (btcheadersdb corrupt)",
                     tx.GetHash().ToString(), bathronBlockHeight);
    }

    // V1 (pre-activation block): legacy truncate (these heights were new appends).
    uint32_t revertToHeight = payload.startHeight - 1;
    uint256 prevHash = payload.headers[0].hashPrevBlock;
    for (size_t i = 0; i < payload.headers.size(); i++) {
        uint32_t h = payload.startHeight + i;
        uint256 hash = payload.headers[i].GetHash();
        batch.EraseHeader(h, hash);
    }
    batch.WriteTip(revertToHeight, prevHash);

    return true;
}
