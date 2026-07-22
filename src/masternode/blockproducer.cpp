// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "masternode/blockproducer.h"

#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "logging.h"
#include "pubkey.h"

#include <algorithm>

namespace mn_consensus {

// Maximum fallback slots before we clamp (1 hour / fallbackWindow)
// Prevents integer overflow and limits how long we wait for any single producer
static const int MAX_FALLBACK_SLOTS = 360;  // 360 * 10s = 1 hour

arith_uint256 ComputeMNBlockScore(const uint256& prevBlockHash, int nHeight, const uint256& proTxHash)
{
    // score = SHA256(prevBlockHash || height || proTxHash)
    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    ss << prevBlockHash;
    ss << nHeight;
    ss << proTxHash;
    return UintToArith256(ss.GetHash());
}

/**
 * Calculate the producer slot from block header data.
 *
 * Pure function - depends only on block data for consensus determinism.
 *
 * Reference: minBlockTime = prevTime + nTargetSpacing
 * - Slot 0: blockTime in [minBlockTime, minBlockTime + leaderTimeout)
 * - Slot N: blockTime in [minBlockTime + leaderTimeout + (N-1)*fallbackWindow, ...)
 *
 * @param pindexPrev  Previous block index
 * @param nBlockTime  Block timestamp
 * @return            Producer slot (0 = primary, 1+ = fallback)
 */
int GetProducerSlot(const CBlockIndex* pindexPrev, int64_t nBlockTime)
{
    if (!pindexPrev) {
        return 0;
    }

    const Consensus::Params& consensus = Params().GetConsensus();

    // NOTE (multi-operator liveness fix): we no longer force slot 0 during the
    // bootstrap height range. The slot-0 force froze multi-operator chains at the
    // bootstrap→DMM handoff: with no fallback, if the deterministic slot-0 producer's
    // node didn't produce, no other node could take over (single-operator masked this
    // because Seed holds every MN and is always the slot-0 producer). Bootstrap-mined
    // blocks (generatebootstrap) don't pass through this — they're exempt from the
    // producer/signature check in validation — so allowing fallback here is safe and
    // only affects DMM-scheduler blocks, which now recover via the normal fallback
    // path below (slot 0 within the leader window, slot>0 after leaderTimeout).
    int64_t prevTime = pindexPrev->GetBlockTime();

    // minBlockTime = earliest valid block time (same reference as scheduler)
    // dt = time elapsed since minBlockTime
    int64_t minBlockTime = prevTime + consensus.nTargetSpacing;
    int64_t dt = nBlockTime - minBlockTime;

    // Debug logging for slot calculation
    LogPrint(BCLog::MASTERNODE, "DMM-SLOT: prevTime=%d, nBlockTime=%d, minBlockTime=%d, dt=%d\n",
             prevTime, nBlockTime, minBlockTime, dt);

    // Block before minBlockTime: treat as primary (slot 0)
    // This handles blocks that arrive slightly early due to clock drift
    if (dt < 0) {
        return 0;
    }

    // Within leader timeout window = primary producer (slot 0)
    // Block in [minBlockTime, minBlockTime + leaderTimeout)
    if (dt < consensus.nHuLeaderTimeoutSeconds) {
        return 0;
    }

    // Past leader timeout = calculate fallback slot
    // Fallback windows start at minBlockTime + leaderTimeout
    int64_t extra = dt - consensus.nHuLeaderTimeoutSeconds;
    int slot = 1 + (int)(extra / consensus.nHuFallbackRecoverySeconds);

    // Clamp to max fallback slots
    if (slot > MAX_FALLBACK_SLOTS) {
        slot = MAX_FALLBACK_SLOTS;
    }

    LogPrint(BCLog::MASTERNODE, "DMM-SLOT: Calculated slot=%d (extra=%d, fallbackWindow=%d)\n",
             slot, extra, consensus.nHuFallbackRecoverySeconds);

    return slot;
}

/**
 * Get the expected block producer based on block header data.
 *
 * This function uses GetProducerSlot() to determine which MN should have
 * produced this block. The result is deterministic and identical on all nodes.
 *
 * IMPORTANT: This function is used BOTH by:
 * 1. The scheduler (to check if local MN should produce)
 * 2. Verification (to check if signature matches expected producer)
 *
 * @param pindexPrev     Previous block index
 * @param nBlockTime     Block timestamp
 * @param mnList         DMN list at pindexPrev
 * @param outMn          [out] Expected producer MN
 * @param outProducerIndex [out] Producer index (0 = primary, 1+ = fallback)
 * @return               true if producer found
 */
bool GetExpectedProducer(const CBlockIndex* pindexPrev,
                         int64_t nBlockTime,
                         const CDeterministicMNList& mnList,
                         CDeterministicMNCPtr& outMn,
                         int& outProducerIndex)
{
    outMn = nullptr;
    outProducerIndex = 0;

    if (!pindexPrev) {
        return false;
    }

    auto scores = CalculateBlockProducerScores(pindexPrev, mnList);
    if (scores.empty()) {
        LogPrint(BCLog::MASTERNODE, "%s: No confirmed MNs for block %d\n",
                 __func__, pindexPrev->nHeight + 1);
        return false;
    }

    int slot = GetProducerSlot(pindexPrev, nBlockTime);
    outProducerIndex = slot % (int)scores.size();  // Wrap around using modulo
    outMn = scores[outProducerIndex].second;

    if (outProducerIndex > 0) {
        LogPrint(BCLog::MASTERNODE, "%s: Block %d expected producer #%d: %s (slot=%d, nTime=%d)\n",
                 __func__, pindexPrev->nHeight + 1, outProducerIndex,
                 outMn->proTxHash.ToString().substr(0, 16), slot, nBlockTime);
    }

    return true;
}

std::vector<int> ComputeMissedProducerIndices(int producerSlot, int numScores)
{
    std::vector<int> missed;
    if (numScores <= 0 || producerSlot <= 0) {
        return missed;
    }
    const int winner = producerSlot % numScores;     // matches scores[slot % n] selection
    std::vector<bool> seen(numScores, false);
    for (int s = 0; s < producerSlot; s++) {
        const int idx = s % numScores;
        if (idx == winner) continue;                 // the actual producer did not miss
        if (seen[idx]) continue;                     // penalize each missed MN at most once
        seen[idx] = true;
        missed.push_back(idx);
    }
    return missed;
}

bool ShouldSkipPoSePunishment(int64_t dtSincePrev, int64_t nStaleTimeout, size_t nMissed, size_t nProducers)
{
    // Chain-wide outage recovery: the gap itself proves the network (not an
    // individual MN) was down. Mirrors the finality cold-start bypass.
    if (nStaleTimeout > 0 && dtSincePrev > nStaleTimeout) {
        return true;
    }
    if (nProducers == 0) {
        return true;  // nothing sensible to punish against
    }
    // Breadth cap: punishing > ceil(N/3) MNs in ONE block contradicts the < 1/3
    // BFT fault assumption — treat as network turbulence.
    const size_t maxIndividualFaults = (nProducers + 2) / 3;  // ceil(N/3)
    return nMissed > maxIndividualFaults;
}

std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>>
CalculateBlockProducerScores(const CBlockIndex* pindexPrev, const CDeterministicMNList& mnList)
{
    std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>> scores;

    if (!pindexPrev) {
        return scores;
    }

    const uint256& prevBlockHash = pindexPrev->GetBlockHash();
    const int nHeight = pindexPrev->nHeight + 1;

    scores.reserve(mnList.GetValidMNsCount());

    const Consensus::Params& consensus = Params().GetConsensus();

    // Only valid (non-PoSe-banned), confirmed MNs
    mnList.ForEachMN(true /* onlyValid */, [&](const CDeterministicMNCPtr& dmn) {
        // BATHRON: MNs registered during bootstrap phase are trusted and don't need confirmedHash
        // This solves the chicken-and-egg problem: bootstrap MNs must produce blocks,
        // but they can't be confirmed until subsequent blocks are mined.
        // Bootstrap phase = height <= nDMMBootstrapHeight (header catch-up, burn claims/mint, ProRegTx blocks)
        bool isBootstrapMN = (dmn->pdmnState->nRegisteredHeight <= consensus.nDMMBootstrapHeight);

        // Skip unconfirmed MNs (prevents hash grinding), EXCEPT bootstrap MNs
        if (!isBootstrapMN && dmn->pdmnState->confirmedHash.IsNull()) {
            return;
        }

        arith_uint256 score = ComputeMNBlockScore(prevBlockHash, nHeight, dmn->proTxHash);
        scores.emplace_back(score, dmn);
    });

    // Sort descending by score
    std::sort(scores.begin(), scores.end(),
        [](const auto& a, const auto& b) {
            if (a.first == b.first) {
                // Tie-breaker: proTxHash lexicographically
                return a.second->proTxHash < b.second->proTxHash;
            }
            return a.first > b.first;
        });

    return scores;
}

bool GetBlockProducer(const CBlockIndex* pindexPrev,
                      const CDeterministicMNList& mnList,
                      CDeterministicMNCPtr& outMn)
{
    outMn = nullptr;

    if (!pindexPrev) {
        return false;
    }

    auto scores = CalculateBlockProducerScores(pindexPrev, mnList);

    if (scores.empty()) {
        LogPrint(BCLog::MASTERNODE, "%s: No confirmed MNs for block %d\n",
                 __func__, pindexPrev->nHeight + 1);
        return false;
    }

    outMn = scores[0].second;

    LogPrint(BCLog::MASTERNODE, "%s: Block %d producer: %s (score: %s)\n",
             __func__, pindexPrev->nHeight + 1,
             outMn->proTxHash.ToString().substr(0, 16),
             scores[0].first.ToString().substr(0, 16));

    return true;
}

bool SignBlockMNOnly(CBlock& block, const CKey& operatorKey)
{
    if (!operatorKey.IsValid()) {
        return error("%s: Invalid ECDSA operator key\n", __func__);
    }

    // Sign the block hash with ECDSA
    uint256 hashToSign = block.GetHash();
    std::vector<unsigned char> vchSig;
    if (!operatorKey.Sign(hashToSign, vchSig)) {
        return error("%s: ECDSA signing failed\n", __func__);
    }

    block.vchBlockSig = vchSig;

    // Debug: verify signature immediately
    CPubKey pubKey = operatorKey.GetPubKey();
    bool verified = pubKey.Verify(hashToSign, vchSig);

    LogPrintf("%s: Block %s signed with ECDSA (sig size: %d, pubkey: %s, verified: %d)\n",
             __func__, hashToSign.ToString().substr(0, 16), vchSig.size(),
             HexStr(pubKey).substr(0, 32), verified);

    return true;
}

bool VerifyBlockProducerSignature(const CBlock& block,
                                  const CBlockIndex* pindexPrev,
                                  const CDeterministicMNList& mnList,
                                  CValidationState& state)
{
    if (!pindexPrev) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-no-prev");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // I4: STRICT TIMESTAMP VALIDATION - Prevent future timestamp attacks
    // ═══════════════════════════════════════════════════════════════════════════
    // A block with a far-future timestamp could manipulate the fallback slot
    // calculation to make an attacker-controlled MN appear as the expected
    // producer. We reject blocks more than MAX_FUTURE_TIME seconds in the future.
    // ═══════════════════════════════════════════════════════════════════════════
    const int64_t MAX_FUTURE_TIME = 120;  // 2 minutes max future time
    int64_t currentTime = GetTime();
    if (block.nTime > currentTime + MAX_FUTURE_TIME) {
        return state.DoS(10, false, REJECT_INVALID, "bad-mn-time-future", false,
                         strprintf("Block timestamp %d is too far in future (now=%d, max=%d)",
                                   block.nTime, currentTime, currentTime + MAX_FUTURE_TIME));
    }

    // Check signature exists
    if (block.vchBlockSig.empty()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-empty");
    }

    // BATHRON v1: Verify ECDSA signature (typically 70-72 bytes DER encoded)
    if (block.vchBlockSig.size() < 64 || block.vchBlockSig.size() > 73) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-size", false,
                         strprintf("Bad ECDSA sig size: %d", block.vchBlockSig.size()));
    }

    // PROPER CONSENSUS: Use GetExpectedProducer based on block.nTime
    //
    // This is deterministic and uses the SAME formula as the scheduler:
    // - Producer slot is computed from (block.nTime - prevTime)
    // - Slot 0 = primary producer
    // - Slot 1+ = fallback producers
    //
    // The scheduler aligns block.nTime to the slot grid when creating blocks.
    // Verification uses this nTime to determine which MN was expected to sign.
    // This ensures production and verification use IDENTICAL rules.

    CDeterministicMNCPtr expectedMn;
    int producerIndex = 0;

    if (!GetExpectedProducer(pindexPrev, block.nTime, mnList, expectedMn, producerIndex)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-no-producers", false,
                         "No confirmed masternodes for block production");
    }

    // Get operator pubkey (ECDSA)
    const CPubKey& pubKey = expectedMn->pdmnState->pubKeyOperator;
    if (!pubKey.IsValid()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-invalid-key", false,
                         strprintf("Invalid operator key for expected producer %s",
                                   expectedMn->proTxHash.ToString().substr(0, 16)));
    }

    // Verify signature against expected producer
    uint256 hashToVerify = block.GetHash();
    if (!pubKey.Verify(hashToVerify, block.vchBlockSig)) {
        // Log detailed failure info for debugging
        LogPrintf("%s: Signature verification FAILED:\n"
                  "  - Block hash: %s\n"
                  "  - Block nTime: %d\n"
                  "  - PrevBlock time: %d\n"
                  "  - Expected producer #%d: %s\n"
                  "  - Sig size: %d\n",
                  __func__, hashToVerify.ToString().substr(0, 16),
                  block.nTime, pindexPrev->GetBlockTime(),
                  producerIndex, expectedMn->proTxHash.ToString().substr(0, 16),
                  block.vchBlockSig.size());

        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-verify", false,
                         strprintf("ECDSA sig verification failed - expected producer #%d: %s",
                                   producerIndex, expectedMn->proTxHash.ToString().substr(0, 16)));
    }

    // Success!
    if (producerIndex > 0) {
        LogPrintf("%s: Block %s verified (ECDSA), fallback producer #%d: %s\n",
                 __func__, block.GetHash().ToString().substr(0, 16), producerIndex,
                 expectedMn->proTxHash.ToString().substr(0, 16));
    } else {
        LogPrint(BCLog::MASTERNODE, "%s: Block %s verified (ECDSA), primary producer: %s\n",
                 __func__, block.GetHash().ToString().substr(0, 16),
                 expectedMn->proTxHash.ToString().substr(0, 16));
    }

    return true;
}

bool VerifyBlockProducerSignatureWithPoSe(const CBlock& block,
                                          const CBlockIndex* pindexPrev,
                                          const CDeterministicMNList& mnList,
                                          CValidationState& state,
                                          std::vector<uint256>& outSkippedMNs,
                                          int& outProducerIndex)
{
    outSkippedMNs.clear();
    outProducerIndex = 0;

    // First verify the signature using existing logic
    const Consensus::Params& consensus = Params().GetConsensus();

    // Skip during bootstrap phase
    if (pindexPrev->nHeight + 1 <= consensus.nDMMBootstrapHeight) {
        return true;
    }

    // Validate signature size (ECDSA DER format: 70-72 bytes typically)
    if (block.vchBlockSig.size() < 64 || block.vchBlockSig.size() > 73) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-size", false,
                         strprintf("Bad ECDSA sig size: %d", block.vchBlockSig.size()));
    }

    // Get expected producer and index
    CDeterministicMNCPtr expectedMn;
    if (!GetExpectedProducer(pindexPrev, block.nTime, mnList, expectedMn, outProducerIndex)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-no-producers", false,
                         "No confirmed masternodes for block production");
    }

    // Get operator pubkey (ECDSA)
    const CPubKey& pubKey = expectedMn->pdmnState->pubKeyOperator;
    if (!pubKey.IsValid()) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-invalid-key", false,
                         strprintf("Invalid operator key for expected producer %s",
                                   expectedMn->proTxHash.ToString().substr(0, 16)));
    }

    // Verify signature
    uint256 hashToVerify = block.GetHash();
    if (!pubKey.Verify(hashToVerify, block.vchBlockSig)) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-sig-verify", false,
                         strprintf("ECDSA sig verification failed - expected producer #%d: %s",
                                   outProducerIndex, expectedMn->proTxHash.ToString().substr(0, 16)));
    }

    // If fallback was used (producerIndex > 0), collect the skipped MNs for PoSe penalty
    if (outProducerIndex > 0) {
        auto scores = CalculateBlockProducerScores(pindexPrev, mnList);

        // Collect all MNs that were skipped (slots 0 to producerIndex-1)
        for (int i = 0; i < outProducerIndex && i < (int)scores.size(); i++) {
            const auto& skippedMn = scores[i].second;
            outSkippedMNs.push_back(skippedMn->proTxHash);

            LogPrintf("%s: MN %s MISSED production slot #%d for block %d (fallback #%d produced)\n",
                      __func__, skippedMn->proTxHash.ToString().substr(0, 16), i,
                      pindexPrev->nHeight + 1, outProducerIndex);
        }
    }

    return true;
}

} // namespace mn_consensus
