// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/signaling.h"

#include "masternode/activemasternode.h"
#include "chain.h"
#include "chainparams.h"
#include "masternode/deterministicmns.h"
#include "hash.h"
#include "key.h"
#include "logging.h"
#include "netmessagemaker.h"
#include "state/finality.h"
#include "state/metrics.h"
#include "state/quorum.h"
#include "protocol.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "../validation.h"

#include <set>
#include <thread>  // For std::this_thread::sleep_for

namespace hu {

std::unique_ptr<CHuSignalingManager> huSignalingManager;

// ============================================================================
// Initialization
// ============================================================================

void InitHuSignaling()
{
    huSignalingManager = std::make_unique<CHuSignalingManager>();
    LogPrintf("Quorum Signaling: Initialized\n");
}

void ShutdownHuSignaling()
{
    huSignalingManager.reset();
    LogPrintf("Quorum Signaling: Shutdown\n");
}

// ============================================================================
// CHuSignalingManager Implementation
// ============================================================================

bool CHuSignalingManager::OnNewBlock(const CBlockIndex* pindex, CConnman* connman)
{
    if (!pindex || !connman) {
        return false;
    }

    // Only masternodes sign blocks
    if (!fMasterNode || !activeMasternodeManager || !activeMasternodeManager->IsReady()) {
        return false;
    }

    const uint256& blockHash = pindex->GetBlockHash();

    // ═══════════════════════════════════════════════════════════════════════════
    // OPERATOR-BASED FINALITY — VRF sortition
    // ═══════════════════════════════════════════════════════════════════════════
    // - FINALITY: one vote per unique OPERATOR; committee = ECVRF self-selection
    // - NO producer exclusion (removed 2026-06-30): safety comes from the 2/3
    //   operator threshold + full ConnectBlock validation, not from excluding
    //   the producer — see dmn-finality.md §2/§3.5a
    // ═══════════════════════════════════════════════════════════════════════════
    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindex->pprev);

    // NOTE: no artificial pre-sign delay. OnNewBlock runs from NotifyBlockConnected
    // (validation.cpp, after UpdateTip + SetTipIndex), so the block is already fully
    // connected here. Signatures we send before a peer has the block are no longer
    // lost — peers buffer them in mapPendingSigs and replay on connect (see
    // ProcessHuSignature / ProcessPendingSigs). Removing the 100ms sleep cuts the
    // floor + variance off the finality delay and stops blocking cs_main per block.

    const Consensus::Params& consensus = Params().GetConsensus();

    // Finality committee = ECVRF sortition (the ONLY path; no legacy top-N). Each
    // managed operator self-selects below via its own VRF proof over the finality seed.
    // VRF inputs shared by all our managed operators this block: the seed hash(H-k)
    // (the VRF input alpha) and N = unique operators (must match the verifier's N in
    // IsOperatorVrfSelected, which uses the same mnList = list for pindex->pprev).
    const uint256 vrfSeed = GetHuFinalitySeedHash(pindex, consensus.nHuFinalitySeedOffset);
    const int vrfN = static_cast<int>(GetUniqueOperators(mnList).size());

    // Check which of our managed operators are VRF-drawn to sign this block
    std::vector<uint256> managedProTxHashes = activeMasternodeManager->GetManagedProTxHashes();

    bool anySigned = false;
    int signedCount = 0;

    // Finality counts one vote per UNIQUE OPERATOR (GetUniqueOperatorCount). All MNs
    // sharing an operator key derive the SAME VRF key → identical sortition + identical
    // vote, so signing with every managed MN is pure redundancy: e.g. Seed (8 MNs / 1
    // operator) would do 8 identical VRF proves + 8 ECDSA signs + 8 broadcasts + 8 DB
    // writes per block, all under cs_main, for a single counted vote — amplifying its
    // cs_main hold ~8x and adding finality-delay variance. Sign ONCE per unique operator.
    std::set<CPubKey> handledOperators;

    for (const uint256& proTxHash : managedProTxHashes) {
        if (proTxHash.IsNull()) continue;

        // Get this MN's operator
        auto dmn = mnList.GetMN(proTxHash);
        if (!dmn) continue;

        const CPubKey& myOperator = dmn->pdmnState->pubKeyOperator;

        // One signature per unique managed operator (see note above). Later MNs of an
        // already-signed operator add nothing to the operator-counted quorum.
        if (!handledOperators.insert(myOperator).second) continue;

        // Committee membership = ECVRF sortition self-selection. NO producer exclusion:
        // with 1-operator-1-vote + the 2/3 threshold, the producer's single self-vote
        // cannot finalize anything alone, and an invalid block is rejected by ConnectBlock
        // regardless of votes — so excluding it bought only a marginal equivocation margin
        // (+1 on producer-Byzantine blocks) while shrinking the voting pool to N-1, which
        // breaks the textbook 3f+1 fault-tolerance at small N (the §17 K=3 finality stall).
        // Removed 2026-06-30 — see dmn-finality.md §2/§3.5a.
        // Derive our dedicated VRF key from the operator key, prove over the seed, and
        // test the output against the threshold. Sign only if drawn; the proof is
        // attached to the signature so verifiers confirm membership without the secret.
        CKey opKey;
        CDeterministicMNCPtr opDmn;
        if (!activeMasternodeManager->GetOperatorKey(proTxHash, opKey, opDmn)) {
            continue;
        }
        CKey vrfKey;
        if (!vrf::DeriveKeyFromOperator(opKey, vrfKey)) {
            continue;
        }
        vrf::Proof vrfProof{};
        const std::vector<unsigned char> msg(vrfSeed.begin(), vrfSeed.end());
        if (!vrf::Prove(vrfProof, vrfKey.begin(), msg)) {
            continue;
        }
        vrf::Output out{};
        if (!vrf::ProofToHash(out, vrfProof)) {
            continue;
        }
        if (!IsVrfSelected(out, consensus.nHuExpectedCommitteeSize, vrfN)) {
            LogPrint(BCLog::STATE, "MN Finality: Operator %s not VRF-selected for height %d\n",
                     HexStr(myOperator).substr(0, 16), pindex->nHeight);
            continue;
        }

        {
            LOCK(cs);
            // Already signed this block with THIS specific MN?
            auto it = mapSigCache.find(blockHash);
            if (it != mapSigCache.end() && it->second.count(proTxHash)) {
                continue;  // Already signed with this MN
            }
        }

        // Sign the block with this MN
        CHuSignature sig;
        if (!SignBlockWithMN(blockHash, proTxHash, sig)) {
            LogPrintf("MN Finality: ERROR - Failed to sign block %s with MN %s\n",
                      blockHash.ToString().substr(0, 16), proTxHash.ToString().substr(0, 16));
            continue;
        }

        // Attach the VRF sortition proof (membership evidence).
        sig.vchVrfProof.assign(vrfProof.begin(), vrfProof.end());

        {
            LOCK(cs);
            mapSigCache[blockHash][sig.proTxHash] = sig.vchSig;
        }

        if (finalityHandler) {
            finalityHandler->AddSignature(sig);
        }

        BroadcastSignature(sig, connman);
        signedCount++;

        LogPrintf("MN Finality: Signed block %s with MN %s (operator %s)\n",
                  blockHash.ToString().substr(0, 16),
                  proTxHash.ToString().substr(0, 16),
                  HexStr(myOperator).substr(0, 16));

        anySigned = true;
    }

    if (signedCount == 0) {
        LogPrint(BCLog::STATE, "MN Finality: No signatures sent for block %s (no managed operator VRF-selected)\n",
                 blockHash.ToString().substr(0, 16));
    } else if (anySigned) {
        LogPrintf("MN Finality: Sent %d signatures for block %s at height %d\n",
                  signedCount, blockHash.ToString().substr(0, 16), pindex->nHeight);
    }

    return anySigned;
}

bool CHuSignalingManager::ProcessHuSignature(const CHuSignature& sig, CNode* pfrom, CConnman* connman, bool* pfMisbehave)
{

    // Basic validation
    if (sig.blockHash.IsNull() || sig.proTxHash.IsNull() || sig.vchSig.empty()) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Invalid signature structure\n");
        if (pfMisbehave) *pfMisbehave = true;  // R2: malformed = malicious, ban the peer
        return false;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // I3: RATE LIMITING - Prevent DoS via signature spam
    // ═══════════════════════════════════════════════════════════════════════════
    // Each peer can submit at most RATE_LIMIT_MAX_SIGS signatures per minute.
    // This prevents an attacker from overwhelming the node with invalid signatures.
    // ═══════════════════════════════════════════════════════════════════════════
    if (pfrom) {
        LOCK(cs);
        int64_t now = GetTime();
        auto& rateLimit = mapPeerRateLimit[pfrom->GetId()];

        // Reset counter if window expired
        if (now - rateLimit.lastResetTime > RATE_LIMIT_WINDOW_SECONDS) {
            rateLimit.count = 0;
            rateLimit.lastResetTime = now;
        }

        // Check rate limit
        if (++rateLimit.count > RATE_LIMIT_MAX_SIGS) {
            int windowSecs = RATE_LIMIT_WINDOW_SECONDS;  // Avoid ODR-use of static constexpr
            LogPrint(BCLog::STATE, "Quorum Signaling: Rate-limit peer %d (%d sigs in %ds)\n",
                     pfrom->GetId(), rateLimit.count, windowSecs);
            return false;
        }
    }

    // Check if we already have this signature
    {
        LOCK(cs);
        auto it = mapSigCache.find(sig.blockHash);
        if (it != mapSigCache.end() && it->second.count(sig.proTxHash)) {
            // Already have this signature
            return false;
        }
    }

    // Resolve the block via its connect-time finality context — NOT via
    // mapBlockIndex under cs_main. On a loaded node cs_main is held for long
    // stretches by connect/RPC work, and every signature that queued on it here
    // delayed the moment this node OBSERVED finality (this was the last per-sig
    // cs_main left after the counting path moved off it). GetOrBuild takes cs_main
    // at most ONCE per block (restart boundary); a miss = block not connected yet.
    HuBlockFinalityContext blockCtx;
    if (!GetOrBuildFinalityContext(sig.blockHash, blockCtx)) {
        // Block not connected yet — BUFFER the (still-unvalidated) signature and
        // replay it once the block connects, instead of dropping it. This closes
        // the block/signature propagation race that the pre-sign 100ms sleep used
        // to paper over. Bounded (distinct hashes x per-hash x TTL) so junk hashes
        // can't grow memory. Not counted as a peer failure (legit race).
        LOCK(cs);
        auto itp = mapPendingSigs.find(sig.blockHash);
        if (itp == mapPendingSigs.end() && mapPendingSigs.size() >= MAX_PENDING_SIG_BLOCKS) {
            return false;  // too many distinct pending blocks — drop (DoS guard)
        }
        auto& bucket = mapPendingSigs[sig.blockHash];
        if (bucket.second.empty()) bucket.first = GetTimeMillis();  // arrival stamp
        if (bucket.second.size() >= MAX_PENDING_SIGS_PER_BLOCK) return false;
        for (const auto& p : bucket.second) {
            if (p.proTxHash == sig.proTxHash) return false;  // dedup within bucket
        }
        bucket.second.push_back(sig);
        LogPrint(BCLog::STATE, "Quorum Signaling: buffered sig for not-yet-connected block %s (%zu pending)\n",
                 sig.blockHash.ToString().substr(0, 16), bucket.second.size());
        return true;
    }

    // Validate the signature against the precomputed context (pure crypto, no locks)
    if (!ValidateSignatureFromContext(sig, blockCtx)) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Invalid signature from %s for block %s\n",
                 sig.proTxHash.ToString().substr(0, 16), sig.blockHash.ToString().substr(0, 16));
        // R2: an honest peer NEVER relays a crypto-invalid finality sig (it validates
        // before BroadcastSignature below) — so this is unambiguously malicious.
        if (pfMisbehave) *pfMisbehave = true;
        return false;
    }

    // I5: Valid signature received

    // No slashing layer (deliberate design decision).
    // Conflicting-block equivocation at the same height is rejected at the chain
    // level by HasConflictingFinality / WouldViolateHuFinality (validation.cpp).

    // Add to cache and finality handler
    {
        LOCK(cs);
        mapSigCache[sig.blockHash][sig.proTxHash] = sig.vchSig;
    }

    if (finalityHandler) {
        finalityHandler->AddSignature(sig);
    }

    // Metric only — the authoritative, operator-counted finalization fires inside
    // AddSignature. Align this log trigger to the active auto-scaled threshold
    // (ceil(2/3·min(E,N))).
    const Consensus::Params& consensus = Params().GetConsensus();
    int sigCount = GetSignatureCount(sig.blockHash);
    const int activeThreshold = hu::HuActiveFinalityThreshold(consensus, hu::HuFinalityOperatorCount(sig.blockHash));
    if (sigCount == activeThreshold) {
        LogPrintf("Quorum Signaling: Block %s reached quorum (%d/%d signatures)\n",
                  sig.blockHash.ToString().substr(0, 16), sigCount, activeThreshold);
    }

    // Relay to other peers
    BroadcastSignature(sig, connman, pfrom);

    LogPrint(BCLog::STATE, "Quorum Signaling: Accepted signature %d/%d from %s for block %s\n",
             sigCount, activeThreshold,
             sig.proTxHash.ToString().substr(0, 16), sig.blockHash.ToString().substr(0, 16));

    return true;
}

// MULTI-MN: Sign block with a specific MN
bool CHuSignalingManager::SignBlockWithMN(const uint256& blockHash, const uint256& proTxHash, CHuSignature& sigOut)
{
    if (!activeMasternodeManager || !activeMasternodeManager->IsReady()) {
        return false;
    }

    // Get operator key for this specific proTxHash
    CKey operatorKey;
    CDeterministicMNCPtr dmn;
    auto keyResult = activeMasternodeManager->GetOperatorKey(proTxHash, operatorKey, dmn);
    if (!keyResult) {
        LogPrintf("MULTI-MN Quorum: Failed to get operator key for %s: %s\n",
                  proTxHash.ToString().substr(0, 16), keyResult.getError());
        return false;
    }

    // Create message to sign: "HUSIG" || blockHash
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("HUSIG");
    ss << blockHash;
    uint256 msgHash = ss.GetHash();

    // Sign with ECDSA
    std::vector<unsigned char> vchSig;
    if (!operatorKey.SignCompact(msgHash, vchSig)) {
        LogPrintf("MULTI-MN Quorum: Failed to sign block hash with MN %s\n",
                  proTxHash.ToString().substr(0, 16));
        return false;
    }

    sigOut.blockHash = blockHash;
    sigOut.proTxHash = proTxHash;
    sigOut.vchSig = vchSig;

    return true;
}

bool CHuSignalingManager::ValidateSignatureFromContext(const CHuSignature& sig, const HuBlockFinalityContext& ctx) const
{
    // Resolve the signer against the block's OWN MN list, precomputed at connect
    // (context = GetListForBlock(pprev) over valid MNs — same population as the
    // counting fast path). No cs_main, no MN-list reconstruction per signature.
    auto itOp = ctx.operatorByProTx.find(sig.proTxHash);
    if (itOp == ctx.operatorByProTx.end()) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Unknown MN %s\n", sig.proTxHash.ToString().substr(0, 16));
        return false;
    }
    const CPubKey& signerOperator = itOp->second;

    // ═══════════════════════════════════════════════════════════════════════════
    // MN-BASED VALIDATION v4.0
    // ═══════════════════════════════════════════════════════════════════════════
    // Check if signer's OPERATOR is in quorum (no exclusion)
    // Security comes from 2/3 threshold, not from excluding producer
    // ═══════════════════════════════════════════════════════════════════════════
    // Committee membership = ECVRF sortition (the ONLY path). Membership is PROVEN by
    // the ECVRF proof carried with the signature, evaluated over the finality seed
    // hash(H-k) against the signer's REGISTERED VRF key. An attacker cannot reuse
    // another operator's proof (it only selects that operator's key) nor forge one
    // without the VRF secret. Verification only (no secret), so this runs on every node.
    auto itVrf = ctx.vrfByProTx.find(sig.proTxHash);
    if (itVrf == ctx.vrfByProTx.end() || !itVrf->second.IsValid() || itVrf->second.size() != vrf::PUBKEY_SIZE) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Operator %s has no VRF key at height %d\n",
                 HexStr(signerOperator).substr(0, 16), ctx.nHeight);
        return false;
    }
    const CPubKey& signerVrf = itVrf->second;
    if (sig.vchVrfProof.size() != vrf::PROOF_SIZE) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Missing/short VRF proof from %s for height %d\n",
                 sig.proTxHash.ToString().substr(0, 16), ctx.nHeight);
        return false;
    }
    // NO producer exclusion (removed 2026-06-30, symmetric with the signing path): the
    // producer's operator MAY vote on its own block. 1-op-1-vote + 2/3 makes a self-vote
    // unable to finalize alone, ConnectBlock rejects invalid blocks regardless, and
    // including the producer restores the textbook 3f+1 fault-tolerance at small N.
    // See dmn-finality.md §2/§3.5a.
    // DoS ordering: do the ECDSA recover + operator-match (binds the signature to a
    // known operator) BEFORE the ECVRF verify. Both are equal-cost curve ops, but the
    // ECDSA check is unconditionally required and rejects forged/replayed sigs from a
    // non-operator without paying for a VRF verify first.
    CHashWriter ss(SER_GETHASH, 0);
    ss << std::string("HUSIG");
    ss << sig.blockHash;
    uint256 msgHash = ss.GetHash();

    CPubKey recoveredPubKey;
    if (!recoveredPubKey.RecoverCompact(msgHash, sig.vchSig)) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Failed to recover pubkey from signature\n");
        return false;
    }
    if (recoveredPubKey != signerOperator) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Signature pubkey mismatch for operator %s\n",
                 HexStr(signerOperator).substr(0, 16));
        return false;
    }

    // Finally the ECVRF selection proof (only reached by a sig that already binds to
    // this operator's ECDSA key). Same math as IsOperatorVrfSelected, off the
    // precomputed seed and eligible-operator count (N) — identical accept/reject.
    vrf::Proof proof;
    std::copy(sig.vchVrfProof.begin(), sig.vchVrfProof.end(), proof.begin());
    std::vector<unsigned char> vrfMsg(ctx.vrfSeed.begin(), ctx.vrfSeed.end());
    vrf::Output vrfOutput;
    if (!vrf::Verify(vrfOutput, proof, signerVrf.begin(), vrfMsg)) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Invalid VRF proof from operator %s for height %d\n",
                 HexStr(signerOperator).substr(0, 16), ctx.nHeight);
        return false;
    }
    const Consensus::Params& consensus = Params().GetConsensus();
    const int N = static_cast<int>(ctx.eligibleOperators.size());
    if (!IsVrfSelected(vrfOutput, consensus.nHuExpectedCommitteeSize, N)) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Operator %s not VRF-selected for height %d\n",
                 HexStr(signerOperator).substr(0, 16), ctx.nHeight);
        return false;
    }

    return true;
}

void CHuSignalingManager::BroadcastSignature(const CHuSignature& sig, CConnman* connman, CNode* pfrom)
{
    if (!connman) {
        return;
    }

    {
        LOCK(cs);
        // Track relayed signatures to avoid spam
        if (mapRelayedSigs[sig.blockHash].count(sig.proTxHash)) {
            return;  // Already relayed this signature
        }
        mapRelayedSigs[sig.blockHash].insert(sig.proTxHash);
    }

    // Broadcast to each unique peer ADDRESS once (not once per connection). A node
    // may hold several connections to the same remote (inbound + outbound, or extra
    // outbounds on a small over-connected network); sending the sig on every one of
    // them multiplies the per-block message load through the 50ms socket-send poll and
    // is what turned a messy topology into a gossip storm (finality delay 2ms→seconds).
    // Dedup by CService so each distinct node receives the sig exactly once per relay
    // hop — storm-proof regardless of how tangled the connection graph is. Combined
    // with the per-signature relay dedup above, total sends stay O(unique peers).
    std::set<CService> sentTo;
    if (pfrom) sentTo.insert(static_cast<CService>(pfrom->addr));  // never echo to source node
    connman->ForEachNode([&](CNode* pnode) {
        if (pnode == pfrom) {
            return;  // Don't send back to sender
        }
        if (!pnode->fSuccessfullyConnected || pnode->fDisconnect) {
            return;
        }
        if (!sentTo.insert(static_cast<CService>(pnode->addr)).second) {
            return;  // already sent this signature to this node via another connection
        }

        CNetMsgMaker msgMaker(pnode->GetSendVersion());
        connman->PushMessage(pnode, msgMaker.Make(NetMsgType::HUSIG, sig));
    });
}

int CHuSignalingManager::GetSignatureCount(const uint256& blockHash) const
{
    LOCK(cs);
    auto it = mapSigCache.find(blockHash);
    if (it == mapSigCache.end()) {
        return 0;
    }
    return static_cast<int>(it->second.size());
}

bool CHuSignalingManager::HasQuorum(const uint256& blockHash) const
{
    const Consensus::Params& consensus = Params().GetConsensus();

    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY: Verify minimum quorum size before declaring finality
    // ═══════════════════════════════════════════════════════════════════════════
    // With too few confirmed MNs, an attacker controlling a small number of MNs
    // could reach threshold and finalize malicious blocks.
    // Example: With only 2 MNs and threshold=2, attacker needs only 2 MNs.
    // We require at least nHuQuorumSize confirmed MNs for secure finality.
    // ═══════════════════════════════════════════════════════════════════════════

    // Operator-based + bootstrap-aware: count the unique operators ELIGIBLE for
    // finality (same bootstrap-MN trust as block production), not the raw
    // confirmed-MN count. Resolved from the block's connect-time context (the same
    // GetUniqueOperators population, precomputed — no cs_main / MN-list rebuild
    // here). The Sybil floor (>= nHuQuorumSize distinct operators) is preserved.
    // An unknown block (context unresolvable) skips the floor check, exactly like
    // the old pindex==nullptr path, and falls through to the finality handler.
    {
        HuBlockFinalityContext qctx;
        if (GetOrBuildFinalityContext(blockHash, qctx) &&
            static_cast<int>(qctx.eligibleOperators.size()) < consensus.nHuQuorumSize) {
            LogPrint(BCLog::STATE, "Quorum Finality: Insufficient operators (%zu/%d) for block %s\n",
                     qctx.eligibleOperators.size(), consensus.nHuQuorumSize, blockHash.ToString().substr(0, 16));
            return false;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // OPERATOR-CENTRIC QUORUM: Use finalityHandler which counts unique operators
    // ═══════════════════════════════════════════════════════════════════════════
    if (finalityHandler) {
        CFinalityManager finality;
        if (finalityHandler->GetFinality(blockHash, finality)) {
            return finality.HasFinality(HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(blockHash)));
        }
    }
    // Fallback to raw signature count if finalityHandler not available.
    return GetSignatureCount(blockHash) >= HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(blockHash));
}

void CHuSignalingManager::Cleanup(int nCurrentHeight)
{
    LOCK(cs);

    // Evict stale buffered signatures whose block never connected. Runs every block
    // (cheap) so mapPendingSigs stays bounded even though the sig-cache cleanup below
    // only runs every 100 blocks.
    {
        const int64_t nowMs = GetTimeMillis();
        for (auto it = mapPendingSigs.begin(); it != mapPendingSigs.end(); ) {
            if (nowMs - it->second.first > PENDING_SIG_TTL_MS) it = mapPendingSigs.erase(it);
            else ++it;
        }
    }

    // I3 hardening: evict stale per-peer rate-limit entries. mapPeerRateLimit was
    // insert-only (operator[] in ProcessHuSignature, keyed on a MONOTONIC NodeId,
    // never erased) — every connect/husig/disconnect cycle left a permanent entry,
    // so an unauthenticated peer could grow it without bound = remote memory-
    // exhaustion DoS. An entry whose window has fully expired would reset its counter
    // to 0 on next access anyway, so erasing it here is behavior-preserving; the sweep
    // bounds the map to peers active within the last few windows. Runs every block.
    {
        const int64_t nowSec = GetTime();
        const int64_t staleAfter = 2 * static_cast<int64_t>(RATE_LIMIT_WINDOW_SECONDS);
        for (auto it = mapPeerRateLimit.begin(); it != mapPeerRateLimit.end(); ) {
            if (nowSec - it->second.lastResetTime > staleAfter) it = mapPeerRateLimit.erase(it);
            else ++it;
        }
    }

    // Drop cached per-block finality contexts well behind the tip (keep a generous
    // window so late-arriving signatures for recent blocks still hit the cache).
    PruneFinalityContextsBelow(nCurrentHeight - 200);

    // Only cleanup every 100 blocks
    if (nCurrentHeight - nLastCleanupHeight < 100) {
        return;
    }
    nLastCleanupHeight = nCurrentHeight;

    // ═══════════════════════════════════════════════════════════════════════════
    // I2: INTELLIGENT CLEANUP - Only remove finalized blocks
    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY: Never delete signatures for blocks that haven't reached finality.
    // We only clean up blocks that are:
    // 1. Older than KEEP_BLOCKS behind current height
    // 2. Already finalized (have quorum signatures in DB)
    // ═══════════════════════════════════════════════════════════════════════════
    const int KEEP_BLOCKS = 100;
    const Consensus::Params& consensus = Params().GetConsensus();

    std::vector<uint256> toRemove;

    for (const auto& entry : mapSigCache) {
        const uint256& blockHash = entry.first;
        // Get block height
        int blockHeight = -1;
        {
            LOCK(cs_main);
            auto it = mapBlockIndex.find(blockHash);
            if (it != mapBlockIndex.end()) {
                blockHeight = it->second->nHeight;
            }
        }

        // Skip blocks we can't identify or that are too recent
        if (blockHeight < 0 || nCurrentHeight - blockHeight < KEEP_BLOCKS) {
            continue;
        }

        // Only remove if the block is finalized
        bool isFinalized = false;

        // Check in-memory finality handler
        if (finalityHandler) {
            CFinalityManager finality;
            if (finalityHandler->GetFinality(blockHash, finality)) {
                if (finality.HasFinality(HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(blockHash)))) {
                    isFinalized = true;
                }
            }
        }

        // Also check DB for persisted finality (IsBlockFinal derives threshold internally)
        if (!isFinalized && pFinalityDB) {
            if (pFinalityDB->IsBlockFinal(blockHash)) {
                isFinalized = true;
            }
        }

        if (isFinalized) {
            toRemove.push_back(blockHash);
        }
    }

    // Remove finalized old blocks from caches
    int removedCount = 0;
    for (const auto& hash : toRemove) {
        mapSigCache.erase(hash);
        mapRelayedSigs.erase(hash);
        removedCount++;
    }

    if (removedCount > 0) {
        LogPrint(BCLog::STATE, "Quorum Signaling: Cleanup removed %d finalized blocks older than %d\n",
                 removedCount, nCurrentHeight - KEEP_BLOCKS);
    }

    LogPrint(BCLog::STATE, "Quorum Signaling: Cleanup complete. Cache sizes: sigs=%zu, relayed=%zu\n",
             mapSigCache.size(), mapRelayedSigs.size());
}

size_t CHuSignalingManager::PeerRateLimitEntryCount() const
{
    LOCK(cs);
    return mapPeerRateLimit.size();
}

void CHuSignalingManager::InjectPeerRateLimitForTest(NodeId id, int64_t lastResetTime)
{
    LOCK(cs);
    auto& e = mapPeerRateLimit[id];
    e.count = 0;
    e.lastResetTime = lastResetTime;
}

// ============================================================================
// Global Functions
// ============================================================================

void CHuSignalingManager::ProcessPendingSigs(const uint256& blockHash, CConnman* connman)
{
    std::vector<CHuSignature> pending;
    {
        LOCK(cs);
        auto it = mapPendingSigs.find(blockHash);
        if (it == mapPendingSigs.end()) return;
        pending = std::move(it->second.second);
        mapPendingSigs.erase(it);
    }
    // Re-run the full receive path now that the block is known: each sig is looked
    // up (found this time), validated, cached and counted. pfrom=nullptr → skip the
    // per-peer rate limit (already applied on original arrival).
    for (const auto& sig : pending) {
        ProcessHuSignature(sig, nullptr, connman);
    }
}

void NotifyBlockConnected(const CBlockIndex* pindex, CConnman* connman)
{
    if (!huSignalingManager) {
        return;
    }

    // Record block received time for finality delay tracking (v4.0)
    g_hu_metrics.lastBlockReceivedTime.store(GetTimeMicros());

    // Precompute this block's finality operator context while cs_main is still held
    // (we are inside ConnectTip). The hot signature-counting path then observes
    // finality WITHOUT re-taking cs_main — so a loaded node (producer + burn/header
    // daemons) records finality in ms instead of seconds. Deterministic (same
    // GetListForBlock(pprev)), so it changes only observation latency, not validity.
    CacheBlockFinalityContext(pindex);

    // If we're a MN, sign the block
    huSignalingManager->OnNewBlock(pindex, connman);
    // The block is now connected/known: replay any signatures peers sent us before
    // we had it (buffered instead of dropped — see ProcessHuSignature). This is what
    // lets us drop the pre-sign sleep without losing signatures to the race.
    huSignalingManager->ProcessPendingSigs(pindex->GetBlockHash(), connman);
    huSignalingManager->Cleanup(pindex->nHeight);
}

// NOTE: Bootstrap height and cold start timeout are now network-specific
// via consensus.nDMMBootstrapHeight and consensus.nStaleChainTimeout

bool PreviousBlockHasQuorum(const CBlockIndex* pindexPrev)
{
    if (!pindexPrev) {
        return true;  // Genesis - no previous block to check
    }

    const Consensus::Params& consensus = Params().GetConsensus();

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON Bootstrap Exception: Blocks during bootstrap phase exempt from quorum
    // ═══════════════════════════════════════════════════════════════════════════
    // Uses consensus.nDMMBootstrapHeight (network-specific):
    // - Mainnet/Testnet: 10 blocks
    // - Regtest: 2 blocks
    // During this phase, MNs are being registered and confirmed.
    // ═══════════════════════════════════════════════════════════════════════════
    if (pindexPrev->nHeight <= consensus.nDMMBootstrapHeight) {
        return true;  // Bootstrap blocks exempt - no HU signatures yet
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Cold Start Recovery: If tip is very old, bypass quorum check
    // ═══════════════════════════════════════════════════════════════════════════
    // SECURITY: Uses consensus.nStaleChainTimeout (network-specific):
    // - Mainnet: 3600s (1h) - requires 1h+ outage to exploit
    // - Testnet: 600s (10min) - balanced for testing
    // - Regtest: 60s - fast for automated tests
    //
    // This handles network-wide restarts where:
    // - All nodes have the same stale tip
    // - No recent HU signatures exist (weren't exchanged during reindex)
    // - We need to allow DMM to produce the next block to restart finality
    // ═══════════════════════════════════════════════════════════════════════════
    int64_t tipAge = GetTime() - pindexPrev->GetBlockTime();
    if (tipAge > consensus.nStaleChainTimeout) {
        LogPrintf("Quorum Signaling: COLD START (tip age=%ds, threshold=%ds) - bypassing quorum check\n",
                 (int)tipAge, (int)consensus.nStaleChainTimeout);
        return true;
    }

    // Check if previous block has quorum
    const uint256& prevHash = pindexPrev->GetBlockHash();

    if (huSignalingManager && huSignalingManager->HasQuorum(prevHash)) {
        return true;
    }

    // Also check the finality handler (for persisted data)
    if (finalityHandler) {
        CFinalityManager finality;
        if (finalityHandler->GetFinality(prevHash, finality)) {
            if (finality.HasFinality(HuActiveFinalityThreshold(consensus, HuFinalityOperatorCount(prevHash)))) {
                return true;
            }
        }
    }

    // Check DB for persisted finality (IsBlockFinal derives the active threshold internally)
    if (pFinalityDB && pFinalityDB->IsBlockFinal(prevHash)) {
        return true;
    }

    int sigCount = huSignalingManager ? huSignalingManager->GetSignatureCount(prevHash) : 0;
    LogPrint(BCLog::STATE, "Quorum Signaling: Previous block %s lacks quorum (%d signatures)\n",
             prevHash.ToString().substr(0, 16), sigCount);

    return false;
}

} // namespace hu
