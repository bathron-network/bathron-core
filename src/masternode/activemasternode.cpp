// Copyright (c) 2014-2016 The Dash developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "activemasternode.h"

#include "blockassembler.h"
#include "net/net.h"  // For g_connman and CNode
#include "consensus/merkle.h"
#include "consensus/mn_validation.h"
#include "masternode/blockproducer.h"
#include "key_io.h"
#include "net/netbase.h"
#include "primitives/block.h"
#include "node/shutdown.h"
#include "masternode/tiertwo_sync_state.h"
#include "state/signaling.h"
#include "utiltime.h"
#include "validation.h"

// Keep track of the active Masternode
CActiveDeterministicMasternodeManager* activeMasternodeManager{nullptr};

// Definition of static constexpr members (required for ODR-use in C++14)
constexpr int CActiveDeterministicMasternodeManager::DMM_BLOCK_INTERVAL_SECONDS;
constexpr int CActiveDeterministicMasternodeManager::DMM_CHECK_INTERVAL_SECONDS;
constexpr int CActiveDeterministicMasternodeManager::DMM_MISSED_BLOCK_TIMEOUT;

static bool GetLocalAddress(CService& addrRet)
{
    // First try to find whatever our own local address is known internally.
    // Addresses could be specified via 'externalip' or 'bind' option, discovered via UPnP
    // or added by TorController. Use some random dummy IPv4 peer to prefer the one
    // reachable via IPv4.
    CNetAddr addrDummyPeer;
    bool fFound{false};
    if (LookupHost("8.8.8.8", addrDummyPeer, false)) {
        fFound = GetLocal(addrRet, &addrDummyPeer) && CActiveDeterministicMasternodeManager::IsValidNetAddr(addrRet);
    }
    if (!fFound && Params().IsRegTestNet()) {
        if (Lookup("127.0.0.1", addrRet, GetListenPort(), false)) {
            fFound = true;
        }
    }
    if (!fFound) {
        // If we have some peers, let's try to find our local address from one of them
        g_connman->ForEachNodeContinueIf([&fFound, &addrRet](CNode* pnode) {
            if (pnode->addr.IsIPv4())
                fFound = GetLocal(addrRet, &pnode->addr) && CActiveDeterministicMasternodeManager::IsValidNetAddr(addrRet);
            return !fFound;
        });
    }
    return fFound;
}

std::string CActiveDeterministicMasternodeManager::GetStatus() const
{
    switch (state) {
        case MASTERNODE_WAITING_FOR_PROTX:    return "Waiting for ProTx to appear on-chain";
        case MASTERNODE_POSE_BANNED:          return "Masternode was PoSe banned";
        case MASTERNODE_REMOVED:              return "Masternode removed from list";
        case MASTERNODE_OPERATOR_KEY_CHANGED: return "Operator key changed or revoked";
        case MASTERNODE_PROTX_IP_CHANGED:     return "IP address specified in ProTx changed";
        case MASTERNODE_READY:                return "Ready";
        case MASTERNODE_ERROR:                return "Error. " + strError;
        default:                              return "Unknown";
    }
}

OperationResult CActiveDeterministicMasternodeManager::AddOperatorKey(const std::string& strMNOperatorPrivKey)
{
    LOCK(cs_main); // Lock cs_main so the node doesn't perform any action while we setup the Masternode

    // OPERATOR-CENTRIC v4.0: Only ONE key allowed per daemon
    // This check is also enforced in init.cpp, but we double-check here for safety
    if (info.HasAnyKey()) {
        return errorOut("ERROR: Operator key already set. Only ONE key allowed per daemon (Operator-Centric model).");
    }

    if (strMNOperatorPrivKey.empty()) {
        return errorOut("ERROR: Masternode operator priv key cannot be empty.");
    }

    CKey opSk = KeyIO::DecodeSecret(strMNOperatorPrivKey);
    if (!opSk.IsValid()) {
        return errorOut(_("Invalid mnoperatorprivatekey. Please see the documentation."));
    }

    // OPERATOR-CENTRIC v4.0: Store the single operator key
    // All MNs with this key will be discovered in Init() using GetMNsByOperatorKey()
    CPubKey pubKey = opSk.GetPubKey();

    if (!info.AddOperatorKey(opSk)) {
        // Should never happen since we check HasAnyKey() above
        return errorOut("ERROR: Failed to add operator key.");
    }

    LogPrintf("OPERATOR-CENTRIC: Operator key set: %s (1 key = N MNs)\n",
              HexStr(pubKey).substr(0, 16));

    return {true};
}

// MULTI-MN: Get operator key for a specific proTxHash
OperationResult CActiveDeterministicMasternodeManager::GetOperatorKey(const uint256& proTxHash, CKey& key, CDeterministicMNCPtr& dmn) const
{
    if (!IsReady()) {
        return errorOut("Active masternode not ready");
    }

    // Check if we manage this proTxHash
    if (!info.HasMN(proTxHash)) {
        return errorOut(strprintf("ProTxHash %s not managed by this daemon", proTxHash.ToString()));
    }

    dmn = deterministicMNManager->GetListAtChainTip().GetValidMN(proTxHash);
    if (!dmn) {
        return errorOut(strprintf("Masternode %s not registered or PoSe banned", proTxHash.ToString()));
    }

    // Get the key for this proTxHash
    if (!info.GetOperatorKey(proTxHash, key)) {
        return errorOut(strprintf("Failed to get operator key for %s", proTxHash.ToString()));
    }

    // Verify key matches on-chain registration
    if (key.GetPubKey() != dmn->pdmnState->pubKeyOperator) {
        return errorOut("Operator key changed or revoked on-chain");
    }

    return {true};
}

// Legacy: Get operator key for the first managed MN
OperationResult CActiveDeterministicMasternodeManager::GetOperatorKey(CKey& key, CDeterministicMNCPtr& dmn) const
{
    if (!IsReady()) {
        return errorOut("Active masternode not ready");
    }

    // Get first managed proTxHash
    uint256 firstProTxHash = info.GetFirstProTxHash();
    if (firstProTxHash.IsNull()) {
        return errorOut("No masternodes managed");
    }

    return GetOperatorKey(firstProTxHash, key, dmn);
}

void CActiveDeterministicMasternodeManager::Init(const CBlockIndex* pindexTip)
{
    // set masternode arg if called from RPC
    if (!fMasterNode) {
        gArgs.ForceSetArg("-masternode", "1");
        fMasterNode = true;
    }

    if (!deterministicMNManager->IsDIP3Enforced(pindexTip->nHeight)) {
        state = MASTERNODE_ERROR;
        strError = "Evo upgrade is not active yet.";
        LogPrintf("%s -- ERROR: %s\n", __func__, strError);
        return;
    }

    LOCK(cs_main);

    // Check that our local network configuration is correct
    if (!fListen) {
        state = MASTERNODE_ERROR;
        strError = "Masternode must accept connections from outside. Make sure listen configuration option is not overwritten by some another parameter.";
        LogPrintf("%s ERROR: %s\n", __func__, strError);
        return;
    }

    if (!GetLocalAddress(info.service)) {
        state = MASTERNODE_ERROR;
        strError = "Can't detect valid external address. Please consider using the externalip configuration option if problem persists. Make sure to use IPv4 address only.";
        LogPrintf("%s ERROR: %s\n", __func__, strError);
        return;
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindexTip);

    // OPERATOR-CENTRIC: Clear previous MN mappings and rediscover
    info.ClearManagedMNs();

    // OPERATOR-CENTRIC: For each operator key, find ALL MNs with that key
    LogPrintf("OPERATOR-CENTRIC: Looking for MNs for %zu operator key(s) at height %d (mnList size: %d)\n",
              info.GetOperatorKeyCount(), pindexTip->nHeight, mnList.GetValidMNsCount());

    int totalMNsFound = 0;

    for (const auto& [pubKeyId, opKey] : info.operatorKeys) {
        CPubKey pubKey = opKey.GetPubKey();

        // OPERATOR-CENTRIC: Find ALL MNs with this operator key (not just one!)
        std::vector<CDeterministicMNCPtr> mns = mnList.GetMNsByOperatorKey(pubKey);

        if (mns.empty()) {
            LogPrintf("OPERATOR-CENTRIC: Key %s - no MNs found on-chain yet\n", HexStr(pubKey).substr(0, 16));
            continue;
        }

        LogPrintf("OPERATOR-CENTRIC: Key %s - found %zu MN(s)\n", HexStr(pubKey).substr(0, 16), mns.size());

        for (const auto& dmn : mns) {
            // Note: GetMNsByOperatorKey already filters out PoSe-banned MNs
            info.AddManagedMN(dmn->proTxHash, pubKeyId);
            totalMNsFound++;

            LogPrintf("OPERATOR-CENTRIC:   -> MN %s (height %d)\n",
                      dmn->proTxHash.ToString().substr(0, 16),
                      dmn->pdmnState->nRegisteredHeight);
        }
    }

    LogPrintf("OPERATOR-CENTRIC: Managing %d MN(s) with %zu operator key(s)\n",
              totalMNsFound, info.GetOperatorKeyCount());

    if (totalMNsFound == 0) {
        // No MNs found yet - stay in waiting state
        LogPrintf("OPERATOR-CENTRIC: No MNs found on-chain yet, waiting...\n");
        return;
    }

    // Check socket connectivity (skip on regtest) - only check once for the daemon
    if (!Params().IsRegTestNet()) {
        const std::string& strService = info.service.ToString();
        LogPrintf("%s: Checking inbound connection to '%s'\n", __func__, strService);
        SOCKET hSocket = CreateSocket(info.service);
        if (hSocket == INVALID_SOCKET) {
            state = MASTERNODE_ERROR;
            strError = "DMN connectivity check failed, could not create socket to DMN running at " + strService;
            LogPrintf("%s -- ERROR: %s\n", __func__, strError);
            return;
        }
        bool fConnected = ConnectSocketDirectly(info.service, hSocket, nConnectTimeout, true) && IsSelectableSocket(hSocket);
        CloseSocket(hSocket);

        if (!fConnected) {
            state = MASTERNODE_ERROR;
            strError = "DMN connectivity check failed, could not connect to DMN running at " + strService;
            LogPrintf("%s ERROR: %s\n", __func__, strError);
            return;
        }
    } else {
        LogPrintf("%s: Skipping connectivity check (regtest)\n", __func__);
    }

    state = MASTERNODE_READY;
    LogPrintf("OPERATOR-CENTRIC: Masternode manager READY with %d MN(s)\n", totalMNsFound);

    // Start the DMM block producer scheduler
    StartDMMScheduler();
}

void CActiveDeterministicMasternodeManager::Reset(masternode_state_t _state, const CBlockIndex* pindexTip)
{
    // Stop the scheduler before reset
    StopDMMScheduler();

    state = _state;
    // MN might have reappeared in same block with a new ProTx
    Init(pindexTip);
}

void CActiveDeterministicMasternodeManager::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    LogPrint(BCLog::MASTERNODE, "%s: height=%d, fInitialDownload=%d, fMasterNode=%d, state=%d, managedMNs=%zu\n",
              __func__, pindexNew->nHeight, fInitialDownload, fMasterNode, state, info.GetManagedCount());

    // Allow MN init at genesis (height 0-1) even during initial download
    // Also allow init during IBD if we're still WAITING_FOR_PROTX (e.g., during -reindex)
    // This fixes the race condition where Init() runs before evoDB is loaded
    bool isBootstrapPhase = (pindexNew->nHeight < 2);
    bool needsMNInit = (state == MASTERNODE_WAITING_FOR_PROTX && !info.HasAnyMN());

    if (fInitialDownload && !isBootstrapPhase && !needsMNInit)
        return;

    if (!fMasterNode || !deterministicMNManager->IsDIP3Enforced(pindexNew->nHeight))
        return;

    if (state == MASTERNODE_READY) {
        // OPERATOR-CENTRIC: Check all our managed MNs for changes
        CDeterministicMNList newList = deterministicMNManager->GetListForBlock(pindexNew);

        bool anyKeyChanged = false;
        bool anyPoSeBanned = false;
        std::vector<uint256> toRemove;

        // Check each managed MN for removal or key change
        for (const auto& [proTxHash, pubKeyId] : info.managedMNs) {
            auto newDmn = newList.GetValidMN(proTxHash);
            if (newDmn == nullptr) {
                // GetValidMN() excludes PoSe-banned MNs; GetMN() still returns them.
                // Distinguish a PoSe ban (operator should run protx_update_service to
                // revive) from a genuine removal (collateral spent / ProReg gone).
                auto bannedDmn = newList.GetMN(proTxHash);
                if (bannedDmn != nullptr && bannedDmn->IsPoSeBanned()) {
                    LogPrintf("OPERATOR-CENTRIC: MN %s PoSe-banned\n", proTxHash.ToString().substr(0, 16));
                    anyPoSeBanned = true;
                } else {
                    LogPrintf("OPERATOR-CENTRIC: MN %s removed from list\n", proTxHash.ToString().substr(0, 16));
                }
                toRemove.push_back(proTxHash);
                continue;
            }

            // Check if operator key changed (shouldn't happen if we're the operator)
            CKey ourKey;
            if (info.GetKeyByPubKeyId(pubKeyId, ourKey)) {
                if (newDmn->pdmnState->pubKeyOperator != ourKey.GetPubKey()) {
                    LogPrintf("OPERATOR-CENTRIC: MN %s operator key changed on-chain\n", proTxHash.ToString().substr(0, 16));
                    toRemove.push_back(proTxHash);
                    anyKeyChanged = true;
                }
            }
        }

        // Remove MNs that are no longer valid
        for (const auto& proTxHash : toRemove) {
            info.RemoveManagedMN(proTxHash);
        }

        // OPERATOR-CENTRIC: Also check if new MNs appeared with our keys
        for (const auto& [pubKeyId, opKey] : info.operatorKeys) {
            CPubKey pubKey = opKey.GetPubKey();
            std::vector<CDeterministicMNCPtr> mns = newList.GetMNsByOperatorKey(pubKey);
            for (const auto& dmn : mns) {
                if (!info.HasMN(dmn->proTxHash)) {
                    // New MN appeared with our key!
                    info.AddManagedMN(dmn->proTxHash, pubKeyId);
                    LogPrintf("OPERATOR-CENTRIC: New MN %s appeared with our key\n",
                              dmn->proTxHash.ToString().substr(0, 16));
                }
            }
        }

        // Check if we still have any valid MNs
        if (!info.HasAnyMN()) {
            // All MNs gone - reset and try to re-init. Report the most actionable
            // cause first: a PoSe ban (revive via protx_update_service) over an
            // operator-key change over a plain removal.
            if (anyPoSeBanned) {
                Reset(MASTERNODE_POSE_BANNED, pindexNew);
            } else if (anyKeyChanged) {
                Reset(MASTERNODE_OPERATOR_KEY_CHANGED, pindexNew);
            } else {
                Reset(MASTERNODE_REMOVED, pindexNew);
            }
            return;
        }

        // =============================================
        // DMM Block Producer Scheduler - Try producing
        // =============================================
        // When we receive a new block tip, check if we are the designated
        // producer for the NEXT block and produce if so
        TryProducingBlock(pindexNew);

    } else {
        // MN might have (re)appeared with a new ProTx or we've found some peers
        // and figured out our local address
        Init(pindexNew);
    }
}

bool CActiveDeterministicMasternodeManager::IsValidNetAddr(const CService& addrIn)
{
    // TODO: check IPv6 and TOR addresses
    return Params().IsRegTestNet() || (addrIn.IsIPv4() && IsReachable(addrIn) && addrIn.IsRoutable());
}

// ============================================================================
// DMM Block Producer Scheduler Implementation
// ============================================================================

/**
 * Calculate the aligned block timestamp for production.
 *
 * This function calculates what nTime the block should have based on the
 * current time and the slot grid. The scheduler must align nTime to slot
 * boundaries so that verification (which uses the same slot calculation)
 * produces identical results.
 *
 * CRITICAL: Block timestamps MUST respect nTargetSpacing (60s) between blocks.
 * The minimum valid nTime for the next block is: prevTime + nTargetSpacing.
 *
 * Slot boundaries (after respecting nTargetSpacing):
 * - Slot 0 (primary): nTime in [minTime, minTime + leaderTimeout)
 * - Slot 1 (fallback 1): nTime = minTime + leaderTimeout
 * - Slot 2 (fallback 2): nTime = minTime + leaderTimeout + fallbackWindow
 * - etc.
 *
 * @param pindexPrev     Previous block index
 * @param nNow           Current local time
 * @param outSlot        [out] Calculated slot index
 * @return               Aligned block timestamp (0 if too early to produce)
 */
static int64_t CalculateAlignedBlockTime(const CBlockIndex* pindexPrev, int64_t nNow, int& outSlot)
{
    outSlot = 0;

    if (!pindexPrev) {
        // Round to nearest time slot for consensus validity
        const int slotLength = Params().GetConsensus().nTimeSlotLength;
        return (nNow / slotLength) * slotLength;
    }

    const Consensus::Params& consensus = Params().GetConsensus();
    int64_t prevTime = pindexPrev->GetBlockTime();

    // NOTE (multi-operator liveness fix): the former bootstrap branch forced slot 0 +
    // 1s spacing for DMM-scheduler blocks at height <= nDMMBootstrapHeight, which (with
    // GetProducerSlot's matching slot-0 force) left no producer fallback and froze
    // multi-operator chains at the bootstrap→DMM handoff. DMM blocks now use the normal
    // path below (nTargetSpacing enforced + fallback after leaderTimeout). Bootstrap-MINED
    // blocks (generatebootstrap) don't use this function and are producer-check-exempt in
    // validation, so this only affects the autonomous DMM blocks and restores their liveness.

    // ═══════════════════════════════════════════════════════════════════════════
    // ENFORCE nTargetSpacing: Block cannot be produced until nTargetSpacing
    // seconds have passed since the previous block.
    // ═══════════════════════════════════════════════════════════════════════════
    int64_t minBlockTime = prevTime + consensus.nTargetSpacing;

    // If current time is before minBlockTime, we cannot produce yet
    if (nNow < minBlockTime) {
        // Return 0 to signal "too early to produce"
        return 0;
    }

    // Calculate time since minimum block time (not since prevTime!)
    // This determines our slot within the production window
    int64_t dt = nNow - minBlockTime;

    // Primary producer window: block can be produced at minBlockTime
    if (dt < consensus.nHuLeaderTimeoutSeconds) {
        outSlot = 0;
        // CRITICAL: Always use minBlockTime in primary slot to keep chain on schedule.
        // This ensures that if a node restarts late (but still within leader timeout),
        // it produces the block with the IDEAL timestamp rather than current time.
        // This prevents permanent chain time drift from node restarts.
        //
        // Ensure minBlockTime is slot-aligned (safety for edge cases)
        int64_t slotLen = consensus.nTimeSlotLength;
        int64_t alignedMinTime = (minBlockTime / slotLen) * slotLen;
        return alignedMinTime;
    }

    // Past leader timeout - we're in fallback territory
    // Calculate which fallback slot we're in
    int64_t extra = dt - consensus.nHuLeaderTimeoutSeconds;
    int rawSlot = 1 + (extra / consensus.nHuFallbackRecoverySeconds);

    // Clamp to max fallback slots
    if (rawSlot > 360) {
        rawSlot = 360;
    }

    outSlot = rawSlot;

    // Align nTime to the START of this fallback slot
    // Base is minBlockTime (not prevTime!) to respect nTargetSpacing
    int64_t alignedTime = minBlockTime + consensus.nHuLeaderTimeoutSeconds +
                          (rawSlot - 1) * consensus.nHuFallbackRecoverySeconds;

    // Round UP to nearest valid time slot (divisible by nTimeSlotLength)
    int64_t slotLen = consensus.nTimeSlotLength;
    if (alignedTime % slotLen != 0) {
        alignedTime = ((alignedTime / slotLen) + 1) * slotLen;
    }

    return alignedTime;
}

bool CActiveDeterministicMasternodeManager::IsLocalBlockProducer(const CBlockIndex* pindexPrev, int64_t& outAlignedTime, uint256& outProTxHash) const
{
    outAlignedTime = 0;
    outProTxHash = UINT256_ZERO;

    if (!pindexPrev) {
        return false;
    }

    // Must be ready
    if (!IsReady()) {
        return false;
    }

    // Get the MN list at this height
    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindexPrev);

    // Calculate aligned block time and slot
    int64_t nNow = GetTime();
    int slot = 0;
    int64_t alignedTime = CalculateAlignedBlockTime(pindexPrev, nNow, slot);

    // If alignedTime is 0, it means we're too early (nTargetSpacing not elapsed)
    if (alignedTime == 0) {
        return false;
    }

    // Use GetExpectedProducer with the aligned time to check who should produce
    // This uses the SAME function that verification will use
    CDeterministicMNCPtr expectedMn;
    int producerIndex = 0;

    if (!mn_consensus::GetExpectedProducer(pindexPrev, alignedTime, mnList, expectedMn, producerIndex)) {
        // No confirmed MNs yet - we can't produce
        return false;
    }

    // MULTI-MN: Check if expected producer is ANY of our managed MNs
    bool isUs = info.HasMN(expectedMn->proTxHash);

    if (isUs) {
        outAlignedTime = alignedTime;
        outProTxHash = expectedMn->proTxHash;

        if (producerIndex > 0) {
            LogPrintf("DMM-SCHEDULER: Local MN %s is FALLBACK producer #%d for block %d (slot=%d, alignedTime=%d)\n",
                     outProTxHash.ToString().substr(0, 16), producerIndex, pindexPrev->nHeight + 1,
                     slot, alignedTime);
        } else {
            LogPrint(BCLog::MASTERNODE, "DMM-SCHEDULER: Local MN %s is PRIMARY producer for block %d\n",
                     outProTxHash.ToString().substr(0, 16), pindexPrev->nHeight + 1);
        }
    }

    return isUs;
}

bool CActiveDeterministicMasternodeManager::TryProducingBlock(const CBlockIndex* pindexPrev)
{
    if (!pindexPrev) {
        return false;
    }

    // Basic state checks
    if (!IsReady()) {
        return false;
    }

    // CRITICAL: Don't produce blocks while ActivateBestChain is running
    // This prevents deadlock when P2P blocks arrive during sync
    // Uses counter to handle recursive/nested calls correctly
    if (g_activating_best_chain.load() > 0) {
        static int64_t nLastABCWarnTime = 0;
        int64_t nNow = GetTime();
        if (nNow - nLastABCWarnTime > 10) {
            LogPrintf("DMM-SCHEDULER: ActivateBestChain in progress, skipping block production\n");
            nLastABCWarnTime = nNow;
        }
        return false;
    }

    // BATHRON: Check sync state (includes bootstrap phase check)
    if (!g_tiertwo_sync_state.IsBlockchainSynced()) {
        static int64_t nLastSyncWarnTime = 0;
        int64_t nNow = GetTime();
        if (nNow - nLastSyncWarnTime > 30) {
            LogPrintf("DMM-SCHEDULER: Waiting for blockchain sync (height=%d)\n", pindexPrev->nHeight);
            nLastSyncWarnTime = nNow;
        }
        return false;
    }

    // BATHRON: Headers-first sync awareness with STALL DETECTION
    // ===============================================================================
    // Problem: headers > blocks is NORMAL during headers-first sync. We must not
    // immediately stop block production just because we received headers ahead of blocks.
    //
    // Solution: Check how many headers are ahead:
    // - headers > 1 ahead: genuine sync in progress, DON'T produce (would deadlock ActivateBestChain)
    // - headers == 1 ahead: could be poison header attack, PRODUCE (ensures liveness)
    //
    // EXCEPTION: Bootstrap phase (height <= nDMMBootstrapHeight) skips this check.
    {
        LOCK(cs_main);
        const Consensus::Params& consensus = Params().GetConsensus();
        int nNextHeight = pindexPrev->nHeight + 1;

        // Stall detection state (persistent across calls)
        static int64_t nStallStartTime = 0;

        // Skip IBD check during bootstrap phase - network is starting fresh
        if (nNextHeight <= consensus.nDMMBootstrapHeight) {
            LogPrint(BCLog::MASTERNODE, "DMM-SCHEDULER: Bootstrap phase (height=%d <= %d), skipping IBD check\n",
                     nNextHeight, consensus.nDMMBootstrapHeight);
            nStallStartTime = 0; // Reset stall tracker
        } else if (pindexBestHeader &&
                   !(pindexBestHeader->nStatus & BLOCK_FAILED_MASK) &&
                   chainActive.Height() < pindexBestHeader->nHeight) {
            // Headers > blocks: be careful about when to produce
            // ===================================================
            // Two scenarios:
            // 1. SYNCING: headers far ahead (>1 block) - we're catching up, DON'T produce
            //    Producing would cause deadlock with ActivateBestChain in progress
            // 2. NEAR TIP: headers just 1 ahead - could be poison header attack, PRODUCE
            //    This ensures liveness against header-based DoS
            int nCurrentBlocks = chainActive.Height();
            int nCurrentHeaders = pindexBestHeader->nHeight;
            int nHeadersAhead = nCurrentHeaders - nCurrentBlocks;

            if (nHeadersAhead > 1) {
                // We're genuinely syncing - blocks are coming from P2P
                // DON'T produce - would cause ActivateBestChain deadlock
                static int64_t nLastSyncWarnTime = 0;
                int64_t nNow = GetTime();
                if (nNow - nLastSyncWarnTime > 30) {
                    LogPrintf("DMM-SCHEDULER: Sync in progress (headers=%d, blocks=%d, ahead=%d), NOT producing\n",
                              nCurrentHeaders, nCurrentBlocks, nHeadersAhead);
                    nLastSyncWarnTime = nNow;
                }
                return false;
            }

            // Headers only 1 ahead - could be poison header, continue production
            static int64_t nLastHeaderWarnTime = 0;
            int64_t nNow = GetTime();
            if (nNow - nLastHeaderWarnTime > 30) {
                LogPrintf("DMM-SCHEDULER: Single header ahead (headers=%d > blocks=%d), continuing production\n",
                          nCurrentHeaders, nCurrentBlocks);
                nLastHeaderWarnTime = nNow;
            }
        } else {
            // headers == blocks or no best header - reset stall tracker
            if (nStallStartTime != 0) {
                LogPrint(BCLog::MASTERNODE, "DMM-SCHEDULER: Blocks caught up, resetting stall tracker\n");
                nStallStartTime = 0;
            }
        }
    }

    // BATHRON v2: HU quorum is now DECOUPLED from block production
    // =========================================================
    // Design principle (ETH2/Tendermint pattern):
    // - DMM produces blocks based on IsBlockchainSynced() only
    // - HU finality runs asynchronously and seals blocks after-the-fact
    // - Anti-reorg protection: never reorg below lastFinalizedHeight
    // - This ensures LIVENESS even when some MNs are offline
    //
    // The old design blocked block production until quorum was reached,
    // which caused chain stalls when MNs went offline (e.g., overnight).
    //
    // Now we just log the quorum status for monitoring purposes.
    {
        const Consensus::Params& consensus = Params().GetConsensus();
        int sigCount = hu::huSignalingManager ? hu::huSignalingManager->GetSignatureCount(pindexPrev->GetBlockHash()) : 0;
        bool hasQuorum = hu::PreviousBlockHasQuorum(pindexPrev);

        // Log quorum status (not blocking)
        static int64_t nLastQuorumLogTime = 0;
        int64_t nNow = GetTime();
        if (nNow - nLastQuorumLogTime > 60) {
            LogPrint(BCLog::MASTERNODE, "DMM-SCHEDULER: Block %d HU status: %d signatures (%s)\n",
                      pindexPrev->nHeight, sigCount,
                      hasQuorum ? "finalized" : "pending");
            nLastQuorumLogTime = nNow;
        }
    }

    // Rate limiting - prevent double production for same height
    int nNextHeight = pindexPrev->nHeight + 1;

    if (nLastProducedHeight.load() >= nNextHeight) {
        // Already produced for this height
        return false;
    }

    // NOTE: We no longer check nLastBlockProduced here because:
    // 1. CalculateAlignedBlockTime() now enforces nTargetSpacing based on chain data
    // 2. The chain-based timing (prevBlockTime + nTargetSpacing) is the authoritative source
    // 3. nLastBlockProduced was a local clock check which could drift vs chain state
    // The nTargetSpacing enforcement in CalculateAlignedBlockTime() ensures blocks
    // cannot be produced faster than 60s apart based on actual chain timestamps.

    // MULTI-MN: Check if we are the designated producer and get the aligned block time + proTxHash
    // The aligned time is calculated based on slot boundaries and MUST be used
    // as the block's nTime to ensure verification produces the same result
    int64_t nAlignedBlockTime = 0;
    uint256 producerProTxHash;
    if (!IsLocalBlockProducer(pindexPrev, nAlignedBlockTime, producerProTxHash)) {
        return false;
    }

    // HA Failover: Check if we need to wait before producing
    // Secondary daemons wait nProduceDelay seconds to give primary a chance to produce first.
    // WARNING: If both daemons produce, blocks will likely DIFFER (different mempool/tx order).
    // This is NOT active-active - it's cold standby with automatic failover.
    if (nProduceDelay > 0) {
        int64_t nNow = GetTime();
        int64_t nEarliestProduceTime = nAlignedBlockTime + nProduceDelay;

        if (nNow < nEarliestProduceTime) {
            // Not yet time to produce for this HA daemon
            LogPrint(BCLog::MASTERNODE, "HA FAILOVER: Waiting %ds before producing block %d (now=%d, earliest=%d)\n",
                     (int)(nEarliestProduceTime - nNow), nNextHeight, (int)nNow, (int)nEarliestProduceTime);
            return false;
        }

        // CRITICAL: Re-check chainActive after delay - primary may have produced while we waited
        {
            LOCK(cs_main);
            if (chainActive.Height() >= nNextHeight) {
                LogPrintf("HA FAILOVER: Block %d already produced by primary during delay, skipping\n", nNextHeight);
                return false;
            }
        }

        LogPrintf("HA FAILOVER: Delay elapsed, secondary daemon producing block %d (delay=%ds)\n",
                  nNextHeight, nProduceDelay);
    }

    LogPrintf("DMM-SCHEDULER: Block producer for height %d is local MN %s (alignedTime=%d) - creating block...\n",
              nNextHeight, producerProTxHash.ToString().substr(0, 16), nAlignedBlockTime);

    // MULTI-MN: Get operator key for the SPECIFIC MN that should produce
    CKey operatorKey;
    CDeterministicMNCPtr dmn;
    auto keyResult = GetOperatorKey(producerProTxHash, operatorKey, dmn);
    if (!keyResult) {
        LogPrintf("DMM-SCHEDULER: ERROR - Failed to get operator key for %s: %s\n",
                  producerProTxHash.ToString().substr(0, 16), keyResult.getError());
        return false;
    }

    // Get payout script from the MN registration (already a CScript)
    CScript scriptPubKey = dmn->pdmnState->scriptPayout;

    // Create block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    {
        LOCK(cs_main);
        pblocktemplate = BlockAssembler(Params(), false).CreateNewBlock(
            scriptPubKey,
            nullptr,    // pwallet
            true,       // fMNBlock
            nullptr,    // availableCoins
            false,      // fNoMempoolTx
            false,      // fTestValidity - we'll sign and validate ourselves
            const_cast<CBlockIndex*>(pindexPrev),
            false,      // stopOnNewBlock
            true        // fIncludeQfc
        );
    }

    if (!pblocktemplate) {
        LogPrintf("DMM-SCHEDULER: ERROR - CreateNewBlock failed\n");
        return false;
    }

    CBlock* pblock = &pblocktemplate->block;

    // CRITICAL: Set the block's nTime to the aligned time calculated by IsLocalBlockProducer
    // This ensures that verification (which uses GetExpectedProducer with block.nTime)
    // produces the SAME producer as the scheduler determined.
    // Without this, there would be a mismatch between production and verification.
    pblock->nTime = nAlignedBlockTime;

    // Finalize merkle root (not done by CreateNewBlock when fTestValidity=false)
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);

    // Sign the block with operator key
    if (!mn_consensus::SignBlockMNOnly(*pblock, operatorKey)) {
        LogPrintf("DMM-SCHEDULER: ERROR - SignBlockMNOnly failed\n");
        return false;
    }

    LogPrintf("DMM-SCHEDULER: Block %s signed successfully (sig size: %d)\n",
              pblock->GetHash().ToString().substr(0, 16), pblock->vchBlockSig.size());

    // CRITICAL: Re-check that chain tip hasn't moved since we started creating the block
    // This prevents deadlock when blocks arrive from P2P while we're creating our block.
    // If another ActivateBestChain is in progress, submitting our stale block would cause
    // lock contention on m_cs_chainstate.
    {
        LOCK(cs_main);
        if (chainActive.Tip() != pindexPrev) {
            LogPrintf("DMM-SCHEDULER: Chain tip moved during block creation (was %s height=%d, now %s height=%d), abandoning block\n",
                      pindexPrev->GetBlockHash().ToString().substr(0, 16), pindexPrev->nHeight,
                      chainActive.Tip()->GetBlockHash().ToString().substr(0, 16), chainActive.Tip()->nHeight);
            return false;
        }
    }

    // Submit the block
    std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(*pblock);
    bool fAccepted = ProcessNewBlock(shared_pblock, nullptr);

    if (fAccepted) {
        nLastBlockProduced.store(GetTime());
        nLastProducedHeight.store(nNextHeight);

        LogPrintf("DMM-SCHEDULER: Block %s submitted and ACCEPTED at height %d\n",
                  pblock->GetHash().ToString().substr(0, 16), nNextHeight);
        return true;
    } else {
        LogPrintf("DMM-SCHEDULER: Block %s REJECTED\n", pblock->GetHash().ToString().substr(0, 16));
        return false;
    }
}

void CActiveDeterministicMasternodeManager::StartDMMScheduler()
{
    if (fDMMSchedulerRunning.load()) {
        LogPrint(BCLog::MASTERNODE, "DMM-SCHEDULER: Already running\n");
        return;
    }

    fDMMSchedulerRunning.store(true);
    LogPrintf("DMM-SCHEDULER: Starting periodic block producer thread (check interval=%ds, block interval=%ds)\n",
              DMM_CHECK_INTERVAL_SECONDS, DMM_BLOCK_INTERVAL_SECONDS);

    dmmSchedulerThread = std::thread([this]() {
        while (fDMMSchedulerRunning.load() && !ShutdownRequested()) {
            // Check frequently (every DMM_CHECK_INTERVAL_SECONDS) to not miss our production window
            // The fallback rotates every nHuFallbackRecoverySeconds (15s on testnet),
            // so we need to check more often than that to catch our slot
            for (int i = 0; i < DMM_CHECK_INTERVAL_SECONDS * 10 && fDMMSchedulerRunning.load() && !ShutdownRequested(); ++i) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            if (!fDMMSchedulerRunning.load() || ShutdownRequested()) {
                break;
            }

            // Get current chain tip
            const CBlockIndex* pindexTip = nullptr;
            {
                LOCK(cs_main);
                pindexTip = chainActive.Tip();
            }

            if (pindexTip && IsReady()) {
                TryProducingBlock(pindexTip);
            }
        }
        LogPrintf("DMM-SCHEDULER: Periodic thread stopped\n");
    });
}

void CActiveDeterministicMasternodeManager::StopDMMScheduler()
{
    if (!fDMMSchedulerRunning.load()) {
        return;
    }

    LogPrintf("DMM-SCHEDULER: Stopping periodic thread...\n");
    fDMMSchedulerRunning.store(false);

    if (dmmSchedulerThread.joinable()) {
        dmmSchedulerThread.join();
    }
    LogPrintf("DMM-SCHEDULER: Stopped\n");
}


// ============================================================================
// DMN-Only Helper Functions (Legacy system removed)
// ============================================================================

bool GetActiveDMNKeys(CKey& key, CTxIn& vin)
{
    if (activeMasternodeManager == nullptr) {
        return error("%s: Active Masternode not initialized", __func__);
    }
    CDeterministicMNCPtr dmn;
    auto res = activeMasternodeManager->GetOperatorKey(key, dmn);
    if (!res) {
        return error("%s: %s", __func__, res.getError());
    }
    vin = CTxIn(dmn->collateralOutpoint);
    return true;
}

