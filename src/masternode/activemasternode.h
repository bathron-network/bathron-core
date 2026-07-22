// Copyright (c) 2014-2021 The Dash Core developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_ACTIVEMASTERNODE_H
#define BATHRON_ACTIVEMASTERNODE_H

#include "key.h"
#include "masternode/deterministicmns.h"
#include "operationresult.h"
#include "sync.h"
#include "validationinterface.h"
#include "vrf.h"

#include <atomic>
#include <thread>

class CActiveDeterministicMasternodeManager;

extern CActiveDeterministicMasternodeManager* activeMasternodeManager;

/**
 * OPERATOR-CENTRIC v4.0: Structure to hold information about managed masternodes
 *
 * Blueprint 15: One operator key = N masternodes
 * - EXACTLY ONE operatorPubKey per daemon (enforced at init)
 * - Identity = operatorPubKey (not proTxHash)
 * - One key in bathron.conf = N MNs found on-chain automatically
 * - Multiple different keys on same daemon = REJECTED (prevents Sybil)
 *
 * Structure:
 * - operatorKey: the single operator key (stored in map for compatibility)
 * - managedMNs: set of proTxHashes found on-chain with our key
 */
struct CActiveMasternodeInfo
{
    // OPERATOR-CENTRIC v4.0: Single operator key (stored in map for compatibility)
    // Only ONE entry allowed - enforced at daemon init in init.cpp
    std::map<uint256, CKey> operatorKeys;

    // OPERATOR-CENTRIC v4.0: MNs found on-chain for our operator key
    // All MNs use the same key, so pubKeyId is always the same
    std::map<uint256, uint256> managedMNs;

    // Shared service address for all managed MNs
    CService service;

    // Legacy single-MN accessors (for backward compatibility)
    CPubKey GetFirstPubKeyOperator() const {
        if (operatorKeys.empty()) return CPubKey();
        return operatorKeys.begin()->second.GetPubKey();
    }
    CKey GetFirstKeyOperator() const {
        if (operatorKeys.empty()) return CKey();
        return operatorKeys.begin()->second;
    }
    uint256 GetFirstProTxHash() const {
        if (managedMNs.empty()) return UINT256_ZERO;
        return managedMNs.begin()->first;
    }

    // MULTI-MN v4.0: Check if we manage a specific proTxHash
    bool HasMN(const uint256& proTxHash) const {
        return managedMNs.count(proTxHash) > 0;
    }

    // MULTI-MN v4.0: Get operator key for a specific proTxHash
    bool GetOperatorKey(const uint256& proTxHash, CKey& keyOut) const {
        auto it = managedMNs.find(proTxHash);
        if (it == managedMNs.end()) return false;

        auto keyIt = operatorKeys.find(it->second);
        if (keyIt == operatorKeys.end()) return false;

        keyOut = keyIt->second;
        return true;
    }

    // VRF (étape 3.1b): derive the dedicated VRF key for a managed MN from its
    // operator key (vrf::DeriveKeyFromOperator). No separate secret is stored —
    // the operator key the node already holds is the single source. Used by the
    // finality signing path to produce the sortition proof for this block.
    // MULTI-MN v4.0: Get all managed proTxHashes
    std::vector<uint256> GetManagedProTxHashes() const {
        std::vector<uint256> result;
        result.reserve(managedMNs.size());
        for (const auto& p : managedMNs) {
            if (!p.first.IsNull()) {
                result.push_back(p.first);
            }
        }
        return result;
    }

    // MULTI-MN v4.0: Get operator key by pubkey hash
    bool GetKeyByPubKeyId(const uint256& pubKeyId, CKey& keyOut) const {
        auto it = operatorKeys.find(pubKeyId);
        if (it != operatorKeys.end()) {
            keyOut = it->second;
            return true;
        }
        return false;
    }

    // MULTI-MN v4.0: Add an operator key (called during config loading)
    bool AddOperatorKey(const CKey& key) {
        CPubKey pubKey = key.GetPubKey();
        uint256 pubKeyId = pubKey.GetHash();
        if (operatorKeys.count(pubKeyId) > 0) {
            return false;  // Already added
        }
        operatorKeys[pubKeyId] = key;
        return true;
    }

    // MULTI-MN v4.0: Register a MN as managed (called when found on-chain)
    void AddManagedMN(const uint256& proTxHash, const uint256& pubKeyId) {
        managedMNs[proTxHash] = pubKeyId;
    }

    // MULTI-MN v4.0: Remove a MN (called when MN disappears from chain)
    void RemoveManagedMN(const uint256& proTxHash) {
        managedMNs.erase(proTxHash);
    }

    // MULTI-MN v4.0: Clear all managed MNs (for re-init)
    void ClearManagedMNs() {
        managedMNs.clear();
    }

    // Count of operator keys loaded
    size_t GetOperatorKeyCount() const { return operatorKeys.size(); }

    // Count of MNs actually managed (found on-chain)
    size_t GetManagedCount() const { return managedMNs.size(); }

    // Check if any MN is managed
    bool HasAnyMN() const { return !managedMNs.empty(); }

    // Check if we have any operator keys
    bool HasAnyKey() const { return !operatorKeys.empty(); }
};

class CActiveDeterministicMasternodeManager : public CValidationInterface
{
public:
    enum masternode_state_t {
        MASTERNODE_WAITING_FOR_PROTX,
        MASTERNODE_POSE_BANNED,
        MASTERNODE_REMOVED,
        MASTERNODE_OPERATOR_KEY_CHANGED,
        MASTERNODE_PROTX_IP_CHANGED,
        MASTERNODE_READY,
        MASTERNODE_ERROR,
    };

private:
    masternode_state_t state{MASTERNODE_WAITING_FOR_PROTX};
    std::string strError;
    CActiveMasternodeInfo info;

    std::atomic<int64_t> nLastBlockProduced{0};
    std::atomic<int> nLastProducedHeight{0};
    std::atomic<bool> fDMMSchedulerRunning{false};
    std::thread dmmSchedulerThread;
    static constexpr int DMM_BLOCK_INTERVAL_SECONDS = 60;    // Minimum time between blocks we produce
    static constexpr int DMM_CHECK_INTERVAL_SECONDS = 2;     // How often to check if we should produce (reduced for reliability)
    static constexpr int DMM_MISSED_BLOCK_TIMEOUT = 90;

    // HA Failover: Delay before producing blocks (-mn_produce_delay)
    // Primary=0, Secondary=5, Tertiary=10. ECDSA deterministic signatures ensure identical blocks.
    int nProduceDelay{0};

public:
    ~CActiveDeterministicMasternodeManager() override { StopDMMScheduler(); }
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override;

    void Init(const CBlockIndex* pindexTip);
    void Reset(masternode_state_t _state, const CBlockIndex* pindexTip);

    // MULTI-MN: Add operator key (can be called multiple times for multi-MN)
    OperationResult AddOperatorKey(const std::string& strMNOperatorPrivKey);

    // Legacy single-key setter (calls AddOperatorKey internally)
    OperationResult SetOperatorKey(const std::string& strMNOperatorPrivKey) { return AddOperatorKey(strMNOperatorPrivKey); }

    // MULTI-MN: Get operator key for a specific proTxHash
    OperationResult GetOperatorKey(const uint256& proTxHash, CKey& key, CDeterministicMNCPtr& dmn) const;

    // Legacy: Get operator key for the first managed MN
    OperationResult GetOperatorKey(CKey& key, CDeterministicMNCPtr& dmn) const;

    // MULTI-MN: Get all managed proTxHashes
    std::vector<uint256> GetManagedProTxHashes() const { return info.GetManagedProTxHashes(); }

    // MULTI-MN: Get count of managed MNs
    size_t GetManagedCount() const { return info.GetManagedCount(); }

    // HA Failover: Set production delay (from -mn_produce_delay)
    void SetProduceDelay(int nDelay) { nProduceDelay = nDelay; }
    int GetProduceDelay() const { return nProduceDelay; }

    // Accessors for first MN (multi-MN mode uses info.GetManagedMNs())
    const uint256 GetProTx() const { return info.GetFirstProTxHash(); }

    const CActiveMasternodeInfo* GetInfo() const { return &info; }
    masternode_state_t GetState() const { return state; }
    std::string GetStatus() const;
    bool IsReady() const { return state == MASTERNODE_READY; }

    static bool IsValidNetAddr(const CService& addrIn);

    bool TryProducingBlock(const CBlockIndex* pindexPrev);

    /**
     * MULTI-MN: Check if any local MN is the designated block producer.
     *
     * @param pindexPrev        Previous block index
     * @param outAlignedTime    [out] The aligned block timestamp to use if producing
     * @param outProTxHash      [out] The proTxHash of the MN that should produce
     * @return                  true if a local MN should produce the next block
     */
    bool IsLocalBlockProducer(const CBlockIndex* pindexPrev, int64_t& outAlignedTime, uint256& outProTxHash) const;

    void StartDMMScheduler();
    void StopDMMScheduler();
};

bool GetActiveDMNKeys(CKey& key, CTxIn& vin);

#endif // BATHRON_ACTIVEMASTERNODE_H
