// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_TIERTWO_TIERTWO_SYNC_STATE_H
#define BATHRON_TIERTWO_TIERTWO_SYNC_STATE_H

#include <atomic>

// Sync states
#define MASTERNODE_SYNC_INITIAL 0
#define MASTERNODE_SYNC_FINISHED 999

// Sync timeout: consider synced if we received a finalized block in last 120 seconds
#define BATHRON_SYNC_TIMEOUT 120

class TierTwoSyncState {
public:
    // Synced if we received a finalized block recently (quorum achieved)
    bool IsBlockchainSynced() const;
    bool IsSynced() const { return IsBlockchainSynced(); }

    // Called when a finalized block is received (has HU quorum)
    void OnFinalizedBlock(int64_t timestamp);

    // Set current chain height (called from validation)
    void SetChainHeight(int height) { m_chain_height.store(height); }
    int GetChainHeight() const { return m_chain_height.load(); }

    // Get sync phase
    int GetSyncPhase() const { return IsSynced() ? MASTERNODE_SYNC_FINISHED : MASTERNODE_SYNC_INITIAL; }

    // Reset state
    void ResetData() { m_last_finalized_time.store(0); }

private:
    std::atomic<int> m_chain_height{0};
    std::atomic<int64_t> m_last_finalized_time{0};
};

extern TierTwoSyncState g_tiertwo_sync_state;

#endif // BATHRON_TIERTWO_TIERTWO_SYNC_STATE_H
