// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SETTLEMENTDB_H
#define SETTLEMENTDB_H

/**
 * Settlement Layer Database
 *
 * Ref: doc/blueprints/done/BP30-SETTLEMENT.md
 *
 * Provides DB-driven helpers for UTXO classification:
 * - IsVault(outpoint) -> bool
 * - IsM1Receipt(outpoint) -> bool
 * - IsM0Standard(outpoint) -> bool (not in any index)
 */

#include "dbwrapper.h"
#include "state/settlement.h"

#include <functional>
#include <memory>
#include <vector>

class CSettlementDB
{
private:
    std::unique_ptr<CDBWrapper> db;

public:
    explicit CSettlementDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CSettlementDB();

    // Vault operations
    bool WriteVault(const VaultEntry& vault);
    bool ReadVault(const COutPoint& outpoint, VaultEntry& vault) const;
    bool EraseVault(const COutPoint& outpoint);
    bool IsVault(const COutPoint& outpoint) const;

    /**
     * ForEachVault - Iterate over all vaults in the database
     *
     * BP30 v2.0: Used by wallet to find vaults for TX_UNLOCK (bearer model).
     * Any vault can be used to back any M1 - no linkage required.
     *
     * @param func Callback function (return false to stop iteration)
     */
    void ForEachVault(std::function<bool(const VaultEntry&)> func) const;

    /**
     * FindVaultsForAmount - Find vault(s) to cover a specific M0 amount
     *
     * BP30 v2.0: For bearer model unlock. Finds smallest set of vaults
     * that covers the requested amount. Prefers single exact match.
     *
     * @param amount M0 amount needed
     * @param vaults Output vector of matching vaults
     * @return true if vaults found with sum >= amount
     */
    bool FindVaultsForAmount(CAmount amount, std::vector<VaultEntry>& vaults) const;

    // M1 Receipt operations
    bool WriteReceipt(const M1Receipt& receipt);
    bool ReadReceipt(const COutPoint& outpoint, M1Receipt& receipt) const;
    bool EraseReceipt(const COutPoint& outpoint);
    bool IsM1Receipt(const COutPoint& outpoint) const;

    // B4.4 O2b — fee-receipt owner (destination covenant). Present iff the outpoint
    // is an M1 fee-receipt registered at connect under UPGRADE_FEE_RECEIPT_PINNED;
    // ownerScript = the including block's coinbase vout[0] script. Absence = legacy
    // (pre-gate) fee-receipt = unowned = spendable by anyone (current behaviour).
    bool WriteFeeOwner(const COutPoint& outpoint, const CScript& ownerScript);
    bool ReadFeeOwner(const COutPoint& outpoint, CScript& ownerScript) const;
    bool IsFeeOwned(const COutPoint& outpoint) const;

    /**
     * ForEachFeeOwner - iterate all fee-owner entries ('F' prefix).
     * Used by the sweep tooling (RPC sweepfees) to find the fee-receipts a
     * given producer owns. Callback returns false to stop iteration.
     */
    void ForEachFeeOwner(std::function<bool(const COutPoint&, const CScript&)> func) const;

    // Settlement state snapshots
    bool WriteState(const SettlementState& state);
    bool ReadState(uint32_t height, SettlementState& state) const;
    bool ReadLatestState(SettlementState& state) const;

    // Unlock undo data (BP30 v2.1 - keyed by txid)
    bool WriteUnlockUndo(const uint256& txid, const UnlockUndoData& undoData);
    bool ReadUnlockUndo(const uint256& txid, UnlockUndoData& undoData) const;

    // Transfer undo data (BP30 v2.2 - keyed by txid)
    bool WriteTransferUndo(const uint256& txid, const TransferUndoData& undoData);
    bool ReadTransferUndo(const uint256& txid, TransferUndoData& undoData) const;

    // Best block tracking (BP30 v2.2 - chain consistency)
    bool WriteBestBlock(const uint256& blockHash);
    bool ReadBestBlock(uint256& blockHash) const;

    // ATOMICITY FIX: Commit marker for crash recovery
    // Written AFTER all DBs (Settlement/Burnclaim) have committed.
    // At startup, if this differs from chain tip → need reindex.
    bool WriteAllCommitted(const uint256& blockHash);
    bool ReadAllCommitted(uint256& blockHash) const;

    // F3 Burnscan tracking: last processed BTC block for catch-up RPC
    // Written after each burnscan iteration to track progress.
    // Used for: (1) resume after restart, (2) reorg detection via hash mismatch
    bool WriteBurnscanProgress(uint32_t height, const uint256& hash);
    bool ReadBurnscanProgress(uint32_t& height, uint256& hash) const;

    /**
     * IsM0Standard - Check if outpoint is a standard M0 UTXO
     *
     * DB-driven: returns true if NOT in any settlement index (V/R).
     * This is the canonical way to determine if a UTXO is standard M0.
     */
    bool IsM0Standard(const COutPoint& outpoint) const;

    // Batch operations for atomic updates
    class Batch
    {
    private:
        CDBBatch batch;
        CSettlementDB& parent;

    public:
        explicit Batch(CSettlementDB& db);

        void WriteVault(const VaultEntry& vault);
        void EraseVault(const COutPoint& outpoint);
        void WriteReceipt(const M1Receipt& receipt);
        void EraseReceipt(const COutPoint& outpoint);
        void WriteFeeOwner(const COutPoint& outpoint, const CScript& ownerScript);  // B4.4 O2b
        void EraseFeeOwner(const COutPoint& outpoint);                              // B4.4 O2b
        void WriteState(const SettlementState& state);
        void WriteUnlockUndo(const uint256& txid, const UnlockUndoData& undoData);
        void EraseUnlockUndo(const uint256& txid);
        void WriteTransferUndo(const uint256& txid, const TransferUndoData& undoData);
        void EraseTransferUndo(const uint256& txid);
        void WriteBestBlock(const uint256& blockHash);

        // GC schedule of unlock/transfer undo data — see SETTLEMENT_UNDO_PRUNE_DEPTH.
        void WriteUndoPruneSchedule(uint32_t height, const uint256& txid, uint8_t undoType);
        void EraseUndoPruneSchedule(uint32_t height, const uint256& txid);

        bool Commit();
    };

    Batch CreateBatch() { return Batch(*this); }

    /**
     * PruneUndoAtHeight - GC unlock/transfer undo data scheduled at a height.
     *
     * For each (txid, undoType) scheduled at `undoHeight`, stages (into `batch`) the
     * erasure of the corresponding DB_UNLOCK_UNDO / DB_TRANSFER_UNDO record and the
     * schedule entry. Safe iff undoHeight is deeper than any possible reorg (see
     * SETTLEMENT_UNDO_PRUNE_DEPTH): the undo record is then never read again. Erase
     * is idempotent, so a reorged-away tx (undo already erased on disconnect) just
     * cleans up its stale schedule entry. Deterministic across nodes; caller commits.
     */
    void PruneUndoAtHeight(uint32_t undoHeight, Batch& batch);

    // Sync to disk
    bool Sync();
};

// Global settlement DB instance
extern std::unique_ptr<CSettlementDB> g_settlementdb;

/**
 * InitSettlementDB - Initialize the settlement database
 *
 * Called during node startup. Creates the database and optionally wipes it.
 *
 * @param nCacheSize DB cache size in bytes
 * @param fMemory If true, use in-memory database (for tests)
 * @param fWipe If true, wipe and recreate DB
 * @return true on success
 */
bool InitSettlementDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

/**
 * InitSettlementAtGenesis - Initialize settlement state at genesis
 *
 * Creates genesis SettlementState with:
 *   M0_vaulted = 0
 *   M1_supply = 0
 *   M0_shielded = 0
 *   M0_total_supply = 0
 *
 * @param genesisBlockHash Hash of genesis block
 * @return true on success
 */
bool InitSettlementAtGenesis(const uint256& genesisBlockHash);

/**
 * CheckSettlementDBConsistency - Verify settlement DB matches chain tip
 *
 * BP30 v2.2: Called at startup after LoadChainTip to detect DB/chain inconsistency.
 *
 * @param chainTipHash The current chain tip hash
 * @param chainTipHeight The current chain tip height
 * @param fRequireRebuild[out] Set to true if settlement DB needs full rebuild
 * @return true if consistent (or empty DB), false if corrupted/orphaned
 */
bool CheckSettlementDBConsistency(const uint256& chainTipHash, int chainTipHeight, bool& fRequireRebuild);

/**
 * RebuildSettlementFromChain - Reconstruct settlement state from blockchain
 *
 * BP30 Rebuild-From-Truth: Replays all blocks from height=1 to chain tip,
 * reconstructing the settlement state (m0_total, m0_vaulted, m1_supply, etc.)
 * by calling ProcessSpecialTxsInBlock for each block.
 *
 * This makes settlement/ a cache, not a source of truth.
 *
 * @return true on success, false on error
 */
bool RebuildSettlementFromChain();

/**
 * IsSettlementDBMissing - Check if settlement directory exists
 *
 * @return true if settlement/ directory is missing or empty
 */
bool IsSettlementDBMissing();

#endif // SETTLEMENTDB_H
