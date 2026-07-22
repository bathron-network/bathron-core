// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_HTLCDB_H
#define BATHRON_HTLCDB_H

/**
 * HTLC Database Layer
 *
 * Ref: doc/blueprints/todo/02-HTLC-M1.md
 *
 * Provides persistence for HTLC records:
 * - WriteHTLC / ReadHTLC / EraseHTLC (by outpoint)
 * - GetByHashlock (for cross-chain matching)
 * - GetActive / GetExpired (for wallet listing)
 */

#include "dbwrapper.h"
#include "htlc/htlc.h"

#include <functional>
#include <memory>
#include <vector>

class CHtlcDB
{
private:
    std::unique_ptr<CDBWrapper> db;

public:
    explicit CHtlcDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CHtlcDB();

    // === HTLC Record Operations ===

    /**
     * WriteHTLC - Store HTLC record
     * @param htlc The HTLC record to store
     * @return true on success
     */
    bool WriteHTLC(const HTLCRecord& htlc);

    /**
     * ReadHTLC - Retrieve HTLC record by outpoint
     * @param outpoint The HTLC outpoint
     * @param htlc Output: the HTLC record
     * @return true if found
     */
    bool ReadHTLC(const COutPoint& outpoint, HTLCRecord& htlc) const;

    /**
     * EraseHTLC - Remove HTLC record
     * @param outpoint The HTLC outpoint to erase
     * @return true on success
     */
    bool EraseHTLC(const COutPoint& outpoint);

    /**
     * IsHTLC - Check if outpoint is an active HTLC
     * @param outpoint The outpoint to check
     * @return true if exists in HTLC index
     */
    bool IsHTLC(const COutPoint& outpoint) const;

    // === Hashlock Index Operations ===

    /**
     * WriteHashlockIndex - Add outpoint to hashlock index
     * @param hashlock The hashlock
     * @param outpoint The HTLC outpoint
     */
    bool WriteHashlockIndex(const uint256& hashlock, const COutPoint& outpoint);

    /**
     * EraseHashlockIndex - Remove outpoint from hashlock index
     * @param hashlock The hashlock
     * @param outpoint The HTLC outpoint to remove
     */
    bool EraseHashlockIndex(const uint256& hashlock, const COutPoint& outpoint);

    /**
     * GetByHashlock - Find all HTLCs with a specific hashlock
     *
     * Used for cross-chain matching: when you see a hashlock on another chain,
     * you can find the corresponding HTLC on BATHRON.
     *
     * @param hashlock The hashlock to search for
     * @param outpoints Output: matching HTLC outpoints
     * @return true if any found
     */
    bool GetByHashlock(const uint256& hashlock, std::vector<COutPoint>& outpoints) const;

    // === Query Operations ===

    /**
     * ForEachHTLC - Iterate over all HTLCs
     * @param func Callback (return false to stop)
     */
    void ForEachHTLC(std::function<bool(const HTLCRecord&)> func) const;

    /**
     * GetActive - Get all active (non-resolved) HTLCs
     * @param htlcs Output: active HTLC records
     */
    void GetActive(std::vector<HTLCRecord>& htlcs) const;


    // === Undo Data Operations ===

    /**
     * WriteCreateUndo - Store undo data for HTLC_CREATE_M1
     * @param txid The create transaction ID
     * @param undoData The undo data
     */
    bool WriteCreateUndo(const uint256& txid, const HTLCCreateUndoData& undoData);

    /**
     * ReadCreateUndo - Retrieve create undo data
     * @param txid The create transaction ID
     * @param undoData Output: the undo data
     */
    bool ReadCreateUndo(const uint256& txid, HTLCCreateUndoData& undoData) const;

    /**
     * EraseCreateUndo - Remove create undo data
     * @param txid The create transaction ID
     */
    bool EraseCreateUndo(const uint256& txid);

    /**
     * WriteResolveUndo - Store undo data for HTLC_CLAIM or HTLC_REFUND
     * @param txid The resolve transaction ID
     * @param undoData The undo data
     */
    bool WriteResolveUndo(const uint256& txid, const HTLCResolveUndoData& undoData);

    /**
     * ReadResolveUndo - Retrieve resolve undo data
     * @param txid The resolve transaction ID
     * @param undoData Output: the undo data
     */
    bool ReadResolveUndo(const uint256& txid, HTLCResolveUndoData& undoData) const;

    /**
     * EraseResolveUndo - Remove resolve undo data
     * @param txid The resolve transaction ID
     */
    bool EraseResolveUndo(const uint256& txid);

    // === Best Block Tracking ===

    bool WriteBestBlock(const uint256& blockHash);
    bool ReadBestBlock(uint256& blockHash) const;

    // ==========================================================================
    // HTLC3S - 3-Secret HTLC Operations (FlowSwap)
    // ==========================================================================

    // === HTLC3S Record Operations ===

    bool WriteHTLC3S(const HTLC3SRecord& htlc);
    bool ReadHTLC3S(const COutPoint& outpoint, HTLC3SRecord& htlc) const;
    bool EraseHTLC3S(const COutPoint& outpoint);
    bool IsHTLC3S(const COutPoint& outpoint) const;

    // === HTLC3S Hashlock Index Operations (3 separate indices) ===

    bool WriteHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint);
    bool WriteHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint);
    bool WriteHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint);

    bool EraseHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint);
    bool EraseHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint);
    bool EraseHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint);

    // Cross-chain matching: find HTLC3S by any revealed secret
    bool GetByHashlock3SUser(const uint256& hashlock, std::vector<COutPoint>& outpoints) const;
    bool GetByHashlock3SLp1(const uint256& hashlock, std::vector<COutPoint>& outpoints) const;
    bool GetByHashlock3SLp2(const uint256& hashlock, std::vector<COutPoint>& outpoints) const;

    // === HTLC3S Query Operations ===

    void ForEachHTLC3S(std::function<bool(const HTLC3SRecord&)> func) const;
    void GetActive3S(std::vector<HTLC3SRecord>& htlcs) const;

    // === HTLC3S Undo Data Operations ===

    bool WriteCreate3SUndo(const uint256& txid, const HTLC3SCreateUndoData& undoData);
    bool ReadCreate3SUndo(const uint256& txid, HTLC3SCreateUndoData& undoData) const;
    bool EraseCreate3SUndo(const uint256& txid);

    bool WriteResolve3SUndo(const uint256& txid, const HTLC3SResolveUndoData& undoData);
    bool ReadResolve3SUndo(const uint256& txid, HTLC3SResolveUndoData& undoData) const;
    bool EraseResolve3SUndo(const uint256& txid);

    // === Batch Operations ===

    class Batch
    {
    private:
        CDBBatch batch;
        CHtlcDB& parent;

    public:
        explicit Batch(CHtlcDB& db);

        void WriteHTLC(const HTLCRecord& htlc);
        void EraseHTLC(const COutPoint& outpoint);
        void WriteHashlockIndex(const uint256& hashlock, const COutPoint& outpoint);
        void EraseHashlockIndex(const uint256& hashlock, const COutPoint& outpoint);
        void WriteCreateUndo(const uint256& txid, const HTLCCreateUndoData& undoData);
        void EraseCreateUndo(const uint256& txid);
        void WriteResolveUndo(const uint256& txid, const HTLCResolveUndoData& undoData);
        void EraseResolveUndo(const uint256& txid);
        void WriteBestBlock(const uint256& blockHash);

        // Prune schedule (GC of resolved HTLCs — see HTLC_PRUNE_DEPTH). Written at
        // resolution height by ApplyHTLC*Claim/Refund; consumed by PruneResolvedAtHeight.
        void WritePruneSchedule(uint32_t height, const COutPoint& outpoint, bool is3S);
        void ErasePruneSchedule(uint32_t height, const COutPoint& outpoint);

        // HTLC3S batch operations
        void WriteHTLC3S(const HTLC3SRecord& htlc);
        void EraseHTLC3S(const COutPoint& outpoint);
        void WriteHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint);
        void WriteHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint);
        void WriteHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint);
        void EraseHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint);
        void EraseHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint);
        void EraseHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint);
        void WriteCreate3SUndo(const uint256& txid, const HTLC3SCreateUndoData& undoData);
        void EraseCreate3SUndo(const uint256& txid);
        void WriteResolve3SUndo(const uint256& txid, const HTLC3SResolveUndoData& undoData);
        void EraseResolve3SUndo(const uint256& txid);

        bool Commit();
    };

    Batch CreateBatch() { return Batch(*this); }

    /**
     * PruneResolvedAtHeight - GC resolved HTLC/HTLC3S records scheduled at a height.
     *
     * For each outpoint scheduled at `resolveHeight`, stages (into `batch`) the
     * erasure of its record, hashlock index/indices, and create+resolve undo data —
     * but ONLY if the record still exists AND is RESOLVED (defensive: a resolution
     * that was reorged away leaves the record ACTIVE or gone, in which case only the
     * stale schedule entry is cleaned up, never an active record). The schedule
     * entry itself is always erased. Caller commits the batch.
     *
     * Safe iff resolveHeight is deeper than any possible reorg (see HTLC_PRUNE_DEPTH):
     * a pruned record can then never be needed by an undo. Deterministic across nodes.
     */
    void PruneResolvedAtHeight(uint32_t resolveHeight, Batch& batch);

    // Total number of live HTLC + HTLC3S records (test/introspection helper).
    size_t CountRecords() const;

    // Sync to disk
    bool Sync();
};

// Global HTLC DB instance
extern std::unique_ptr<CHtlcDB> g_htlcdb;

/**
 * InitHtlcDB - Initialize the HTLC database
 *
 * Called during node startup after InitSettlementDB.
 *
 * @param nCacheSize DB cache size in bytes
 * @param fMemory If true, use in-memory database (for tests)
 * @param fWipe If true, wipe and recreate DB
 * @return true on success
 */
bool InitHtlcDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

/**
 * IsHtlcDBMissing - Check if htlc directory exists
 * @return true if htlc/ directory is missing or empty
 */

#endif // BATHRON_HTLCDB_H
