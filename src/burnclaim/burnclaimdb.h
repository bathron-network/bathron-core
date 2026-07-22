// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BURNCLAIMDB_H
#define BATHRON_BURNCLAIMDB_H

/**
 * Burn Claim Database (BP11)
 *
 * LevelDB storage for BTC burn claims with the following schema:
 *
 * Key Prefixes:
 *   'Cc' || btc_txid (32 bytes)  -> BurnClaimRecord (main record)
 *   'Cs' || status (1) || claim_height (4 BE) || btc_txid -> (empty) (status index)
 *   'Cd' || bathron_dest (20) || btc_txid -> (empty) (destination index)
 *   'Cm' -> uint64_t (M0BTC supply counter, in satoshis)
 *   'Cb' -> uint256 (best block hash for consistency check)
 *
 * NORMATIVE: StoreBurnClaim() is an "upsert" that:
 *   1. Loads existing record (if present)
 *   2. Deletes old index keys
 *   3. Writes new record
 *   4. Writes new index keys
 */

#include "burnclaim/burnclaim.h"
#include "dbwrapper.h"

#include <functional>
#include <memory>
#include <vector>

class CBurnClaimDB
{
private:
    std::unique_ptr<CDBWrapper> db;

    // Internal: delete indices for a record
    void DeleteIndices(CDBBatch& batch, const BurnClaimRecord& record);
    // Internal: write indices for a record
    void WriteIndices(CDBBatch& batch, const BurnClaimRecord& record);

public:
    explicit CBurnClaimDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CBurnClaimDB();

    //==========================================================================
    // Claim Record Operations
    //==========================================================================

    /**
     * Store a burn claim record (upsert).
     *
     * If a record with the same btcTxid exists, it is overwritten.
     * Old indices are cleaned up, new indices are created.
     */
    bool StoreBurnClaim(const BurnClaimRecord& record);

    /**
     * Get a burn claim record by BTC txid.
     */
    bool GetBurnClaim(const uint256& btcTxid, BurnClaimRecord& record) const;

    /**
     * Delete a burn claim record and its indices.
     */
    bool DeleteBurnClaim(const uint256& btcTxid);

    /**
     * Check if a burn claim exists.
     */
    bool ExistsBurnClaim(const uint256& btcTxid) const;

    //==========================================================================
    // Iteration
    //==========================================================================

    /**
     * Iterate over all PENDING claims.
     *
     * Used for finalization: find claims eligible for PENDING -> FINAL.
     *
     * @param func Callback (return false to stop)
     */
    void ForEachPendingClaim(std::function<bool(const BurnClaimRecord&)> func) const;

    /**
     * Iterate over all FINAL claims.
     *
     * @param func Callback (return false to stop)
     */
    void ForEachFinalClaim(std::function<bool(const BurnClaimRecord&)> func) const;


    //==========================================================================
    // M0BTC Supply Counter
    //==========================================================================

    /**
     * Get current M0BTC supply (satoshis).
     *
     * Only counts FINAL claims.
     */
    uint64_t GetM0BTCSupply() const;

    /**
     * Increment M0BTC supply.
     *
     * Called by ConnectMintM0BTC() when claims finalize.
     */
    bool IncrementM0BTCSupply(uint64_t amount);

    /**
     * Decrement M0BTC supply.
     *
     * Called by DisconnectMintM0BTC() on reorg.
     */
    bool DecrementM0BTCSupply(uint64_t amount);

    //==========================================================================
    // Consistency
    //==========================================================================

    /**
     * Write best block hash (for chain consistency check).
     */
    bool WriteBestBlock(const uint256& blockHash);

    /**
     * Read best block hash.
     */
    bool ReadBestBlock(uint256& blockHash) const;

    //==========================================================================
    // Batch Operations
    //==========================================================================

    class Batch
    {
    private:
        CDBBatch batch;
        CBurnClaimDB& parent;
        // R6: running supply delta for THIS batch. Increment/Decrement must
        // compose within one batch (a block can mint several claims), so they
        // accumulate here on top of the committed value rather than each
        // re-reading the committed DB total (which loses all but the last write).
        int64_t m_supplyDelta = 0;
        // Write committed-supply + m_supplyDelta (floored at 0) into the batch.
        void WriteSupplyWithDelta();

    public:
        explicit Batch(CBurnClaimDB& db);

        void StoreBurnClaim(const BurnClaimRecord& record);
        void DeleteBurnClaim(const uint256& btcTxid);
        void UpdateClaimStatus(const uint256& btcTxid, BurnClaimStatus newStatus, uint32_t finalHeight);
        void IncrementM0BTCSupply(uint64_t amount);
        void DecrementM0BTCSupply(uint64_t amount);
        void WriteBestBlock(const uint256& blockHash);

        bool Commit();
    };

    Batch CreateBatch() { return Batch(*this); }

    //==========================================================================
    // Statistics
    //==========================================================================

    struct Stats {
        size_t totalRecords;
        size_t pendingCount;
        size_t finalCount;
        uint64_t m0btcSupply;       // Satoshis (FINAL only)
        uint64_t pendingAmount;     // Satoshis (PENDING only)
    };

    Stats GetStats() const;

    // Sync to disk
    bool Sync();

    // Get raw DB wrapper (for advanced operations)
    CDBWrapper* GetDB() { return db.get(); }
};

// Global burn claim DB instance
extern std::unique_ptr<CBurnClaimDB> g_burnclaimdb;

/**
 * Initialize the burn claim database.
 *
 * @param nCacheSize DB cache size in bytes
 * @param fMemory If true, use in-memory database (for tests)
 * @param fWipe If true, wipe and recreate DB
 * @return true on success
 */
bool InitBurnClaimDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

/**
 * Check burn claim DB consistency with chain tip.
 *
 * @param chainTipHash Current chain tip hash
 * @param fRequireRebuild[out] Set to true if rebuild needed
 * @return true if consistent
 */
bool CheckBurnClaimDBConsistency(const uint256& chainTipHash, bool& fRequireRebuild);

// NOTE: EnsureGenesisBurnsInDB() REMOVED - unified genesis flow uses TX_BURN_CLAIM at Block 1

#endif // BATHRON_BURNCLAIMDB_H
