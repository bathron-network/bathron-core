// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCHEADERSDB_H
#define BATHRON_BTCHEADERSDB_H

/**
 * BTC Headers On-Chain Database (BP-SPVMNPUB)
 *
 * LevelDB storage for BTC headers published via TX_BTC_HEADERS.
 * This is the CONSENSUS source for BTC headers - separate from btcspv (sync).
 *
 * Key Schema:
 *   't' -> (uint32_t height, uint256 hash)   // Current tip
 *   'h' || height (4 bytes BE) -> uint256    // Hash at height
 *   'H' || hash (32 bytes) -> BtcBlockHeader // Header data
 *   'b' -> uint256                           // Best BATHRON block (consistency)
 *   'p' -> (uint256 proTxHash, int height)   // Last publisher (anti-spam)
 *
 * CRITICAL: This DB must be committed atomically with other consensus DBs
 * (settlement, evo, burnclaim) in the final commit phase.
 */

#include "btcspv/btcspv.h"
#include "dbwrapper.h"
#include "uint256.h"
#include "arith_uint256.h"
#include "serialize.h"

#include <map>
#include <memory>
#include <vector>

namespace btcheadersdb {

// ============================================================================
// Reorg undo (BP-BTCHEADERS-REORG, V2)
// ============================================================================
// Captures everything a TX_BTC_HEADERS connect overwrote in the active-chain
// index, so a BATHRON-reorg disconnect can restore the prior btcheadersdb state
// byte-for-byte. Stored keyed by txid (mirrors settlement's undo pattern).
// (Headers themselves in 'H' are append-only and never erased.)

/** One active-chain (height -> hash, chainwork) entry that was overwritten. */
struct ReplacedHeaderEntry {
    uint32_t height{0};
    uint256  oldHash;
    uint256  oldWork;   // arith_uint256 serialized as uint256

    SERIALIZE_METHODS(ReplacedHeaderEntry, obj) {
        READWRITE(obj.height, obj.oldHash, obj.oldWork);
    }
};

struct CBtcHeadersReorgUndo {
    uint32_t oldTipHeight{0};
    uint256  oldTipHash;
    uint256  oldTipWork;        // arith_uint256 serialized as uint256
    uint32_t newTipHeight{0};   // highest height the connect wrote
    // Active entries [startHeight..oldTipHeight] that were overwritten/erased.
    std::vector<ReplacedHeaderEntry> replaced;

    SERIALIZE_METHODS(CBtcHeadersReorgUndo, obj) {
        READWRITE(obj.oldTipHeight, obj.oldTipHash, obj.oldTipWork,
                  obj.newTipHeight, obj.replaced);
    }
};

class CBtcHeadersDB
{
private:
    std::unique_ptr<CDBWrapper> db;
    mutable RecursiveMutex cs;

public:
    explicit CBtcHeadersDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    ~CBtcHeadersDB();

    //==========================================================================
    // Tip Access
    //==========================================================================

    /**
     * Get current on-chain BTC tip.
     *
     * @param heightOut[out] Tip height
     * @param hashOut[out] Tip hash
     * @return true if tip exists, false if DB is empty
     */
    bool GetTip(uint32_t& heightOut, uint256& hashOut) const;

    /**
     * Get tip height only.
     * Returns 0 if DB is empty.
     */
    uint32_t GetTipHeight() const;

    /**
     * Get tip hash only.
     * Returns uint256() if DB is empty.
     */
    uint256 GetTipHash() const;

    //==========================================================================
    // Header Access
    //==========================================================================

    /**
     * Get header by height.
     *
     * @param height BTC block height
     * @param out[out] Header data
     * @return true if found
     */
    bool GetHeaderByHeight(uint32_t height, BtcBlockHeader& out) const;

    /**
     * Get header by hash.
     *
     * @param hash BTC block hash
     * @param out[out] Header data
     * @return true if found
     */
    bool GetHeaderByHash(const uint256& hash, BtcBlockHeader& out) const;

    /**
     * Get hash at height.
     *
     * @param height BTC block height
     * @param out[out] Block hash
     * @return true if found
     */
    bool GetHashAtHeight(uint32_t height, uint256& out) const;

    //==========================================================================
    // Chainwork (BP-BTCHEADERS-REORG, V2)
    //==========================================================================

    /** Tip cumulative chainwork. Returns false if not stored (pre-V2 DB). */
    bool GetTipWork(arith_uint256& out) const;

    /** Stored cumulative chainwork at an active-chain height ('w' index). */
    bool GetChainWorkAt(uint32_t height, arith_uint256& out) const;

    /**
     * Cumulative chainwork at active-chain `height`, computing it if the 'w'
     * index is absent (pre-V2 / not-yet-backfilled) by walking the active chain
     * down from `height`, summing GetBlockProof, until a stored 'w' or the
     * lowest stored header (base = 0). Deterministic. Returns false if `height`
     * is not on the active chain.
     */
    bool GetOrComputeChainWork(uint32_t height, arith_uint256& out) const;

    //==========================================================================
    // Reorg undo (keyed by txid)
    //==========================================================================

    bool ReadReorgUndo(const uint256& txid, CBtcHeadersReorgUndo& out) const;
    bool HasReorgUndo(const uint256& txid) const;

    //==========================================================================
    // Consistency
    //==========================================================================

    /**
     * Write best BATHRON block hash (for chain consistency check).
     */
    bool WriteBestBlock(const uint256& blockHash);

    /**
     * Read best BATHRON block hash.
     */
    bool ReadBestBlock(uint256& blockHash) const;

    //==========================================================================
    // Publisher Tracking (anti-spam cooldown)
    //==========================================================================

    /**
     * Get last publisher info.
     *
     * @param proTxHashOut[out] ProTxHash of last publisher
     * @param heightOut[out] BATHRON block height of last publication
     * @return true if found, false if no publication yet
     */
    bool GetLastPublisher(uint256& proTxHashOut, int& heightOut) const;

    //==========================================================================
    // Batch Operations (for atomic commit)
    //==========================================================================

    class Batch
    {
    private:
        CDBBatch batch;
        CBtcHeadersDB& parent;

        // Track tip updates within this batch
        uint32_t newTipHeight{0};
        uint256 newTipHash;
        bool hasTipUpdate{false};

        // Read-back of pending chainwork / tip-work writes (spv-headers-0): lets
        // multiple TX_BTC_HEADERS chunks in one block accumulate across the single
        // Commit() instead of re-reading the stale committed DB.
        std::map<uint32_t, arith_uint256> pendingWork;
        arith_uint256 pendingTipWork;
        bool hasTipWork{false};

    public:
        explicit Batch(CBtcHeadersDB& db);

        /**
         * Write a header at specified height.
         */
        void WriteHeader(uint32_t height, const BtcBlockHeader& header);

        /**
         * Erase header at specified height.
         */
        void EraseHeader(uint32_t height, const uint256& hash);

        /**
         * Update tip.
         */
        void WriteTip(uint32_t height, const uint256& hash);

        /**
         * Write best BATHRON block hash.
         */
        void WriteBestBlock(const uint256& blockHash);

        /**
         * Write last publisher info (anti-spam tracking).
         */
        void WriteLastPublisher(const uint256& proTxHash, int bathronHeight);

        //----------------------------------------------------------------------
        // Chainwork + reorg undo (BP-BTCHEADERS-REORG, V2)
        //----------------------------------------------------------------------

        /** Write cumulative chainwork at an active-chain height ('w' index). */
        void WriteChainWork(uint32_t height, const arith_uint256& work);

        /** Write the tip cumulative chainwork ('c'). */
        void WriteTipWork(const arith_uint256& work);

        /** Persist reorg undo for a TX_BTC_HEADERS (keyed by txid). */
        void WriteReorgUndo(const uint256& txid, const CBtcHeadersReorgUndo& undo);

        /** Erase reorg undo after a successful disconnect. */
        void EraseReorgUndo(const uint256& txid);

        /**
         * Write ONLY the active-chain height->hash pointer ('h' index), without
         * touching the append-only 'H' header data. Used by reorg undo restore.
         */
        void WriteHeightIndex(uint32_t height, const uint256& hash);

        /**
         * Erase ONLY the active-chain height->hash pointer ('h' index) and its
         * chainwork, keeping the append-only 'H' header data intact.
         */
        void EraseHeightIndex(uint32_t height);

        /**
         * Read-back of writes pending in THIS uncommitted batch. Lets multiple
         * TX_BTC_HEADERS chunks within one block accumulate correctly before the
         * single Commit() (finding spv-headers-0): a later chunk sees the earlier
         * chunks' tip and per-height chainwork instead of the stale committed DB.
         * Each returns false if nothing pending (caller falls back to the DB).
         */
        bool GetPendingTip(uint32_t& heightOut, uint256& hashOut) const;
        bool GetPendingTipWork(arith_uint256& out) const;
        bool GetPendingChainWork(uint32_t height, arith_uint256& out) const;

        /**
         * Commit batch to database.
         */
        bool Commit();
    };

    Batch CreateBatch() { return Batch(*this); }

    //==========================================================================
    // Statistics
    //==========================================================================

    struct Stats {
        uint32_t tipHeight;
        uint256 tipHash;
        uint256 bestBathronBlock;
        size_t headerCount;
    };

    Stats GetStats() const;

    // Sync to disk
    bool Sync();

    // Get raw DB wrapper
    CDBWrapper* GetDB() { return db.get(); }
};

} // namespace btcheadersdb

// Global instance
extern std::unique_ptr<btcheadersdb::CBtcHeadersDB> g_btcheadersdb;

/**
 * Initialize the BTC headers database.
 */
bool InitBtcHeadersDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

/**
 * Check BTC headers DB consistency with chain tip.
 *
 * @param chainTipHash Current BATHRON chain tip hash
 * @param fRequireRebuild[out] Set to true if rebuild needed
 * @return true if consistent
 */
bool CheckBtcHeadersDBConsistency(const uint256& chainTipHash, bool& fRequireRebuild);

// NOTE: BootstrapBtcHeadersDBFromSPV removed - Block 1 TX_BTC_HEADERS handles this

#endif // BATHRON_BTCHEADERSDB_H
