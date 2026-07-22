// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btcheaders/btcheadersdb.h"
#include "btcheaders/btcheaders.h"  // For BTCHEADERS_BOOTSTRAP_HEIGHT/HASH
#include "btcspv/btcspv.h"          // For g_btc_spv, BtcHeaderIndex
#include "clientversion.h"
#include "logging.h"
#include "util/system.h"
#include "validation.h"  // For LookupBlockIndex, chainActive

// Global instance
std::unique_ptr<btcheadersdb::CBtcHeadersDB> g_btcheadersdb;

namespace btcheadersdb {

// DB key prefixes
static const char DB_TIP = 't';             // 't' -> (uint32_t height, uint256 hash)
static const char DB_HEIGHT_HASH = 'h';     // 'h' || height -> uint256 hash (active chain)
static const char DB_HASH_HEADER = 'H';     // 'H' || hash (32 bytes) -> BtcBlockHeader
static const char DB_BEST_BLOCK = 'b';      // 'b' -> uint256 (BATHRON block hash)
static const char DB_LAST_PUBLISHER = 'p';  // 'p' -> (uint256 proTxHash, int height) (anti-spam)
// BP-BTCHEADERS-REORG (V2):
static const char DB_CHAINWORK = 'w';       // 'w' || height -> uint256 (cumulative work, active chain)
static const char DB_TIP_WORK = 'c';        // 'c' -> uint256 (tip cumulative work)
static const char DB_REORG_UNDO = 'D';      // 'D' || txid (32) -> CBtcHeadersReorgUndo

//==============================================================================
// Key construction helpers
//==============================================================================

static std::pair<char, uint32_t> MakeHeightKey(uint32_t height)
{
    return std::make_pair(DB_HEIGHT_HASH, height);
}

static std::pair<char, uint256> MakeHashKey(const uint256& hash)
{
    return std::make_pair(DB_HASH_HEADER, hash);
}

static std::pair<char, uint32_t> MakeWorkKey(uint32_t height)
{
    return std::make_pair(DB_CHAINWORK, height);
}

static std::pair<char, uint256> MakeUndoKey(const uint256& txid)
{
    return std::make_pair(DB_REORG_UNDO, txid);
}

//==============================================================================
// CBtcHeadersDB Implementation
//==============================================================================

CBtcHeadersDB::CBtcHeadersDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    fs::path dbPath = GetDataDir() / "btcheadersdb";
    db = std::make_unique<CDBWrapper>(dbPath, nCacheSize, fMemory, fWipe);
    LogPrintf("BtcHeadersDB: opened at %s (cache=%zu, memory=%d, wipe=%d)\n",
              dbPath.string(), nCacheSize, fMemory, fWipe);
}

CBtcHeadersDB::~CBtcHeadersDB() = default;

//==============================================================================
// Tip Access
//==============================================================================

bool CBtcHeadersDB::GetTip(uint32_t& heightOut, uint256& hashOut) const
{
    LOCK(cs);
    std::pair<uint32_t, uint256> tip;
    if (!db->Read(DB_TIP, tip)) {
        return false;
    }
    heightOut = tip.first;
    hashOut = tip.second;
    return true;
}

uint32_t CBtcHeadersDB::GetTipHeight() const
{
    uint32_t height;
    uint256 hash;
    if (GetTip(height, hash)) {
        return height;
    }
    return 0;
}

uint256 CBtcHeadersDB::GetTipHash() const
{
    uint32_t height;
    uint256 hash;
    if (GetTip(height, hash)) {
        return hash;
    }
    return uint256();
}

//==============================================================================
// Header Access
//==============================================================================

bool CBtcHeadersDB::GetHeaderByHeight(uint32_t height, BtcBlockHeader& out) const
{
    LOCK(cs);
    uint256 hash;
    if (!db->Read(MakeHeightKey(height), hash)) {
        return false;
    }
    return db->Read(MakeHashKey(hash), out);
}

bool CBtcHeadersDB::GetHeaderByHash(const uint256& hash, BtcBlockHeader& out) const
{
    LOCK(cs);
    return db->Read(MakeHashKey(hash), out);
}

bool CBtcHeadersDB::GetHashAtHeight(uint32_t height, uint256& out) const
{
    LOCK(cs);
    return db->Read(MakeHeightKey(height), out);
}

//==============================================================================
// Chainwork (BP-BTCHEADERS-REORG, V2)
//==============================================================================

bool CBtcHeadersDB::GetTipWork(arith_uint256& out) const
{
    LOCK(cs);
    uint256 w;
    if (!db->Read(DB_TIP_WORK, w)) {
        return false;
    }
    out = UintToArith256(w);
    return true;
}

bool CBtcHeadersDB::GetChainWorkAt(uint32_t height, arith_uint256& out) const
{
    LOCK(cs);
    uint256 w;
    if (!db->Read(MakeWorkKey(height), w)) {
        return false;
    }
    out = UintToArith256(w);
    return true;
}

bool CBtcHeadersDB::GetOrComputeChainWork(uint32_t height, arith_uint256& out) const
{
    LOCK(cs);
    if (!g_btc_spv) {
        return false; // need the proof-of-work helper
    }
    if (!db->Exists(MakeHeightKey(height))) {
        return false; // height not on the active chain
    }

    // Walk down the active chain from `height`, summing GetBlockProof, until we
    // hit a stored 'w' (base) or the lowest stored header (base contribution 0).
    arith_uint256 acc; // 0
    uint32_t h = height;
    while (true) {
        arith_uint256 w;
        if (GetChainWorkAt(h, w)) { // base found: w already includes header_h and below
            acc += w;
            break;
        }
        BtcBlockHeader hdr;
        if (!GetHeaderByHeight(h, hdr)) {
            break; // below the DB: nothing more to add (base 0)
        }
        acc += g_btc_spv->GetBlockProof(hdr);
        if (h == 0) break;
        h--;
    }
    out = acc;
    return true;
}

bool CBtcHeadersDB::ReadReorgUndo(const uint256& txid, CBtcHeadersReorgUndo& out) const
{
    LOCK(cs);
    return db->Read(MakeUndoKey(txid), out);
}

bool CBtcHeadersDB::HasReorgUndo(const uint256& txid) const
{
    LOCK(cs);
    return db->Exists(MakeUndoKey(txid));
}

//==============================================================================
// Consistency
//==============================================================================

bool CBtcHeadersDB::WriteBestBlock(const uint256& blockHash)
{
    LOCK(cs);
    return db->Write(DB_BEST_BLOCK, blockHash);
}

bool CBtcHeadersDB::ReadBestBlock(uint256& blockHash) const
{
    LOCK(cs);
    return db->Read(DB_BEST_BLOCK, blockHash);
}

//==============================================================================
// Publisher Tracking (anti-spam)
//==============================================================================

bool CBtcHeadersDB::GetLastPublisher(uint256& proTxHashOut, int& heightOut) const
{
    LOCK(cs);
    std::pair<uint256, int> pubInfo;
    if (!db->Read(DB_LAST_PUBLISHER, pubInfo)) {
        return false;
    }
    proTxHashOut = pubInfo.first;
    heightOut = pubInfo.second;
    return true;
}

//==============================================================================
// Batch Operations
//==============================================================================

CBtcHeadersDB::Batch::Batch(CBtcHeadersDB& parent_)
    : batch(CLIENT_VERSION), parent(parent_)
{
}

void CBtcHeadersDB::Batch::WriteHeader(uint32_t height, const BtcBlockHeader& header)
{
    uint256 hash = header.GetHash();

    // Write height -> hash mapping
    batch.Write(MakeHeightKey(height), hash);

    // Write hash -> header mapping
    batch.Write(MakeHashKey(hash), header);

    // Track tip update (latest height written)
    if (!hasTipUpdate || height > newTipHeight) {
        newTipHeight = height;
        newTipHash = hash;
        hasTipUpdate = true;
    }

    LogPrint(BCLog::MASTERNODE, "BtcHeadersDB::Batch: WriteHeader h=%u hash=%s\n",
             height, hash.ToString().substr(0, 16));
}

void CBtcHeadersDB::Batch::EraseHeader(uint32_t height, const uint256& hash)
{
    // Erase height -> hash mapping
    batch.Erase(MakeHeightKey(height));

    // Erase hash -> header mapping
    batch.Erase(MakeHashKey(hash));

    LogPrint(BCLog::MASTERNODE, "BtcHeadersDB::Batch: EraseHeader h=%u hash=%s\n",
             height, hash.ToString().substr(0, 16));
}

void CBtcHeadersDB::Batch::WriteTip(uint32_t height, const uint256& hash)
{
    batch.Write(DB_TIP, std::make_pair(height, hash));
    newTipHeight = height;
    newTipHash = hash;
    hasTipUpdate = true;

    LogPrint(BCLog::MASTERNODE, "BtcHeadersDB::Batch: WriteTip h=%u hash=%s\n",
             height, hash.ToString().substr(0, 16));
}

void CBtcHeadersDB::Batch::WriteBestBlock(const uint256& blockHash)
{
    batch.Write(DB_BEST_BLOCK, blockHash);
}

void CBtcHeadersDB::Batch::WriteLastPublisher(const uint256& proTxHash, int bathronHeight)
{
    batch.Write(DB_LAST_PUBLISHER, std::make_pair(proTxHash, bathronHeight));
    LogPrint(BCLog::MASTERNODE, "BtcHeadersDB::Batch: WriteLastPublisher %s at BATHRON height %d\n",
             proTxHash.ToString().substr(0, 16), bathronHeight);
}

void CBtcHeadersDB::Batch::WriteChainWork(uint32_t height, const arith_uint256& work)
{
    batch.Write(MakeWorkKey(height), ArithToUint256(work));
    pendingWork[height] = work;   // read-back for same-block chunk accumulation
}

void CBtcHeadersDB::Batch::WriteTipWork(const arith_uint256& work)
{
    batch.Write(DB_TIP_WORK, ArithToUint256(work));
    pendingTipWork = work;
    hasTipWork = true;
}

bool CBtcHeadersDB::Batch::GetPendingTip(uint32_t& heightOut, uint256& hashOut) const
{
    if (!hasTipUpdate) return false;
    heightOut = newTipHeight;
    hashOut = newTipHash;
    return true;
}

bool CBtcHeadersDB::Batch::GetPendingTipWork(arith_uint256& out) const
{
    if (!hasTipWork) return false;
    out = pendingTipWork;
    return true;
}

bool CBtcHeadersDB::Batch::GetPendingChainWork(uint32_t height, arith_uint256& out) const
{
    auto it = pendingWork.find(height);
    if (it == pendingWork.end()) return false;
    out = it->second;
    return true;
}

void CBtcHeadersDB::Batch::WriteReorgUndo(const uint256& txid, const CBtcHeadersReorgUndo& undo)
{
    batch.Write(MakeUndoKey(txid), undo);
}

void CBtcHeadersDB::Batch::EraseReorgUndo(const uint256& txid)
{
    batch.Erase(MakeUndoKey(txid));
}

void CBtcHeadersDB::Batch::WriteHeightIndex(uint32_t height, const uint256& hash)
{
    batch.Write(MakeHeightKey(height), hash);
    if (!hasTipUpdate || height > newTipHeight) {
        newTipHeight = height;
        newTipHash = hash;
        hasTipUpdate = true;
    }
}

void CBtcHeadersDB::Batch::EraseHeightIndex(uint32_t height)
{
    batch.Erase(MakeHeightKey(height));
    batch.Erase(MakeWorkKey(height));
    pendingWork.erase(height);
}

bool CBtcHeadersDB::Batch::Commit()
{
    LOCK(parent.cs);
    bool ok = parent.db->WriteBatch(batch);
    if (ok && hasTipUpdate) {
        LogPrint(BCLog::MASTERNODE, "BtcHeadersDB: committed batch, new tip h=%u hash=%s\n",
                 newTipHeight, newTipHash.ToString().substr(0, 16));
    }
    return ok;
}

//==============================================================================
// Statistics
//==============================================================================

CBtcHeadersDB::Stats CBtcHeadersDB::GetStats() const
{
    LOCK(cs);
    Stats stats;
    stats.tipHeight = 0;
    stats.headerCount = 0;

    GetTip(stats.tipHeight, stats.tipHash);
    ReadBestBlock(stats.bestBathronBlock);

    // Count headers (iterate through height keys)
    // This is O(n) but only used for diagnostics
    std::unique_ptr<CDBIterator> pcursor(db->NewIterator());
    pcursor->Seek(MakeHeightKey(0));
    while (pcursor->Valid()) {
        std::pair<char, uint32_t> key;
        if (!pcursor->GetKey(key) || key.first != DB_HEIGHT_HASH) {
            break;
        }
        stats.headerCount++;
        pcursor->Next();
    }

    return stats;
}

bool CBtcHeadersDB::Sync()
{
    LOCK(cs);
    return db->Sync();
}

} // namespace btcheadersdb

//==============================================================================
// Global Functions
//==============================================================================

bool InitBtcHeadersDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    try {
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(nCacheSize, fMemory, fWipe);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("ERROR: InitBtcHeadersDB: %s\n", e.what());
        return false;
    }
}

bool CheckBtcHeadersDBConsistency(const uint256& chainTipHash, bool& fRequireRebuild)
{
    fRequireRebuild = false;

    if (!g_btcheadersdb) {
        LogPrintf("BtcHeadersDB: not initialized, skipping consistency check\n");
        return true;
    }

    uint256 dbBestBlock;
    if (!g_btcheadersdb->ReadBestBlock(dbBestBlock)) {
        // Empty/fresh DB - OK
        LogPrintf("BtcHeadersDB: fresh database, no consistency check needed\n");
        return true;
    }

    if (dbBestBlock == chainTipHash) {
        LogPrintf("BtcHeadersDB: consistent with chain tip %s\n",
                  chainTipHash.ToString().substr(0, 16));
        return true;
    }

    // Check if dbBestBlock is in the active chain (an ancestor of the tip)
    // This is valid because btcheadersdb is only updated when TX_BTC_HEADERS is processed,
    // so it may be behind the chain tip if no headers were published recently.
    CBlockIndex* pindex = LookupBlockIndex(dbBestBlock);
    if (pindex && chainActive.Contains(pindex)) {
        LogPrintf("BtcHeadersDB: consistent (db=%s at height %d, tip=%s)\n",
                  dbBestBlock.ToString().substr(0, 16), pindex->nHeight,
                  chainTipHash.ToString().substr(0, 16));
        return true;
    }

    // Best block not in active chain - this can happen after reindex/bootstrap
    // where btcheadersdb was restored from another node. BTC header data is
    // chain-independent (BTC signet headers), so just update the marker.
    LogPrintf("BtcHeadersDB: db=%s not in active chain (tip=%s) - updating marker\n",
              dbBestBlock.ToString().substr(0, 16),
              chainTipHash.ToString().substr(0, 16));
    g_btcheadersdb->WriteBestBlock(chainTipHash);
    LogPrintf("BtcHeadersDB: best block marker updated to %s\n",
              chainTipHash.ToString().substr(0, 16));
    return true;
}

// NOTE: BootstrapBtcHeadersDBFromSPV removed.
// Block 1 TX_BTC_HEADERS populates btcheadersdb via consensus replay.
// No pre-distribution of btcspv snapshots needed.

