// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "burnclaim/burnclaimdb.h"
#include "clientversion.h"
#include "logging.h"
#include "util/system.h"

#include <algorithm>

// Global instance
std::unique_ptr<CBurnClaimDB> g_burnclaimdb;

// DB key prefixes (from BP11 spec)
static const char DB_CLAIM = 'c';           // 'Cc' || btc_txid -> BurnClaimRecord
static const char DB_STATUS_INDEX = 's';    // 'Cs' || status || height || btc_txid -> (empty)
static const char DB_DEST_INDEX = 'd';      // 'Cd' || dest || btc_txid -> (empty)
static const char DB_M0BTC_SUPPLY = 'm';    // 'Cm' -> uint64_t
static const char DB_BEST_BLOCK = 'b';      // 'Cb' -> uint256

// Namespace prefix
static const char DB_NAMESPACE = 'C';

//==============================================================================
// Key construction helpers
//==============================================================================

// Helper to create CDataStream with raw bytes (no compactsize prefix)
// This is necessary because CDBBatch::Write serializes std::vector with compactsize
static CDataStream MakeRawKeyStream(const std::vector<uint8_t>& key)
{
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss.write((const char*)key.data(), key.size());
    return ss;
}

static std::vector<uint8_t> MakeClaimKey(const uint256& btcTxid)
{
    std::vector<uint8_t> key;
    key.reserve(34);
    key.push_back(DB_NAMESPACE);
    key.push_back(DB_CLAIM);
    key.insert(key.end(), btcTxid.begin(), btcTxid.end());
    return key;
}

static std::vector<uint8_t> MakeStatusIndexKey(BurnClaimStatus status, uint32_t claimHeight, const uint256& btcTxid)
{
    std::vector<uint8_t> key;
    key.reserve(39);
    key.push_back(DB_NAMESPACE);
    key.push_back(DB_STATUS_INDEX);
    key.push_back(static_cast<uint8_t>(status));
    // Big-endian height for proper sorting
    key.push_back((claimHeight >> 24) & 0xFF);
    key.push_back((claimHeight >> 16) & 0xFF);
    key.push_back((claimHeight >> 8) & 0xFF);
    key.push_back(claimHeight & 0xFF);
    key.insert(key.end(), btcTxid.begin(), btcTxid.end());
    return key;
}

static std::vector<uint8_t> MakeStatusIndexPrefix(BurnClaimStatus status)
{
    std::vector<uint8_t> key;
    key.push_back(DB_NAMESPACE);
    key.push_back(DB_STATUS_INDEX);
    key.push_back(static_cast<uint8_t>(status));
    return key;
}

static std::vector<uint8_t> MakeDestIndexKey(const uint160& dest, const uint256& btcTxid)
{
    std::vector<uint8_t> key;
    key.reserve(54);
    key.push_back(DB_NAMESPACE);
    key.push_back(DB_DEST_INDEX);
    key.insert(key.end(), dest.begin(), dest.end());
    key.insert(key.end(), btcTxid.begin(), btcTxid.end());
    return key;
}

static std::vector<uint8_t> MakeDestIndexPrefix(const uint160& dest)
{
    std::vector<uint8_t> key;
    key.reserve(22);
    key.push_back(DB_NAMESPACE);
    key.push_back(DB_DEST_INDEX);
    key.insert(key.end(), dest.begin(), dest.end());
    return key;
}

static std::vector<uint8_t> MakeSupplyKey()
{
    return {DB_NAMESPACE, DB_M0BTC_SUPPLY};
}

static std::vector<uint8_t> MakeBestBlockKey()
{
    return {DB_NAMESPACE, DB_BEST_BLOCK};
}

//==============================================================================
// CBurnClaimDB Implementation
//==============================================================================

CBurnClaimDB::CBurnClaimDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    fs::path dbPath = GetDataDir() / "burnclaimdb";
    db = std::make_unique<CDBWrapper>(dbPath, nCacheSize, fMemory, fWipe);
}

CBurnClaimDB::~CBurnClaimDB() = default;

void CBurnClaimDB::DeleteIndices(CDBBatch& batch, const BurnClaimRecord& record)
{
    // Delete status index (use raw key stream to avoid compactsize prefix)
    auto statusKey = MakeStatusIndexKey(record.status, record.claimHeight, record.btcTxid);
    batch.Erase(MakeRawKeyStream(statusKey));

    // Delete destination index
    auto destKey = MakeDestIndexKey(record.bathronDest, record.btcTxid);
    batch.Erase(MakeRawKeyStream(destKey));
}

void CBurnClaimDB::WriteIndices(CDBBatch& batch, const BurnClaimRecord& record)
{
    // Write status index (empty value - existence check only)
    // Use raw key stream to avoid compactsize prefix on vector keys
    auto statusKey = MakeStatusIndexKey(record.status, record.claimHeight, record.btcTxid);
    batch.Write(MakeRawKeyStream(statusKey), std::vector<uint8_t>());

    // Write destination index
    auto destKey = MakeDestIndexKey(record.bathronDest, record.btcTxid);
    batch.Write(MakeRawKeyStream(destKey), std::vector<uint8_t>());
}

bool CBurnClaimDB::StoreBurnClaim(const BurnClaimRecord& record)
{
    CDBBatch batch(CLIENT_VERSION);

    // Check for existing record to clean up old indices
    BurnClaimRecord existingRecord;
    if (GetBurnClaim(record.btcTxid, existingRecord)) {
        DeleteIndices(batch, existingRecord);
    }

    // Write new record (use raw key stream to avoid compactsize prefix)
    auto claimKey = MakeClaimKey(record.btcTxid);
    batch.Write(MakeRawKeyStream(claimKey), record);

    // Write new indices
    WriteIndices(batch, record);

    return db->WriteBatch(batch);
}

bool CBurnClaimDB::GetBurnClaim(const uint256& btcTxid, BurnClaimRecord& record) const
{
    auto key = MakeClaimKey(btcTxid);
    return db->Read(MakeRawKeyStream(key), record);
}

bool CBurnClaimDB::DeleteBurnClaim(const uint256& btcTxid)
{
    BurnClaimRecord record;
    if (!GetBurnClaim(btcTxid, record)) {
        return true;  // Already doesn't exist
    }

    CDBBatch batch(CLIENT_VERSION);

    // Delete indices
    DeleteIndices(batch, record);

    // Delete main record (use raw key stream)
    auto claimKey = MakeClaimKey(btcTxid);
    batch.Erase(MakeRawKeyStream(claimKey));

    return db->WriteBatch(batch);
}

bool CBurnClaimDB::ExistsBurnClaim(const uint256& btcTxid) const
{
    auto key = MakeClaimKey(btcTxid);
    return db->Exists(MakeRawKeyStream(key));
}

void CBurnClaimDB::ForEachPendingClaim(std::function<bool(const BurnClaimRecord&)> func) const
{
    auto prefix = MakeStatusIndexPrefix(BurnClaimStatus::PENDING);
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    // Seek with raw key stream (no compactsize prefix)
    it->Seek(MakeRawKeyStream(prefix));

    while (it->Valid()) {
        // Get raw key bytes from iterator (keys were written as raw bytes)
        CDataStream keyStream = it->GetKey();
        std::vector<uint8_t> key(keyStream.begin(), keyStream.end());

        // Check prefix match
        if (key.size() < prefix.size() ||
            !std::equal(prefix.begin(), prefix.end(), key.begin())) {
            break;
        }

        // Extract btcTxid from key (last 32 bytes)
        if (key.size() < 39) {  // 2 prefix + 1 status + 4 height + 32 txid
            it->Next();
            continue;
        }

        uint256 btcTxid;
        memcpy(btcTxid.begin(), &key[7], 32);

        BurnClaimRecord record;
        if (GetBurnClaim(btcTxid, record)) {
            if (!func(record)) {
                break;
            }
        }
        it->Next();
    }
}

void CBurnClaimDB::ForEachFinalClaim(std::function<bool(const BurnClaimRecord&)> func) const
{
    auto prefix = MakeStatusIndexPrefix(BurnClaimStatus::FINAL);
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    // Seek with raw key stream (no compactsize prefix)
    it->Seek(MakeRawKeyStream(prefix));

    while (it->Valid()) {
        // Get raw key bytes from iterator (keys were written as raw bytes)
        CDataStream keyStream = it->GetKey();
        std::vector<uint8_t> key(keyStream.begin(), keyStream.end());

        // Check prefix match
        if (key.size() < prefix.size() ||
            !std::equal(prefix.begin(), prefix.end(), key.begin())) {
            break;
        }

        // Extract btcTxid from key
        if (key.size() < 39) {
            it->Next();
            continue;
        }

        uint256 btcTxid;
        memcpy(btcTxid.begin(), &key[7], 32);

        BurnClaimRecord record;
        if (GetBurnClaim(btcTxid, record)) {
            if (!func(record)) {
                break;
            }
        }
        it->Next();
    }
}


uint64_t CBurnClaimDB::GetM0BTCSupply() const
{
    auto key = MakeSupplyKey();
    uint64_t supply = 0;
    db->Read(MakeRawKeyStream(key), supply);
    return supply;
}

bool CBurnClaimDB::IncrementM0BTCSupply(uint64_t amount)
{
    uint64_t current = GetM0BTCSupply();
    uint64_t newSupply = current + amount;

    // Overflow check
    if (newSupply < current) {
        LogPrintf("ERROR: M0BTC supply overflow! current=%llu, adding=%llu\n", current, amount);
        return false;
    }

    auto key = MakeSupplyKey();
    return db->Write(MakeRawKeyStream(key), newSupply);
}

bool CBurnClaimDB::DecrementM0BTCSupply(uint64_t amount)
{
    uint64_t current = GetM0BTCSupply();

    // Underflow check
    if (amount > current) {
        LogPrintf("ERROR: M0BTC supply underflow! current=%llu, removing=%llu\n", current, amount);
        return false;
    }

    uint64_t newSupply = current - amount;
    auto key = MakeSupplyKey();
    return db->Write(MakeRawKeyStream(key), newSupply);
}

bool CBurnClaimDB::WriteBestBlock(const uint256& blockHash)
{
    auto key = MakeBestBlockKey();
    return db->Write(MakeRawKeyStream(key), blockHash);
}

bool CBurnClaimDB::ReadBestBlock(uint256& blockHash) const
{
    auto key = MakeBestBlockKey();
    return db->Read(MakeRawKeyStream(key), blockHash);
}

CBurnClaimDB::Stats CBurnClaimDB::GetStats() const
{
    Stats stats = {};
    stats.m0btcSupply = GetM0BTCSupply();

    ForEachPendingClaim([&](const BurnClaimRecord& record) {
        stats.totalRecords++;
        stats.pendingCount++;
        stats.pendingAmount += record.burnedSats;
        return true;
    });

    ForEachFinalClaim([&](const BurnClaimRecord& record) {
        stats.totalRecords++;
        stats.finalCount++;
        return true;
    });

    return stats;
}

bool CBurnClaimDB::Sync()
{
    return db->Sync();
}

//==============================================================================
// Batch Implementation
//==============================================================================

CBurnClaimDB::Batch::Batch(CBurnClaimDB& db)
    : batch(CLIENT_VERSION), parent(db)
{
}

void CBurnClaimDB::Batch::StoreBurnClaim(const BurnClaimRecord& record)
{
    // Check for existing record to clean up old indices
    BurnClaimRecord existingRecord;
    if (parent.GetBurnClaim(record.btcTxid, existingRecord)) {
        parent.DeleteIndices(batch, existingRecord);
    }

    // Write new record (use raw key stream)
    auto claimKey = MakeClaimKey(record.btcTxid);
    batch.Write(MakeRawKeyStream(claimKey), record);

    // Write new indices
    parent.WriteIndices(batch, record);
}

void CBurnClaimDB::Batch::DeleteBurnClaim(const uint256& btcTxid)
{
    BurnClaimRecord record;
    if (parent.GetBurnClaim(btcTxid, record)) {
        parent.DeleteIndices(batch, record);
        auto claimKey = MakeClaimKey(btcTxid);
        batch.Erase(MakeRawKeyStream(claimKey));
    }
}

void CBurnClaimDB::Batch::UpdateClaimStatus(const uint256& btcTxid, BurnClaimStatus newStatus, uint32_t finalHeight)
{
    BurnClaimRecord record;
    if (!parent.GetBurnClaim(btcTxid, record)) {
        LogPrintf("ERROR: UpdateClaimStatus - claim not found: %s\n", btcTxid.ToString());
        return;
    }

    // Delete old indices
    parent.DeleteIndices(batch, record);

    // Update status
    record.status = newStatus;
    record.finalHeight = finalHeight;

    // Write updated record (use raw key stream)
    auto claimKey = MakeClaimKey(btcTxid);
    batch.Write(MakeRawKeyStream(claimKey), record);

    // Write new indices
    parent.WriteIndices(batch, record);
}

// R6: write the committed supply plus the running in-batch delta. Reading
// parent.GetM0BTCSupply() each time is fine — it stays at the committed value
// until Commit() — but the cumulative delta is what makes multiple
// Increment/Decrement calls in one batch compose instead of clobbering.
void CBurnClaimDB::Batch::WriteSupplyWithDelta()
{
    int64_t total = static_cast<int64_t>(parent.GetM0BTCSupply()) + m_supplyDelta;
    if (total < 0) total = 0;   // floor (matches the legacy decrement clamp)
    uint64_t newSupply = static_cast<uint64_t>(total);
    auto key = MakeSupplyKey();
    batch.Write(MakeRawKeyStream(key), newSupply);
}

void CBurnClaimDB::Batch::IncrementM0BTCSupply(uint64_t amount)
{
    m_supplyDelta += static_cast<int64_t>(amount);
    WriteSupplyWithDelta();
}

void CBurnClaimDB::Batch::DecrementM0BTCSupply(uint64_t amount)
{
    m_supplyDelta -= static_cast<int64_t>(amount);
    WriteSupplyWithDelta();
}

void CBurnClaimDB::Batch::WriteBestBlock(const uint256& blockHash)
{
    auto key = MakeBestBlockKey();
    batch.Write(MakeRawKeyStream(key), blockHash);
}

bool CBurnClaimDB::Batch::Commit()
{
    return parent.db->WriteBatch(batch);
}

//==============================================================================
// Global Functions
//==============================================================================

bool InitBurnClaimDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    try {
        g_burnclaimdb = std::make_unique<CBurnClaimDB>(nCacheSize, fMemory, fWipe);
        LogPrintf("Burn claim DB initialized\n");
        return true;
    } catch (const std::exception& e) {
        LogPrintf("ERROR: Failed to initialize burn claim DB: %s\n", e.what());
        return false;
    }
}

bool CheckBurnClaimDBConsistency(const uint256& chainTipHash, bool& fRequireRebuild)
{
    fRequireRebuild = false;

    if (!g_burnclaimdb) {
        LogPrintf("Burn claim DB not initialized\n");
        return false;
    }

    uint256 dbBestBlock;
    if (!g_burnclaimdb->ReadBestBlock(dbBestBlock)) {
        // Empty DB - OK, will be populated
        LogPrintf("Burn claim DB is empty (new or wiped)\n");
        return true;
    }

    if (dbBestBlock != chainTipHash) {
        // BurnClaim writes its best block on EVERY connected block (unlike
        // btcheaders, which only writes when headers are published and so may
        // legitimately lag behind the tip). A mismatch here is therefore a genuine
        // crash/rollback inconsistency, not a benign lag — and the state is
        // consensus-tied (PENDING/FINAL claims + M0BTC supply, read by the next
        // block's CreateMintM0BTC), so it cannot be silently trusted. Require a
        // rebuild rather than starting on an inconsistent DB (cross-cutting-3).
        LogPrintf("BurnClaim DB best block mismatch: DB=%s, Chain=%s — rebuild required\n",
                  dbBestBlock.ToString(), chainTipHash.ToString());
        fRequireRebuild = true;
        return false;
    }

    return true;
}

// NOTE: EnsureGenesisBurnsInDB() REMOVED - daemon-only burn detection flow
