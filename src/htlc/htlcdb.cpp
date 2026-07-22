// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "htlc/htlcdb.h"

#include "clientversion.h"
#include "logging.h"

#include <algorithm>
#include <fs.h>

// Global HTLC DB instance
std::unique_ptr<CHtlcDB> g_htlcdb;

// DB key helpers
namespace {

template<typename T>
std::pair<char, T> MakeKey(char prefix, const T& key)
{
    return std::make_pair(prefix, key);
}

// Hashlock index key: 'L' + hashlock + outpoint
struct HashlockIndexKey
{
    uint256 hashlock;
    COutPoint outpoint;

    SERIALIZE_METHODS(HashlockIndexKey, obj)
    {
        READWRITE(obj.hashlock, obj.outpoint);
    }
};

// Prune-schedule key: 'X' + height + outpoint. Height is serialized FIRST so that
// all entries scheduled at the same height are contiguous in the DB, letting
// PruneResolvedAtHeight seek to a height and iterate just that height's entries.
struct PruneScheduleKey
{
    uint32_t height;
    COutPoint outpoint;

    SERIALIZE_METHODS(PruneScheduleKey, obj)
    {
        READWRITE(obj.height, obj.outpoint);
    }
};

} // anonymous namespace

// =============================================================================
// Constructor / Destructor
// =============================================================================

CHtlcDB::CHtlcDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    fs::path path = GetDataDir() / "htlc";
    db = std::make_unique<CDBWrapper>(path, nCacheSize, fMemory, fWipe);
}

CHtlcDB::~CHtlcDB() = default;

// =============================================================================
// HTLC Record Operations
// =============================================================================

bool CHtlcDB::WriteHTLC(const HTLCRecord& htlc)
{
    return db->Write(MakeKey(DB_HTLC, htlc.htlcOutpoint), htlc);
}

bool CHtlcDB::ReadHTLC(const COutPoint& outpoint, HTLCRecord& htlc) const
{
    return db->Read(MakeKey(DB_HTLC, outpoint), htlc);
}

bool CHtlcDB::EraseHTLC(const COutPoint& outpoint)
{
    return db->Erase(MakeKey(DB_HTLC, outpoint));
}

bool CHtlcDB::IsHTLC(const COutPoint& outpoint) const
{
    return db->Exists(MakeKey(DB_HTLC, outpoint));
}

// =============================================================================
// Hashlock Index Operations
// =============================================================================

bool CHtlcDB::WriteHashlockIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Write(MakeKey(DB_HTLC_HASHLOCK, key), true);  // Value is just a marker
}

bool CHtlcDB::EraseHashlockIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Erase(MakeKey(DB_HTLC_HASHLOCK, key));
}

bool CHtlcDB::GetByHashlock(const uint256& hashlock, std::vector<COutPoint>& outpoints) const
{
    outpoints.clear();

    // Iterate over all entries with this hashlock prefix
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    HashlockIndexKey prefix{hashlock, COutPoint()};
    it->Seek(MakeKey(DB_HTLC_HASHLOCK, prefix));

    while (it->Valid()) {
        std::pair<char, HashlockIndexKey> key;
        if (it->GetKey(key) && key.first == DB_HTLC_HASHLOCK && key.second.hashlock == hashlock) {
            outpoints.push_back(key.second.outpoint);
            it->Next();
        } else {
            break;  // No more entries for this hashlock
        }
    }

    return !outpoints.empty();
}

// =============================================================================
// Query Operations
// =============================================================================

void CHtlcDB::ForEachHTLC(std::function<bool(const HTLCRecord&)> func) const
{
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    auto prefix = std::make_pair(DB_HTLC, COutPoint());
    it->Seek(prefix);

    while (it->Valid()) {
        std::pair<char, COutPoint> key;
        if (it->GetKey(key) && key.first == DB_HTLC) {
            HTLCRecord htlc;
            if (it->GetValue(htlc)) {
                if (!func(htlc)) {
                    break;  // Callback returned false, stop iteration
                }
            }
            it->Next();
        } else {
            break;  // No more HTLC entries
        }
    }
}

void CHtlcDB::GetActive(std::vector<HTLCRecord>& htlcs) const
{
    htlcs.clear();
    ForEachHTLC([&](const HTLCRecord& htlc) {
        if (htlc.IsActive()) {
            htlcs.push_back(htlc);
        }
        return true;  // Continue iteration
    });
}

// =============================================================================
// Undo Data Operations
// =============================================================================

bool CHtlcDB::WriteCreateUndo(const uint256& txid, const HTLCCreateUndoData& undoData)
{
    return db->Write(MakeKey(DB_HTLC_CREATE_UNDO, txid), undoData);
}

bool CHtlcDB::ReadCreateUndo(const uint256& txid, HTLCCreateUndoData& undoData) const
{
    return db->Read(MakeKey(DB_HTLC_CREATE_UNDO, txid), undoData);
}

bool CHtlcDB::EraseCreateUndo(const uint256& txid)
{
    return db->Erase(MakeKey(DB_HTLC_CREATE_UNDO, txid));
}

bool CHtlcDB::WriteResolveUndo(const uint256& txid, const HTLCResolveUndoData& undoData)
{
    return db->Write(MakeKey(DB_HTLC_RESOLVE_UNDO, txid), undoData);
}

bool CHtlcDB::ReadResolveUndo(const uint256& txid, HTLCResolveUndoData& undoData) const
{
    return db->Read(MakeKey(DB_HTLC_RESOLVE_UNDO, txid), undoData);
}

bool CHtlcDB::EraseResolveUndo(const uint256& txid)
{
    return db->Erase(MakeKey(DB_HTLC_RESOLVE_UNDO, txid));
}

// =============================================================================
// Best Block Tracking
// =============================================================================

bool CHtlcDB::WriteBestBlock(const uint256& blockHash)
{
    return db->Write(std::make_pair(DB_HTLC_BEST_BLOCK, uint256()), blockHash);
}

bool CHtlcDB::ReadBestBlock(uint256& blockHash) const
{
    return db->Read(std::make_pair(DB_HTLC_BEST_BLOCK, uint256()), blockHash);
}

// =============================================================================
// Batch Operations
// =============================================================================

CHtlcDB::Batch::Batch(CHtlcDB& db) : batch(CLIENT_VERSION), parent(db) {}

void CHtlcDB::Batch::WriteHTLC(const HTLCRecord& htlc)
{
    batch.Write(MakeKey(DB_HTLC, htlc.htlcOutpoint), htlc);
}

void CHtlcDB::Batch::EraseHTLC(const COutPoint& outpoint)
{
    batch.Erase(MakeKey(DB_HTLC, outpoint));
}

void CHtlcDB::Batch::WriteHashlockIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Write(MakeKey(DB_HTLC_HASHLOCK, key), true);
}

void CHtlcDB::Batch::EraseHashlockIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Erase(MakeKey(DB_HTLC_HASHLOCK, key));
}

void CHtlcDB::Batch::WriteCreateUndo(const uint256& txid, const HTLCCreateUndoData& undoData)
{
    batch.Write(MakeKey(DB_HTLC_CREATE_UNDO, txid), undoData);
}

void CHtlcDB::Batch::EraseCreateUndo(const uint256& txid)
{
    batch.Erase(MakeKey(DB_HTLC_CREATE_UNDO, txid));
}

void CHtlcDB::Batch::WriteResolveUndo(const uint256& txid, const HTLCResolveUndoData& undoData)
{
    batch.Write(MakeKey(DB_HTLC_RESOLVE_UNDO, txid), undoData);
}

void CHtlcDB::Batch::EraseResolveUndo(const uint256& txid)
{
    batch.Erase(MakeKey(DB_HTLC_RESOLVE_UNDO, txid));
}

void CHtlcDB::Batch::WriteBestBlock(const uint256& blockHash)
{
    batch.Write(std::make_pair(DB_HTLC_BEST_BLOCK, uint256()), blockHash);
}

void CHtlcDB::Batch::WritePruneSchedule(uint32_t height, const COutPoint& outpoint, bool is3S)
{
    PruneScheduleKey key{height, outpoint};
    batch.Write(MakeKey(DB_HTLC_PRUNE_SCHED, key), static_cast<uint8_t>(is3S ? 1 : 0));
}

void CHtlcDB::Batch::ErasePruneSchedule(uint32_t height, const COutPoint& outpoint)
{
    PruneScheduleKey key{height, outpoint};
    batch.Erase(MakeKey(DB_HTLC_PRUNE_SCHED, key));
}

bool CHtlcDB::Batch::Commit()
{
    return parent.db->WriteBatch(batch);
}

bool CHtlcDB::Sync()
{
    return db->Sync();
}

// =============================================================================
// HTLC3S - 3-Secret HTLC Operations (FlowSwap)
// =============================================================================

bool CHtlcDB::WriteHTLC3S(const HTLC3SRecord& htlc)
{
    return db->Write(MakeKey(DB_HTLC3S, htlc.htlcOutpoint), htlc);
}

bool CHtlcDB::ReadHTLC3S(const COutPoint& outpoint, HTLC3SRecord& htlc) const
{
    return db->Read(MakeKey(DB_HTLC3S, outpoint), htlc);
}

bool CHtlcDB::EraseHTLC3S(const COutPoint& outpoint)
{
    return db->Erase(MakeKey(DB_HTLC3S, outpoint));
}

bool CHtlcDB::IsHTLC3S(const COutPoint& outpoint) const
{
    return db->Exists(MakeKey(DB_HTLC3S, outpoint));
}

// === HTLC3S Hashlock Index Operations ===

bool CHtlcDB::WriteHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Write(MakeKey(DB_HTLC3S_HASHLOCK_USER, key), true);
}

bool CHtlcDB::WriteHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Write(MakeKey(DB_HTLC3S_HASHLOCK_LP1, key), true);
}

bool CHtlcDB::WriteHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Write(MakeKey(DB_HTLC3S_HASHLOCK_LP2, key), true);
}

bool CHtlcDB::EraseHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Erase(MakeKey(DB_HTLC3S_HASHLOCK_USER, key));
}

bool CHtlcDB::EraseHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Erase(MakeKey(DB_HTLC3S_HASHLOCK_LP1, key));
}

bool CHtlcDB::EraseHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    return db->Erase(MakeKey(DB_HTLC3S_HASHLOCK_LP2, key));
}

bool CHtlcDB::GetByHashlock3SUser(const uint256& hashlock, std::vector<COutPoint>& outpoints) const
{
    outpoints.clear();
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    HashlockIndexKey prefix{hashlock, COutPoint()};
    it->Seek(MakeKey(DB_HTLC3S_HASHLOCK_USER, prefix));

    while (it->Valid()) {
        std::pair<char, HashlockIndexKey> key;
        if (it->GetKey(key) && key.first == DB_HTLC3S_HASHLOCK_USER && key.second.hashlock == hashlock) {
            outpoints.push_back(key.second.outpoint);
            it->Next();
        } else {
            break;
        }
    }
    return !outpoints.empty();
}

bool CHtlcDB::GetByHashlock3SLp1(const uint256& hashlock, std::vector<COutPoint>& outpoints) const
{
    outpoints.clear();
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    HashlockIndexKey prefix{hashlock, COutPoint()};
    it->Seek(MakeKey(DB_HTLC3S_HASHLOCK_LP1, prefix));

    while (it->Valid()) {
        std::pair<char, HashlockIndexKey> key;
        if (it->GetKey(key) && key.first == DB_HTLC3S_HASHLOCK_LP1 && key.second.hashlock == hashlock) {
            outpoints.push_back(key.second.outpoint);
            it->Next();
        } else {
            break;
        }
    }
    return !outpoints.empty();
}

bool CHtlcDB::GetByHashlock3SLp2(const uint256& hashlock, std::vector<COutPoint>& outpoints) const
{
    outpoints.clear();
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    HashlockIndexKey prefix{hashlock, COutPoint()};
    it->Seek(MakeKey(DB_HTLC3S_HASHLOCK_LP2, prefix));

    while (it->Valid()) {
        std::pair<char, HashlockIndexKey> key;
        if (it->GetKey(key) && key.first == DB_HTLC3S_HASHLOCK_LP2 && key.second.hashlock == hashlock) {
            outpoints.push_back(key.second.outpoint);
            it->Next();
        } else {
            break;
        }
    }
    return !outpoints.empty();
}

// === HTLC3S Query Operations ===

void CHtlcDB::ForEachHTLC3S(std::function<bool(const HTLC3SRecord&)> func) const
{
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    auto prefix = std::make_pair(DB_HTLC3S, COutPoint());
    it->Seek(prefix);

    while (it->Valid()) {
        std::pair<char, COutPoint> key;
        if (it->GetKey(key) && key.first == DB_HTLC3S) {
            HTLC3SRecord htlc;
            if (it->GetValue(htlc)) {
                if (!func(htlc)) {
                    break;
                }
            }
            it->Next();
        } else {
            break;
        }
    }
}

void CHtlcDB::GetActive3S(std::vector<HTLC3SRecord>& htlcs) const
{
    htlcs.clear();
    ForEachHTLC3S([&](const HTLC3SRecord& htlc) {
        if (htlc.IsActive()) {
            htlcs.push_back(htlc);
        }
        return true;
    });
}

// =============================================================================
// Prune schedule (GC of resolved HTLCs) — see HTLC_PRUNE_DEPTH
// =============================================================================

void CHtlcDB::PruneResolvedAtHeight(uint32_t resolveHeight, Batch& batch)
{
    // Collect the outpoints scheduled at this exact height (contiguous in the DB
    // because the key serializes height first).
    std::vector<std::pair<COutPoint, uint8_t>> scheduled;
    {
        std::unique_ptr<CDBIterator> it(db->NewIterator());
        PruneScheduleKey prefix{resolveHeight, COutPoint()};
        it->Seek(MakeKey(DB_HTLC_PRUNE_SCHED, prefix));
        while (it->Valid()) {
            std::pair<char, PruneScheduleKey> key;
            if (it->GetKey(key) && key.first == DB_HTLC_PRUNE_SCHED &&
                key.second.height == resolveHeight) {
                uint8_t is3S = 0;
                it->GetValue(is3S);
                scheduled.emplace_back(key.second.outpoint, is3S);
                it->Next();
            } else {
                break;
            }
        }
    }

    for (const auto& entry : scheduled) {
        const COutPoint& outpoint = entry.first;
        const bool is3S = entry.second != 0;

        // Always drop the schedule entry (cleans up entries whose resolution was
        // reorged away as well).
        batch.ErasePruneSchedule(resolveHeight, outpoint);

        if (is3S) {
            HTLC3SRecord rec;
            // Defensive: only erase a record that still exists AND is resolved. A
            // reorged-away resolution leaves it ACTIVE (or gone) → leave it be.
            if (ReadHTLC3S(outpoint, rec) && rec.IsResolved()) {
                batch.EraseHTLC3S(outpoint);
                batch.EraseHashlock3SUserIndex(rec.hashlock_user, outpoint);
                batch.EraseHashlock3SLp1Index(rec.hashlock_lp1, outpoint);
                batch.EraseHashlock3SLp2Index(rec.hashlock_lp2, outpoint);
                batch.EraseResolve3SUndo(rec.resolveTxid);
                batch.EraseCreate3SUndo(outpoint.hash); // create txid == htlcOutpoint.hash
            }
        } else {
            HTLCRecord rec;
            if (ReadHTLC(outpoint, rec) && rec.IsResolved()) {
                batch.EraseHTLC(outpoint);
                batch.EraseHashlockIndex(rec.hashlock, outpoint);
                batch.EraseResolveUndo(rec.resolveTxid);
                batch.EraseCreateUndo(outpoint.hash); // create txid == htlcOutpoint.hash
            }
        }
    }
}

size_t CHtlcDB::CountRecords() const
{
    size_t n = 0;
    ForEachHTLC([&](const HTLCRecord&) { n++; return true; });
    ForEachHTLC3S([&](const HTLC3SRecord&) { n++; return true; });
    return n;
}

// === HTLC3S Undo Data Operations ===

bool CHtlcDB::WriteCreate3SUndo(const uint256& txid, const HTLC3SCreateUndoData& undoData)
{
    return db->Write(MakeKey(DB_HTLC3S_CREATE_UNDO, txid), undoData);
}

bool CHtlcDB::ReadCreate3SUndo(const uint256& txid, HTLC3SCreateUndoData& undoData) const
{
    return db->Read(MakeKey(DB_HTLC3S_CREATE_UNDO, txid), undoData);
}

bool CHtlcDB::EraseCreate3SUndo(const uint256& txid)
{
    return db->Erase(MakeKey(DB_HTLC3S_CREATE_UNDO, txid));
}

bool CHtlcDB::WriteResolve3SUndo(const uint256& txid, const HTLC3SResolveUndoData& undoData)
{
    return db->Write(MakeKey(DB_HTLC3S_RESOLVE_UNDO, txid), undoData);
}

bool CHtlcDB::ReadResolve3SUndo(const uint256& txid, HTLC3SResolveUndoData& undoData) const
{
    return db->Read(MakeKey(DB_HTLC3S_RESOLVE_UNDO, txid), undoData);
}

bool CHtlcDB::EraseResolve3SUndo(const uint256& txid)
{
    return db->Erase(MakeKey(DB_HTLC3S_RESOLVE_UNDO, txid));
}

// === HTLC3S Batch Operations ===

void CHtlcDB::Batch::WriteHTLC3S(const HTLC3SRecord& htlc)
{
    batch.Write(MakeKey(DB_HTLC3S, htlc.htlcOutpoint), htlc);
}

void CHtlcDB::Batch::EraseHTLC3S(const COutPoint& outpoint)
{
    batch.Erase(MakeKey(DB_HTLC3S, outpoint));
}

void CHtlcDB::Batch::WriteHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Write(MakeKey(DB_HTLC3S_HASHLOCK_USER, key), true);
}

void CHtlcDB::Batch::WriteHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Write(MakeKey(DB_HTLC3S_HASHLOCK_LP1, key), true);
}

void CHtlcDB::Batch::WriteHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Write(MakeKey(DB_HTLC3S_HASHLOCK_LP2, key), true);
}

void CHtlcDB::Batch::EraseHashlock3SUserIndex(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Erase(MakeKey(DB_HTLC3S_HASHLOCK_USER, key));
}

void CHtlcDB::Batch::EraseHashlock3SLp1Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Erase(MakeKey(DB_HTLC3S_HASHLOCK_LP1, key));
}

void CHtlcDB::Batch::EraseHashlock3SLp2Index(const uint256& hashlock, const COutPoint& outpoint)
{
    HashlockIndexKey key{hashlock, outpoint};
    batch.Erase(MakeKey(DB_HTLC3S_HASHLOCK_LP2, key));
}

void CHtlcDB::Batch::WriteCreate3SUndo(const uint256& txid, const HTLC3SCreateUndoData& undoData)
{
    batch.Write(MakeKey(DB_HTLC3S_CREATE_UNDO, txid), undoData);
}

void CHtlcDB::Batch::EraseCreate3SUndo(const uint256& txid)
{
    batch.Erase(MakeKey(DB_HTLC3S_CREATE_UNDO, txid));
}

void CHtlcDB::Batch::WriteResolve3SUndo(const uint256& txid, const HTLC3SResolveUndoData& undoData)
{
    batch.Write(MakeKey(DB_HTLC3S_RESOLVE_UNDO, txid), undoData);
}

void CHtlcDB::Batch::EraseResolve3SUndo(const uint256& txid)
{
    batch.Erase(MakeKey(DB_HTLC3S_RESOLVE_UNDO, txid));
}

// =============================================================================
// InitHtlcDB - Initialize the HTLC database
// =============================================================================

bool InitHtlcDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    try {
        g_htlcdb.reset();
        g_htlcdb = std::make_unique<CHtlcDB>(nCacheSize, fMemory, fWipe);
        LogPrint(BCLog::HTLC, "HTLC: Initialized database (cache=%zu, memory=%d, wipe=%d)\n",
                 nCacheSize, fMemory, fWipe);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("ERROR: Failed to initialize HTLC database: %s\n", e.what());
        return false;
    }
}

// =============================================================================
// IsHtlcDBMissing - Check if htlc directory exists
// =============================================================================

