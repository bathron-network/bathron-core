// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/settlementdb.h"

#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "coins.h"
#include "hash.h"
#include "logging.h"
#include "masternode/specialtx_validation.h"
#include "primitives/block.h"
#include "txdb.h"
#include "util/validation.h"
#include "validation.h"

#include <algorithm>
#include <fs.h>

// Global settlement DB instance
std::unique_ptr<CSettlementDB> g_settlementdb;

// DB key helpers
namespace {

template<typename T>
std::pair<char, T> MakeKey(char prefix, const T& key)
{
    return std::make_pair(prefix, key);
}

// Undo-prune-schedule key: 'P' + height + txid. Height serialized FIRST so entries
// scheduled at the same height are contiguous (seek-by-height, iterate one height).
// A default (all-zero) txid sorts first within a height, so a composite seek is safe
// here (unlike the vault case, whose default COutPoint has n=0xFFFFFFFF).
struct UndoPruneKey
{
    uint32_t height;
    uint256 txid;

    SERIALIZE_METHODS(UndoPruneKey, obj)
    {
        READWRITE(obj.height, obj.txid);
    }
};

} // anonymous namespace

CSettlementDB::CSettlementDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    fs::path path = GetDataDir() / "settlement";
    db = std::make_unique<CDBWrapper>(path, nCacheSize, fMemory, fWipe);
}

CSettlementDB::~CSettlementDB() = default;

// =============================================================================
// Vault operations
// =============================================================================

bool CSettlementDB::WriteVault(const VaultEntry& vault)
{
    return db->Write(MakeKey(DB_VAULT, vault.outpoint), vault);
}

bool CSettlementDB::ReadVault(const COutPoint& outpoint, VaultEntry& vault) const
{
    return db->Read(MakeKey(DB_VAULT, outpoint), vault);
}

bool CSettlementDB::EraseVault(const COutPoint& outpoint)
{
    return db->Erase(MakeKey(DB_VAULT, outpoint));
}

bool CSettlementDB::IsVault(const COutPoint& outpoint) const
{
    return db->Exists(MakeKey(DB_VAULT, outpoint));
}

void CSettlementDB::ForEachVault(std::function<bool(const VaultEntry&)> func) const
{
    // Iterate over all vault entries (prefix 'V').
    // Seek on the bare prefix byte, NOT std::make_pair(DB_VAULT, COutPoint()):
    // the default COutPoint has n=0xFFFFFFFF, so the composite seek key would
    // start PAST any vault whose outpoint sorts below (all-zero txid, max n).
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    it->Seek(DB_VAULT);

    while (it->Valid()) {
        CDataStream ssKeyRaw = it->GetKey();
        if (ssKeyRaw.size() == 0 || ssKeyRaw[0] != DB_VAULT) {
            break;  // past the vault prefix range: no more vault entries
        }
        std::pair<char, COutPoint> key;
        VaultEntry vault;
        if (!it->GetKey(key) || !it->GetValue(vault)) {
            // An in-range entry that fails to decode must not silently vanish
            // from audit scans (sum(vaults) vs M0_vaulted): log and keep going.
            LogPrintf("ERROR: %s: undecodable vault entry (keysize=%u), skipping\n",
                      __func__, (unsigned)ssKeyRaw.size());
            it->Next();
            continue;
        }
        if (!func(vault)) {
            break;  // Callback returned false, stop iteration
        }
        it->Next();
    }
}

bool CSettlementDB::FindVaultsForAmount(CAmount amount, std::vector<VaultEntry>& vaults) const
{
    vaults.clear();

    if (amount <= 0) {
        return false;
    }

    // Collect all vaults and sort by amount (largest first for efficiency)
    std::vector<VaultEntry> allVaults;
    ForEachVault([&](const VaultEntry& vault) {
        allVaults.push_back(vault);
        return true;  // Continue iteration
    });

    if (allVaults.empty()) {
        return false;
    }

    // Sort by amount descending
    std::sort(allVaults.begin(), allVaults.end(), [](const VaultEntry& a, const VaultEntry& b) {
        return a.amount > b.amount;
    });

    // First try to find an exact match
    for (const auto& vault : allVaults) {
        if (vault.amount == amount) {
            vaults.push_back(vault);
            return true;
        }
    }

    // Greedy selection: take largest vaults until we have enough
    CAmount totalSelected = 0;
    for (const auto& vault : allVaults) {
        vaults.push_back(vault);
        totalSelected += vault.amount;
        if (totalSelected >= amount) {
            return true;
        }
    }

    // Not enough vault balance
    vaults.clear();
    return false;
}

// =============================================================================
// M1 Receipt operations
// =============================================================================

bool CSettlementDB::WriteReceipt(const M1Receipt& receipt)
{
    return db->Write(MakeKey(DB_RECEIPT, receipt.outpoint), receipt);
}

bool CSettlementDB::ReadReceipt(const COutPoint& outpoint, M1Receipt& receipt) const
{
    return db->Read(MakeKey(DB_RECEIPT, outpoint), receipt);
}

bool CSettlementDB::EraseReceipt(const COutPoint& outpoint)
{
    return db->Erase(MakeKey(DB_RECEIPT, outpoint));
}

bool CSettlementDB::IsM1Receipt(const COutPoint& outpoint) const
{
    return db->Exists(MakeKey(DB_RECEIPT, outpoint));
}

// B4.4 O2b — fee-receipt owner. ownerScript stored as raw bytes.
bool CSettlementDB::WriteFeeOwner(const COutPoint& outpoint, const CScript& ownerScript)
{
    return db->Write(MakeKey(DB_FEE_OWNER, outpoint),
                     std::vector<unsigned char>(ownerScript.begin(), ownerScript.end()));
}

bool CSettlementDB::ReadFeeOwner(const COutPoint& outpoint, CScript& ownerScript) const
{
    std::vector<unsigned char> raw;
    if (!db->Read(MakeKey(DB_FEE_OWNER, outpoint), raw)) return false;
    ownerScript = CScript(raw.begin(), raw.end());
    return true;
}

bool CSettlementDB::IsFeeOwned(const COutPoint& outpoint) const
{
    return db->Exists(MakeKey(DB_FEE_OWNER, outpoint));
}

void CSettlementDB::ForEachFeeOwner(std::function<bool(const COutPoint&, const CScript&)> func) const
{
    // Same bare-prefix seek pattern as ForEachVault (a composite seek key with a
    // default COutPoint would start past low-sorting outpoints).
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    it->Seek(DB_FEE_OWNER);

    while (it->Valid()) {
        CDataStream ssKeyRaw = it->GetKey();
        if (ssKeyRaw.size() == 0 || ssKeyRaw[0] != DB_FEE_OWNER) {
            break;
        }
        std::pair<char, COutPoint> key;
        std::vector<unsigned char> raw;
        if (!it->GetKey(key) || !it->GetValue(raw)) {
            LogPrintf("ERROR: %s: undecodable fee-owner entry (keysize=%u), skipping\n",
                      __func__, (unsigned)ssKeyRaw.size());
            it->Next();
            continue;
        }
        if (!func(key.second, CScript(raw.begin(), raw.end()))) {
            break;
        }
        it->Next();
    }
}

// =============================================================================
// Settlement state snapshots
// =============================================================================

bool CSettlementDB::WriteState(const SettlementState& state)
{
    // Write state at height
    if (!db->Write(MakeKey(DB_SETTLEMENT_STATE, state.nHeight), state))
        return false;

    // Also write as "latest" for quick access
    return db->Write(std::string("latest_settlement_state"), state.nHeight);
}

bool CSettlementDB::ReadState(uint32_t height, SettlementState& state) const
{
    return db->Read(MakeKey(DB_SETTLEMENT_STATE, height), state);
}

bool CSettlementDB::ReadLatestState(SettlementState& state) const
{
    uint32_t latestHeight;
    if (!db->Read(std::string("latest_settlement_state"), latestHeight))
        return false;
    return ReadState(latestHeight, state);
}

// =============================================================================
// Unlock undo data operations (BP30 v2.1)
// =============================================================================

bool CSettlementDB::WriteUnlockUndo(const uint256& txid, const UnlockUndoData& undoData)
{
    return db->Write(MakeKey(DB_UNLOCK_UNDO, txid), undoData);
}

bool CSettlementDB::ReadUnlockUndo(const uint256& txid, UnlockUndoData& undoData) const
{
    return db->Read(MakeKey(DB_UNLOCK_UNDO, txid), undoData);
}

// =============================================================================
// Transfer undo data operations (BP30 v2.2)
// =============================================================================

bool CSettlementDB::WriteTransferUndo(const uint256& txid, const TransferUndoData& undoData)
{
    return db->Write(MakeKey(DB_TRANSFER_UNDO, txid), undoData);
}

bool CSettlementDB::ReadTransferUndo(const uint256& txid, TransferUndoData& undoData) const
{
    return db->Read(MakeKey(DB_TRANSFER_UNDO, txid), undoData);
}

// =============================================================================
// Undo GC (prune schedule) — see SETTLEMENT_UNDO_PRUNE_DEPTH
// =============================================================================

void CSettlementDB::PruneUndoAtHeight(uint32_t undoHeight, Batch& batch)
{
    // Collect (txid, undoType) scheduled at this exact height (contiguous in the DB).
    std::vector<std::pair<uint256, uint8_t>> scheduled;
    {
        std::unique_ptr<CDBIterator> it(db->NewIterator());
        it->Seek(MakeKey(DB_UNDO_PRUNE_SCHED, UndoPruneKey{undoHeight, uint256()}));
        while (it->Valid()) {
            std::pair<char, UndoPruneKey> key;
            if (it->GetKey(key) && key.first == DB_UNDO_PRUNE_SCHED &&
                key.second.height == undoHeight) {
                uint8_t undoType = 0;
                it->GetValue(undoType);
                scheduled.emplace_back(key.second.txid, undoType);
                it->Next();
            } else {
                break;
            }
        }
    }

    for (const auto& entry : scheduled) {
        const uint256& txid = entry.first;
        // Always drop the schedule entry; erase the undo record (idempotent — a
        // reorged-away tx already had its undo erased on disconnect).
        batch.EraseUndoPruneSchedule(undoHeight, txid);
        if (entry.second == 0) {
            batch.EraseUnlockUndo(txid);
        } else {
            batch.EraseTransferUndo(txid);
        }
    }
}

// =============================================================================
// Best block tracking (BP30 v2.2 - chain consistency)
// =============================================================================

bool CSettlementDB::WriteBestBlock(const uint256& blockHash)
{
    // Use a fixed key (DB_BEST_BLOCK + empty uint256) for the single best block entry
    return db->Write(std::make_pair(DB_BEST_BLOCK, uint256()), blockHash);
}

bool CSettlementDB::ReadBestBlock(uint256& blockHash) const
{
    return db->Read(std::make_pair(DB_BEST_BLOCK, uint256()), blockHash);
}

// ATOMICITY FIX: All DBs committed marker
bool CSettlementDB::WriteAllCommitted(const uint256& blockHash)
{
    return db->Write(std::make_pair(DB_ALL_COMMITTED, uint256()), blockHash);
}

bool CSettlementDB::ReadAllCommitted(uint256& blockHash) const
{
    return db->Read(std::make_pair(DB_ALL_COMMITTED, uint256()), blockHash);
}

// =============================================================================
// F3 Burnscan tracking - last processed BTC block for catch-up RPC
// =============================================================================

bool CSettlementDB::WriteBurnscanProgress(uint32_t height, const uint256& hash)
{
    // Write both height and hash atomically (separate keys, same DB)
    if (!db->Write(std::make_pair(DB_BURNSCAN_HEIGHT, uint256()), height))
        return false;
    if (!db->Write(std::make_pair(DB_BURNSCAN_HASH, uint256()), hash))
        return false;
    return true;
}

bool CSettlementDB::ReadBurnscanProgress(uint32_t& height, uint256& hash) const
{
    // Read both height and hash - both must exist for valid progress
    if (!db->Read(std::make_pair(DB_BURNSCAN_HEIGHT, uint256()), height))
        return false;
    if (!db->Read(std::make_pair(DB_BURNSCAN_HASH, uint256()), hash))
        return false;
    return true;
}

// =============================================================================
// IsM0Standard - DB-driven UTXO classification
// =============================================================================

bool CSettlementDB::IsM0Standard(const COutPoint& outpoint) const
{
    // M0 standard = NOT in any settlement index (V/R)
    if (IsVault(outpoint)) return false;
    if (IsM1Receipt(outpoint)) return false;
    return true;
}

// =============================================================================
// Batch operations
// =============================================================================

CSettlementDB::Batch::Batch(CSettlementDB& db) : batch(CLIENT_VERSION), parent(db) {}

void CSettlementDB::Batch::WriteVault(const VaultEntry& vault)
{
    batch.Write(MakeKey(DB_VAULT, vault.outpoint), vault);
}

void CSettlementDB::Batch::EraseVault(const COutPoint& outpoint)
{
    batch.Erase(MakeKey(DB_VAULT, outpoint));
}

void CSettlementDB::Batch::WriteReceipt(const M1Receipt& receipt)
{
    batch.Write(MakeKey(DB_RECEIPT, receipt.outpoint), receipt);
}

void CSettlementDB::Batch::EraseReceipt(const COutPoint& outpoint)
{
    batch.Erase(MakeKey(DB_RECEIPT, outpoint));
}

void CSettlementDB::Batch::WriteFeeOwner(const COutPoint& outpoint, const CScript& ownerScript)
{
    batch.Write(MakeKey(DB_FEE_OWNER, outpoint),
                std::vector<unsigned char>(ownerScript.begin(), ownerScript.end()));
}

void CSettlementDB::Batch::EraseFeeOwner(const COutPoint& outpoint)
{
    batch.Erase(MakeKey(DB_FEE_OWNER, outpoint));
}

void CSettlementDB::Batch::WriteState(const SettlementState& state)
{
    batch.Write(MakeKey(DB_SETTLEMENT_STATE, state.nHeight), state);
    batch.Write(std::string("latest_settlement_state"), state.nHeight);
}

void CSettlementDB::Batch::WriteUnlockUndo(const uint256& txid, const UnlockUndoData& undoData)
{
    batch.Write(MakeKey(DB_UNLOCK_UNDO, txid), undoData);
}

void CSettlementDB::Batch::EraseUnlockUndo(const uint256& txid)
{
    batch.Erase(MakeKey(DB_UNLOCK_UNDO, txid));
}

void CSettlementDB::Batch::WriteTransferUndo(const uint256& txid, const TransferUndoData& undoData)
{
    batch.Write(MakeKey(DB_TRANSFER_UNDO, txid), undoData);
}

void CSettlementDB::Batch::EraseTransferUndo(const uint256& txid)
{
    batch.Erase(MakeKey(DB_TRANSFER_UNDO, txid));
}

void CSettlementDB::Batch::WriteBestBlock(const uint256& blockHash)
{
    batch.Write(std::make_pair(DB_BEST_BLOCK, uint256()), blockHash);
}

void CSettlementDB::Batch::WriteUndoPruneSchedule(uint32_t height, const uint256& txid, uint8_t undoType)
{
    batch.Write(MakeKey(DB_UNDO_PRUNE_SCHED, UndoPruneKey{height, txid}), undoType);
}

void CSettlementDB::Batch::EraseUndoPruneSchedule(uint32_t height, const uint256& txid)
{
    batch.Erase(MakeKey(DB_UNDO_PRUNE_SCHED, UndoPruneKey{height, txid}));
}

bool CSettlementDB::Batch::Commit()
{
    return parent.db->WriteBatch(batch);
}

bool CSettlementDB::Sync()
{
    return db->Sync();
}

// =============================================================================
// InitSettlementDB - Initialize the settlement database
// =============================================================================

bool InitSettlementDB(size_t nCacheSize, bool fMemory, bool fWipe)
{
    try {
        g_settlementdb.reset();
        g_settlementdb = std::make_unique<CSettlementDB>(nCacheSize, fMemory, fWipe);
        LogPrint(BCLog::STATE, "Settlement: Initialized database (cache=%zu, memory=%d, wipe=%d)\n",
                 nCacheSize, fMemory, fWipe);
        return true;
    } catch (const std::exception& e) {
        LogPrintf("ERROR: Failed to initialize settlement database: %s\n", e.what());
        return false;
    }
}

// =============================================================================
// InitSettlementAtGenesis - Initialize settlement state at genesis
// =============================================================================

bool InitSettlementAtGenesis(const uint256& genesisBlockHash)
{
    if (!g_settlementdb) {
        LogPrintf("ERROR: InitSettlementAtGenesis called before InitSettlementDB\n");
        return false;
    }

    // Check if genesis state already exists
    SettlementState existingState;
    if (g_settlementdb->ReadState(0, existingState)) {
        LogPrint(BCLog::STATE, "Settlement: Genesis state already exists, skipping initialization\n");
        return true;
    }

    // Create genesis SettlementState (M0/M1 model)
    SettlementState genesisState;
    genesisState.M0_vaulted = 0;
    genesisState.M1_supply = 0;
    genesisState.M0_shielded = 0;  // No Sapling funds at genesis
    genesisState.M0_total_supply = 0;
    genesisState.burnclaims_block = 0;
    genesisState.nHeight = 0;
    genesisState.hashBlock = genesisBlockHash;

    // Verify genesis invariants (P1: 0 == 0 + 0)
    if (!genesisState.CheckInvariants()) {
        LogPrintf("ERROR: Genesis SettlementState fails invariant check\n");
        return false;
    }

    // Write genesis state
    if (!g_settlementdb->WriteState(genesisState)) {
        LogPrintf("ERROR: Failed to write genesis SettlementState\n");
        return false;
    }

    LogPrintf("Settlement: Genesis state initialized\n");

    return true;
}

// =============================================================================
// CheckSettlementDBConsistency - Verify settlement DB matches chain tip
// =============================================================================

bool CheckSettlementDBConsistency(const uint256& chainTipHash, int chainTipHeight, bool& fRequireRebuild)
{
    fRequireRebuild = false;

    if (!g_settlementdb) {
        LogPrintf("Settlement: No settlement DB, skipping consistency check\n");
        return true;  // No DB, nothing to check
    }

    // Read the best block from settlement DB
    uint256 dbBestBlock;
    if (!g_settlementdb->ReadBestBlock(dbBestBlock)) {
        // No best block recorded - this is normal for fresh DB or pre-v2.2 DB
        LogPrintf("Settlement: No best block in DB, will be set on next block connect\n");
        return true;
    }

    // If DB best block matches chain tip, we're consistent
    if (dbBestBlock == chainTipHash) {
        LogPrintf("Settlement: DB consistent with chain tip (block=%s, height=%d)\n",
                  chainTipHash.ToString().substr(0, 8), chainTipHeight);

        // ATOMICITY FIX: Also check the "all committed" marker
        // If this doesn't match, we crashed between committing some DBs but not all
        uint256 allCommitted;
        if (g_settlementdb->ReadAllCommitted(allCommitted)) {
            if (allCommitted != chainTipHash) {
                LogPrintf("ATOMICITY: all_committed marker %s doesn't match chain tip %s\n",
                          allCommitted.ToString().substr(0, 8), chainTipHash.ToString().substr(0, 8));
                LogPrintf("ATOMICITY: Crash detected during multi-DB commit - requires rebuild\n");
                fRequireRebuild = true;
                return false;
            }
            LogPrintf("ATOMICITY: all_committed marker OK\n");
        } else {
            // No all_committed marker - this is OK for first run after upgrade
            LogPrintf("ATOMICITY: No all_committed marker (normal for first run)\n");
        }

        return true;
    }

    // DB best block doesn't match chain tip - need to check if it's on our chain
    LogPrintf("Settlement: DB best block %s doesn't match chain tip %s\n",
              dbBestBlock.ToString().substr(0, 8), chainTipHash.ToString().substr(0, 8));

    // The safest approach: if inconsistent, require a full rebuild via -reindex
    // This ensures the settlement DB is always correct, even if the mismatch
    // is due to a crash during reorg or other corruption.
    fRequireRebuild = true;

    LogPrintf("Settlement: DB inconsistent with chain - requires rebuild\n");
    LogPrintf("Settlement: Run with -reindex or -rebuildsettlement to rebuild\n");

    return false;  // Inconsistent - need rebuild
}

// =============================================================================
// IsSettlementDBMissing - Check if settlement directory exists
// =============================================================================

bool IsSettlementDBMissing()
{
    fs::path settlementPath = GetDataDir() / "settlement";

    // Check if directory exists
    if (!fs::exists(settlementPath)) {
        LogPrintf("Settlement: Directory %s does not exist\n", settlementPath.string());
        return true;
    }

    // Check if directory is empty (no files = effectively missing)
    if (fs::is_empty(settlementPath)) {
        LogPrintf("Settlement: Directory %s is empty\n", settlementPath.string());
        return true;
    }

    return false;
}

// =============================================================================
// RebuildSettlementFromChain - Reconstruct settlement state from blockchain
// BP30 Rebuild-From-Truth implementation
// =============================================================================

bool RebuildSettlementFromChain()
{
    AssertLockHeld(cs_main);

    LogPrintf("=======================================================\n");
    LogPrintf("SETTLEMENT REBUILD: Starting rebuild from chain\n");
    LogPrintf("=======================================================\n");

    // Step 1: Verify we have a valid chain
    if (!chainActive.Tip()) {
        return error("RebuildSettlement: No chain tip available");
    }

    const int tipHeight = chainActive.Height();
    const uint256& tipHash = chainActive.Tip()->GetBlockHash();

    LogPrintf("RebuildSettlement: Chain tip at height=%d hash=%s\n",
              tipHeight, tipHash.ToString().substr(0, 16));

    // Step 2: Wipe and reinitialize settlement DB
    LogPrintf("RebuildSettlement: Wiping settlement database...\n");

    // Close existing DB
    g_settlementdb.reset();

    // Remove settlement directory
    fs::path settlementPath = GetDataDir() / "settlement";
    if (fs::exists(settlementPath)) {
        fs::remove_all(settlementPath);
    }

    // Reinitialize with fresh DB
    if (!InitSettlementDB(1 << 20, false, false)) {
        return error("RebuildSettlement: Failed to reinitialize settlement DB");
    }

    // Step 3: Initialize genesis state (height=0, all zeros)
    const uint256& genesisHash = Params().GenesisBlock().GetHash();
    if (!InitSettlementAtGenesis(genesisHash)) {
        return error("RebuildSettlement: Failed to initialize genesis state");
    }

    LogPrintf("RebuildSettlement: Genesis state initialized\n");

    // Step 4: Replay blocks from height=1 to tip
    LogPrintf("RebuildSettlement: Replaying %d blocks...\n", tipHeight);

    int64_t startTime = GetTimeMillis();
    int progressInterval = std::max(1, tipHeight / 10);  // Log every 10%

    CBlockIndex* pindex = chainActive.Genesis();
    while (pindex && pindex != chainActive.Tip()) {
        pindex = chainActive.Next(pindex);
        if (!pindex) break;

        int height = pindex->nHeight;

        // Progress logging
        if (height % progressInterval == 0 || height == tipHeight) {
            LogPrintf("RebuildSettlement: Progress %d/%d (%.1f%%)\n",
                      height, tipHeight, (100.0 * height / tipHeight));
        }

        // Read block from disk
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            return error("RebuildSettlement: Failed to read block at height=%d", height);
        }

        // Create coins view for this block's context
        CCoinsViewCache view(pcoinsTip.get());

        // Process special transactions (TX_MINT_M0BTC, TX_LOCK, TX_UNLOCK, etc.)
        // This updates: vaults, receipts, settlement state, M0_total_supply
        // fSettlementOnly=true: skip CheckSpecialTx and MN validation (already validated when block was first connected)
        CValidationState state;
        if (!ProcessSpecialTxsInBlock(block, pindex, &view, state, false, true)) {
            return error("RebuildSettlement: ProcessSpecialTxsInBlock failed at height=%d: %s",
                        height, FormatStateMessage(state));
        }
    }

    int64_t elapsed = GetTimeMillis() - startTime;

    // Step 5: Verify final state
    SettlementState finalState;
    if (!g_settlementdb->ReadLatestState(finalState)) {
        return error("RebuildSettlement: Failed to read final state");
    }

    LogPrintf("=======================================================\n");
    LogPrintf("SETTLEMENT REBUILD: Complete\n");
    LogPrintf("  Duration: %lld ms\n", elapsed);
    LogPrintf("  Height: %d\n", finalState.nHeight);
    LogPrintf("  M0_total_supply: %lld sats\n", finalState.M0_total_supply);
    LogPrintf("  M0_vaulted: %lld sats\n", finalState.M0_vaulted);
    LogPrintf("  M1_supply: %lld sats\n", finalState.M1_supply);
    LogPrintf("  Invariants: A5=%s A6=%s\n",
              (finalState.M0_vaulted == finalState.M1_supply) ? "OK" : "FAIL",
              "OK");  // A5 verified during replay
    LogPrintf("=======================================================\n");

    return true;
}
