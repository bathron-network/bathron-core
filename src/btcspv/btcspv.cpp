// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <btcspv/btcspv.h>
#include <dbwrapper.h>
#include <hash.h>
#include <logging.h>
#include <utilstrencodings.h>

#include <algorithm>

// Global instance
std::unique_ptr<CBtcSPV> g_btc_spv;

// Database key prefixes (from BP09 spec)
static const char DB_HEADER = 'H';        // 'BH' || hash -> BtcHeaderIndex
static const char DB_BEST_HEIGHT = 'b';   // 'Bb' || height -> hash (best chain only)
static const char DB_TIP_HASH = 't';      // 'Bt' -> best tip hash
static const char DB_TIP_WORK = 'w';      // 'Bw' -> best chainwork
static const char DB_TIP_HEIGHT = 'h';    // 'Bh' -> best height
static const char DB_MIN_HEIGHT = 'm';    // 'Bm' -> minimum supported height (persisted at init)

// Bitcoin mainnet parameters
const BtcNetworkParams& GetBtcMainnetParams() {
    static BtcNetworkParams params;
    static bool initialized = false;
    if (!initialized) {
        params.magic = 0xD9B4BEF9;
        params.genesisHash = uint256S("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        params.defaultPort = 8333;
        // powLimit = 00000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        params.powLimit = UintToArith256(uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        initialized = true;
    }
    return params;
}

// Bitcoin Signet parameters
const BtcNetworkParams& GetBtcSignetParams() {
    static BtcNetworkParams params;
    static bool initialized = false;
    if (!initialized) {
        params.magic = 0x0A03CF40;
        params.genesisHash = uint256S("00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6");
        params.defaultPort = 38333;
        // Signet has same powLimit format
        params.powLimit = UintToArith256(uint256S("00000377ae000000000000000000000000000000000000000000000000000000"));
        initialized = true;
    }
    return params;
}

// Mainnet checkpoints
const std::vector<BtcCheckpoint>& GetBtcMainnetCheckpoints() {
    static std::vector<BtcCheckpoint> checkpoints;
    static bool initialized = false;
    if (!initialized) {
        // Checkpoint at block 800000 (2023)
        checkpoints.push_back({
            800000,
            uint256S("00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054"),
            UintToArith256(uint256S("0000000000000000000000000000000000000000576594be759cea81fc0e5428"))
        });
        // Checkpoint at block 840000 (2024 - halving)
        checkpoints.push_back({
            840000,
            uint256S("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"),
            UintToArith256(uint256S("0000000000000000000000000000000000000000634ce635e3ca168c6e40c980"))
        });
        initialized = true;
    }
    return checkpoints;
}

// Signet checkpoints
const std::vector<BtcCheckpoint>& GetBtcSignetCheckpoints() {
    static std::vector<BtcCheckpoint> checkpoints;
    static bool initialized = false;
    if (!initialized) {
        // Signet checkpoint at block 200000
        checkpoints.push_back({
            200000,
            uint256S("0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c"),
            UintToArith256(uint256S("0000000000000000000000000000000000000000000000000000024389c5fcd1"))
        });
        // Signet checkpoint at block 280000
        checkpoints.push_back({
            280000,
            uint256S("00000007cf38f0abf5564dde6a748fbd09d4c29f755405ae936d6b9b13d5db3c"),
            UintToArith256(uint256S("000000000000000000000000000000000000000000000000000008d0d4c63c66"))
        });
        // Signet checkpoint at block 286000 (genesis checkpoint for ultra-clean genesis v3.1)
        // BEFORE first burn at 286326, allows all burns to be discovered dynamically
        checkpoints.push_back({
            286000,
            uint256S("0000000732c0c78558a50be0774d99188f65ee374e10ff9816deaf42df9f7780"),
            UintToArith256(uint256S("000000000000000000000000000000000000000000000000000009f3cf1f88dc"))
        });
        initialized = true;
    }
    return checkpoints;
}

// Genesis header for Signet at height 286000 (BATHRON SPV starting point)
// This is the FULL 80-byte header, hardcoded so new nodes can sync from here
// Raw hex: 00000020b4db62a731350ea5e718564de86bc6b524f09c43e655fe8108a6c0db09000000
//          f3d440fbab37ab5a7de6ee128dc5b5833bdf9437913c8a7b8ce3232bdb1c317411025e69d720141d1644790b
bool GetBtcSignetGenesisHeader(BtcBlockHeader& header) {
    // Block 286000 on Signet
    header.nVersion = 0x20000000;  // Version 536870912
    header.hashPrevBlock = uint256S("00000009dbc0a60881fe55e6439cf024b5c66be84d5618e7a50e3531a762dbb4");
    // Verified: double-SHA256(serialized header) == checkpoint hash 0000000732c0...
    // (previous literals had transcription typos in merkleRoot/nTime/nNonce that did
    // NOT hash to the checkpoint; the raw-hex comment above was always correct).
    header.hashMerkleRoot = uint256S("74311cdb2b23e38c7b8a3c913794df3b83b5c58d12eee67d5aab37abfb40d4f3");
    header.nTime = 1767768593;     // unix time of signet block 286000
    header.nBits = 0x1d1420d7;     // Difficulty bits
    header.nNonce = 192496662;     // Nonce
    return true;
}

// Genesis header for Mainnet at height 800000 (BATHRON SPV starting point).
// Verified: double-SHA256(serialized header) == checkpoint hash
// 00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054 (real BTC block 800000).
bool GetBtcMainnetGenesisHeader(BtcBlockHeader& header) {
    header.nVersion = 0x341d6000;
    header.hashPrevBlock  = uint256S("000000000000000000012117ad9f72c1c0e42227c2d042dca23e6b96bd9fbb55");
    header.hashMerkleRoot = uint256S("91f01a00530c8c83617190048ea8b0814d506cf24dfdbcf8893f8f0cab7f0855");
    header.nTime = 1690168629;
    header.nBits = 0x17053894;
    header.nNonce = 106861918;
    return true;
}

// BtcBlockHeader implementation
uint256 BtcBlockHeader::GetHash() const {
    return SerializeHash(*this);
}

void BtcBlockHeader::SetNull() {
    nVersion = 0;
    hashPrevBlock.SetNull();
    hashMerkleRoot.SetNull();
    nTime = 0;
    nBits = 0;
    nNonce = 0;
}

void BtcHeaderIndex::SetNull() {
    hash.SetNull();
    hashPrevBlock.SetNull();
    height = 0;
    chainWorkSer.SetNull();
    header.SetNull();
}

// Status to string
std::string BtcHeaderStatusToString(BtcHeaderStatus status) {
    switch (status) {
        case BtcHeaderStatus::VALID: return "valid";
        case BtcHeaderStatus::INVALID_POW: return "invalid-pow";
        case BtcHeaderStatus::INVALID_PREVBLOCK: return "bad-prevblock";
        case BtcHeaderStatus::INVALID_TIMESTAMP_FUTURE: return "future-timestamp";
        case BtcHeaderStatus::INVALID_TIMESTAMP_MTP: return "timestamp-below-mtp";
        case BtcHeaderStatus::INVALID_RETARGET: return "invalid-retarget";
        case BtcHeaderStatus::INVALID_CHECKPOINT: return "checkpoint-mismatch";
        case BtcHeaderStatus::DUPLICATE: return "duplicate";
        case BtcHeaderStatus::ORPHAN: return "orphan";
        default: return "unknown";
    }
}

// CBtcSPV implementation
CBtcSPV::CBtcSPV() : m_bestHeight(0), m_minSupportedHeight(UINT32_MAX), m_testnet(false) {
    m_bestTipHash.SetNull();
    m_bestChainWork = 0;
}

CBtcSPV::~CBtcSPV() {
    Shutdown();
}

bool CBtcSPV::Init(const std::string& datadir, bool testnet) {
    LOCK(m_cs_spv);
    return InitLocked(datadir, testnet);
}

bool CBtcSPV::InitLocked(const std::string& datadir, bool testnet) {
    // MUST be called with m_cs_spv held
    m_testnet = testnet;
    m_datadir = datadir;  // Store for Reload()

    // Set network params
    m_netParams = testnet ? GetBtcSignetParams() : GetBtcMainnetParams();
    m_checkpoints = testnet ? GetBtcSignetCheckpoints() : GetBtcMainnetCheckpoints();

    // BP-BTCHEADERS-HARDENING: load the FULL header of the genesis checkpoint and
    // SELF-CHECK it hashes to the checkpoint hash. This header is the difficulty
    // parent for the first seeded BTC header (so R6 validates it during bootstrap
    // instead of trusting the seeder). A wrong hardcode aborts the node here rather
    // than silently shipping a corrupt anchor (this is exactly the guard that the
    // earlier mistranscribed signet header would have tripped). Regtest has no BTC
    // checkpoint, so it simply has no genesis header (R6 is unconditional there).
    m_hasGenesisCheckpointHeader = false;
    if (!m_checkpoints.empty()) {
        const BtcCheckpoint& gcp = m_testnet ? m_checkpoints.back() : m_checkpoints.front();
        bool gotHeader = m_testnet ? GetBtcSignetGenesisHeader(m_genesisCheckpointHeader)
                                   : GetBtcMainnetGenesisHeader(m_genesisCheckpointHeader);
        if (gotHeader) {
            if (m_genesisCheckpointHeader.GetHash() != gcp.hash) {
                LogPrintf("BTC-SPV: FATAL — hardcoded genesis header at %u hashes to %s, expected %s\n",
                          gcp.height, m_genesisCheckpointHeader.GetHash().ToString(), gcp.hash.ToString());
                return false;
            }
            m_hasGenesisCheckpointHeader = true;
            LogPrintf("BTC-SPV: genesis checkpoint header at %u verified (hash matches)\n", gcp.height);
        }
    }

    // Open database
    std::string dbpath = datadir + "/btcspv";
    try {
        // Cache size 2MB: write_buffer_size=512KB forces periodic memtable flush
        // during header sync. 100MB was overkill for a ~2MB database and caused
        // all data to stay in unflushed memtable, leading to incomplete backups.
        m_db = std::make_unique<CDBWrapper>(dbpath, 2 * 1024 * 1024, false, false);
    } catch (const std::exception& e) {
        LogPrintf("BTC-SPV: Failed to open database: %s\n", e.what());
        return false;
    }

    // Load tip from database (no nested lock - LoadTipLocked expects lock held)
    if (!LoadTipLocked()) {
        // Initialize with genesis or checkpoint
        if (!m_checkpoints.empty()) {
            // For Signet: use the LAST checkpoint (286000) as starting point
            // This is where we have the full header hardcoded
            const BtcCheckpoint& cp = m_testnet ? m_checkpoints.back() : m_checkpoints.front();
            m_bestTipHash = cp.hash;
            m_bestHeight = cp.height;
            m_bestChainWork = cp.chainWork;

            // Store the header index for the checkpoint
            BtcHeaderIndex cpIndex;
            cpIndex.hash = cp.hash;
            cpIndex.height = cp.height;
            cpIndex.SetChainWork(cp.chainWork);

            // Use the verified hardcoded genesis header (signet 286000 / mainnet
            // 800000) so the checkpoint carries its real header for chain validation.
            if (m_hasGenesisCheckpointHeader && cp.hash == m_genesisCheckpointHeader.GetHash()) {
                cpIndex.header = m_genesisCheckpointHeader;
                cpIndex.hashPrevBlock = cpIndex.header.hashPrevBlock;
                LogPrintf("BTC-SPV: Using verified genesis header at height %u\n", cp.height);
            } else {
                // Fallback: null header (older checkpoints)
                cpIndex.header.SetNull();
            }
            StoreHeaderLocked(cpIndex);

            // Store height -> hash mapping for best chain
            m_db->Write(std::make_pair(DB_BEST_HEIGHT, cp.height), cp.hash);

            // CRITICAL: Persist the minimum supported height in DB
            // This is the OLDEST checkpoint height - burns below this cannot be verified
            m_minSupportedHeight = cp.height;
            m_db->Write(std::make_pair(DB_MIN_HEIGHT, 0), m_minSupportedHeight);

            LogPrintf("BTC-SPV: Initialized from checkpoint at height %d (min_supported=%d)\n",
                      cp.height, m_minSupportedHeight);
        } else {
            // Start from genesis
            m_bestTipHash = m_netParams.genesisHash;
            m_bestHeight = 0;
            m_bestChainWork = 0;
            m_minSupportedHeight = 0;  // Full sync from genesis
            m_db->Write(std::make_pair(DB_MIN_HEIGHT, 0), m_minSupportedHeight);
            LogPrintf("BTC-SPV: Initialized from genesis (min_supported=0)\n");
        }
        StoreTipLocked();
    }

    LogPrintf("BTC-SPV: Initialized. Tip height=%d hash=%s testnet=%d\n",
              m_bestHeight, m_bestTipHash.ToString().substr(0, 16), testnet);
    return true;
}

void CBtcSPV::Shutdown() {
    LOCK(m_cs_spv);
    ShutdownLocked();
}

void CBtcSPV::ShutdownLocked() {
    // MUST be called with m_cs_spv held
    if (m_db) {
        StoreTipLocked();
        // Force memtable flush to SSTables so backups capture all data.
        // LevelDB destructor does NOT flush the memtable — it only frees it.
        // Without this, data exists only in WAL and may be lost during tar backup/restore.
        m_db->Compact();
        m_db.reset();
    }
    m_headerCache.clear();
}

bool CBtcSPV::Reload() {
    LOCK(m_cs_spv);  // Single lock for entire reload operation

    // COMMIT 5: Hot reload SPV store without daemon restart
    // =====================================================
    // This allows ops to update the btcspv directory (e.g., copy headers from
    // a synced node) and reload without restarting the daemon.
    //
    // Procedure:
    // 1. Store current state in case we need to recover
    // 2. Shutdown cleanly
    // 3. Re-initialize from disk
    // 4. If Init fails, log error (state is lost, but that's acceptable for ops)

    if (m_datadir.empty()) {
        LogPrintf("BTC-SPV: Reload failed - datadir not set (Init never called?)\n");
        return false;
    }

    // Save current state info for logging
    uint32_t oldHeight = m_bestHeight;
    uint256 oldTip = m_bestTipHash;

    LogPrintf("BTC-SPV: Reloading from %s (current tip: height=%d hash=%s)\n",
              m_datadir, oldHeight, oldTip.ToString().substr(0, 16));

    // Shutdown current instance (no nested lock)
    ShutdownLocked();

    // Re-initialize (no nested lock)
    if (!InitLocked(m_datadir, m_testnet)) {
        LogPrintf("BTC-SPV: Reload FAILED - Init returned false\n");
        // State is now inconsistent - SPV is unavailable until next restart
        // This is acceptable for ops scenarios
        return false;
    }

    // Repair any stale height-index entries left by a pre-fix reorg.
    RepairHeightIndexLocked();

    LogPrintf("BTC-SPV: Reload SUCCESS - old tip: height=%d, new tip: height=%d hash=%s\n",
              oldHeight, m_bestHeight, m_bestTipHash.ToString().substr(0, 16));
    return true;
}

bool CBtcSPV::LoadTipLocked() {
    // MUST be called with m_cs_spv held
    if (!m_db) return false;

    uint256 tipHash;
    if (!m_db->Read(std::make_pair(DB_TIP_HASH, 0), tipHash)) {
        return false;
    }

    uint32_t height;
    if (!m_db->Read(std::make_pair(DB_TIP_HEIGHT, 0), height)) {
        return false;
    }

    uint256 workSer;
    if (!m_db->Read(std::make_pair(DB_TIP_WORK, 0), workSer)) {
        return false;
    }

    // Load min supported height (persisted at init time)
    uint32_t minHeight;
    if (!m_db->Read(std::make_pair(DB_MIN_HEIGHT, 0), minHeight)) {
        // Migration: DB was created before DB_MIN_HEIGHT was added
        // Fall back to lowest checkpoint as a safe default
        if (!m_checkpoints.empty()) {
            minHeight = m_checkpoints[0].height;
            for (const auto& cp : m_checkpoints) {
                if (cp.height < minHeight) {
                    minHeight = cp.height;
                }
            }
            // Persist for future loads
            m_db->Write(std::make_pair(DB_MIN_HEIGHT, 0), minHeight);
            LogPrintf("BTC-SPV: Migrated DB_MIN_HEIGHT=%d from checkpoint fallback\n", minHeight);
        } else {
            minHeight = 0;  // Genesis
        }
    }

    m_bestTipHash = tipHash;
    m_bestHeight = height;
    m_bestChainWork = UintToArith256(workSer);
    m_minSupportedHeight = minHeight;

    LogPrintf("BTC-SPV: Loaded tip height=%d hash=%s min_supported=%d\n",
              m_bestHeight, m_bestTipHash.ToString().substr(0, 16), m_minSupportedHeight);
    return true;
}

bool CBtcSPV::StoreTipLocked() {
    // MUST be called with m_cs_spv held
    if (!m_db) return false;

    // Use direct writes to avoid any batch serialization issues
    if (!m_db->Write(std::make_pair(DB_TIP_HASH, 0), m_bestTipHash)) return false;
    if (!m_db->Write(std::make_pair(DB_TIP_HEIGHT, 0), m_bestHeight)) return false;
    // fSync=true on last write: forces LevelDB WAL flush to disk.
    // Ensures btcspv backup is complete even if process is killed shortly after.
    if (!m_db->Write(std::make_pair(DB_TIP_WORK, 0), ArithToUint256(m_bestChainWork), true)) return false;
    return true;
}

bool CBtcSPV::StoreHeader(const BtcHeaderIndex& index) {
    LOCK(m_cs_spv);
    return StoreHeaderLocked(index);
}

bool CBtcSPV::StoreHeaderLocked(const BtcHeaderIndex& index) {
    // MUST be called with m_cs_spv held
    if (!m_db) return false;

    auto key = std::make_pair(DB_HEADER, index.hash);

    if (!m_db->Write(key, index)) {
        LogPrintf("BTC-SPV: StoreHeader failed h=%d\n", index.height);
        return false;
    }

    // Update cache
    m_headerCache[index.hash] = index;
    if (m_headerCache.size() > MAX_CACHE_SIZE) {
        m_headerCache.erase(m_headerCache.begin());
    }

    return true;
}

bool CBtcSPV::GetHeader(const uint256& hash, BtcHeaderIndex& out) const {
    LOCK(m_cs_spv);
    return GetHeaderLocked(hash, out);
}

bool CBtcSPV::GetHeaderLocked(const uint256& queryHash, BtcHeaderIndex& out) const {
    // MUST be called with m_cs_spv held

    // CRITICAL: Make a local copy of the hash to avoid aliasing issues.
    // Callers like GetMedianTimePastLocked do: GetHeaderLocked(current.hashPrevBlock, current)
    // If queryHash is a reference to out.hashPrevBlock, the Read() below would overwrite
    // queryHash through the out parameter, corrupting the key comparison.
    const uint256 hash = queryHash;

    // Check cache first
    auto it = m_headerCache.find(hash);
    if (it != m_headerCache.end()) {
        out = it->second;
        return true;
    }

    // Use same key format as StoreHeaderLocked
    auto key = std::make_pair(DB_HEADER, hash);

    // Check database
    if (m_db && m_db->Read(key, out)) {
        // Verify integrity - the stored hash should match the key
        if (hash != out.hash) {
            LogPrintf("BTC-SPV: GetHeader integrity check failed: queried=%s got=%s\n",
                      hash.ToString().substr(0, 16), out.hash.ToString().substr(0, 16));
            return false;
        }
        // Cache valid entry
        m_headerCache[hash] = out;
        return true;
    }

    return false;
}

bool CBtcSPV::GetHeaderAtHeight(uint32_t height, BtcHeaderIndex& out) const {
    LOCK(m_cs_spv);
    return GetHeaderAtHeightLocked(height, out);
}

bool CBtcSPV::GetHeaderAtHeightLocked(uint32_t height, BtcHeaderIndex& out) const {
    // MUST be called with m_cs_spv held
    if (!m_db) return false;

    // Read hash at height from best chain index
    uint256 hash;
    if (!m_db->Read(std::make_pair(DB_BEST_HEIGHT, height), hash)) {
        return false;
    }

    return GetHeaderLocked(hash, out);
}

uint32_t CBtcSPV::GetTipHeight() const {
    return m_bestHeight;
}

uint256 CBtcSPV::GetTipHash() const {
    return m_bestTipHash;
}

arith_uint256 CBtcSPV::GetTipChainWork() const {
    return m_bestChainWork;
}

bool CBtcSPV::IsInBestChain(const uint256& blockHash) const {
    LOCK(m_cs_spv);
    BtcHeaderIndex index;
    if (!GetHeaderLocked(blockHash, index)) {
        return false;
    }

    // Check if this hash is in the best chain at this height
    uint256 bestHashAtHeight;
    if (!m_db || !m_db->Read(std::make_pair(DB_BEST_HEIGHT, index.height), bestHashAtHeight)) {
        return false;
    }

    return bestHashAtHeight == blockHash;
}

uint32_t CBtcSPV::GetConfirmations(const uint256& blockHash) const {
    LOCK(m_cs_spv);

    // Check if in best chain (inline to avoid nested lock)
    BtcHeaderIndex index;
    if (!GetHeaderLocked(blockHash, index)) {
        return 0;
    }

    uint256 bestHashAtHeight;
    if (!m_db || !m_db->Read(std::make_pair(DB_BEST_HEIGHT, index.height), bestHashAtHeight)) {
        return 0;
    }

    if (bestHashAtHeight != blockHash) {
        return 0;  // Not in best chain
    }

    return m_bestHeight - index.height + 1;
}

// Calculate work for a single block (from BP09 spec)
arith_uint256 CBtcSPV::GetBlockProof(const BtcBlockHeader& header) const {
    arith_uint256 target;
    bool negative, overflow;
    target.SetCompact(header.nBits, &negative, &overflow);

    if (negative || overflow || target == 0) {
        return 0;
    }

    // Work = 2^256 / (target + 1)
    // Bitcoin uses: (~target / (target + 1)) + 1
    return (~target / (target + 1)) + 1;
}

bool CBtcSPV::CheckProofOfWork(const BtcBlockHeader& header) const {
    uint256 hash = header.GetHash();

    arith_uint256 target;
    bool negative, overflow;
    target.SetCompact(header.nBits, &negative, &overflow);

    // Check range
    if (negative || target == 0 || overflow || target > m_netParams.powLimit) {
        return false;
    }

    // Check PoW: hash must be below target
    if (UintToArith256(hash) > target) {
        return false;
    }

    return true;
}

int64_t CBtcSPV::GetMedianTimePastLocked(const BtcHeaderIndex& index) const {
    // MUST be called with m_cs_spv held
    // Get timestamps of last 11 blocks
    std::vector<int64_t> timestamps;
    BtcHeaderIndex current = index;

    for (int i = 0; i < 11 && !current.hash.IsNull(); i++) {
        // DEBUG: Check for null headers (checkpoint case)
        if (current.header.IsNull() && i > 0) {
            LogPrintf("BTC-SPV: MTP walk hit NULL header at depth %d, h=%d hash=%s\n",
                      i, current.height, current.hash.ToString().substr(0, 16));
            break;  // Can't get timestamps from null headers
        }
        timestamps.push_back(current.header.nTime);
        if (current.hashPrevBlock.IsNull()) break;
        if (!GetHeaderLocked(current.hashPrevBlock, current)) {
            LogPrintf("BTC-SPV: MTP walk failed to get parent at depth %d, prevBlock=%s\n",
                      i, current.hashPrevBlock.ToString().substr(0, 16));
            break;
        }
    }

    if (timestamps.empty()) return 0;

    std::sort(timestamps.begin(), timestamps.end());
    int64_t mtp = timestamps[timestamps.size() / 2];

    // DEBUG: Log MTP calculation for troubleshooting
    if (index.height >= 201240 && index.height <= 201250) {
        LogPrintf("BTC-SPV: MTP for h=%d: collected %zu timestamps, MTP=%ld\n",
                  index.height, timestamps.size(), mtp);
    }

    return mtp;
}

bool CBtcSPV::CheckTimestampLocked(const BtcBlockHeader& header, const BtcHeaderIndex& prev) const {
    // MUST be called with m_cs_spv held
    // Check not too far in future (2 hours)
    int64_t now = GetTime();
    if (header.nTime > now + 2 * 60 * 60) {
        return false;
    }

    // Check timestamp > median of last 11 blocks
    int64_t mtp = GetMedianTimePastLocked(prev);
    bool valid = (int64_t)header.nTime > mtp;

    // DEBUG: Log failures for troubleshooting
    if (!valid && prev.height >= 201240 && prev.height <= 201250) {
        LogPrintf("BTC-SPV: CheckTimestamp FAIL at h=%d: headerTime=%u, MTP=%ld (diff=%ld)\n",
                  prev.height + 1, header.nTime, mtp, (int64_t)header.nTime - mtp);
    }

    return valid;
}

bool CBtcSPV::CheckDifficultyRetargetLocked(const BtcBlockHeader& header, const BtcHeaderIndex& prev) const {
    // MUST be called with m_cs_spv held
    uint32_t height = prev.height + 1;

    // Retarget every 2016 blocks
    if (height % 2016 != 0) {
        // No retarget: nBits must match previous
        return header.nBits == prev.header.nBits;
    }

    // Get first block of this retarget period
    BtcHeaderIndex first;
    if (!GetHeaderAtHeightLocked(height - 2016, first)) {
        // Can't verify - rely on checkpoints for testnet
        if (m_testnet) {
            LogPrint(BCLog::NET, "BTC-SPV: Cannot verify retarget at %d (missing ancestor), relying on checkpoint\n", height);
            return true;
        }
        return false;
    }

    int64_t actualTime = prev.header.nTime - first.header.nTime;

    // Clamp to [0.25x, 4x] adjustment
    const int64_t targetTimespan = 2016 * 600;  // 2 weeks in seconds
    if (actualTime < targetTimespan / 4) {
        actualTime = targetTimespan / 4;
    }
    if (actualTime > targetTimespan * 4) {
        actualTime = targetTimespan * 4;
    }

    // Calculate new target
    arith_uint256 newTarget;
    newTarget.SetCompact(prev.header.nBits);
    newTarget *= actualTime;
    newTarget /= targetTimespan;

    // Cap at powLimit
    if (newTarget > m_netParams.powLimit) {
        newTarget = m_netParams.powLimit;
    }

    // Check header matches expected (compare compact form)
    return header.nBits == newTarget.GetCompact();
}

bool CBtcSPV::GetCheckpointHash(uint32_t height, uint256& hashOut) const {
    for (const auto& cp : m_checkpoints) {
        if (cp.height == height) { hashOut = cp.hash; return true; }
    }
    return false;
}

uint32_t CBtcSPV::HighestCheckpointHeight() const {
    uint32_t h = 0;
    for (const auto& cp : m_checkpoints) {
        if (cp.height > h) h = cp.height;
    }
    return h;
}

bool CBtcSPV::GetGenesisCheckpoint(uint32_t& heightOut, uint256& hashOut) const {
    if (m_checkpoints.empty()) return false;
    // Matches Init: signet uses the LAST checkpoint (286000), mainnet the first.
    const BtcCheckpoint& cp = m_testnet ? m_checkpoints.back() : m_checkpoints.front();
    heightOut = cp.height;
    hashOut = cp.hash;
    return true;
}

bool CBtcSPV::GetGenesisCheckpointHeader(BtcBlockHeader& out) const {
    if (!m_hasGenesisCheckpointHeader) return false;
    out = m_genesisCheckpointHeader;
    return true;
}

uint32_t CBtcSPV::ExpectedNextBits(uint32_t height, const BtcBlockHeader& parent,
                                   const BtcBlockHeader* periodFirst) const {
    // No lock: pure function of m_netParams (immutable post-init) + inputs.
    // No retarget: nBits must equal the parent's.
    if (height % 2016 != 0) {
        return parent.nBits;
    }
    // Retarget boundary: need the first header of the period (height-2016).
    if (!periodFirst) {
        return 0; // unavailable -> caller decides (testnet: rely on checkpoints)
    }
    int64_t actualTime = (int64_t)parent.nTime - (int64_t)periodFirst->nTime;
    const int64_t targetTimespan = 2016 * 600; // 2 weeks
    if (actualTime < targetTimespan / 4) actualTime = targetTimespan / 4;
    if (actualTime > targetTimespan * 4) actualTime = targetTimespan * 4;

    arith_uint256 newTarget;
    newTarget.SetCompact(parent.nBits);
    newTarget *= actualTime;
    newTarget /= targetTimespan;
    if (newTarget > m_netParams.powLimit) {
        newTarget = m_netParams.powLimit;
    }
    return newTarget.GetCompact();
}

bool CBtcSPV::ValidateHeaderLocked(const BtcBlockHeader& header, const BtcHeaderIndex& prev,
                                    BtcHeaderStatus& status) const {
    // MUST be called with m_cs_spv held

    // 1. Check prev_hash links
    if (header.hashPrevBlock != prev.hash) {
        status = BtcHeaderStatus::INVALID_PREVBLOCK;
        return false;
    }

    // 2. Check PoW
    if (!CheckProofOfWork(header)) {
        status = BtcHeaderStatus::INVALID_POW;
        return false;
    }

    // 3. Check timestamps
    if (!CheckTimestampLocked(header, prev)) {
        // Determine which timestamp check failed
        int64_t now = GetTime();
        if (header.nTime > now + 2 * 60 * 60) {
            status = BtcHeaderStatus::INVALID_TIMESTAMP_FUTURE;
        } else {
            status = BtcHeaderStatus::INVALID_TIMESTAMP_MTP;
        }
        return false;
    }

    // 4. Check difficulty retarget
    if (!CheckDifficultyRetargetLocked(header, prev)) {
        if (m_testnet) {
            // On Signet, log warning but rely on checkpoint anchoring
            LogPrint(BCLog::NET, "BTC-SPV: Signet retarget mismatch at height %d (checkpoint anchoring enforced)\n",
                     prev.height + 1);
        } else {
            status = BtcHeaderStatus::INVALID_RETARGET;
            return false;
        }
    }

    status = BtcHeaderStatus::VALID;
    return true;
}

bool CBtcSPV::VerifyChainCheckpointsLocked(const BtcHeaderIndex& tip) const {
    // MUST be called with m_cs_spv held
    //
    // Walk back from tip through hashPrevBlock pointers to find checkpoint heights.
    // We CANNOT use GetHeaderAtHeightLocked() here because DB_BEST_HEIGHT hasn't been
    // updated yet for the new chain we're trying to activate. Instead, walk back
    // from the tip and collect the hashes at checkpoint heights.
    //
    // Collect required checkpoints (at or below tip height, at or above min supported height)
    // We only have headers from m_minSupportedHeight onward, so we can't verify
    // checkpoints below that (they're implicitly trusted via the starting checkpoint).
    std::map<uint32_t, uint256> requiredCheckpoints;
    for (const auto& cp : m_checkpoints) {
        if (cp.height <= tip.height && cp.height >= m_minSupportedHeight) {
            requiredCheckpoints[cp.height] = cp.hash;
        }
    }

    if (requiredCheckpoints.empty()) {
        return true; // No checkpoints to verify
    }

    // Walk back from tip to find headers at checkpoint heights
    BtcHeaderIndex current = tip;
    uint32_t minCheckpointHeight = requiredCheckpoints.begin()->first;

    while (current.height >= minCheckpointHeight) {
        auto it = requiredCheckpoints.find(current.height);
        if (it != requiredCheckpoints.end()) {
            // This height is a checkpoint - verify hash matches
            if (current.hash != it->second) {
                LogPrintf("BTC-SPV: VerifyChainCheckpoints FAIL at h=%d: expected %s, got %s\n",
                          current.height, it->second.ToString().substr(0, 16),
                          current.hash.ToString().substr(0, 16));
                return false;
            }
            // Checkpoint verified - remove from required set
            requiredCheckpoints.erase(it);
            if (requiredCheckpoints.empty()) {
                return true; // All checkpoints verified
            }
            // Update minCheckpointHeight
            minCheckpointHeight = requiredCheckpoints.begin()->first;
        }

        // Walk back to parent
        if (current.hashPrevBlock.IsNull() || current.height == 0) {
            break;
        }

        BtcHeaderIndex parent;
        if (!GetHeaderLocked(current.hashPrevBlock, parent)) {
            // Can't walk back further - check if we've verified all required checkpoints
            break;
        }
        current = parent;
    }

    // Check if any checkpoints remain unverified
    if (!requiredCheckpoints.empty()) {
        LogPrintf("BTC-SPV: VerifyChainCheckpoints FAIL - %zu checkpoints not found in chain walk\n",
                  requiredCheckpoints.size());
        for (const auto& cp : requiredCheckpoints) {
            LogPrintf("BTC-SPV:   Missing checkpoint h=%d hash=%s\n",
                      cp.first, cp.second.ToString().substr(0, 16));
        }
        return false;
    }

    return true;
}

void CBtcSPV::RepairHeightIndexLocked() {
    // MUST be called with m_cs_spv held. Walk the best chain from the tip via
    // hash links (always correct) and rewrite any stale height-index entry.
    if (!m_db) return;
    BtcHeaderIndex current;
    if (!GetHeaderLocked(m_bestTipHash, current)) return;
    uint32_t floor = (m_minSupportedHeight == UINT32_MAX) ? 0 : m_minSupportedHeight;
    size_t fixed = 0;
    while (true) {
        uint256 stored;
        bool have = m_db->Read(std::make_pair(DB_BEST_HEIGHT, current.height), stored);
        if (!have || stored != current.hash) {
            m_db->Write(std::make_pair(DB_BEST_HEIGHT, current.height), current.hash);
            fixed++;
        }
        if (current.height <= floor || current.hashPrevBlock.IsNull() || current.height == 0) {
            break;
        }
        BtcHeaderIndex parent;
        if (!GetHeaderLocked(current.hashPrevBlock, parent)) {
            break;
        }
        current = parent;
    }
    if (fixed > 0) {
        LogPrintf("BTC-SPV: height-index repair rewrote %zu stale entries\n", fixed);
    }
}

void CBtcSPV::UpdateBestChainLocked(const BtcHeaderIndex& newTip) {
    // MUST be called with m_cs_spv held
    if (!m_db) return;

    // ═══════════════════════════════════════════════════════════════════════
    // DEFENSE-IN-DEPTH: Verify chain goes through all required checkpoints
    // ═══════════════════════════════════════════════════════════════════════
    // This is a second layer of protection. Headers are already validated
    // against checkpoints in AddHeader(), but we verify again before
    // activating a new best chain to prevent any edge case exploits.
    // ═══════════════════════════════════════════════════════════════════════
    if (!VerifyChainCheckpointsLocked(newTip)) {
        LogPrintf("BTC-SPV: CRITICAL - Refusing to activate tip %s (checkpoint violation)\n",
                  newTip.hash.ToString().substr(0, 16));
        return; // Do NOT update best chain
    }

    // ═══════════════════════════════════════════════════════════════════════
    // Write DB_BEST_HEIGHT for ALL heights from old tip+1 to new tip
    // ═══════════════════════════════════════════════════════════════════════
    // This ensures GetHeaderAtHeightLocked() works correctly for all heights
    // in the best chain, not just checkpoints and the tip.
    // ═══════════════════════════════════════════════════════════════════════
    // Rewrite the best-chain height index along the NEW chain, walking back from
    // the new tip until the stored hash already matches (the true fork point).
    // This correctly handles REORGS: heights on the losing branch BELOW the old
    // tip are overwritten. (Previously only [m_bestHeight+1 .. tip] were written,
    // so a reorg left the reorged heights pointing at the dead branch — making
    // GetHeaderAtHeightLocked() return stale hashes for that range.)
    {
        BtcHeaderIndex current = newTip;
        while (true) {
            uint256 storedHash;
            bool haveStored = m_db->Read(std::make_pair(DB_BEST_HEIGHT, current.height), storedHash);
            if (haveStored && storedHash == current.hash) {
                break; // reached the fork point: index already on the new chain
            }
            m_db->Write(std::make_pair(DB_BEST_HEIGHT, current.height), current.hash);
            if (current.hashPrevBlock.IsNull() || current.height == 0) {
                break;
            }
            BtcHeaderIndex parent;
            if (!GetHeaderLocked(current.hashPrevBlock, parent)) {
                break;
            }
            current = parent;
        }
    }

    // Update tip state (in memory)
    m_bestTipHash = newTip.hash;
    m_bestHeight = newTip.height;
    m_bestChainWork = newTip.GetChainWork();

    // Write tip metadata (fSync=true on last write to flush WAL to disk)
    m_db->Write(std::make_pair(DB_TIP_HASH, 0), m_bestTipHash);
    m_db->Write(std::make_pair(DB_TIP_HEIGHT, 0), m_bestHeight);
    m_db->Write(std::make_pair(DB_TIP_WORK, 0), ArithToUint256(m_bestChainWork), true);

    LogPrint(BCLog::NET, "BTC-SPV: New tip height=%d hash=%s\n",
             m_bestHeight, m_bestTipHash.ToString().substr(0, 16));
}

BtcHeaderStatus CBtcSPV::AddHeader(const BtcBlockHeader& header) {
    LOCK(m_cs_spv);  // Single lock for entire operation

    uint256 hash = header.GetHash();

    // Check for duplicate
    BtcHeaderIndex existing;
    if (GetHeaderLocked(hash, existing)) {
        // Tip recovery: if this header exists in DB but is beyond our current
        // tip (e.g. headers persisted but tip wasn't due to missing fSync),
        // update the tip so the chain state is consistent.
        if (existing.GetChainWork() > m_bestChainWork) {
            UpdateBestChainLocked(existing);
        }
        return BtcHeaderStatus::DUPLICATE;
    }

    // Get parent
    BtcHeaderIndex parent;
    if (!GetHeaderLocked(header.hashPrevBlock, parent)) {
        // Check if this is at checkpoint height
        for (const auto& cp : m_checkpoints) {
            if (hash == cp.hash) {
                // This is a checkpoint - accept without parent
                BtcHeaderIndex index;
                index.hash = hash;
                index.hashPrevBlock = header.hashPrevBlock;
                index.height = cp.height;
                index.SetChainWork(cp.chainWork);
                index.header = header;

                if (!StoreHeaderLocked(index)) {
                    return BtcHeaderStatus::ORPHAN;
                }

                if (index.GetChainWork() > m_bestChainWork) {
                    UpdateBestChainLocked(index);
                }

                return BtcHeaderStatus::VALID;
            }
        }
        return BtcHeaderStatus::ORPHAN;
    }

    // Validate
    BtcHeaderStatus status;
    if (!ValidateHeaderLocked(header, parent, status)) {
        return status;
    }

    // Calculate chainwork
    arith_uint256 work = GetBlockProof(header);
    arith_uint256 totalWork = parent.GetChainWork() + work;

    // Create index entry
    BtcHeaderIndex index;
    index.hash = hash;
    index.hashPrevBlock = header.hashPrevBlock;
    index.height = parent.height + 1;
    index.SetChainWork(totalWork);
    index.header = header;

    // ═══════════════════════════════════════════════════════════════════════
    // STRICT CHECKPOINT ENFORCEMENT (BP-SPV-BLOCK1 Step B)
    // ═══════════════════════════════════════════════════════════════════════
    // If this header is at a checkpoint height, its hash MUST match the
    // checkpoint hash. This prevents accepting alternate chains that diverge
    // at or before checkpoints, ensuring deterministic SPV validation.
    // ═══════════════════════════════════════════════════════════════════════
    for (const auto& cp : m_checkpoints) {
        if (index.height == cp.height) {
            if (index.hash != cp.hash) {
                LogPrintf("BTC-SPV: CHECKPOINT VIOLATION at height %d: expected %s, got %s\n",
                          cp.height, cp.hash.ToString().substr(0, 16), index.hash.ToString().substr(0, 16));
                return BtcHeaderStatus::INVALID_CHECKPOINT;
            }
            // Hash matches checkpoint - continue with normal validation
            LogPrint(BCLog::NET, "BTC-SPV: Checkpoint %d validated: %s\n",
                     cp.height, cp.hash.ToString().substr(0, 16));
            break;
        }
    }

    // ═══════════════════════════════════════════════════════════════════════
    // BP12 A7 - Canonical Chain Verification (Halving Boundaries)
    // ═══════════════════════════════════════════════════════════════════════
    // A7 checkpoints verify chain identity at halving boundaries.
    // This ensures BATHRON only accepts THE Bitcoin chain, not forks.
    // ═══════════════════════════════════════════════════════════════════════
    if (!VerifyCanonicalChain(index.height, index.hash, m_testnet)) {
        return BtcHeaderStatus::INVALID_CHECKPOINT;  // Reuse status - same effect
    }

    // Store
    if (!StoreHeaderLocked(index)) {
        return BtcHeaderStatus::ORPHAN;
    }

    // Update best chain if this is heavier
    if (totalWork > m_bestChainWork) {
        UpdateBestChainLocked(index);
    }

    return BtcHeaderStatus::VALID;
}

CBtcSPV::BatchResult CBtcSPV::AddHeaders(const std::vector<BtcBlockHeader>& headers) {
    BatchResult result;
    result.accepted = 0;
    result.rejected = 0;
    result.tipHeight = m_bestHeight;

    for (const auto& header : headers) {
        BtcHeaderStatus status = AddHeader(header);

        if (status == BtcHeaderStatus::VALID || status == BtcHeaderStatus::DUPLICATE) {
            result.accepted++;
        } else {
            result.rejected++;
            if (result.firstRejectReason.empty()) {
                result.firstRejectReason = BtcHeaderStatusToString(status);
                result.firstRejectHash = header.GetHash();
            }
            // Stop processing on first invalid (non-duplicate) header
            if (status != BtcHeaderStatus::DUPLICATE) {
                break;
            }
        }
    }

    result.tipHeight = m_bestHeight;
    return result;
}

// Internal helper - verify merkle proof with given hashes (no format conversion)
static bool VerifyMerkleProofInternal(const uint256& txid,
                                       const uint256& merkleRoot,
                                       const std::vector<uint256>& proof,
                                       uint32_t txIndex) {
    uint256 current = txid;
    uint32_t idx = txIndex;

    for (const uint256& sibling : proof) {
        if (idx & 1) {
            // Current is right child - hash(sibling, current)
            current = Hash(sibling.begin(), sibling.end(), current.begin(), current.end());
        } else {
            // Current is left child - hash(current, sibling)
            current = Hash(current.begin(), current.end(), sibling.begin(), sibling.end());
        }
        idx >>= 1;
    }

    return current == merkleRoot;
}

// Helper to reverse bytes of a uint256 (BE <-> LE conversion)
static uint256 ReverseBytes(const uint256& in) {
    uint256 out;
    for (size_t i = 0; i < 32; i++) {
        out.begin()[i] = in.begin()[31 - i];
    }
    return out;
}

bool CBtcSPV::VerifyMerkleProof(const uint256& txid,
                                 const uint256& merkleRoot,
                                 const std::vector<uint256>& proof,
                                 uint32_t txIndex) const {
    // COMMIT 3 FIX: Try-both-verify for BE/LE merkle proof compatibility
    // ==================================================================
    // Problem: Bitcoin Core displays hashes in "display format" (hex reversed),
    // but internally uses "internal format" (raw bytes). Users may provide
    // proofs in either format, causing silent verification failures.
    //
    // Solution: Try verification with original format first, then with
    // byte-reversed hashes. This is safe because a random collision with
    // reversed bytes is astronomically unlikely (2^-256).
    //
    // Sanity checks added to catch obvious errors early.

    // Sanity check 1: Proof length
    // Max reasonable tree depth is ~30 (supports 2^30 = 1B transactions)
    if (proof.size() > 30) {
        LogPrintf("VerifyMerkleProof: proof too long (%zu > 30)\n", proof.size());
        return false;
    }

    // Sanity check 2: txIndex range
    // txIndex must be < 2^proof.size() for the proof to make sense
    if (proof.size() > 0 && txIndex >= (1u << proof.size())) {
        LogPrintf("VerifyMerkleProof: txIndex %u out of range for proof size %zu\n",
                  txIndex, proof.size());
        return false;
    }

    // Try 1: Original format (internal/LE - what parsemerkleblock produces)
    if (VerifyMerkleProofInternal(txid, merkleRoot, proof, txIndex)) {
        return true;
    }

    // Try 2: Reversed format (display/BE - what users might copy from explorers)
    // Reverse both the txid and all proof hashes
    std::vector<uint256> reversedProof;
    reversedProof.reserve(proof.size());
    for (const uint256& h : proof) {
        reversedProof.push_back(ReverseBytes(h));
    }

    uint256 reversedTxid = ReverseBytes(txid);
    if (VerifyMerkleProofInternal(reversedTxid, merkleRoot, reversedProof, txIndex)) {
        LogPrint(BCLog::NET, "VerifyMerkleProof: succeeded with reversed (BE) format\n");
        return true;
    }

    // Try 3: Mixed format - only proof hashes reversed (txid already correct)
    // This handles the case where txid is from ComputeBtcTxid (correct format)
    // but proof hashes are copy-pasted from explorer (display format)
    if (VerifyMerkleProofInternal(txid, merkleRoot, reversedProof, txIndex)) {
        LogPrint(BCLog::NET, "VerifyMerkleProof: succeeded with mixed format (correct txid, BE proof)\n");
        return true;
    }

    return false;
}

bool CBtcSPV::IsSynced() const {
    // Consider synced if we have headers up to recent time
    // (within 2 hours of current time)
    BtcHeaderIndex tip;
    if (!GetHeader(m_bestTipHash, tip)) {
        return false;
    }

    int64_t now = GetTime();
    int64_t tipTime = tip.header.nTime;

    // Within 2 hours
    return (now - tipTime) < 2 * 60 * 60;
}

uint32_t CBtcSPV::GetHeaderCount() const {
    return m_bestHeight + 1;
}

uint32_t CBtcSPV::GetMinSupportedHeight() const {
    // Returns the minimum BTC block height that this SPV instance can verify.
    // This is persisted in DB at init time (DB_MIN_HEIGHT key).
    //
    // CRITICAL: This value comes from DB, not from checkpoint constants.
    // This ensures that if the DB is partially wiped or starts at a different
    // height than expected, GetMinSupportedHeight() reflects the actual state.
    //
    // If m_minSupportedHeight == UINT32_MAX, SPV is not properly initialized
    // and burn claims should be rejected.
    if (m_minSupportedHeight == UINT32_MAX) {
        LogPrintf("WARNING: GetMinSupportedHeight called before SPV initialized\n");
        return UINT32_MAX;  // Reject all burns if SPV not ready
    }
    return m_minSupportedHeight;
}

// ═══════════════════════════════════════════════════════════════════════════════
// BP12 - A7 Canonical Chain Checkpoints
// ═══════════════════════════════════════════════════════════════════════════════

// A7 Mainnet checkpoints (halving boundaries)
// These define "what Bitcoin means for BATHRON"
const std::vector<A7Checkpoint>& GetA7MainnetCheckpoints() {
    static std::vector<A7Checkpoint> checkpoints;
    static bool initialized = false;
    if (!initialized) {
        // First halving (Nov 2012)
        checkpoints.push_back({
            210000,
            uint256S("000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")
        });
        // Second halving (Jul 2016)
        checkpoints.push_back({
            420000,
            uint256S("000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74ffa1")
        });
        // Third halving (May 2020)
        checkpoints.push_back({
            630000,
            uint256S("0000000000000000000f2adce67e49b0b6bdeb9de8b7c3d7e93b21e7fc1e819d")
        });
        // Fourth halving (Apr 2024)
        checkpoints.push_back({
            840000,
            uint256S("0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5")
        });
        initialized = true;
    }
    return checkpoints;
}

// A7 Signet checkpoints (fewer checkpoints for test network)
const std::vector<A7Checkpoint>& GetA7SignetCheckpoints() {
    static std::vector<A7Checkpoint> checkpoints;
    static bool initialized = false;
    if (!initialized) {
        // Signet block 200000 (arbitrary but stable checkpoint)
        checkpoints.push_back({
            200000,
            uint256S("0000007d60f5ffc47975418ac8331c0ea52cf551730ef7ead7ff9082a536f13c")
        });
        initialized = true;
    }
    return checkpoints;
}

bool VerifyCanonicalChain(uint32_t height, const uint256& blockHash, bool testnet) {
    const std::vector<A7Checkpoint>& checkpoints = testnet ?
        GetA7SignetCheckpoints() : GetA7MainnetCheckpoints();

    // Check each checkpoint - only enforced at exact heights
    for (const auto& cp : checkpoints) {
        if (height == cp.height) {
            if (blockHash != cp.expectedHash) {
                LogPrintf("A7: CANONICAL CHAIN VIOLATION at height %d\n", height);
                LogPrintf("A7: Expected: %s\n", cp.expectedHash.ToString());
                LogPrintf("A7: Got:      %s\n", blockHash.ToString());
                return false;
            }
            LogPrint(BCLog::NET, "A7: Checkpoint verified at height %d\n", height);
        }
    }

    return true;
}
