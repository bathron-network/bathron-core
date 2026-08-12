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
static const char DB_SOURCE_NET = 'n';    // 'Bn' -> BtcSourceNet tag (uint8) — refuses a store built for another Bitcoin network

std::string BtcSourceNetToString(BtcSourceNet net) {
    switch (net) {
        case BtcSourceNet::BITCOIN_MAINNET: return "mainnet";
        case BtcSourceNet::BITCOIN_TESTNET4: return "testnet4";
    }
    return "unknown";
}

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
        params.nPowTargetSpacing = 600;
        params.nPowTargetTimespan = 14 * 24 * 60 * 60;
        params.fPowAllowMinDifficultyBlocks = false;
        params.enforceBIP94 = false;
        params.genesisCheckpointHeight = 800000;
        initialized = true;
    }
    return params;
}

// Bitcoin Testnet4 parameters (BIP-94; Bitcoin Core v28.1 CTestNet4Params).
// The BATHRON measurement network reads Testnet4 as its Bitcoin source.
// There is deliberately NO Signet params function anymore: Signet header PoW is
// CPU-forgeable (~2^27 hashes measured) because BIP-325 authentication lives in
// the coinbase witness, which TX_BTC_HEADERS does not carry.
const BtcNetworkParams& GetBtcTestnet4Params() {
    static BtcNetworkParams params;
    static bool initialized = false;
    if (!initialized) {
        // pchMessageStart {0x1c,0x16,0x3f,0x28} read as LE uint32 (same
        // convention as mainnet 0xD9B4BEF9 == wire F9 BE B4 D9).
        params.magic = 0x283F161C;
        params.genesisHash = uint256S("00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043");
        params.defaultPort = 48333;
        // Same powLimit as mainnet (BIP-94) — NOT the forgeable Signet 2^233.
        params.powLimit = UintToArith256(uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        params.nPowTargetSpacing = 600;
        params.nPowTargetTimespan = 14 * 24 * 60 * 60;
        params.fPowAllowMinDifficultyBlocks = true;   // 20-minute exception
        params.enforceBIP94 = true;                   // timewarp + first-block retarget
        params.genesisCheckpointHeight = 145152;      // retarget boundary (72*2016)
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

// Testnet4 checkpoints.
// Provenance (2026-08-03): hashes cross-verified on three independent sources —
// (1) local Bitcoin Core v28.1 full header validation (headers synced from P2P),
// (2) mempool.space/testnet4, (3) mempool.emzy.de/testnet4. Chainwork values
// from source (1) `getblockheader`.
const std::vector<BtcCheckpoint>& GetBtcTestnet4Checkpoints() {
    static std::vector<BtcCheckpoint> checkpoints;
    static bool initialized = false;
    if (!initialized) {
        // Genesis checkpoint at 145152 = 72*2016, a RETARGET BOUNDARY: its nBits
        // is the BIP-94 base for the next retarget, it can never be a
        // min-difficulty block, and min-difficulty walk-backs from any height in
        // (145152, 147168) terminate at or above it.
        checkpoints.push_back({
            145152,
            uint256S("00000000000000014694285ac2a2980339778e6b73d2199a65a5f62f2df44d2d"),
            UintToArith256(uint256S("000000000000000000000000000000000000000000000d12d1787a7afe99cead"))
        });
        // Recent anchor at 146000 (raises the consensus reorg floor near the
        // measurement-genesis era; itself a min-difficulty block, which is
        // valid off-boundary under the 20-minute rule).
        checkpoints.push_back({
            146000,
            uint256S("00000000000774b867c9eabbc5eba5919e97bb8f7b06f9e86547c7f86966f054"),
            UintToArith256(uint256S("000000000000000000000000000000000000000000000d43aaed4f5b953a147d"))
        });
        initialized = true;
    }
    return checkpoints;
}

// Genesis header for Testnet4 at height 145152 (BATHRON SPV starting point).
// FULL 80-byte header, hardcoded so new nodes can sync from here. Verified:
// double-SHA256(serialized header) == checkpoint hash 00000000000000014694…
// Raw hex: 00204d2aea88567d77979f36589bd4f772a630252a8bf3a5ff4231d40100000000
//          0000005e8775da75a4015b3309e6dbbee0c7cdf6c2fe4fed9a8d9551556f767f4b
//          af72cd37606adf74021942ae6220
bool GetBtcTestnet4GenesisHeader(BtcBlockHeader& header) {
    header.nVersion = 0x2a4d2000;
    header.hashPrevBlock  = uint256S("0000000000000001d43142ffa5f38b2a2530a672f7d49b58369f97777d5688ea");
    header.hashMerkleRoot = uint256S("72af4b7f766f5551958d9aed4ffec2f6cdc7e0bedbe609335b01a475da75875e");
    header.nTime = 1784690637;
    header.nBits = 0x190274df;
    header.nNonce = 543338050;
    return true;
}

// The 10 REAL Testnet4 headers 145142..145151, pinned as MTP CONTEXT below the
// genesis checkpoint: the 11-block median-time-past window for heights just
// above the pin must match Bitcoin Core exactly (real Testnet4 carries
// negative timestamp gaps — 145156 is 6375 s earlier than its parent, legal
// because MTP reaches below the pin). Same provenance as the checkpoints
// (Core v28.1 P2P + mempool.space + mempool.emzy.de, 2026-08-03); linkage into
// the pinned 145152 header is verified at init — a bad literal aborts startup.
const std::vector<BtcBlockHeader>& GetBtcTestnet4GenesisContext() {
    static std::vector<BtcBlockHeader> ctx;
    static bool initialized = false;
    if (!initialized) {
        auto mk = [](int32_t v, const char* prev, const char* merkle,
                     uint32_t t, uint32_t bits, uint32_t nonce) {
            BtcBlockHeader h;
            h.nVersion = v;
            h.hashPrevBlock = uint256S(prev);
            h.hashMerkleRoot = uint256S(merkle);
            h.nTime = t;
            h.nBits = bits;
            h.nNonce = nonce;
            return h;
        };
        // h=145142
        ctx.push_back(mk(0x2ac1e000, "00000000009fc968763bb1b2ca7ffe8c8ffe584dc8b50e554445f48ea24c34bc",
                         "1ba9981228aaf4c43274d456ee56e4a9ddd61c9eeecd047b358c23b63655183b",
                         1784683913U, 0x1d00ffff, 2723807704U));
        // h=145143
        ctx.push_back(mk(0x2960a000, "0000000000d763d68061e3f30e5b1861a710c87d634a5e5ce58d5d8dc647cede",
                         "7d4e7b795c91a0a79c70d363f4bf93a835d1da8690f7812b8c2596032ce8c96b",
                         1784685114U, 0x1d00ffff, 3169255732U));
        // h=145144
        ctx.push_back(mk(0x29e78000, "0000000000ba4bad937308c09c315375d8bc04807fbe976c7ac63c0f2a2b238b",
                         "4cbaedc142c09b23c683ab94e9462b9c26dd11d29f366f0adf12f49064f3e315",
                         1784686315U, 0x1d00ffff, 1395130410U));
        // h=145145
        ctx.push_back(mk(0x32ece000, "0000000000d2a78f9ac577828fdedade1c9e7c4b9c26a07b082be3e8ac84e7d3",
                         "047bd42fbf8cb8fb5b3306dfc92173cf3f546dbfa153c3a44289b7c716546dd0",
                         1784687516U, 0x1d00ffff, 1635188866U));
        // h=145146
        ctx.push_back(mk(0x27f38000, "000000000051c6c7a26efb38edfd0168028e37850f81d88a0155649b5cf6dd6d",
                         "ac4218d9ed83a80b003e2f4d7536e011fd90460c9f7a36e498b591eab7b3c419",
                         1784688717U, 0x1d00ffff, 1412497870U));
        // h=145147
        ctx.push_back(mk(0x2c852000, "000000000061ab701205c34a137e58e753a7e9da771ae8a5c05a8497111e7b4a",
                         "8f2698c9bf42e82087a200bb555c3f73ab1bc3643534461dd6571867d060fdf5",
                         1784689918U, 0x1d00ffff, 860947120U));
        // h=145148
        ctx.push_back(mk(0x26ac8000, "0000000000171506feab172badf069c8af59e836936cfb482ce4c7c5ae75fe1e",
                         "39363e587daed4b560d58d7b5e97843f58ad70b35ecc09e4b6bd93ab65f214d1",
                         1784691119U, 0x1d00ffff, 456852056U));
        // h=145149
        ctx.push_back(mk(0x32204000, "00000000009572b52135e98b588efe5782d9598f083135116968e445b6ab6e4f",
                         "98e105cb5e6a98c8d4537f8b50ded866d0276015c56e8e7c8668e603c5e85e64",
                         1784692320U, 0x1d00ffff, 3257532690U));
        // h=145150
        ctx.push_back(mk(0x31baa000, "0000000000ee6364dc9a9e2d711ae3e4b550c3e1a82bcf52236bad294bcc0031",
                         "f5cebdb44ccca66224524693720754b590b1d4160cd89d816fc9f9795043d695",
                         1784693521U, 0x1d00ffff, 1284767758U));
        // h=145151 (real-difficulty block; parent of the pinned 145152)
        ctx.push_back(mk(0x20d28000, "0000000000e3c0fa33fe245a4efe83184034455ce956e4793b9f691ba521e0ba",
                         "60ef6f87d93368bf282ab2f48334a10985f3b5db77925b325b0c5c93cf551452",
                         1784687517U, 0x190228f4, 3046116884U));
        initialized = true;
    }
    return ctx;
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
        case BtcHeaderStatus::INVALID_TIMEWARP: return "timewarp-attack";
        case BtcHeaderStatus::INVALID_CHECKPOINT: return "checkpoint-mismatch";
        case BtcHeaderStatus::DUPLICATE: return "duplicate";
        case BtcHeaderStatus::ORPHAN: return "orphan";
        default: return "unknown";
    }
}

// CBtcSPV implementation
CBtcSPV::CBtcSPV() : m_bestHeight(0), m_minSupportedHeight(UINT32_MAX) {
    m_bestTipHash.SetNull();
    m_bestChainWork = 0;
}

CBtcSPV::~CBtcSPV() {
    Shutdown();
}

bool CBtcSPV::Init(const std::string& datadir, BtcSourceNet sourceNet) {
    LOCK(m_cs_spv);
    return InitLocked(datadir, sourceNet);
}

bool CBtcSPV::InitForTest(const std::string& datadir, const BtcNetworkParams& params,
                          const std::vector<BtcCheckpoint>& checkpoints,
                          const BtcBlockHeader* pinnedHeader) {
    // TEST-ONLY: explicit harness params (cheap powLimit for synthetic mining).
    // Never a Bitcoin network; production init goes through InitLocked.
    LOCK(m_cs_spv);
    m_datadir = datadir;
    m_netParams = params;
    m_checkpoints = checkpoints;
    m_hasGenesisCheckpointHeader = false;
    if (pinnedHeader) {
        m_genesisCheckpointHeader = *pinnedHeader;
        m_hasGenesisCheckpointHeader = true;
    }
    return InitCommonLocked(datadir);
}

bool CBtcSPV::InitLocked(const std::string& datadir, BtcSourceNet sourceNet) {
    // MUST be called with m_cs_spv held
    m_sourceNet = sourceNet;
    m_datadir = datadir;  // Store for Reload()

    // Set network params — from the COMMITTED source network, never a runtime flag.
    const bool t4 = (sourceNet == BtcSourceNet::BITCOIN_TESTNET4);
    m_netParams = t4 ? GetBtcTestnet4Params() : GetBtcMainnetParams();
    m_checkpoints = t4 ? GetBtcTestnet4Checkpoints() : GetBtcMainnetCheckpoints();

    // BP-BTCHEADERS-HARDENING: load the FULL header of the genesis checkpoint and
    // SELF-CHECK it hashes to the checkpoint hash. This header is the difficulty
    // parent for the first seeded BTC header (so R6 validates it during bootstrap
    // instead of trusting the seeder). A wrong hardcode aborts the node here rather
    // than silently shipping a corrupt anchor.
    m_hasGenesisCheckpointHeader = false;
    if (!m_checkpoints.empty()) {
        const BtcCheckpoint* gcp = nullptr;
        for (const auto& cp : m_checkpoints) {
            if (cp.height == m_netParams.genesisCheckpointHeight) { gcp = &cp; break; }
        }
        if (!gcp) {
            LogPrintf("BTC-SPV: FATAL — no checkpoint at genesisCheckpointHeight %u\n",
                      m_netParams.genesisCheckpointHeight);
            return false;
        }
        bool gotHeader = t4 ? GetBtcTestnet4GenesisHeader(m_genesisCheckpointHeader)
                            : GetBtcMainnetGenesisHeader(m_genesisCheckpointHeader);
        if (gotHeader) {
            if (m_genesisCheckpointHeader.GetHash() != gcp->hash) {
                LogPrintf("BTC-SPV: FATAL — hardcoded genesis header at %u hashes to %s, expected %s\n",
                          gcp->height, m_genesisCheckpointHeader.GetHash().ToString(), gcp->hash.ToString());
                return false;
            }
            m_hasGenesisCheckpointHeader = true;
            LogPrintf("BTC-SPV: genesis checkpoint header at %u verified (hash matches, source=%s)\n",
                      gcp->height, BtcSourceNetToString(sourceNet));
        }
    }

    // MTP context below the pin (testnet4): verify the pinned real headers
    // chain into the genesis checkpoint header, then index them by height.
    // A bad literal aborts startup, exactly like a bad pinned header.
    m_genesisContext.clear();
    if (t4 && m_hasGenesisCheckpointHeader) {
        const std::vector<BtcBlockHeader>& ctx = GetBtcTestnet4GenesisContext();
        const uint32_t firstHeight = m_netParams.genesisCheckpointHeight - (uint32_t)ctx.size();
        for (size_t i = 0; i < ctx.size(); i++) {
            const uint256 expectedChild = (i + 1 < ctx.size())
                ? ctx[i + 1].hashPrevBlock
                : m_genesisCheckpointHeader.hashPrevBlock;
            if (ctx[i].GetHash() != expectedChild) {
                LogPrintf("BTC-SPV: FATAL — genesis MTP context broken at %u (hashes to %s, child expects %s)\n",
                          firstHeight + (uint32_t)i, ctx[i].GetHash().ToString(),
                          expectedChild.ToString());
                return false;
            }
            m_genesisContext[firstHeight + (uint32_t)i] = ctx[i];
        }
        LogPrintf("BTC-SPV: genesis MTP context %u..%u verified (chains into the pin)\n",
                  firstHeight, m_netParams.genesisCheckpointHeight - 1);
    }

    return InitCommonLocked(datadir);
}

bool CBtcSPV::InitCommonLocked(const std::string& datadir) {
    // MUST be called with m_cs_spv held; params/checkpoints/pinned header set.
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

    // Source-network tag (M-3, PHASE 2.6 review): a store built while tracking
    // another Bitcoin network (e.g. a signet-era datadir) is REFUSED instead of
    // silently serving its stale tip/min-height. First open stamps the tag.
    {
        uint8_t storedNet = 0;
        if (m_db->Read(std::make_pair(DB_SOURCE_NET, 0), storedNet)) {
            if (storedNet != (uint8_t)m_sourceNet) {
                LogPrintf("BTC-SPV: FATAL — btcspv store was built for source net %u, "
                          "this node is committed to %s. Wipe %s to resync.\n",
                          storedNet, BtcSourceNetToString(m_sourceNet), dbpath);
                m_db.reset();
                return false;
            }
        } else {
            m_db->Write(std::make_pair(DB_SOURCE_NET, 0), (uint8_t)m_sourceNet);
        }
    }

    // Load tip from database (no nested lock - LoadTipLocked expects lock held)
    if (!LoadTipLocked()) {
        // Initialize with genesis or checkpoint
        if (!m_checkpoints.empty()) {
            // Start from the genesis checkpoint (the one whose full header is
            // pinned in code — testnet4 145152 / mainnet 800000).
            const BtcCheckpoint* gcpp = nullptr;
            for (const auto& c : m_checkpoints) {
                if (c.height == m_netParams.genesisCheckpointHeight) { gcpp = &c; break; }
            }
            const BtcCheckpoint& cp = gcpp ? *gcpp : m_checkpoints.front();
            m_bestTipHash = cp.hash;
            m_bestHeight = cp.height;
            m_bestChainWork = cp.chainWork;

            // Store the header index for the checkpoint
            BtcHeaderIndex cpIndex;
            cpIndex.hash = cp.hash;
            cpIndex.height = cp.height;
            cpIndex.SetChainWork(cp.chainWork);

            // Use the verified hardcoded genesis header (testnet4 145152 / mainnet
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

            // Store the pinned MTP context headers (below the pin) so the
            // 11-block median-time-past walk crosses the pin exactly as
            // Bitcoin Core's does. They carry no chainwork and are not part
            // of the best-height index — pure ancestry for MTP.
            for (const auto& kv : m_genesisContext) {
                BtcHeaderIndex ctxIndex;
                ctxIndex.hash = kv.second.GetHash();
                ctxIndex.hashPrevBlock = kv.second.hashPrevBlock;
                ctxIndex.height = kv.first;
                ctxIndex.SetChainWork(arith_uint256());
                ctxIndex.header = kv.second;
                StoreHeaderLocked(ctxIndex);
            }
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

    LogPrintf("BTC-SPV: Initialized. Tip height=%d hash=%s btc_source=%s\n",
              m_bestHeight, m_bestTipHash.ToString().substr(0, 16),
              BtcSourceNetToString(m_sourceNet));
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
    if (!InitLocked(m_datadir, m_sourceNet)) {
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
    // MUST be called with m_cs_spv held.
    // Ancestors are resolved by PARENT LINKS from `prev` (not the best-chain
    // height index) so side branches are validated against their own history.
    // The cursor only ever moves down: ExpectedNextBits requests heights in
    // non-increasing order (min-difficulty walk-back, then/or period-first).
    uint32_t height = prev.height + 1;
    BtcHeaderIndex cursor = prev;
    bool cursorValid = true;
    auto getAncestor = [this, &cursor, &cursorValid](uint32_t h, BtcBlockHeader& out) {
        if (!cursorValid || h > cursor.height) return false;
        while (cursor.height > h) {
            BtcHeaderIndex up;
            if (!GetHeaderLocked(cursor.hashPrevBlock, up)) { cursorValid = false; return false; }
            cursor = up;
        }
        if (cursor.header.IsNull()) return false;
        out = cursor.header;
        return true;
    };

    uint32_t expected = ExpectedNextBits(height, prev.header, header.nTime, getAncestor);
    if (expected == 0) {
        // Required ancestor unavailable (below the pinned checkpoint). Strict:
        // reject — the testnet4 pin sits on a retarget boundary precisely so
        // this can only happen on a malformed branch.
        LogPrint(BCLog::NET, "BTC-SPV: retarget unverifiable at height %d (missing ancestor)\n", height);
        return false;
    }
    return header.nBits == expected;
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
    // Matches Init: the checkpoint at genesisCheckpointHeight (the one whose
    // full header is pinned in code).
    for (const auto& cp : m_checkpoints) {
        if (cp.height == m_netParams.genesisCheckpointHeight) {
            heightOut = cp.height;
            hashOut = cp.hash;
            return true;
        }
    }
    heightOut = m_checkpoints.front().height;
    hashOut = m_checkpoints.front().hash;
    return true;
}

bool CBtcSPV::GetGenesisCheckpointHeader(BtcBlockHeader& out) const {
    if (!m_hasGenesisCheckpointHeader) return false;
    out = m_genesisCheckpointHeader;
    return true;
}

bool CBtcSPV::GetGenesisContextHeader(uint32_t height, BtcBlockHeader& out) const {
    // No lock: m_genesisContext / pinned header are immutable post-init.
    if (m_hasGenesisCheckpointHeader && height == m_netParams.genesisCheckpointHeight) {
        out = m_genesisCheckpointHeader;
        return true;
    }
    auto it = m_genesisContext.find(height);
    if (it == m_genesisContext.end()) return false;
    out = it->second;
    return true;
}

uint32_t CBtcSPV::ExpectedNextBits(uint32_t height, const BtcBlockHeader& parent,
                                   uint32_t newHeaderTime,
                                   const std::function<bool(uint32_t, BtcBlockHeader&)>& getAncestor) const {
    // No lock: pure function of m_netParams (immutable post-init) + inputs.
    // Faithful port of Bitcoin Core v28.1 GetNextWorkRequired /
    // CalculateNextWorkRequired (pow.cpp), including the Testnet4
    // min-difficulty exception and the BIP-94 first-block retarget base.
    const uint32_t interval = (uint32_t)m_netParams.DifficultyAdjustmentInterval();
    const uint32_t powLimitCompact = m_netParams.powLimit.GetCompact();

    if (height % interval != 0) {
        if (m_netParams.fPowAllowMinDifficultyBlocks) {
            // 20-minute exception: a block whose timestamp is more than
            // 2*spacing past its parent MUST carry powLimit nBits (Core
            // enforces exact equality with GetNextWorkRequired's result).
            if ((int64_t)newHeaderTime > (int64_t)parent.nTime + m_netParams.nPowTargetSpacing * 2) {
                return powLimitCompact;
            }
            // Otherwise: nBits of the last non-min-difficulty block of the
            // period (walk back; the first block of a period never carries
            // the min-difficulty exception, so the walk stops there).
            BtcBlockHeader idx = parent;
            uint32_t idxHeight = height - 1;
            while (idxHeight != 0 && idxHeight % interval != 0 && idx.nBits == powLimitCompact) {
                BtcBlockHeader up;
                if (!getAncestor(idxHeight - 1, up)) {
                    return 0; // ancestor unavailable -> caller decides
                }
                idx = up;
                idxHeight--;
            }
            return idx.nBits;
        }
        return parent.nBits;
    }

    // Retarget boundary: need the first header of the closing period.
    BtcBlockHeader firstHdr;
    if (!getAncestor(height - interval, firstHdr)) {
        return 0; // unavailable -> caller decides
    }

    int64_t actualTime = (int64_t)parent.nTime - (int64_t)firstHdr.nTime;
    const int64_t targetTimespan = m_netParams.nPowTargetTimespan;
    if (actualTime < targetTimespan / 4) actualTime = targetTimespan / 4;
    if (actualTime > targetTimespan * 4) actualTime = targetTimespan * 4;

    arith_uint256 newTarget;
    // BIP-94 block-storm fix: the retarget base is the FIRST block of the
    // closing period (its difficulty is real — the min-difficulty exception
    // never applies on a boundary). Legacy (mainnet): the last block.
    newTarget.SetCompact(m_netParams.enforceBIP94 ? firstHdr.nBits : parent.nBits);
    newTarget *= actualTime;
    newTarget /= targetTimespan;
    if (newTarget > m_netParams.powLimit) {
        newTarget = m_netParams.powLimit;
    }
    return newTarget.GetCompact();
}

bool CBtcSPV::CheckTimewarp(uint32_t height, const BtcBlockHeader& header,
                            const BtcBlockHeader& parent) const {
    // BIP-94 timewarp rule (Core validation.cpp ContextualCheckBlockHeader):
    // the first block of a difficulty period may not be earlier than the last
    // block of the previous period minus BTC_MAX_TIMEWARP (600 s).
    if (!m_netParams.enforceBIP94) return true;
    if (height % (uint32_t)m_netParams.DifficultyAdjustmentInterval() != 0) return true;
    return (int64_t)header.nTime >= (int64_t)parent.nTime - BTC_MAX_TIMEWARP;
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

    // 4. Check difficulty retarget — STRICT on every network. (The old
    // signet-era "log only" advisory path is gone: Testnet4 difficulty is
    // real and fully verifiable from headers, and a lax path here would let
    // a CPU-mined branch carry fake burns.)
    if (!CheckDifficultyRetargetLocked(header, prev)) {
        status = BtcHeaderStatus::INVALID_RETARGET;
        return false;
    }

    // 5. BIP-94 timewarp bound (Testnet4): first block of a period may not be
    // earlier than its parent minus 600 s.
    if (!CheckTimewarp(prev.height + 1, header, prev.header)) {
        status = BtcHeaderStatus::INVALID_TIMEWARP;
        return false;
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
    if (!VerifyCanonicalChain(index.height, index.hash, m_sourceNet)) {
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
        // Third halving (May 2020). NOTE: this constant was WRONG from its
        // introduction (d3895ec8) until 2026-08-03 — dead code in practice
        // (mainnet pin 800000 > 630000, never evaluated), caught by the PHASE
        // 2.6 hostile review. Corrected value verified on mempool.space +
        // mempool.emzy.de.
        checkpoints.push_back({
            630000,
            uint256S("000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d")
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

// A7 Testnet4 checkpoints (fewer checkpoints for test network).
// Provenance (2026-08-03): cross-verified on local Bitcoin Core v28.1 (full
// header validation), mempool.space/testnet4 and mempool.emzy.de/testnet4.
const std::vector<A7Checkpoint>& GetA7Testnet4Checkpoints() {
    static std::vector<A7Checkpoint> checkpoints;
    static bool initialized = false;
    if (!initialized) {
        // Retarget boundary 72*2016 (the SPV genesis checkpoint)
        checkpoints.push_back({
            145152,
            uint256S("00000000000000014694285ac2a2980339778e6b73d2199a65a5f62f2df44d2d")
        });
        // Recent stable anchor
        checkpoints.push_back({
            146000,
            uint256S("00000000000774b867c9eabbc5eba5919e97bb8f7b06f9e86547c7f86966f054")
        });
        initialized = true;
    }
    return checkpoints;
}

bool VerifyCanonicalChain(uint32_t height, const uint256& blockHash, BtcSourceNet sourceNet) {
    const std::vector<A7Checkpoint>& checkpoints = (sourceNet == BtcSourceNet::BITCOIN_TESTNET4) ?
        GetA7Testnet4Checkpoints() : GetA7MainnetCheckpoints();

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
