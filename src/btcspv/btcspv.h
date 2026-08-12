// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCSPV_H
#define BATHRON_BTCSPV_H

#include "arith_uint256.h"
#include "btcspv/btcsourcenet.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

class CDBWrapper;

/**
 * BP09 - Bitcoin SPV Headers
 */

// Bitcoin block header (80 bytes)
struct BtcBlockHeader {
    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    SERIALIZE_METHODS(BtcBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot,
                  obj.nTime, obj.nBits, obj.nNonce);
    }

    uint256 GetHash() const;
    bool IsNull() const { return hashMerkleRoot.IsNull(); }
    void SetNull();
};

// Indexed header storage
struct BtcHeaderIndex {
    uint256 hash;
    uint256 hashPrevBlock;
    uint32_t height;
    uint256 chainWorkSer;  // Stored as uint256 for serialization
    BtcBlockHeader header;

    SERIALIZE_METHODS(BtcHeaderIndex, obj)
    {
        READWRITE(obj.hash, obj.hashPrevBlock, obj.height, obj.chainWorkSer, obj.header);
    }

    arith_uint256 GetChainWork() const { return UintToArith256(chainWorkSer); }
    void SetChainWork(const arith_uint256& work) { chainWorkSer = ArithToUint256(work); }
    bool IsNull() const { return hash.IsNull(); }
    void SetNull();
};

// Bitcoin network parameters
struct BtcNetworkParams {
    uint32_t magic;
    uint256 genesisHash;
    uint16_t defaultPort;
    arith_uint256 powLimit;
    // PoW schedule (Bitcoin Core consensus/params.h equivalents)
    int64_t nPowTargetSpacing{600};
    int64_t nPowTargetTimespan{14 * 24 * 60 * 60};
    // Testnet4 only: 20-minute min-difficulty exception (never at a retarget
    // boundary) — Core pow.cpp GetNextWorkRequired.
    bool fPowAllowMinDifficultyBlocks{false};
    // BIP-94 (Testnet4): retarget from the FIRST block of the closing period
    // (block-storm fix) + timewarp bound on the first block of each period
    // (nTime >= prev.nTime - MAX_TIMEWARP) — Core pow.cpp + validation.cpp.
    bool enforceBIP94{false};
    // Height of the checkpoint whose full 80-byte header is pinned in code
    // (the SPV starting anchor). Replaces the old first-vs-last asymmetry.
    uint32_t genesisCheckpointHeight{0};

    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
};

// BIP-94 timewarp bound (seconds) — Core src/consensus/consensus.h MAX_TIMEWARP.
static constexpr int64_t BTC_MAX_TIMEWARP = 600;

// Hardcoded checkpoint
struct BtcCheckpoint {
    uint32_t height;
    uint256 hash;
    arith_uint256 chainWork;
};

// Header validation result
enum class BtcHeaderStatus {
    VALID,
    INVALID_POW,
    INVALID_PREVBLOCK,
    INVALID_TIMESTAMP_FUTURE,
    INVALID_TIMESTAMP_MTP,
    INVALID_RETARGET,
    INVALID_TIMEWARP,
    INVALID_CHECKPOINT,
    DUPLICATE,
    ORPHAN
};

std::string BtcHeaderStatusToString(BtcHeaderStatus status);

/**
 * CBtcSPV - Bitcoin SPV Client
 */
class CBtcSPV {
public:
    CBtcSPV();
    ~CBtcSPV();

    bool Init(const std::string& datadir, BtcSourceNet sourceNet);
    // TEST-ONLY: init with explicit (harness) network params instead of a named
    // network — lets unit tests use a cheap powLimit for synthetic CPU-minable
    // headers. Never called from production code; clearly-labeled harness
    // params are NOT a Bitcoin network.
    bool InitForTest(const std::string& datadir, const BtcNetworkParams& params,
                     const std::vector<BtcCheckpoint>& checkpoints,
                     const BtcBlockHeader* pinnedHeader);
    void Shutdown();

    // The committed Bitcoin source network (immutable post-init).
    BtcSourceNet GetSourceNet() const { return m_sourceNet; }

    // COMMIT 5: Hot reload - re-initialize SPV store without daemon restart
    // Returns true on success, false if reload failed (original state preserved on failure)
    bool Reload();

    BtcHeaderStatus AddHeader(const BtcBlockHeader& header);
    bool GetHeader(const uint256& hash, BtcHeaderIndex& out) const;
    bool GetHeaderAtHeight(uint32_t height, BtcHeaderIndex& out) const;

    uint32_t GetTipHeight() const;
    uint256 GetTipHash() const;
    arith_uint256 GetTipChainWork() const;
    bool IsInBestChain(const uint256& blockHash) const;
    uint32_t GetConfirmations(const uint256& blockHash) const;

    bool VerifyMerkleProof(const uint256& txid, const uint256& merkleRoot,
                           const std::vector<uint256>& proof, uint32_t txIndex) const;

    bool IsSynced() const;
    uint32_t GetHeaderCount() const;

    // Returns the minimum BTC block height supported by SPV (lowest checkpoint)
    // Burns below this height cannot be verified trustlessly
    uint32_t GetMinSupportedHeight() const;

    struct BatchResult {
        uint32_t accepted;
        uint32_t rejected;
        uint32_t tipHeight;
        std::string firstRejectReason;
        uint256 firstRejectHash;
    };
    BatchResult AddHeaders(const std::vector<BtcBlockHeader>& headers);

    // BP-SPVMNPUB: Made public for TX_BTC_HEADERS validation
    bool CheckProofOfWork(const BtcBlockHeader& header) const;

    // BP-BTCHEADERS-REORG: cumulative-work comparison for consensus reorg.
    // Pure function of header.nBits (no lock needed).
    arith_uint256 GetBlockProof(const BtcBlockHeader& header) const;

    // BP-BTCHEADERS-REORG F1 (R6): expected nBits for a header at `height` given
    // its `parent` — faithful port of Core GetNextWorkRequired/
    // CalculateNextWorkRequired (v28.1), including the Testnet4 min-difficulty
    // exception and BIP-94 first-block retarget. `newHeaderTime` is the nTime of
    // the header being validated (the min-difficulty exception depends on it).
    // `getAncestor(h, out)` must return the header at height `h` on the chain
    // being validated; it is only called for heights within the closing
    // difficulty period. Returns 0 if a required ancestor is unavailable
    // (caller decides: bootstrap cross-tx gap vs hard reject).
    // Pure function of m_netParams (immutable post-init) + inputs — no lock,
    // no local chain state. Lets consensus validate difficulty from btcheadersdb.
    uint32_t ExpectedNextBits(uint32_t height, const BtcBlockHeader& parent,
                              uint32_t newHeaderTime,
                              const std::function<bool(uint32_t, BtcBlockHeader&)>& getAncestor) const;

    // BIP-94 timewarp rule (Core validation.cpp ContextualCheckBlockHeader):
    // on the first block of a difficulty period, nTime must be >=
    // prev.nTime - BTC_MAX_TIMEWARP. Always true when the network does not
    // enforce BIP-94. Pure function — no lock.
    bool CheckTimewarp(uint32_t height, const BtcBlockHeader& header,
                       const BtcBlockHeader& parent) const;

    // BP-BTCHEADERS-REORG F5/F6: consensus access to the per-network BTC
    // checkpoints (immutable post-init). No lock, no local chain state.
    // True if `height` is a checkpoint (its hash in hashOut).
    bool GetCheckpointHash(uint32_t height, uint256& hashOut) const;
    // Highest checkpoint height (0 if none). A reorg may not fork below it.
    uint32_t HighestCheckpointHeight() const;
    // TEST-ONLY: inject an SPV checkpoint into the in-memory set so the A9
    // reorg-below-checkpoint floor (F5) can be exercised without a full network
    // Init(). No consensus path calls this.
    void AddCheckpointForTest(uint32_t height, const uint256& hash) {
        m_checkpoints.push_back({height, hash, arith_uint256()});
    }
    // The SPV genesis checkpoint (testnet4 145152 / mainnet 800000).
    bool GetGenesisCheckpoint(uint32_t& heightOut, uint256& hashOut) const;
    // BP-BTCHEADERS-HARDENING: the FULL header of the genesis checkpoint, used as
    // the difficulty parent for the first seeded header so R6 can validate it
    // during bootstrap (anchors difficulty to the real BTC checkpoint instead of
    // trusting the genesis seeder). Hardcoded per network + hash-checked at init.
    bool HasGenesisCheckpointHeader() const { return m_hasGenesisCheckpointHeader; }
    bool GetGenesisCheckpointHeader(BtcBlockHeader& out) const;
    // MTP context: the pinned REAL headers immediately below the genesis
    // checkpoint (testnet4: 145142..145151), linkage-verified against the pin
    // at init. They exist so the 11-block median-time-past window near the pin
    // matches Bitcoin Core exactly (real Testnet4 has negative timestamp gaps
    // — e.g. 145156 is 6375 s earlier than its parent — which a truncated
    // window would wrongly reject). Returns the context header at `height`
    // (the pin itself included); false outside the pinned range.
    bool GetGenesisContextHeader(uint32_t height, BtcBlockHeader& out) const;

private:
    // Internal locked versions - MUST be called with m_cs_spv held
    bool InitLocked(const std::string& datadir, BtcSourceNet sourceNet);
    bool InitCommonLocked(const std::string& datadir);
    void ShutdownLocked();
    bool ValidateHeaderLocked(const BtcBlockHeader& header, const BtcHeaderIndex& prev, BtcHeaderStatus& status) const;
    bool CheckTimestampLocked(const BtcBlockHeader& header, const BtcHeaderIndex& prev) const;
    bool CheckDifficultyRetargetLocked(const BtcBlockHeader& header, const BtcHeaderIndex& prev) const;
    int64_t GetMedianTimePastLocked(const BtcHeaderIndex& index) const;
    bool VerifyChainCheckpointsLocked(const BtcHeaderIndex& tip) const;
    void UpdateBestChainLocked(const BtcHeaderIndex& newTip);
    // Rebuild the best-chain height index from the tip via hash links — repairs
    // stale entries left by a pre-fix reorg. Idempotent (no-op once consistent).
    void RepairHeightIndexLocked();
    bool StoreHeader(const BtcHeaderIndex& index);
    bool StoreHeaderLocked(const BtcHeaderIndex& index);
    bool GetHeaderLocked(const uint256& hash, BtcHeaderIndex& out) const;
    bool GetHeaderAtHeightLocked(uint32_t height, BtcHeaderIndex& out) const;
    bool LoadTipLocked();
    bool StoreTipLocked();

    std::unique_ptr<CDBWrapper> m_db;
    uint256 m_bestTipHash;
    uint32_t m_bestHeight;
    arith_uint256 m_bestChainWork;
    uint32_t m_minSupportedHeight;  // Persisted in DB - lowest height we have headers for
    BtcNetworkParams m_netParams;
    std::vector<BtcCheckpoint> m_checkpoints;
    BtcBlockHeader m_genesisCheckpointHeader;       // full header at the genesis checkpoint
    bool m_hasGenesisCheckpointHeader{false};        // false until hardcoded+verified for this net
    std::map<uint32_t, BtcBlockHeader> m_genesisContext; // pinned MTP context below the pin
    BtcSourceNet m_sourceNet{BtcSourceNet::BITCOIN_MAINNET};
    std::string m_datadir;  // Stored for Reload()
    mutable std::map<uint256, BtcHeaderIndex> m_headerCache;
    static const size_t MAX_CACHE_SIZE = 1000;
    mutable Mutex m_cs_spv;  // Protects DB + cache operations
};

extern std::unique_ptr<CBtcSPV> g_btc_spv;

const BtcNetworkParams& GetBtcMainnetParams();
const BtcNetworkParams& GetBtcTestnet4Params();
const std::vector<BtcCheckpoint>& GetBtcMainnetCheckpoints();
const std::vector<BtcCheckpoint>& GetBtcTestnet4Checkpoints();

// Genesis header for Testnet4 (hardcoded at height 145152, a retarget
// boundary — its nBits seeds the next BIP-94 retarget and the min-difficulty
// walk-back can never need an ancestor below it).
bool GetBtcTestnet4GenesisHeader(BtcBlockHeader& header);
// The 10 REAL Testnet4 headers 145142..145151 (MTP context below the pin) —
// linkage self-verified at init: they chain into the pinned 145152 header.
const std::vector<BtcBlockHeader>& GetBtcTestnet4GenesisContext();
// Genesis header for Mainnet (hardcoded at height 800000), verified to hash to
// the mainnet genesis checkpoint. Difficulty anchor for the first seeded header.
bool GetBtcMainnetGenesisHeader(BtcBlockHeader& header);

// ═══════════════════════════════════════════════════════════════════════════════
// BP12 - A7 Canonical Chain Checkpoints (Halving Boundaries)
// ═══════════════════════════════════════════════════════════════════════════════
// These checkpoints define "what Bitcoin means for BATHRON" at halving boundaries.
// Unlike SPV checkpoints (which are for PoW validation), A7 checkpoints are
// structural anchors that verify chain identity.
//
// IMPORTANT: Checkpoints are only enforced at their exact heights, never retroactively.
// A chain that matches all checkpoints but diverges afterward is still accepted —
// that's what the kill switch is for.
// ═══════════════════════════════════════════════════════════════════════════════

// A7 Checkpoint (simpler than BtcCheckpoint - just height + hash)
struct A7Checkpoint {
    uint32_t height;
    uint256 expectedHash;
};

/**
 * Get A7 checkpoints for mainnet (halving boundaries).
 */
const std::vector<A7Checkpoint>& GetA7MainnetCheckpoints();

/**
 * Get A7 checkpoints for Testnet4 (test network - fewer checkpoints).
 */
const std::vector<A7Checkpoint>& GetA7Testnet4Checkpoints();

/**
 * Verify that the header at a checkpoint height matches the expected hash.
 *
 * Called during SPV header sync. If the header at an A7 checkpoint height
 * doesn't match the expected hash, the chain is rejected as non-canonical.
 *
 * @param height The height of the header being added
 * @param blockHash The hash of the header
 * @param sourceNet The committed Bitcoin source network
 * @return true if valid (not a checkpoint height, or matches expected hash)
 */
bool VerifyCanonicalChain(uint32_t height, const uint256& blockHash, BtcSourceNet sourceNet);

#endif // BATHRON_BTCSPV_H
