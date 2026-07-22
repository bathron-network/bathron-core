// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_BTCSPV_H
#define BATHRON_BTCSPV_H

#include "arith_uint256.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

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
};

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

    bool Init(const std::string& datadir, bool testnet = false);
    void Shutdown();

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
    // its `parent`. At a retarget boundary (height % 2016 == 0), `periodFirst`
    // must be the header at height-2016; pass nullptr if unavailable (returns 0).
    // Pure function of m_netParams (immutable post-init) + inputs — no lock,
    // no local chain state. Lets consensus validate difficulty from btcheadersdb.
    uint32_t ExpectedNextBits(uint32_t height, const BtcBlockHeader& parent,
                              const BtcBlockHeader* periodFirst) const;

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
    // The SPV genesis checkpoint (signet 286000 / mainnet 800000).
    bool GetGenesisCheckpoint(uint32_t& heightOut, uint256& hashOut) const;
    // BP-BTCHEADERS-HARDENING: the FULL header of the genesis checkpoint, used as
    // the difficulty parent for the first seeded header so R6 can validate it
    // during bootstrap (anchors difficulty to the real BTC checkpoint instead of
    // trusting the genesis seeder). Hardcoded per network + hash-checked at init.
    bool HasGenesisCheckpointHeader() const { return m_hasGenesisCheckpointHeader; }
    bool GetGenesisCheckpointHeader(BtcBlockHeader& out) const;

private:
    // Internal locked versions - MUST be called with m_cs_spv held
    bool InitLocked(const std::string& datadir, bool testnet);
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
    bool m_testnet;
    std::string m_datadir;  // Stored for Reload()
    mutable std::map<uint256, BtcHeaderIndex> m_headerCache;
    static const size_t MAX_CACHE_SIZE = 1000;
    mutable Mutex m_cs_spv;  // Protects DB + cache operations
};

extern std::unique_ptr<CBtcSPV> g_btc_spv;

const BtcNetworkParams& GetBtcMainnetParams();
const BtcNetworkParams& GetBtcSignetParams();
const std::vector<BtcCheckpoint>& GetBtcMainnetCheckpoints();
const std::vector<BtcCheckpoint>& GetBtcSignetCheckpoints();

// Genesis header for Signet (hardcoded at height 286000)
// This allows new nodes to initialize btcspv without external snapshot
bool GetBtcSignetGenesisHeader(BtcBlockHeader& header);
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
 * Get A7 checkpoints for Signet (test network - fewer checkpoints).
 */
const std::vector<A7Checkpoint>& GetA7SignetCheckpoints();

/**
 * Verify that the header at a checkpoint height matches the expected hash.
 *
 * Called during SPV header sync. If the header at an A7 checkpoint height
 * doesn't match the expected hash, the chain is rejected as non-canonical.
 *
 * @param height The height of the header being added
 * @param blockHash The hash of the header
 * @param testnet True if testnet/signet, false for mainnet
 * @return true if valid (not a checkpoint height, or matches expected hash)
 */
bool VerifyCanonicalChain(uint32_t height, const uint256& blockHash, bool testnet);

#endif // BATHRON_BTCSPV_H
