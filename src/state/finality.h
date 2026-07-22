// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_HU_FINALITY_H
#define BATHRON_HU_FINALITY_H

#include "dbwrapper.h"
#include "pubkey.h"
#include "serialize.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <set>
#include <vector>

class CBlockIndex;

/**
 * HU Finality System - ECDSA-based block finality
 *
 * Parameters are network-specific and read from Consensus::Params:
 * - nHuQuorumSize: Sybil floor — min distinct operators to finalize
 * - nHuExpectedCommitteeSize (E): VRF committee cap; threshold = ceil(2/3·min(E,N))
 * - nHuLeaderTimeoutSeconds: DMM leader timeout
 * - nHuMaxReorgDepth: Max reorg depth before finality enforcement
 */

namespace hu {

/**
 * Single HU signature for a block
 */
struct CHuSignature {
    uint256 blockHash;
    uint256 proTxHash;          // Signing MN's proTxHash
    std::vector<unsigned char> vchSig;  // ECDSA signature over SHA256("HUSIG" || blockHash)
    // ECVRF sortition proof (VRF roadmap étape 3.3): the 81-byte proof that this
    // signer's OPERATOR was drawn into the finality committee for `blockHash`,
    // evaluated over the finality seed hash(H-k). NOT part of the ECDSA-signed
    // payload — it is independent evidence, verified separately (IsOperatorVrfSelected).
    // Carries the 81-byte proof for every finality signature: sortition is VRF-only
    // (no legacy top-N path, no activation gate). Always serialized; the chain is
    // fresh-genesis, so no backward-compat version dance is needed.
    std::vector<unsigned char> vchVrfProof;

    SERIALIZE_METHODS(CHuSignature, obj)
    {
        READWRITE(obj.blockHash, obj.proTxHash, obj.vchSig, obj.vchVrfProof);
    }
};

/**
 * HU Finality data for a block
 * Stores all collected signatures
 *
 * IMPORTANT: Quorum threshold is based on UNIQUE OPERATORS, not MN count.
 * A single operator running multiple MNs only counts as ONE signature.
 * This prevents a single operator from reaching quorum alone.
 */
class CFinalityManager {
public:
    uint256 blockHash;
    int nHeight{0};
    std::map<uint256, std::vector<unsigned char>> mapSignatures; // proTxHash -> sig

    CFinalityManager() = default;
    explicit CFinalityManager(const uint256& hash, int height) : blockHash(hash), nHeight(height) {}

    /**
     * Check if block has reached finality threshold
     * @param nThreshold - required unique-operator count (see hu::HuActiveFinalityThreshold)
     *
     * NOTE: This counts UNIQUE OPERATORS, not raw signature count.
     * Use GetUniqueOperatorCount() for the actual operator count.
     */
    bool HasFinality(int nThreshold) const;  // Implemented in finality.cpp
    // NB: no zero-arg overload — callers MUST pass the ACTIVE threshold
    // (hu::HuActiveFinalityThreshold(consensus, N)) so the per-block value is
    // used (the old default-8 overload silently left testnet/regtest finality
    // unguarded; finding hu-finality-0).

    size_t GetSignatureCount() const { return mapSignatures.size(); }

    /**
     * Get count of unique operators who have signed
     * Looks up each proTxHash in MN list to get operator pubkey
     */
    size_t GetUniqueOperatorCount() const;  // Implemented in finality.cpp

    SERIALIZE_METHODS(CFinalityManager, obj)
    {
        READWRITE(obj.blockHash, obj.nHeight, obj.mapSignatures);
    }
};

/**
 * HU Finality Handler
 * Manages finality signatures and enforcement
 */
class CFinalityManagerHandler {
private:
    mutable RecursiveMutex cs;
    std::map<uint256, CFinalityManager> mapFinality;  // blockHash -> finality data
    std::map<int, uint256> mapHeightToBlock;     // height -> blockHash (for quick lookup)

public:
    CFinalityManagerHandler() = default;

    /**
     * Check if a block has HU finality (unique-operator count >= active threshold)
     */
    bool HasFinality(int nHeight, const uint256& blockHash) const;

    /**
     * Check if accepting a block at given height/hash would conflict
     * with an already-finalized block
     */
    bool HasConflictingFinality(int nHeight, const uint256& blockHash) const;

    /**
     * Add a signature to a block's finality data
     * @return true if signature was new and valid
     */
    bool AddSignature(const CHuSignature& sig);

    /**
     * Get finality data for a block
     */
    bool GetFinality(const uint256& blockHash, CFinalityManager& finalityOut) const;

    /**
     * Get signature count for a block
     */
    int GetSignatureCount(const uint256& blockHash) const;

    /**
     * Restore finality data from DB (called during init)
     * Used by I1 to restore persisted signatures on restart
     */
    void RestoreFinality(const CFinalityManager& finality);

    /**
     * Get the last finalized block height and hash
     * Used for monitoring finality lag
     */
    bool GetLastFinalized(int& nHeightOut, uint256& hashOut) const;

    /**
     * Get finality status for monitoring
     * @param tipHeight - current chain tip height
     * @return lag = tipHeight - lastFinalizedHeight
     */
    int GetFinalityLag(int tipHeight) const;
};

// Global handler instance
extern std::unique_ptr<CFinalityManagerHandler> finalityHandler;

/**
 * CFinalityManagerDB - LevelDB persistence for HU finality data
 *
 * Stores finality records indexed by blockHash.
 * Separate from block data to keep block hash immutable.
 */
class CFinalityManagerDB : public CDBWrapper {
public:
    CFinalityManagerDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    /**
     * Write finality data for a block
     */
    bool WriteFinality(const CFinalityManager& finality);

    /**
     * Read finality data for a block
     * @return true if found, false otherwise
     */
    bool ReadFinality(const uint256& blockHash, CFinalityManager& finality) const;

    /**
     * Check if finality data exists for a block
     */
    bool HasFinality(const uint256& blockHash) const;

    /**
     * Check if a block is final (record exists and meets the ACTIVE threshold).
     * The threshold is derived internally from the record's height via
     * hu::HuActiveFinalityThreshold (ceil(2/3·min(E,N))), so callers need not
     * pass it.
     */
    bool IsBlockFinal(const uint256& blockHash) const;
};

// Global DB instance
extern std::unique_ptr<CFinalityManagerDB> pFinalityDB;

/**
 * Initialize HU finality system
 * @param nCacheSize - LevelDB cache size
 * @param fWipe - wipe database on init
 */
void InitHuFinality(size_t nCacheSize = (1 << 20), bool fWipe = false);

/**
 * Shutdown HU finality system
 */
void ShutdownHuFinality();

/**
 * Check if a reorg to newTip would violate HU finality
 * @param pindexNew - proposed new tip
 * @param pindexFork - fork point
 * @return true if reorg is blocked by finality
 */
bool WouldViolateHuFinality(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork);

/**
 * Unique-operator population AT the block identified by `blockHash`, resolved
 * deterministically from that block's OWN MN list (GetUniqueOperators over
 * GetListForBlock(pindex->pprev)) — the exact N the VRF selection uses. This is the
 * value to feed HuActiveFinalityThreshold so the threshold tracks the committee.
 * Returns 0 if the block / MN manager is unavailable (caller treats 0 as "fall back
 * to E"). Lives here (not quorum.cpp) because it touches global chainstate.
 */
int HuFinalityOperatorCount(const uint256& blockHash);

// ── Per-block finality operator context cache ──────────────────────────────────
// The hot signature-counting path (GetUniqueOperatorCount / HuFinalityOperatorCount)
// resolves signers→operators via GetListForBlock(pprev) under cs_main on EVERY
// incoming signature. On a loaded node (block producer + burn/header daemons) cs_main
// is contended, so counting — and therefore the moment the node OBSERVES finality —
// is delayed by seconds even though the network reached finality in milliseconds.
// Fix: precompute the block's operator context once at connect (cs_main already held)
// and cache it; the counting path then reads the cache with NO cs_main. Deterministic
// and identical to the live path (derived from the same GetListForBlock(pprev)), so it
// changes only WHEN a node observes finality, never WHETHER a block is final.
struct HuBlockFinalityContext {
    int nHeight{0};
    uint256 vrfSeed;                              // GetHuFinalitySeedHash(pindex, k) — the VRF input for this block
    std::set<CPubKey> eligibleOperators;          // bootstrap-aware, = keys of GetUniqueOperators(mnList)
    std::map<uint256, CPubKey> operatorByProTx;   // signer proTxHash -> pubKeyOperator (all valid MNs)
    std::map<uint256, CPubKey> vrfByProTx;        // signer proTxHash -> pubKeyVRF (all valid MNs)
    bool valid{false};
};

// Compute + cache a block's finality context. MUST be called with cs_main held
// (e.g. from NotifyBlockConnected at connect time).
void CacheBlockFinalityContext(const CBlockIndex* pindex);
// Read a cached context (no cs_main). Returns false on miss.
bool GetCachedFinalityContext(const uint256& blockHash, HuBlockFinalityContext& out);
// Cached read with build-on-miss: on a miss, takes cs_main ONCE to resolve the block
// and (re)builds + caches its context (restart boundary, late sigs past a prune).
// Returns false only if the block is unknown — callers buffer the signature then.
bool GetOrBuildFinalityContext(const uint256& blockHash, HuBlockFinalityContext& out);
// Drop cached contexts for blocks below nHeight (called from Cleanup).
void PruneFinalityContextsBelow(int nHeight);

} // namespace hu

#endif // BATHRON_HU_FINALITY_H
