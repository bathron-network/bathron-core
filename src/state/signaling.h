// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_SIGNALING_H
#define BATHRON_SIGNALING_H

#include "state/finality.h"
#include "net/net.h"
#include "sync.h"
#include "uint256.h"

#include <map>
#include <set>
#include <memory>

class CBlockIndex;
class CConnman;
class CNode;

namespace hu {

/**
 * HU Signaling Manager
 *
 * Handles the automatic signing and propagation of HU finality signatures.
 * When the local MN's operator is drawn by the per-block ECVRF sortition it
 * signs and broadcasts; a block is final once unique-OPERATOR votes reach
 * ceil(2/3·min(E,N)) (one vote per operator, never per MN).
 */
class CHuSignalingManager {
private:
    mutable RecursiveMutex cs;

    // Track which signatures we've already relayed (to avoid spam)
    std::map<uint256, std::set<uint256>> mapRelayedSigs;  // blockHash -> set of proTxHashes

    // Signature cache: blockHash -> (proTxHash -> signature)
    std::map<uint256, std::map<uint256, std::vector<unsigned char>>> mapSigCache;

    // Height tracking for cleanup
    int nLastCleanupHeight{0};

    // Finality signatures received for a block we have NOT connected yet. Buffered
    // with an arrival timestamp instead of being dropped, so a block/signature
    // propagation race does not lose them; replayed by ProcessPendingSigs() the
    // moment the block connects. This removes the need for the pre-sign sleep.
    // Bounded (blocks x per-block x TTL) to stay DoS-proof against junk hashes.
    std::map<uint256, std::pair<int64_t, std::vector<CHuSignature>>> mapPendingSigs;
    static constexpr size_t MAX_PENDING_SIG_BLOCKS = 64;
    static constexpr size_t MAX_PENDING_SIGS_PER_BLOCK = 256;
    static constexpr int64_t PENDING_SIG_TTL_MS = 300000;  // 5 min

    // ═══════════════════════════════════════════════════════════════════════════
    // I3: Rate limiting per peer (DoS protection)
    // ═══════════════════════════════════════════════════════════════════════════
    struct PeerRateLimit {
        int count{0};
        int64_t lastResetTime{0};
    };
    std::map<NodeId, PeerRateLimit> mapPeerRateLimit;
    static constexpr int RATE_LIMIT_MAX_SIGS = 100;      // Max signatures per minute per peer
    static constexpr int RATE_LIMIT_WINDOW_SECONDS = 60;  // Rate limit window

public:
    CHuSignalingManager() = default;

    /**
     * Called when we receive a new valid block.
     * If we're a MN in the quorum for this block, sign it and broadcast.
     *
     * @param pindex The block index of the new block
     * @param connman Connection manager for broadcasting
     * @return true if we signed and broadcast
     */
    bool OnNewBlock(const CBlockIndex* pindex, CConnman* connman);

    /**
     * Replay any signatures that were buffered while their block was not yet
     * connected. Called right after a block connects (the block is now known,
     * so the sigs validate and count). Drains mapPendingSigs[blockHash].
     */
    void ProcessPendingSigs(const uint256& blockHash, CConnman* connman);

    /**
     * Process a received HU signature from the network.
     * Validates the signature and adds it to the finality handler.
     * Relays to other peers if valid and new.
     *
     * @param sig The received signature
     * @param pfrom The peer that sent it
     * @param connman Connection manager for relaying
     * @return true if signature was valid and new
     * @param pfMisbehave (out, optional) set true ONLY when the signature is
     *        unambiguously malicious (malformed structure or crypto-invalid) so the
     *        P2P handler can Misbehaving()/ban the peer. NOT set for benign drops
     *        (duplicate, buffered, rate-limited) — an honest relayer must never be
     *        punished for those. Closes redteam-plan R2 (unbannable husig flood).
     */
    bool ProcessHuSignature(const CHuSignature& sig, CNode* pfrom, CConnman* connman, bool* pfMisbehave = nullptr);

    /**
     * Get the number of signatures for a block
     */
    int GetSignatureCount(const uint256& blockHash) const;

    /**
     * Check if a block has reached quorum (2/3 signatures)
     */
    bool HasQuorum(const uint256& blockHash) const;

    /**
     * Cleanup old data for blocks that are now deeply buried
     */
    void Cleanup(int nCurrentHeight);

    /**
     * Number of tracked per-peer rate-limit entries. Bounded by the stale-entry
     * sweep in Cleanup() — exposed for monitoring + the DoS regression test.
     */
    size_t PeerRateLimitEntryCount() const;

    /**
     * Test-only: inject a per-peer rate-limit entry with an explicit lastResetTime,
     * to drive the stale-entry sweep without standing up real peers.
     */
    void InjectPeerRateLimitForTest(NodeId id, int64_t lastResetTime);

private:
    /**
     * MULTI-MN: Sign a block with a specific MN's operator key
     * @param blockHash The block to sign
     * @param proTxHash The proTxHash of the MN to sign with
     * @param sigOut Output signature
     * @return true if signing succeeded
     */
    bool SignBlockWithMN(const uint256& blockHash, const uint256& proTxHash, CHuSignature& sigOut);

    /**
     * Validate a signature against the block's connect-time finality context
     * (ECDSA operator binding + ECVRF committee membership). Pure crypto — takes
     * NO locks (in particular no cs_main), so signature processing never queues
     * behind block-connect / RPC work on a loaded node.
     * @return true if signature is from a valid quorum member
     */
    bool ValidateSignatureFromContext(const CHuSignature& sig, const HuBlockFinalityContext& ctx) const;

    /**
     * Broadcast a signature to all peers
     */
    void BroadcastSignature(const CHuSignature& sig, CConnman* connman, CNode* pfrom = nullptr);
};

// Global signaling manager instance
extern std::unique_ptr<CHuSignalingManager> huSignalingManager;

/**
 * Initialize the HU signaling system
 */
void InitHuSignaling();

/**
 * Shutdown the HU signaling system
 */
void ShutdownHuSignaling();

/**
 * Called from validation when a new block is connected.
 * Triggers signature if we're in the quorum.
 */
void NotifyBlockConnected(const CBlockIndex* pindex, CConnman* connman);

/**
 * Check if the previous block has reached quorum.
 * Used by DMM to decide if we can produce the next block.
 *
 * @param pindexPrev The previous block
 * @return true if previous block has 2/3 signatures (or we're in bootstrap)
 */
bool PreviousBlockHasQuorum(const CBlockIndex* pindexPrev);

} // namespace hu

#endif // BATHRON_SIGNALING_H
