// Copyright (c) 2025 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_EVO_BLOCKPRODUCER_H
#define BATHRON_EVO_BLOCKPRODUCER_H

#include "arith_uint256.h"
#include "masternode/deterministicmns.h"
#include "key.h"
#include "primitives/block.h"
#include "uint256.h"

class CBlockIndex;
class CValidationState;

namespace mn_consensus {

/**
 * MN-only block production for BATHRON chain.
 *
 * BATHRON uses pure MN-only consensus from genesis - NO PoS.
 * Masternodes produce all blocks. Selection is hash-based and deterministic:
 *
 *   score(MN) = H(prevBlockHash || height+1 || proTxHash)
 *
 * The MN with the highest score is the legitimate producer for that block.
 *
 * Block signatures use ECDSA with the operator key (~72 bytes DER encoded)
 *
 * Properties:
 * - Deterministic: Same inputs = same selection
 * - Unpredictable: Cannot be known until previous block hash is known
 * - Fair: Each MN has equal probability based on its proTxHash
 * - No grinding: proTxHash is committed before any block it could influence
 */

/**
 * Compute block producer score for a masternode.
 *
 * score = SHA256(prevBlockHash || height || proTxHash)
 *
 * @param prevBlockHash  Hash of the previous block
 * @param nHeight        Height of the block being produced
 * @param proTxHash      ProRegTx hash of the masternode
 * @return               Score as arith_uint256 (higher = selected)
 */
arith_uint256 ComputeMNBlockScore(const uint256& prevBlockHash, int nHeight, const uint256& proTxHash);

/**
 * Select the block producer for a given height.
 *
 * @param pindexPrev     Previous block index
 * @param mnList         DMN list at pindexPrev
 * @param outMn          [out] Selected masternode
 * @return               true if producer found
 */
bool GetBlockProducer(const CBlockIndex* pindexPrev,
                      const CDeterministicMNList& mnList,
                      CDeterministicMNCPtr& outMn);

/**
 * Calculate the producer slot from block header data.
 *
 * This is a PURE function that depends ONLY on block data (nTime, prevTime).
 * It must produce identical results on ALL nodes for consensus.
 *
 * @param pindexPrev  Previous block index (for prevTime)
 * @param nBlockTime  Block timestamp (from block header)
 * @return            Producer slot index (0 = primary, 1+ = fallback)
 */
int GetProducerSlot(const CBlockIndex* pindexPrev, int64_t nBlockTime);

/**
 * Get the expected block producer based on block header data.
 *
 * This function uses GetProducerSlot() to determine which MN should have
 * produced this block. The result is deterministic and identical on all nodes.
 *
 * IMPORTANT: This function is used BOTH by:
 * 1. The scheduler (to check if local MN should produce)
 * 2. Verification (to check if signature matches expected producer)
 *
 * @param pindexPrev       Previous block index
 * @param nBlockTime       Block timestamp
 * @param mnList           DMN list at pindexPrev
 * @param outMn            [out] Expected producer MN
 * @param outProducerIndex [out] Producer index (0 = primary, 1+ = fallback)
 * @return                 true if producer found
 */
bool GetExpectedProducer(const CBlockIndex* pindexPrev,
                         int64_t nBlockTime,
                         const CDeterministicMNList& mnList,
                         CDeterministicMNCPtr& outMn,
                         int& outProducerIndex);

/**
 * Calculate all MN scores for debugging/verification.
 *
 * @param pindexPrev     Previous block index
 * @param mnList         DMN list
 * @return               Vector of (score, MN) pairs, sorted descending
 */
std::vector<std::pair<arith_uint256, CDeterministicMNCPtr>>
CalculateBlockProducerScores(const CBlockIndex* pindexPrev, const CDeterministicMNList& mnList);

/**
 * Producer-selection wraps the slot modulo the number of scored MNs
 * (producer = scores[slot % n]). When a block is produced at slot S, slots
 * 0..S-1 were missed by their assigned producers. Return the DISTINCT score
 * indices that missed, EXCLUDING the actual producer (slot S % n), each at most
 * once. Used to apply PoSe penalties consistently with the modulo selection —
 * without this the raw-index loop over-penalized (and could ban) the real
 * producer and every MN once a fallback slot wrapped past n (dmm-production-4).
 *
 * @param producerSlot   The winning slot S (>0 means a fallback produced).
 * @param numScores      Number of scored (eligible) MNs, n.
 * @return               Distinct indices in [0,n) to penalize, excluding S % n.
 */
std::vector<int> ComputeMissedProducerIndices(int producerSlot, int numScores);

/**
 * PoSe punishment guard (UPGRADE_POSE_PRODUCER_DECAY rule). Returns true when this
 * block's missed-slot punishments must be SKIPPED because the evidence points to a
 * NETWORK event rather than individual faults:
 *  - dtSincePrev > nStaleTimeout: first block after a chain-wide outage (same
 *    principle as the finality cold-start bypass) — its deep fallback slot would
 *    punish every non-producer at once (up to N-1 MNs), and 3 such blocks would
 *    mass-ban honest MNs below the finality quorum floor;
 *  - nMissed > ceil(N/3): a block claiming that more than a third of the producer
 *    set simultaneously "failed" contradicts the BFT operating assumption (< 1/3
 *    faulty) — rocky recovery blocks and healing partitions look like this, three
 *    simultaneous individual faults do not. Also covers recovery blocks 2..k whose
 *    dt is back under the stale threshold.
 * Deterministic: every input is consensus data (block times, slot, list size).
 * Individual/dual outages (nMissed <= ceil(N/3), normal dt) punish as usual.
 */
bool ShouldSkipPoSePunishment(int64_t dtSincePrev, int64_t nStaleTimeout, size_t nMissed, size_t nProducers);

/**
 * Sign block with MN operator ECDSA key.
 *
 * @param block          Block to sign
 * @param operatorKey    ECDSA private key (operator)
 * @return               true if signed
 */
bool SignBlockMNOnly(CBlock& block, const CKey& operatorKey);

/**
 * Verify block signature matches expected producer.
 *
 * @param block          Block to verify
 * @param pindexPrev     Previous block
 * @param mnList         DMN list at pindexPrev
 * @param state          Validation state
 * @return               true if valid
 */
bool VerifyBlockProducerSignature(const CBlock& block,
                                  const CBlockIndex* pindexPrev,
                                  const CDeterministicMNList& mnList,
                                  CValidationState& state);

/**
 * Verify block signature and return skipped producers for PoSe penalty.
 *
 * When a fallback producer signs a block (producerIndex > 0), the primary
 * producer(s) have missed their slot. This function returns those MNs
 * so they can receive PoSe penalties.
 *
 * @param block              Block to verify
 * @param pindexPrev         Previous block
 * @param mnList             DMN list at pindexPrev
 * @param state              Validation state
 * @param outSkippedMNs      [out] MNs that missed their production slot (for PoSe)
 * @param outProducerIndex   [out] Producer slot (0 = primary, 1+ = fallback)
 * @return                   true if valid
 */
bool VerifyBlockProducerSignatureWithPoSe(const CBlock& block,
                                          const CBlockIndex* pindexPrev,
                                          const CDeterministicMNList& mnList,
                                          CValidationState& state,
                                          std::vector<uint256>& outSkippedMNs,
                                          int& outProducerIndex);

} // namespace mn_consensus

#endif // BATHRON_EVO_BLOCKPRODUCER_H
