// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_CONSENSUS_MN_VALIDATION_H
#define BATHRON_CONSENSUS_MN_VALIDATION_H

#include "primitives/block.h"

class CBlockIndex;
class CValidationState;

/**
 * MN-only consensus validation for BATHRON.
 *
 * BATHRON has NO PoS - masternodes produce all blocks.
 * This is the ONLY block production mechanism.
 *
 * Validation checks:
 * 1. Block is signed by the expected MN (hash-based selection)
 * 2. Signature is valid ECDSA signature from operator key
 * 3. MN was active in DMN list at previous block
 */

/**
 * Validate block producer for MN-only consensus.
 *
 * Called from ConnectBlock() / CheckBlock() - this is the main
 * entry point for validating that a block was produced by the
 * correct masternode.
 *
 * @param block          Block to validate
 * @param pindexPrev     Previous block (tip when block was created)
 * @param state          Validation state for error reporting
 * @return               true if block was produced by correct MN
 */
bool CheckBlockMNOnly(const CBlock& block,
                      const CBlockIndex* pindexPrev,
                      CValidationState& state);

/**
 * Check if this node is the expected block producer for next block.
 *
 * Used by mining code to determine if this node should produce
 * the next block.
 *
 * @param pindexPrev     Current tip
 * @return               true if local MN is expected producer
 */

/**
 * Get the proTxHash of the expected block producer.
 *
 * @param pindexPrev     Previous block
 * @param proTxHashRet   [out] ProTxHash of expected producer
 * @return               true if producer found
 */
bool GetExpectedBlockProducer(const CBlockIndex* pindexPrev,
                              uint256& proTxHashRet);

#endif // BATHRON_CONSENSUS_MN_VALIDATION_H
