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
 * 1. Block is signed by the scheduled MN (non-grindable epoch schedule, LOT 9)
 * 2. Signature is valid ECDSA signature from operator key
 * 3. MN was eligible in the epoch-snapshot DMN list
 */

/**
 * Validate block producer for MN-only consensus.
 *
 * Called from ConnectBlock() - this is the main entry point for validating that
 * a block was produced by the scheduled masternode. Resolves the leader through
 * mn_consensus::ResolveScheduledProducer (same engine, same parent as the local
 * scheduler and the AcceptBlock early check) and maps the four O-1 statuses:
 * OK -> signature check; NO_SIGNER -> authoritative empty snapshot: a SIGNED
 * block is deterministically INVALID (bad-dmm-no-eligible-producer, the sole
 * objective case where BLOCK_FAILED_VALID is permitted), an UNSIGNED block is
 * the explicit zero-identity escape hatch (see the .cpp case comment);
 * DEFERRED -> non-persisted Error; FATAL -> LOT 1 latch.
 *
 * @param block          Block to validate
 * @param pindexPrev     Previous block (tip when block was created)
 * @param state          Validation state for error reporting
 * @return               true if block was produced by correct MN
 */
bool CheckBlockMNOnly(const CBlock& block,
                      const CBlockIndex* pindexPrev,
                      CValidationState& state);

#endif // BATHRON_CONSENSUS_MN_VALIDATION_H
