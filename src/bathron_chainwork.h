// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_CHAINWORK_H
#define BATHRON_CHAINWORK_H

#include <stdint.h>
#include "arith_uint256.h"

class CBlockHeader;
class CBlockIndex;

/**
 * HU Chain Work Functions
 *
 * HU uses DMM (Deterministic Masternode Minting) - no PoW/PoS.
 * These functions provide chain selection logic based on block weight.
 */

/**
 * Get block difficulty bits for the next block.
 * In HU, this returns the previous block's nBits (no difficulty adjustment).
 * Block validity is determined by MN consensus, not mining difficulty.
 */
unsigned int GetBlockDifficultyBits(const CBlockIndex* pindexLast, const CBlockHeader* pblock);

/**
 * Calculate chain weight for a block.
 * Used for longest chain selection - each valid block adds weight.
 * In HU, weight is uniform since all blocks are MN-signed.
 */
arith_uint256 GetBlockWeight(const CBlockIndex& block);

#endif // BATHRON_CHAINWORK_H
