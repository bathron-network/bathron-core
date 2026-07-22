// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bathron_chainwork.h"

#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "uint256.h"

/**
 * GetBlockDifficultyBits - returns difficulty bits for next block.
 *
 * In HU (DMM consensus), there's no difficulty adjustment.
 * We simply propagate the previous block's nBits value.
 * Block validity is determined by MN signatures, not hash difficulty.
 */
unsigned int GetBlockDifficultyBits(const CBlockIndex* pindexLast, const CBlockHeader* pblock)
{
    // Genesis block case
    if (pindexLast == nullptr)
        return 0x1e0ffff0;  // Default minimum difficulty

    // DMM: no difficulty adjustment, use previous block's bits
    return pindexLast->nBits;
}

/**
 * GetBlockWeight - calculates chain weight contribution for a block.
 *
 * Used for longest chain selection. In HU's DMM model, each MN-signed
 * block has uniform weight. The calculation uses nBits for compatibility
 * with existing chain selection logic in validation.cpp
 */
arith_uint256 GetBlockWeight(const CBlockIndex& block)
{
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow || bnTarget.IsNull())
        return ARITH_UINT256_ZERO;

    // Weight calculation: higher target = lower weight
    // This ensures chain selection favors properly constructed blocks
    return (~bnTarget / (bnTarget + 1)) + 1;
}
