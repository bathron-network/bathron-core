// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blocksignature.h"

#include "chainparams.h"
#include "masternode/deterministicmns.h"
#include "validation.h"

bool CheckBlockSignature(const CBlock& block)
{
    // Genesis block - no signature required
    if (block.hashPrevBlock.IsNull()) {
        return true;
    }

    // Regtest: Skip signature verification
    if (Params().IsRegTestNet()) {
        return true;
    }

    // Bootstrap phase: Exempt blocks during initial network setup.
    // The first MNs are registered by ProRegTx at block 2+ and cannot sign the
    // blocks that carry their own registration (chicken-and-egg), so blocks 1 to
    // nDMMBootstrapHeight allow MN registration, sync and stabilization.
    const Consensus::Params& consensus = Params().GetConsensus();
    {
        LOCK(cs_main);
        auto it = mapBlockIndex.find(block.hashPrevBlock);
        if (it != mapBlockIndex.end()) {
            int nHeight = it->second->nHeight + 1;  // Height of this block
            if (nHeight <= consensus.nDMMBootstrapHeight) {
                LogPrintf("%s: Bootstrap exemption for block %d (threshold=%d)\n",
                          __func__, nHeight, consensus.nDMMBootstrapHeight);
                return true;
            }
        }
    }

    // DMM blocks: Signature verified by CheckBlockMNOnly in ConnectBlock
    if (block.vchBlockSig.empty()) {
        return error("%s: block has empty vchBlockSig!", __func__);
    }

    return true;
}
