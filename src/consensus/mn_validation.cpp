// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "consensus/mn_validation.h"

#include "masternode/activemasternode.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "masternode/blockproducer.h"
#include "masternode/deterministicmns.h"
#include "logging.h"

bool CheckBlockMNOnly(const CBlock& block,
                      const CBlockIndex* pindexPrev,
                      CValidationState& state)
{
    if (!pindexPrev) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-prev-null");
    }

    // Genesis block has no producer validation
    if (pindexPrev->nHeight < 0) {
        return true;
    }

    // Get DMN list at previous block
    if (!deterministicMNManager) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-manager-null");
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindexPrev);
    const int nHeight = pindexPrev->nHeight + 1;

    // Bootstrap exemption: Allow unsigned blocks during initial network setup
    // Blocks 1 to nDMMBootstrapHeight are generated via generatebootstrap before MNs are online
    // After bootstrap phase, DMM signature verification is strictly enforced
    const Consensus::Params& consensus = Params().GetConsensus();
    if (nHeight <= consensus.nDMMBootstrapHeight) {
        LogPrint(BCLog::MASTERNODE, "%s: Bootstrap block %d (threshold=%d) - MN signature not required\n",
                 __func__, nHeight, consensus.nDMMBootstrapHeight);
        return true;
    }

    // Gate on the SAME eligible producer set the scheduler produces from
    // (CalculateBlockProducerScores = bootstrap-trust MNs registered <=
    // nDMMBootstrapHeight PLUS collateral-confirmed MNs), NOT GetConfirmedMNsCount().
    // The old confirmed-only gate skipped the wrong-producer check for the entire
    // post-bootstrap-pre-confirmation window (up to nMasternodeCollateralMinConf
    // blocks, ~1440 on mainnet) even though those blocks DO have a deterministic
    // expected producer — the production-side analogue of the GetUniqueOperators
    // bootstrap-awareness fix. If the eligible set is empty, there is genuinely no
    // producer to check against, so allow the block.
    if (mn_consensus::CalculateBlockProducerScores(pindexPrev, mnList).empty()) {
        LogPrint(BCLog::MASTERNODE, "%s: No eligible producers at height %d (total: %d), allowing block\n",
                 __func__, nHeight, mnList.GetValidMNsCount());
        return true;
    }

    // Verify block producer signature
    return mn_consensus::VerifyBlockProducerSignature(block, pindexPrev, mnList, state);
}

bool GetExpectedBlockProducer(const CBlockIndex* pindexPrev, uint256& proTxHashRet)
{
    proTxHashRet.SetNull();

    if (!pindexPrev || !deterministicMNManager) {
        return false;
    }

    CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindexPrev);

    if (mnList.GetValidMNsCount() == 0) {
        return false;
    }

    CDeterministicMNCPtr producer;
    if (!mn_consensus::GetBlockProducer(pindexPrev, mnList, producer)) {
        return false;
    }

    proTxHashRet = producer->proTxHash;
    return true;
}
