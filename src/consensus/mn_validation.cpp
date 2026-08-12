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

    if (!deterministicMNManager) {
        return state.DoS(100, false, REJECT_INVALID, "bad-mn-manager-null");
    }

    const int nHeight = pindexPrev->nHeight + 1;

    // BOOTSTRAP MODE (LOT 9 M3.1): strictly below the schedule activation height the
    // chain is launcher-operated — blocks 1..nDMMBootstrapHeight are produced by
    // generatebootstrap before any MN is online, and no producer check applies. From
    // the activation height on, the anchored epoch schedule governs every block and
    // signature verification is strictly enforced. The two windows are adjacent by
    // construction (activation == nDMMBootstrapHeight + 1), so no height can fall
    // outside both — the gap that made the M3 measurement necessary cannot exist.
    const Consensus::Params& consensus = Params().GetConsensus();
    if (nHeight < consensus.DMMScheduleActivationHeight()) {
        LogPrint(BCLog::MASTERNODE, "%s: Bootstrap block %d (activation=%d) - MN signature not required\n",
                 __func__, nHeight, consensus.DMMScheduleActivationHeight());
        return true;
    }

    // LOT 9 M1+M2 — the ONLY producer engine: the non-grindable epoch schedule,
    // resolved from the PARENT alone. The local scheduler, AcceptBlock and this
    // ConnectBlock-side check all obtain the same leader from the same parent.
    CDeterministicMNCPtr expectedMn;
    mn_consensus::DMMScheduleResult schedRes;
    const mn_consensus::ScheduleStatus status =
        mn_consensus::ResolveScheduledProducer(pindexPrev, block.nTime, expectedMn, schedRes);

    switch (status) {
        case mn_consensus::ScheduleStatus::OK:
            // A leader exists; a failure from here on IS a genuine block invalidity.
            return mn_consensus::VerifyScheduledProducerSignature(block, expectedMn, state);

        case mn_consensus::ScheduleStatus::NO_SIGNER:
            // The authoritative snapshot holds no eligible identity: a deterministic
            // consensus stall, identical on every node. A block CLAIMING a producer
            // (it carries a signature) contradicts the schedule — DETERMINISTIC
            // INVALIDITY (M3 PHASE 0). The earlier state.Error variant was REFUTED by
            // an executable reproducer (dmm_no_signer_e2e): the non-invalid failure
            // left the block a candidate, ActivateBestChainStep re-elected it forever
            // (earlier nSequenceId wins the work tie) and the node could never
            // activate an honest sibling — a self-inflicted wedge. NO_SIGNER is a
            // pure CHAIN fact (the empty snapshot is connected, authoritative data),
            // so BLOCK_FAILED_VALID is permitted in this SOLE objective case;
            // DEFERRED and LOCAL_STATE_MISSING_FATAL below remain strictly
            // non-invalidating. An unsigned block claims no producer, and with no
            // eligible identity there is nothing to check it against — the
            // pre-LOT-9 empty-set allowance, scoped to the authoritative case.
            if (!block.vchBlockSig.empty()) {
                LogPrintf("%s: height %d claims a producer (sig present) but the epoch "
                          "snapshot holds NO eligible identity — invalid (bad-dmm-no-eligible-producer)\n",
                          __func__, nHeight);
                return state.DoS(100, false, REJECT_INVALID, "bad-dmm-no-eligible-producer", false,
                                 "block claims a producer but the authoritative epoch snapshot has no eligible identity");
            }
            LogPrint(BCLog::MASTERNODE, "%s: No eligible identity in the epoch snapshot at height %d, unsigned block allowed\n",
                     __func__, nHeight);
            return true;

        case mn_consensus::ScheduleStatus::DEFERRED:
            // Our node has not connected the branch carrying the snapshot: the block
            // is not yet validable HERE. Non-persisted Error — no invalidity, no DoS,
            // no ban, no fallback onto another list. Re-evaluated if the branch joins
            // the active chain.
            return state.Error("dmm-schedule-deferred");

        case mn_consensus::ScheduleStatus::LOCAL_STATE_MISSING_FATAL:
            // OUR reconstructible state is corrupt. Shared LOT 1 latch + controlled
            // shutdown + REINDEX_REQUIRED; the block is never blamed.
            return mn_consensus::HandleFatalScheduleResolution(nHeight, pindexPrev->GetBlockHash(), &state);
    }

    // Unreachable: the switch above covers every ScheduleStatus.
    return state.Error("dmm-schedule-unknown-status");
}
