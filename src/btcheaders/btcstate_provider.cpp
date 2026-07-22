// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "btcheaders/btcstate_provider.h"

#include "arith_uint256.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "burnclaim/burnclaim.h"  // TX_CONFIRMED: strict BTC tx parse + txid

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>

// Snapshot of the btcheaders tip as of the previous BATHRON block.
// Written under cs_main (ConnectBlock start / mempool acceptance); read by
// parallel script-check threads — hence atomic. 0 = no snapshot (fail closed).
static std::atomic<uint32_t> g_btcStateSnapshotTip{0};

void BtcStateCaptureSnapshot()
{
    uint32_t tip = 0;
    if (g_btcheadersdb) tip = g_btcheadersdb->GetTipHeight();
    g_btcStateSnapshotTip.store(tip, std::memory_order_release);
}

bool CompactDifficultyGte(uint32_t nBitsA, uint32_t nBitsB)
{
    bool fNegA = false, fOverA = false, fNegB = false, fOverB = false;
    arith_uint256 targetA, targetB;
    targetA.SetCompact(nBitsA, &fNegA, &fOverA);
    targetB.SetCompact(nBitsB, &fNegB, &fOverB);
    if (fNegA || fOverA || targetA == 0) return false;
    if (fNegB || fOverB || targetB == 0) return false;
    // Higher difficulty == lower target
    return targetA <= targetB;
}

int64_t MedianTimePast(std::vector<int64_t> times)
{
    if (times.empty()) return 0;
    if (times.size() > 11)
        times.erase(times.begin(), times.end() - 11);
    std::sort(times.begin(), times.end());
    return times[times.size() / 2];
}

bool BtcTxConfirmedProofCheck(const BtcStateQuery& q, const uint256& merkleRoot)
{
    // Shape re-checks (the interpreter enforces these too — defense in depth,
    // this function is reachable from tests and future callers).
    if (q.rawBtcTx.empty()) return false;
    if (q.targetScript.empty()) return false;
    if (q.amountOperand < 1) return false;
    if (q.merkleProof.size() % 32 != 0) return false;
    const size_t depth = q.merkleProof.size() / 32;
    if (depth > BTCSTATE_MAX_MERKLE_DEPTH) return false;
    if ((uint64_t)q.txIndex >= (1ULL << depth)) return false;

    // Strict Bitcoin parse (rejects trailing bytes) + txid — burn-claim helpers.
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(q.rawBtcTx, btcTx)) return false;
    if (btcTx.vin.empty()) return false;

    // Anti fake-inclusion (CVE-2017-12842): a 64-byte Merkle leaf is
    // byte-indistinguishable from an internal node. The guard MUST test the
    // txid PREIMAGE — the NON-WITNESS serialization that ComputeBtcTxid hashes
    // and that actually enters the BTC Merkle tree — not the raw witness bytes:
    // for a SegWit tx the two lengths differ, so a 64-byte non-witness form can
    // hide behind a raw size != 64. (For non-SegWit txs the two are identical,
    // so this also covers the plain case.)
    if (btcTx.nonWitnessSerialization.size() == 64) return false;

    const uint256 txid = ComputeBtcTxid(btcTx);

    // Merkle branch: the ONLY thing binding the tx to the consensus header.
    std::vector<uint256> branch(depth);
    for (size_t i = 0; i < depth; ++i)
        memcpy(branch[i].begin(), q.merkleProof.data() + 32 * i, 32);
    if (!g_btc_spv) return false;  // fail closed, like burn claims
    if (!g_btc_spv->VerifyMerkleProof(txid, merkleRoot, branch, q.txIndex))
        return false;

    // Sum every output paying EXACTLY the target script. Values are bounded
    // by BTC consensus once inclusion is proven, but stay fail-closed anyway.
    int64_t total = 0;
    for (const BtcTxOut& out : btcTx.vout) {
        if (out.scriptPubKey != q.targetScript) continue;
        if (out.nValue < 0) return false;
        if (out.nValue > std::numeric_limits<int64_t>::max() - total) return false;
        total += out.nValue;
    }
    return total >= q.amountOperand;
}

bool BtcStateEvaluate(const BtcStateQuery& q)
{
    if (!g_btcheadersdb) return false;

    const uint32_t snapTip = g_btcStateSnapshotTip.load(std::memory_order_acquire);
    if (snapTip < BTCSTATE_REORG_MARGIN) return false;
    const uint32_t floorHeight = snapTip - BTCSTATE_REORG_MARGIN;

    switch (q.qtype) {
    case BTCSTATE_HEIGHT_GTE:
        // "The (immutably buried) BTC chain has reached height h."
        return q.btcHeight <= floorHeight;

    case BTCSTATE_DIFF_GTE:
    case BTCSTATE_DIFF_LT: {
        if (q.btcHeight > floorHeight) return false;  // not deep enough yet
        BtcBlockHeader hdr;
        if (!g_btcheadersdb->GetHeaderByHeight(q.btcHeight, hdr)) return false;
        const bool gte = CompactDifficultyGte(hdr.nBits, q.nBitsOperand);
        // For DIFF_LT also require the operand itself to be a valid compact
        // (CompactDifficultyGte fails closed on either side being invalid,
        // which would make LT trivially "true" — check explicitly).
        if (q.qtype == BTCSTATE_DIFF_LT) {
            bool fNeg = false, fOver = false;
            arith_uint256 t;
            t.SetCompact(q.nBitsOperand, &fNeg, &fOver);
            if (fNeg || fOver || t == 0) return false;
            bool fNegH = false, fOverH = false;
            arith_uint256 th;
            th.SetCompact(hdr.nBits, &fNegH, &fOverH);
            if (fNegH || fOverH || th == 0) return false;
            return !gte;
        }
        return gte;
    }

    case BTCSTATE_MTP_GTE: {
        if (q.btcHeight > floorHeight) return false;
        std::vector<int64_t> times;
        const uint32_t from =
            (q.btcHeight >= 10) ? q.btcHeight - 10 : 0;
        for (uint32_t h = from; h <= q.btcHeight; h++) {
            BtcBlockHeader hdr;
            if (!g_btcheadersdb->GetHeaderByHeight(h, hdr)) return false;
            times.push_back((int64_t)hdr.nTime);
        }
        return MedianTimePast(std::move(times)) >= q.timeOperand;
    }

    case BTCSTATE_TX_CONFIRMED: {
        // Reorg-floor discipline identical to the other queries: the subject
        // BTC block must be buried under the floor (monotone validity)...
        if (q.btcHeight > floorHeight) return false;
        // ...and carry the requested confirmations relative to the snapshot
        // tip (only binds when minDepth > the margin; burial already implies
        // margin+1 confirmations).
        if ((uint64_t)q.btcHeight + (uint64_t)q.minDepth > (uint64_t)snapTip + 1)
            return false;
        // Active-chain header at the claimed height (height index = best chain).
        BtcBlockHeader hdr;
        if (!g_btcheadersdb->GetHeaderByHeight(q.btcHeight, hdr)) return false;
        return BtcTxConfirmedProofCheck(q, hdr.hashMerkleRoot);
    }

    default:
        return false;  // unknown type: fail closed (interpreter rejects earlier)
    }
}

void InstallBtcStateProvider()
{
    SetBtcStateProvider(&BtcStateEvaluate);
}
