// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Copyright (c) 2021 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "blockassembler.h"

#include "btcheaders/btcheaders.h"       // BATHRON: Block 1 genesis BTC headers
#include "btcheaders/btcheadersdb.h"     // BATHRON: btcheadersdb tip for bootstrap gap check
#include "btcspv/btcspv.h"               // BATHRON: Read BTC headers from local SPV
#include "burnclaim/burnclaim.h"
#include "masternode/activemasternode.h"
#include "amount.h"
#include "blocksignature.h"
#include "chain.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/mn_validation.h"
#include "masternode/specialtx_validation.h"  // IsSpecialTxHeightPermanentlyInvalid (rollover guard)
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "masternode/blockproducer.h"
#include "policy/policy.h"
#include "bathron_chainwork.h"
#include "primitives/transaction.h"
#include "timedata.h"
#include "util/system.h"
#include "util/validation.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "key_io.h"
#include <univalue.h>
#include <fstream>

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <algorithm>
#include <boost/thread.hpp>

// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest priority or fee rate, so we might consider
// transactions that depend on transactions that aren't yet in the block.

bool g_fBootstrapGenerating = false;

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // BATHRON Time Protocol V2: Round timestamp to the nearest valid time slot (multiple of 15 seconds)
    // This ensures the block passes the IsValidBlockTimeStamp() check in consensus/params.h
    int nHeight = pindexPrev->nHeight + 1;
    if (consensusParams.IsTimeProtocolV2(nHeight)) {
        nNewTime = GetTimeSlot(nNewTime);
        // If rounding down puts us before median time past, round up to next slot
        if (nNewTime <= pindexPrev->GetMedianTimePast()) {
            nNewTime += consensusParams.nTimeSlotLength;
        }
    }

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Update nBits for header compatibility
    pblock->nBits = GetBlockDifficultyBits(pindexPrev, pblock);

    return nNewTime - nOldTime;
}

static CMutableTransaction NewCoinbase(const int nHeight, const CScript* pScriptPubKey = nullptr)
{
    CMutableTransaction txCoinbase;
    txCoinbase.vout.emplace_back();
    txCoinbase.vout[0].SetEmpty();
    if (pScriptPubKey) txCoinbase.vout[0].scriptPubKey = *pScriptPubKey;
    txCoinbase.vin.emplace_back();
    txCoinbase.vin[0].scriptSig = CScript() << nHeight << OP_0;
    return txCoinbase;
}

CMutableTransaction CreateCoinbaseTx(const CScript& scriptPubKeyIn, CBlockIndex* pindexPrev)
{
    assert(pindexPrev);
    const int nHeight = pindexPrev->nHeight + 1;

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON CONSENSUS: Coinbase outputs = 0, always, all heights
    // ═══════════════════════════════════════════════════════════════════════════
    // All M0 supply comes from TX_MINT_M0BTC (BTC burn claims), NOT coinbase.
    // Block 1: TX_BTC_HEADERS only (BTC headers from checkpoint)
    // Burns: Detected by burn_claim_daemon after network starts
    // Fees are recycled to block producer (not burned) to preserve M0 conservation.
    // ═══════════════════════════════════════════════════════════════════════════
    CMutableTransaction txCoinbase = NewCoinbase(nHeight, &scriptPubKeyIn);

    // Ensure coinbase output value is 0 (GetBlockValue returns 0)
    if (txCoinbase.vout.size() == 1) {
        txCoinbase.vout[0].nValue = 0;  // BATHRON: coinbase = 0 always
    }

    return txCoinbase;
}

bool CreateCoinbaseTx(CBlock* pblock, const CScript& scriptPubKeyIn, CBlockIndex* pindexPrev)
{
    pblock->vtx.emplace_back(MakeTransactionRef(CreateCoinbaseTx(scriptPubKeyIn, pindexPrev)));
    return true;
}

/**
 * Create genesis TX_BTC_HEADERS transactions for block 1.
 *
 * ═══════════════════════════════════════════════════════════════════════════
 * NEW GENESIS FLOW: Block 1 = BTC Headers On-Chain
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Block 1 carries ALL BTC headers from checkpoint to SPV tip.
 * This populates btcheadersdb on ALL nodes via consensus replay.
 * Burns (including pre-launch) are detected by burn_claim_daemon after network starts.
 *
 * Eliminates: btcspv snapshot distribution, special genesis files,
 *             BootstrapBtcHeadersDBFromSPV, reindex chicken-and-egg.
 */
std::vector<CTransactionRef> CreateGenesisHeaderTransactions(uint32_t fromHeight = 0)
{
    std::vector<CTransactionRef> headerTxs;

    if (!g_btc_spv) {
        LogPrintf("GENESIS ERROR: btcspv not initialized - cannot create headers\n");
        return headerTxs;
    }

    // Network-aware genesis checkpoint from btcspv (mainnet 800000 / signet 286000) — the
    // SAME source the SPV verifier uses — NOT the signet-hardcoded fallback const, so the
    // headers chain anchors correctly on mainnet.
    uint32_t genesisCheckpoint = BTCHEADERS_GENESIS_CHECKPOINT;
    {
        uint256 cpHash;
        g_btc_spv->GetGenesisCheckpoint(genesisCheckpoint, cpHash);
    }
    uint32_t startHeight = (fromHeight > 0) ? fromHeight : (genesisCheckpoint + 1);
    uint32_t spvTip = g_btc_spv->GetTipHeight();

    if (spvTip < startHeight) {
        LogPrintf("GENESIS ERROR: btcspv tip (%u) below genesis checkpoint+1 (%u)\n",
                  spvTip, startHeight);
        return headerTxs;
    }

    // Cap how many headers go into THIS block so it stays under MAX_BLOCK_SIZE.
    // The remainder is seeded by subsequent bootstrap (catch-up) blocks.
    //   - Genesis block 1 (fromHeight==0): multiple chunks are fine — they hit the
    //     empty-btcheadersdb branch (anchor F6 + continuations), no extend check.
    //   - Catch-up blocks (fromHeight>0): btcheadersdb is non-empty, so every chunk
    //     must extend tip+1. Since all chunks of a block are validated before any
    //     is processed, only ONE chunk can extend the pre-block tip — cap catch-up
    //     blocks to a single chunk.
    uint32_t perBlockCap = (fromHeight > 0) ? (uint32_t)BTCHEADERS_GENESIS_MAX_COUNT
                                            : MAX_GENESIS_HEADERS_PER_BLOCK;
    uint32_t endHeight = std::min(spvTip, startHeight + perBlockCap - 1);

    uint32_t totalHeaders = endHeight - startHeight + 1;
    LogPrintf("GENESIS: Creating TX_BTC_HEADERS for BTC heights %u-%u (%u headers, ~%u KB)%s\n",
              startHeight, endHeight, totalHeaders, (totalHeaders * 80) / 1024,
              endHeight < spvTip ? " [capped; catch-up will continue]" : "");

    // Split into chunks (max BTCHEADERS_GENESIS_MAX_COUNT per TX)
    uint32_t h = startHeight;
    while (h <= endHeight) {
        uint16_t count = std::min((uint32_t)BTCHEADERS_GENESIS_MAX_COUNT, endHeight - h + 1);

        BtcHeadersPayload payload;
        payload.nVersion = BTCHEADERS_VERSION;
        payload.publisherProTxHash = uint256();  // Null for genesis (no MNs yet)
        payload.startHeight = h;
        payload.count = count;

        // Read headers from local btcspv
        for (uint32_t i = 0; i < count; i++) {
            BtcHeaderIndex idx;
            if (!g_btc_spv->GetHeaderAtHeight(h + i, idx)) {
                LogPrintf("GENESIS ERROR: Cannot read btcspv header at height %u\n", h + i);
                return headerTxs;  // Abort
            }
            payload.headers.push_back(idx.header);
        }

        // No signature for genesis TX (no MNs registered yet)
        // payload.sig remains empty

        // Serialize payload into TX
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;

        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << payload;
        mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());

        headerTxs.push_back(MakeTransactionRef(std::move(mtx)));

        LogPrintf("GENESIS: Created TX_BTC_HEADERS chunk h=%u count=%u (~%u KB)\n",
                  h, count, (count * 80) / 1024);

        h += count;
    }

    LogPrintf("GENESIS: Created %zu TX_BTC_HEADERS (%u total headers)\n",
              headerTxs.size(), totalHeaders);

    return headerTxs;
}

// NOTE: CreateGenesisBurnClaimTransactions() REMOVED
// All burns (including pre-launch burns) are detected by burn_claim_daemon
// after network starts. Block 1 only contains TX_BTC_HEADERS.

BlockAssembler::BlockAssembler(const CChainParams& _chainparams, const bool _defaultPrintPriority)
        : chainparams(_chainparams), defaultPrintPriority(_defaultPrintPriority)
{
    // Largest block you're willing to create:
    nBlockMaxSize = gArgs.GetArg("-blockmaxsize", DEFAULT_BLOCK_MAX_SIZE);
    // Limit to between 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE_CURRENT - 1000), nBlockMaxSize));
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockSize = 1000;
    nBlockSigOps = 100;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn,
                                               CWallet* pwallet,
                                               bool fMNBlock,
                                               void* availableCoins,
                                               bool fNoMempoolTx,
                                               bool fTestValidity,
                                               CBlockIndex* prevBlock,
                                               bool stopOnNewBlock,
                                               bool fIncludeQfc)
{
    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate) return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    LogPrintf("CreateNewBlock: ENTER (fNoMempoolTx=%d)\n", fNoMempoolTx);
    CBlockIndex* pindexPrev = prevBlock ? prevBlock : WITH_LOCK(cs_main, return chainActive.Tip());
    assert(pindexPrev);
    LogPrintf("CreateNewBlock: pindexPrev height=%d\n", pindexPrev->nHeight);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(chainparams.GetConsensus(), nHeight);
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (Params().IsRegTestNet()) {
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);
    }

    // MN-only consensus - always create coinbase
    (void)fMNBlock;  // All blocks are MN blocks
    (void)pwallet;
    (void)availableCoins;
    (void)stopOnNewBlock;
    if (!CreateCoinbaseTx(pblock, scriptPubKeyIn, pindexPrev)) {
        return nullptr;
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON: Daemon-only burn detection flow
    // ═══════════════════════════════════════════════════════════════════════════
    // Block 1: TX_BTC_HEADERS only (BTC headers from checkpoint)
    // Block 2+: TX_MINT_M0BTC finalization (all burns detected by burn_claim_daemon)
    // All burns have K_FINALITY=20 (testnet) / 100 (mainnet)
    // ═══════════════════════════════════════════════════════════════════════════
    {
        const uint32_t height = pindexPrev->nHeight + 1;

        if (height == 1) {
            // Block 1: Insert genesis TX_BTC_HEADERS (all BTC headers from checkpoint)
            std::vector<CTransactionRef> headerTxs = CreateGenesisHeaderTransactions();
            for (auto& tx : headerTxs) {
                pblock->vtx.push_back(std::move(tx));
            }
            if (!headerTxs.empty()) {
                LogPrintf("GENESIS: Block 1 includes %zu TX_BTC_HEADERS\n", headerTxs.size());
            }
            // NOTE: No TX_BURN_CLAIM at Block 1
            // All burns (including pre-launch) are detected by burn_claim_daemon after network starts
        } else if (g_fBootstrapGenerating &&
                   height <= (uint32_t)chainparams.GetConsensus().nDMMBootstrapHeight &&
                   g_btc_spv && g_btcheadersdb) {
            // Bootstrap blocks (2..nDMMBootstrapHeight): publish remaining headers
            // if btcspv has more headers than btcheadersdb (backup may be incomplete)
            // ONLY during generatebootstrap RPC - NOT during live DMM block production
            uint32_t spvTip = g_btc_spv->GetTipHeight();
            uint32_t headersTip = g_btcheadersdb->GetTipHeight();
            if (spvTip > headersTip) {
                LogPrintf("BOOTSTRAP: btcspv(%u) > btcheadersdb(%u), publishing catch-up headers at h=%u\n",
                          spvTip, headersTip, height);
                std::vector<CTransactionRef> headerTxs = CreateGenesisHeaderTransactions(headersTip + 1);
                for (auto& tx : headerTxs) {
                    pblock->vtx.push_back(std::move(tx));
                }
                if (!headerTxs.empty()) {
                    LogPrintf("BOOTSTRAP: Block %u includes %zu catch-up TX_BTC_HEADERS\n",
                              height, headerTxs.size());
                }
            }

            // Also try minting (heights >= 2)
            CTransaction mintTx = CreateMintM0BTC(height);
            if (!mintTx.IsNull()) {
                pblock->vtx.push_back(MakeTransactionRef(std::move(mintTx)));
                LogPrint(BCLog::STATE, "BP11: Added TX_MINT_M0BTC at height %d\n", height);
            }
        } else {
            // Heights >= 2: Normal BP11 finalization of burn claims
            CTransaction mintTx = CreateMintM0BTC(height);
            if (!mintTx.IsNull()) {
                pblock->vtx.push_back(MakeTransactionRef(std::move(mintTx)));
                LogPrint(BCLog::STATE, "BP11: Added TX_MINT_M0BTC at height %d\n", height);
            }
        }
    }

    (void)fIncludeQfc; // Suppress unused parameter warning

    if (!fNoMempoolTx) {
        // Add transactions from mempool
        LogPrintf("CreateNewBlock: acquiring LOCK2(cs_main, mempool.cs) for addPackageTxs...\n");
        LOCK2(cs_main,mempool.cs);
        LogPrintf("CreateNewBlock: LOCK2 acquired, calling addPackageTxs (%d entries)...\n", mempool.size());
        addPackageTxs();
        LogPrintf("CreateNewBlock: addPackageTxs DONE\n");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON: Fees RECYCLED to block producer (not burned)
    // ═══════════════════════════════════════════════════════════════════════════
    // Invariant A5: M0_total = Σ(BTC burns) must hold at all times.
    // If fees were burned, M0_circulating < Σ(BTC burns) would violate A5.
    // Solution: Coinbase = nFees (no block reward, but fees recycled).
    // This preserves M0 conservation: no creation, no destruction.
    // ═══════════════════════════════════════════════════════════════════════════
    if (nFees > 0 && !pblock->vtx.empty() && pblock->vtx[0]->vout.size() > 0) {
        // Update coinbase output to include collected fees
        CMutableTransaction mtx(*pblock->vtx[0]);
        mtx.vout[0].nValue = nFees;
        pblock->vtx[0] = MakeTransactionRef(std::move(mtx));
        LogPrintf("BATHRON: Coinbase receives %ld sats in recycled fees\n", nFees);
    }
    pblocktemplate->vTxFees[0] = -nFees;  // Record fees (negative = from fees)

    LogPrintf("CreateNewBlock(): total size %u txs: %u fees: %ld sigops %d\n", nBlockSize, nBlockTx, nFees, nBlockSigOps);


    // Fill in header
    pblock->hashPrevBlock = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits = GetBlockDifficultyBits(pindexPrev, pblock);
    pblock->nNonce = 0;
    pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(*(pblock->vtx[0]));
    appendSaplingTreeRoot();

    {
        LOCK(cs_main);
        if (prevBlock == nullptr && chainActive.Tip() != pindexPrev) return nullptr; // new block came in, move on

        CValidationState state;
        if (fTestValidity &&
            !TestBlockValidity(state, *pblock, pindexPrev, false, false, false)) {
            throw std::runtime_error(
                    strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
        }
    }

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, unsigned int packageSigOps)
{
    if (nBlockSize + packageSize >= nBlockMaxSize)
        return false;
    if (nBlockSigOps + packageSigOps >= MAX_BLOCK_SIGOPS_CURRENT)
        return false;
    return true;
}

// Block size and sigops have already been tested.  Check that all transactions
// are final.
bool BlockAssembler::TestPackageFinality(const CTxMemPool::setEntries& package)
{
    for (const CTxMemPool::txiter& it : package) {
        if (!IsFinalTx(it->GetSharedTx(), nHeight))
            return false;
    }
    return true;
}

bool BlockAssembler::TestPackageSpecialHeight(const CTxMemPool::setEntries& package)
{
    AssertLockHeld(cs_main);
    for (const CTxMemPool::txiter& it : package) {
        const CTransaction& tx = it->GetTx();
        if (tx.IsNormalType()) continue;
        std::string reason;
        // Height = nHeight (the block being assembled) — the exact context
        // ConnectBlock uses (pindex->nHeight). A same-block-pending parent makes
        // the child fail with a non-tightening reason, so the guard returns
        // false there and the child is still included (ConnectBlock applies the
        // parent first) — no false skip of a valid same-block chain.
        if (IsSpecialTxHeightPermanentlyInvalid(tx, *pcoinsTip, (uint32_t)nHeight, reason)) {
            LogPrint(BCLog::STATE, "BlockAssembler: SKIP tx %s - %s at height %d\n",
                     tx.GetHash().ToString().substr(0, 16), reason, nHeight);
            return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOps.push_back(iter->GetSigOpCount());
    nBlockSize += iter->GetTxSize();
    ++nBlockTx;
    nBlockSigOps += iter->GetSigOpCount();
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", defaultPrintPriority);
    if (fPrintPriority) {
        LogPrintf("feerate %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

void BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
                                            indexed_modified_transaction_set& mapModifiedTx)
{
    for (const CTxMemPool::txiter& it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCountWithAncestors -= it->GetSigOpCount();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    if (mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it))
        return true;
    return false;
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs()
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    LogPrint(BCLog::STATE, "BlockAssembler::addPackageTxs - mempool size=%u\n", mempool.size());

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;
    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareModifiedEntry()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        unsigned int packageSigOps = iter->GetSigOpCountWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOps = modit->nSigOpCountWithAncestors;
        }

        const CTransaction& txCheck = iter->GetTx();
        LogPrint(BCLog::STATE, "BlockAssembler: Evaluating tx %s type=%d size=%lu fees=%lld\n",
                 txCheck.GetHash().ToString().substr(0, 16), (int)txCheck.nType, packageSize, packageFees);

        // Fee-less special TXs - always include them
        // - TX_BURN_CLAIM: BTC burn claims (BP10)
        // - TX_BTC_HEADERS: BTC header publication (BP-SPVMNPUB)
        // - Settlement TXs: TX_LOCK, TX_UNLOCK, TX_TRANSFER_M1 (fees paid separately)
        // - HTLC types: HTLC input == output (no room for fees in current design)
        // - HTLC3S types: 3-secret HTLCs for FlowSwap (same fee model as 1-secret)
        bool isFeelessSpecialTx = (txCheck.nType == CTransaction::TxType::TX_BURN_CLAIM ||
                                   txCheck.nType == CTransaction::TxType::TX_BTC_HEADERS ||
                                   txCheck.nType == CTransaction::TxType::TX_LOCK ||
                                   txCheck.nType == CTransaction::TxType::TX_UNLOCK ||
                                   txCheck.nType == CTransaction::TxType::TX_TRANSFER_M1 ||
                                   txCheck.nType == CTransaction::TxType::HTLC_CREATE_M1 ||
                                   txCheck.nType == CTransaction::TxType::HTLC_CLAIM ||
                                   txCheck.nType == CTransaction::TxType::HTLC_REFUND ||
                                   txCheck.nType == CTransaction::TxType::HTLC_CREATE_3S ||
                                   txCheck.nType == CTransaction::TxType::HTLC_CLAIM_3S ||
                                   txCheck.nType == CTransaction::TxType::HTLC_REFUND_3S);

        CAmount minFee = ::minRelayTxFee.GetFee(packageSize);
        if (packageFees < minFee && !isFeelessSpecialTx) {
            LogPrint(BCLog::STATE, "BlockAssembler: SKIP tx %s - low fees (%lld < %lld)\n",
                     txCheck.GetHash().ToString().substr(0, 16), packageFees, minFee);
            // Skip this TX, but continue processing others (feeless special TXs may follow)
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            ++mi;
            continue;
        }

        if (!TestPackage(packageSize, packageSigOps)) {
            LogPrint(BCLog::STATE, "BlockAssembler: SKIP tx %s - failed TestPackage\n",
                     txCheck.GetHash().ToString().substr(0, 16));
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Test if all tx's are Final
        if (!TestPackageFinality(ancestors)) {
            LogPrint(BCLog::STATE, "BlockAssembler: SKIP tx %s - failed TestPackageFinality\n",
                     txCheck.GetHash().ToString().substr(0, 16));
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // F-HTLC-2 rollover-liveness backstop: skip a package if a special tx in
        // it is permanently height-invalid at this block's height (what
        // ConnectBlock would reject). Skipping (not throwing) keeps production
        // going; failedTx marks it so descendants are skipped too.
        if (!TestPackageSpecialHeight(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        LogPrint(BCLog::STATE, "BlockAssembler: tx %s PASSED all checks, adding package\n",
                 txCheck.GetHash().ToString().substr(0, 16));

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i = 0; i < sortedEntries.size(); ++i) {
            CTxMemPool::txiter& iterSortedEntries = sortedEntries[i];
            bool isShielded = iterSortedEntries->IsShielded();

            // Apply Sapling size restrictions to shielded transactions
            if (isShielded) {
                // Don't add SHIELD transactions if there's no reserved space left in the block
                unsigned int txSize = iterSortedEntries->GetTxSize();
                if (nSizeShielded + txSize > MAX_BLOCK_SHIELDED_TXES_SIZE) {
                    break;
                }
                // Update cumulative size of SHIELD transactions in this block
                nSizeShielded += txSize;
            }

            AddToBlock(iterSortedEntries);
            // Erase from the modified set, if present
            mapModifiedTx.erase(iterSortedEntries);
        }

        // Update transactions that depend on each of these
        UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void BlockAssembler::appendSaplingTreeRoot()
{
    // Update header
    pblock->hashFinalSaplingRoot = CalculateSaplingTreeRoot(pblock, nHeight, chainparams);
}

uint256 CalculateSaplingTreeRoot(CBlock* pblock, int nHeight, const CChainParams& chainparams)
{
    if (NetworkUpgradeActive(nHeight, chainparams.GetConsensus(), Consensus::UPGRADE_V5_0)) {
        SaplingMerkleTree sapling_tree;
        uint256 saplingAnchor = pcoinsTip->GetBestAnchor();
        if (!pcoinsTip->GetSaplingAnchorAt(saplingAnchor, sapling_tree)) {
            // Anchor not found - use empty tree
            LogPrintf("%s: Sapling anchor %s not found, using empty tree\n", __func__, saplingAnchor.ToString());
            sapling_tree = SaplingMerkleTree();
        }

        // Update the Sapling commitment tree.
        for (const auto &tx : pblock->vtx) {
            if (tx->IsShieldedTx()) {
                for (const OutputDescription &odesc : tx->sapData->vShieldedOutput) {
                    sapling_tree.append(odesc.cmu);
                }
            }
        }
        return sapling_tree.root();
    }
    return UINT256_ZERO;
}

bool SolveBlock(std::shared_ptr<CBlock>& pblock, int nHeight)
{
    unsigned int extraNonce = 0;
    IncrementExtraNonce(pblock, nHeight, extraNonce);

    pblock->nNonce = GetRand(std::numeric_limits<uint32_t>::max());
    LogPrint(BCLog::MASTERNODE, "SolveBlock: MN-only mode, height=%d\n", nHeight);
    return true;
}

void IncrementExtraNonce(std::shared_ptr<CBlock>& pblock, int nHeight, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock) {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = CScript() << nHeight << CScriptNum(nExtraNonce);
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(txCoinbase);
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

int32_t ComputeBlockVersion(const Consensus::Params& consensus, int nHeight)
{
    if (NetworkUpgradeActive(nHeight, consensus, Consensus::UPGRADE_V5_0)) {
        return CBlockHeader::CURRENT_VERSION;       // v11 (since 5.2.99)
    } else if (consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_V4_0)) {
        return 7;
    } else if (consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_V3_4)) {
        return 6;
    } else if (consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BIP65)) {
        return 5;
    } else {
        return 3;
    }
}

// MN-only block production functions

bool SignBlockWithMN(CBlock& block)
{
    if (!activeMasternodeManager || !activeMasternodeManager->IsReady()) {
        LogPrintf("%s: Active masternode not ready\n", __func__);
        return false;
    }

    CKey ecdsaKey;
    CDeterministicMNCPtr dmn;
    auto result = activeMasternodeManager->GetOperatorKey(ecdsaKey, dmn);
    if (!result) {
        LogPrintf("%s: Failed to get operator key: %s\n", __func__, result.getError());
        return false;
    }

    // BATHRON: Sign the block with ECDSA
    return mn_consensus::SignBlockMNOnly(block, ecdsaKey);
}

