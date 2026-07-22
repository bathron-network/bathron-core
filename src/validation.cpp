// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013-2014 The NovaCoin Developers
// Copyright (c) 2014-2018 The BlackCoin Developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "validation.h"

#include "blocksignature.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "consensus/consensus.h"
#include "consensus/merkle.h"
#include "consensus/mn_validation.h"
#include "consensus/tx_verify.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "masternode/blockproducer.h"
#include "masternode/evodb.h"
#include "masternode/specialtx_validation.h"
#include "flatfile.h"
#include "guiinterface.h"
#include "state/finality.h"
#include "state/settlementdb.h"
#include "state/settlement_logic.h"  // BP30 v2.5: ParseTransferM1Outputs
#include "state/signaling.h"
#include "btcheaders/btcheaders.h"
#include "btcheaders/btcstate_provider.h"    // BP-SPVMNPUB: BTC header publication
#include "btcheaders/btcheadersdb.h"  // BP-SPVMNPUB: BTC header storage
#include "burnclaim/burnclaim.h"      // BP10/BP11: BTC burn claims
#include "burnclaim/killswitch.h"     // BP12: burns kill switch (mempool policy)
#include "policy/policy.h"
#include "bathron_chainwork.h"
#include "reverse_iterate.h"
#include "script/sigcache.h"
#include "node/shutdown.h"
#include "masternode/tiertwo_sync_state.h"
#include "txdb.h"
#include "undo.h"
#include "util/blockstatecatcher.h"
#include "util/system.h"
#include "util/validation.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "warnings.h"


#include <boost/algorithm/string/replace.hpp>
#include <boost/thread.hpp>
#include <atomic>
#include <deque>


#if defined(NDEBUG)
#error "BATHRON cannot be compiled without assertions."
#endif

bool IsCoinbaseValueValid(const CTransactionRef& tx, CAmount nFees, CValidationState& _state)
{
    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON CONSENSUS RULE C1: Coinbase = recycled fees (no block reward)
    // ═══════════════════════════════════════════════════════════════════════════
    // All M0 supply comes from TX_MINT_M0BTC (BTC burn claims), not coinbase.
    // Block reward = 0 always (no inflation from block production).
    // Transaction fees are recycled to block producer to preserve A5 invariant:
    //   M0_total = Σ(BTC burns) - no M0 can be created or destroyed elsewhere.
    // Coinbase output must equal exactly the fees collected in this block.
    // ═══════════════════════════════════════════════════════════════════════════
    CAmount nCoinbaseValue = 0;
    for (const auto& out : tx->vout) {
        nCoinbaseValue += out.nValue;
    }

    if (nCoinbaseValue != nFees) {
        return _state.DoS(100, false, REJECT_INVALID, "bad-cb-amount",
            false, strprintf("Coinbase must equal fees: got %s, expected %s",
                FormatMoney(nCoinbaseValue), FormatMoney(nFees)));
    }

    return true;
}

/**
 * Global state
 */


/**
 * Mutex to guard access to validation specific variables, such as reading
 * or changing the chainstate.
 *
 * This may also need to be locked when updating the transaction pool, e.g. on
 * AcceptToMemoryPool. See CTxMemPool::cs comment for details.
 *
 * The transaction pool has a separate lock to allow reading from it and the
 * chainstate at the same time.
 */
RecursiveMutex cs_main;

BlockMap mapBlockIndex;
CChain chainActive;
CBlockIndex* pindexBestHeader = nullptr;

int nScriptCheckThreads = 0;
std::atomic<bool> fImporting{false};
std::atomic<bool> fReindex{false};
bool fTxIndex = true;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
size_t nCoinCacheUsage = 5000 * 300;

/* If the tip is older than this (in seconds), the node is considered to be in initial block download. */
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;

/** Fees smaller than this (in sats) are considered zero fee for relaying and mining.
 * ═══════════════════════════════════════════════════════════════════════════════════
 * BATHRON FEE POLICY: 1 M0 = 1 sat, target fee ~10-50 M0 per standard TX
 * ═══════════════════════════════════════════════════════════════════════════════════
 * 100 sat/KB = ~23 sats for a 226-byte standard transaction
 * This is appropriate for a system where 1 M0 = 1 sat.
 *
 * Old value (10,000 sat/KB) was inherited from PIVX and caused ~2,300 sat fees,
 * which is excessive when total supply is only ~14M M0.
 * ═══════════════════════════════════════════════════════════════════════════════════
 */
// Genesis Fee Policy v1.0: 0.05 sat/vB floor
// Anti-spam via mempool economics, not static barrier.
// Fees recycled to MN block producer (A5 invariant preserved).
CFeeRate minRelayTxFee = CFeeRate(50);

CTxMemPool mempool(::minRelayTxFee);

CMoneySupply MoneySupply;

// BP-SPVMNPUB: Temporary blacklist for TX_BTC_HEADERS publishers
// Publishers that send invalid TX (bad startHeight, etc.) are blacklisted for 60 seconds
// This prevents CPU waste on repeated validation of invalid TX from misconfigured MNs
static std::map<uint256, int64_t> g_btcheadersBlacklist;
static RecursiveMutex g_btcheadersBlacklistMutex;
static const int64_t BTCHEADERS_BLACKLIST_DURATION = 60;  // seconds

static void CheckBlockIndex();

/** Constant stuff for coinbase transactions we create: */

// Internal stuff
namespace
{
struct CBlockIndexWorkComparator {
    bool operator()(const CBlockIndex* pa, const CBlockIndex* pb) const
    {
        // First sort by most total work, ...
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

CBlockIndex* pindexBestInvalid;

/**
 * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
 * as good as our current tip or better. Entries may be failed, though.
 */
std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

/**
 * the ChainState Mutex
 * A lock that must be held when modifying this ChainState - held in ActivateBestChain()
 */
Mutex m_cs_chainstate;

/** All pairs A->B, where A (or one if its ancestors) misses transactions, but B has transactions. */
std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;

RecursiveMutex cs_LastBlockFile;
std::vector<CBlockFileInfo> vinfoBlockFile;
int nLastBlockFile = 0;

/**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
RecursiveMutex cs_nBlockSequenceId;
/** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
uint32_t nBlockSequenceId = 1;

/** Dirty block index entries. */
std::set<CBlockIndex*> setDirtyBlockIndex;

/** Dirty block file entries. */
std::set<int> setDirtyFileInfo;
} // anon namespace

/**
 * Counter for nested ActivateBestChain calls.
 * Used by DMM scheduler to avoid producing blocks during chain sync.
 * Uses counter instead of boolean to handle recursive/nested calls correctly.
 */
std::atomic<int> g_activating_best_chain{0};

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    AssertLockHeld(cs_main);
    // Find the first block the caller has in the main chain
    for (const uint256& hash : locator.vHave) {
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex && chain.Contains(pindex)) {
            return pindex;
        }
    }
    return chain.Genesis();
}

CBlockIndex* GetChainTip()
{
    LOCK(cs_main);
    CBlockIndex* p = chainActive.Tip();
    if (!p)
        return nullptr;
    // Do not pass in the chain active tip, because it can change.
    // Instead pass the blockindex directly from mapblockindex, which is const
    return mapBlockIndex.at(p->GetBlockHash());
}

std::unique_ptr<CCoinsViewDB> pcoinsdbview;
std::unique_ptr<CCoinsViewCache> pcoinsTip;
std::unique_ptr<CBlockTreeDB> pblocktree;
// BATHRON: pSporkDB removed - spork system eliminated

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

// See definition for documentation
bool static FlushStateToDisk(CValidationState &state, FlushStateMode mode);
static FlatFileSeq BlockFileSeq();
static FlatFileSeq UndoFileSeq();

bool CheckFinalTx(const CTransactionRef& tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 will require that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST) ? chainActive.Tip()->GetMedianTimePast() : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

// ═══════════════════════════════════════════════════════════════════════════
// BIP68 — relative lock-times (gate UPGRADE_CSV)
// Straight port of the Bitcoin semantics: per-input relative locks encoded in
// nSequence (bit 31 = disabled, bit 22 = time-based in 512 s units, low 16
// bits = value), binding only for tx.nVersion >= 2. Height locks compare
// against the evaluated block's height; time locks against the MTP of the
// block PRECEDING the evaluated block (BIP113-consistent).
// ═══════════════════════════════════════════════════════════════════════════

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    assert(prevHeights->size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    // BIP68 eligibility. NOTE on BATHRON's version space (pre-freeze review):
    // Bitcoin gates BIP68 on nVersion >= 2 (its "version 2" signal). BATHRON
    // has no version 2 — the enum is LEGACY = 1 and SAPLING = 3 — so EVERY v3
    // tx (all special + shielded txs) is BIP68-*eligible*. That is safe and
    // intended: eligibility only makes the relative lock BIND when an input's
    // nSequence has the disable bit (bit 31) CLEAR, i.e. the sender explicitly
    // opts in with a relative-lock sequence. All BATHRON tx builders set
    // SEQUENCE_FINAL / 0xFFFFFFFE (bit 31 SET) -> no unintended timelock; only
    // a deliberately-crafted low nSequence (e.g. via createrawtransaction, or a
    // future CSV covenant) engages the lock — exactly the BIP68 contract. The
    // disable bit, not the tx version, is the real opt-out here.
    bool fEnforceBIP68 = tx.nVersion >= 2 && (flags & LOCKTIME_VERIFY_SEQUENCE);
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            (*prevHeights)[txinIndex] = 0;
            continue;
        }

        const int nCoinHeight = (*prevHeights)[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime = block.GetAncestor(std::max(nCoinHeight - 1, 0))->GetMedianTimePast();
            // NOTE: Subtract 1 to maintain nLockTime semantics.
            // BIP68 relative lock times have the semantics of calculating the
            // first block or time at which the transaction would be valid. When
            // calculating the effective block time or height for the entire
            // transaction, we switch to using the semantics of nLockTime which
            // is the last invalid block or time as per the protocol.
            nMinTime = std::max(nMinTime,
                                nCoinTime +
                                    (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK)
                                              << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) -
                                    1);
        } else {
            nMinHeight = std::max(nMinHeight,
                                  nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    const int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;
    return true;
}

bool SequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

bool CheckSequenceLocks(CTxMemPool& pool, const CTransaction& tx, int flags)
{
    AssertLockHeld(cs_main);

    CBlockIndex* tip = chainActive.Tip();
    if (tip == nullptr) return false;

    // Not yet active at the next block: no sequence-lock constraint.
    if (!Params().GetConsensus().NetworkUpgradeActive(tip->nHeight + 1, Consensus::UPGRADE_CSV))
        return true;

    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate height-
    // based locks because when SequenceLocks() is called within ConnectBlock(),
    // the height of the block *being* evaluated is what is used. Thus if we
    // want to know if a transaction can be part of the *next* block, we need
    // to use one more than chainActive.Height().
    CBlockIndex index;
    index.pprev = tip;
    index.nHeight = tip->nHeight + 1;

    std::vector<int> prevheights;
    prevheights.resize(tx.vin.size());
    CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];
        Coin coin;
        if (!viewMemPool.GetCoin(txin.prevout, coin)) {
            return error("%s: Missing input", __func__);
        }
        if (coin.nHeight == MEMPOOL_HEIGHT) {
            // Assume all mempool transactions confirm in the next block
            prevheights[txinIndex] = tip->nHeight + 1;
        } else {
            prevheights[txinIndex] = coin.nHeight;
        }
    }
    return SequenceLocks(tx, flags, &prevheights, index);
}

void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0)
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed: vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

CAmount GetMinRelayFee(const CTransaction& tx, const CTxMemPool& pool, unsigned int nBytes)
{
    if (tx.IsShieldedTx()) {
        return GetShieldedTxMinFee(tx);
    }
    uint256 hash = tx.GetHash();
    CAmount nFeeDelta = 0;
    pool.ApplyDelta(hash, nFeeDelta);
    if (nFeeDelta > 0)
        return 0;

    return GetMinRelayFee(nBytes);
}

CAmount GetMinRelayFee(unsigned int nBytes)
{
    CAmount nMinFee = ::minRelayTxFee.GetFee(nBytes);
    if (!Params().GetConsensus().MoneyRange(nMinFee)) {
        nMinFee = Params().GetConsensus().nMaxMoneyOut;
    }
    return nMinFee;
}

CAmount GetShieldedTxMinFee(const CTransaction& tx)
{
    assert (tx.IsShieldedTx());
    unsigned int K = DEFAULT_SHIELDEDTXFEE_K;   // Fixed (100) for now
    CAmount nMinFee = ::minRelayTxFee.GetFee(tx.GetTotalSize()) * K;
    if (!Params().GetConsensus().MoneyRange(nMinFee))
        nMinFee = Params().GetConsensus().nMaxMoneyOut;
    return nMinFee;
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

static void UpdateMempoolForReorg(DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // if we are resurrecting a ProReg tx, we need to evict any special transaction that
        // depends on it (which would not be accepted in the mempool, with the current chain)
        if ((*it)->IsProRegTx()) {
            mempool.removeProTxReferences((*it)->GetHash(), MemPoolRemovalReason::REORG);
        }
        // SF2 (B4.8): same problem for settlement/HTLC txs — their vault/receipt/HTLC
        // outputs were just undone from the committed settlement DB, so any mempool
        // tx spending them would be block-invalid (Check* read the committed DB) and
        // could wedge the producer. Evict those spenders, symmetric to ProReg.
        if ((*it)->CreatesSettlementOutputs()) {
            mempool.removeSettlementReferences(**it, MemPoolRemovalReason::REORG);
        }
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() ||
                !AcceptToMemoryPool(mempool, stateDummy, *it, false, nullptr, true)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.emplace_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(pcoinsTip.get(), chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // F-HTLC-2 rollover-liveness: a reorg can also move a height-tightening
    // special tx permanently past its bound for the new next block — evict those
    // (same guard as on connect, symmetric across connect/disconnect).
    mempool.removeForSpecialTxHeightChange(*pcoinsTip, chainActive.Tip()->nHeight + 1);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
                              gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}

static bool IsCurrentForFeeEstimation()
{
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

static bool AcceptToMemoryPoolWorker(CTxMemPool& pool, CValidationState &state, const CTransactionRef& _tx, bool fLimitFree,
                              bool* pfMissingInputs, int64_t nAcceptTime, bool fOverrideMempoolLimit, bool fRejectAbsurdFee, bool ignoreFees,
                              std::vector<COutPoint>& coins_to_uncache) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    const CTransaction& tx = *_tx;

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    if (pfMissingInputs)
        *pfMissingInputs = false;

    // BATHRON: Sapling is always active - no maintenance mode
    // (SPORK_20 removed in 03-SPORKS-MODERNIZATION)

    const CChainParams& params = Params();
    const Consensus::Params& consensus = params.GetConsensus();
    int chainHeight = chainActive.Height();

    // Check transaction
    if (!CheckTransaction(tx, state))
        return error("%s : transaction checks for %s failed with %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));

    int nextBlockHeight = chainHeight + 1;
    // Check transaction contextually against consensus rules at block height
    if (!ContextualCheckTransaction(_tx, state, params, nextBlockHeight, false /* isMined */, IsInitialBlockDownload())) {
        return error("AcceptToMemoryPool: ContextualCheckTransaction failed");
    }

    if (pool.existsProviderTxConflict(tx)) {
        return state.DoS(0, false, REJECT_DUPLICATE, "protx-dup");
    }

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(_tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // Rather not work on nonstandard transactions
    std::string reason;
    if (fRequireStandard && !IsStandardTx(_tx, nextBlockHeight, reason))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason);
    // is it already in the memory pool?
    const uint256& hash = tx.GetHash();
    if (pool.exists(hash)) {
        return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-in-mempool");
    }

    // Check for conflicts with in-memory transactions

    {
        LOCK(pool.cs); // protect pool.mapNextTx
        for (const auto& in : tx.vin) {
            COutPoint outpoint = in.prevout;
            if (pool.mapNextTx.count(outpoint)) {
                // Disable replacement feature for now
                return state.Invalid(false, REJECT_CONFLICT, "txn-mempool-conflict");
            }
        }
    }

    // Check sapling nullifiers
    if (tx.IsShieldedTx()) {
        for (const auto& sd : tx.sapData->vShieldedSpend) {
            if (pool.nullifierExists(sd.nullifier))
                return state.Invalid(false, REJECT_INVALID, "bad-txns-nullifier-double-spent");
        }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        CAmount nValueIn = 0;

        LOCK(pool.cs);
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
        view.SetBackend(viewMemPool);

        // do we already have it?
        for (size_t out = 0; out < tx.vout.size(); out++) {
            COutPoint outpoint(hash, out);
            bool had_coin_in_cache = pcoinsTip->HaveCoinInCache(outpoint);
            if (view.HaveCoin(outpoint)) {
                if (!had_coin_in_cache) {
                    coins_to_uncache.push_back(outpoint);
                }
                return state.Invalid(false, REJECT_ALREADY_KNOWN, "txn-already-known");
            }
        }

        // do all inputs exist?
        for (const CTxIn& txin : tx.vin) {
            if (!pcoinsTip->HaveCoinInCache(txin.prevout)) {
                coins_to_uncache.push_back(txin.prevout);
            }
            if (!view.HaveCoin(txin.prevout)) {
                if (pfMissingInputs) {
                    *pfMissingInputs = true;
                }
                return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            }
        }

        // Sapling: are the sapling spends' requirements met in tx(valid anchors/nullifiers)?
        if (!view.HaveShieldedRequirements(tx))
            return state.Invalid(error("AcceptToMemoryPool: shielded requirements not met"),
                                 REJECT_DUPLICATE, "bad-txns-shielded-requirements-not-met");

        // ═══════════════════════════════════════════════════════════════════════════
        // BP11: TX_MINT_M0BTC cannot be submitted to mempool
        // It is only created by block producers during block assembly and included
        // directly in the block's vtx. Mempool submission would be a protocol violation.
        // ═══════════════════════════════════════════════════════════════════════════
        if (tx.nType == CTransaction::TxType::TX_MINT_M0BTC) {
            return state.DoS(100, false, REJECT_INVALID, "bad-mint-mempool",
                             false, "TX_MINT_M0BTC cannot be submitted to mempool");
        }

        // BP12 Kill Switch (mempool POLICY, not consensus): when burns are disabled
        // on this node, refuse to accept/relay/mine NEW burn claims. This is a
        // node-local emergency brake; it deliberately does NOT reject blocks that
        // already contain TX_BURN_CLAIM (that check was removed from CheckBurnClaim),
        // so differing kill-switch states across operators can never fork the chain.
        if (tx.nType == CTransaction::TxType::TX_BURN_CLAIM && !AreBtcBurnsEnabled()) {
            return state.Invalid(false, REJECT_INVALID, "btc-burns-disabled-emergency",
                                 "BTC burns temporarily disabled on this node");
        }

        if (!CheckSpecialTx(tx, chainActive.Tip(), &view, state)) {
            // BP-SPVMNPUB: If TX_BTC_HEADERS failed for R3-related reasons, blacklist publisher
            if (tx.nType == CTransaction::TxType::TX_BTC_HEADERS) {
                std::string rejectReason = state.GetRejectReason();
                if (rejectReason == "bad-btcheaders-startheight" ||
                    rejectReason == "bad-btcheaders-not-extending-tip" ||
                    rejectReason == "btcheaders-publisher-cooldown") {
                    // Extract publisher and blacklist
                    BtcHeadersPayload payload;
                    if (GetBtcHeadersPayload(tx, payload)) {
                        LOCK(g_btcheadersBlacklistMutex);
                        g_btcheadersBlacklist[payload.publisherProTxHash] = GetTime() + BTCHEADERS_BLACKLIST_DURATION;
                        LogPrint(BCLog::MEMPOOL, "TX_BTC_HEADERS: blacklisting publisher %s for %d seconds (reason: %s)\n",
                                 payload.publisherProTxHash.ToString().substr(0, 16),
                                 BTCHEADERS_BLACKLIST_DURATION, rejectReason);
                    }
                }
            }
            // pass the state returned by the function above
            return false;
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // BP10/BP11: TX_BURN_CLAIM has NO inputs and NO outputs
        // It's a proof-only transaction - validation is done in CheckSpecialTx
        // Skip all input/fee validation and add directly to mempool
        // P1: Check mempool for duplicate btc_txid (anti-spam for concurrent claims)
        // ═══════════════════════════════════════════════════════════════════════════
        if (tx.nType == CTransaction::TxType::TX_BURN_CLAIM) {
            // TX_BURN_CLAIM must have empty vin (no inputs to spend)
            if (!tx.vin.empty()) {
                return state.DoS(100, false, REJECT_INVALID, "bad-burnclaim-has-inputs");
            }
            // TX_BURN_CLAIM must have empty vout (no outputs to create)
            if (!tx.vout.empty()) {
                return state.DoS(100, false, REJECT_INVALID, "bad-burnclaim-has-outputs");
            }

            // P1: Check mempool for duplicate btc_txid
            // This prevents concurrent claims from flooding the mempool
            BurnClaimPayload payload;
            if (GetTxPayload(tx, payload)) {
                uint256 btcTxid = payload.GetBtcTxid();
                LOCK(pool.cs);
                for (const auto& entry : pool.mapTx) {
                    if (entry.GetTx().nType == CTransaction::TxType::TX_BURN_CLAIM) {
                        BurnClaimPayload existingPayload;
                        if (GetTxPayload(entry.GetTx(), existingPayload)) {
                            if (existingPayload.GetBtcTxid() == btcTxid) {
                                LogPrint(BCLog::MEMPOOL, "TX_BURN_CLAIM duplicate btc_txid %s already in mempool\n",
                                         btcTxid.ToString().substr(0, 16));
                                return state.DoS(0, false, REJECT_DUPLICATE, "burnclaim-mempool-duplicate",
                                                 false, "TX_BURN_CLAIM for same btc_txid already in mempool");
                            }
                        }
                    }
                }
            }

            // Create mempool entry with zero fees
            CTxMemPoolEntry entry(_tx, 0 /* fees */, nAcceptTime, chainHeight,
                                  false /* spendsCoinbase */, 0 /* sigOps */);

            // Add to mempool
            pool.addUnchecked(hash, entry, true);

            LogPrint(BCLog::MEMPOOL, "TX_BURN_CLAIM %s added to mempool\n", hash.ToString());
            return true;
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // BP-SPVMNPUB: TX_BTC_HEADERS mempool policy (P1 + P2 + P3)
        // P1: Keep-at-most-one - only one TX_BTC_HEADERS allowed in mempool
        //     Replacement: more headers wins, else smaller txid wins (validation-first)
        // P2: Standard specialtx template (has vin/vout for fee structure)
        // P3: Temporary blacklist for publishers sending invalid TX (anti-spam)
        // ═══════════════════════════════════════════════════════════════════════════
        if (tx.nType == CTransaction::TxType::TX_BTC_HEADERS) {
            // Extract payload for comparison
            BtcHeadersPayload payload;
            if (!GetBtcHeadersPayload(tx, payload)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-btcheaders-payload");
            }

            // P3: Check temporary blacklist (anti-spam for misconfigured MNs)
            {
                LOCK(g_btcheadersBlacklistMutex);
                int64_t now = GetTime();

                // Clean expired entries (lazy cleanup)
                for (auto it = g_btcheadersBlacklist.begin(); it != g_btcheadersBlacklist.end(); ) {
                    if (it->second < now) {
                        it = g_btcheadersBlacklist.erase(it);
                    } else {
                        ++it;
                    }
                }

                // Check if publisher is blacklisted
                auto it = g_btcheadersBlacklist.find(payload.publisherProTxHash);
                if (it != g_btcheadersBlacklist.end() && it->second > now) {
                    LogPrint(BCLog::MEMPOOL, "TX_BTC_HEADERS: publisher %s blacklisted for %lld more seconds\n",
                             payload.publisherProTxHash.ToString().substr(0, 16), it->second - now);
                    return state.DoS(0, false, REJECT_INVALID, "btcheaders-publisher-blacklisted",
                                     false, "Publisher temporarily blacklisted");
                }
            }

            // P1: Keep-at-most-one - scan mempool for existing TX_BTC_HEADERS.
            // Every candidate here already passed CheckSpecialTx/CheckBtcHeadersTx
            // (above), so it is a valid tip-extension or a heavier work-based reorg.
            // It may replace the incumbent only if it reaches a STRICTLY higher
            // resulting tip — see BtcHeadersCandidateReplaces. This prefers the
            // furthest-reaching publication regardless of start height (handles
            // reorg publications) and drops the old equal-count/smaller-txid
            // tie-break that enabled txid-grind eviction churn.
            {
                LOCK(pool.cs);
                for (const auto& entry : pool.mapTx) {
                    if (entry.GetTx().nType == CTransaction::TxType::TX_BTC_HEADERS) {
                        BtcHeadersPayload existingPayload;
                        if (GetBtcHeadersPayload(entry.GetTx(), existingPayload)) {
                            if (!BtcHeadersCandidateReplaces(payload.startHeight, payload.count,
                                                             existingPayload.startHeight, existingPayload.count)) {
                                return state.DoS(0, false, REJECT_INVALID, "btcheaders-not-higher-tip",
                                                 false, "TX_BTC_HEADERS does not reach a higher tip than the mempool candidate");
                            }
                            // Strictly higher resulting tip - remove incumbent before adding new.
                            LogPrint(BCLog::MEMPOOL, "TX_BTC_HEADERS: replacing %s (start=%u,count=%d) with %s (start=%u,count=%d)\n",
                                     entry.GetTx().GetHash().ToString().substr(0, 16), existingPayload.startHeight, existingPayload.count,
                                     tx.GetHash().ToString().substr(0, 16), payload.startHeight, payload.count);
                            pool.removeRecursive(entry.GetTx(), MemPoolRemovalReason::REPLACED);
                            break;  // Only one TX_BTC_HEADERS should exist
                        }
                    }
                }
            }

            // Create mempool entry with zero fees (fee-exempt)
            CTxMemPoolEntry entry(_tx, 0 /* fees */, nAcceptTime, chainHeight,
                                  false /* spendsCoinbase */, 0 /* sigOps */);

            // Add to mempool
            pool.addUnchecked(hash, entry, true);

            LogPrint(BCLog::MEMPOOL, "TX_BTC_HEADERS %s added to mempool (start=%u, count=%d)\n",
                     hash.ToString().substr(0, 16), payload.startHeight, payload.count);
            return true;
        }

        // ═══════════════════════════════════════════════════════════════════════════
        // SECURITY FIX: Prevent TX_LOCK from spending M1 receipts in mempool
        //
        // Attack vector: TX_A (LOCK) creates Receipt_A in mempool, TX_B (LOCK) spends
        // Receipt_A. Since Receipt_A is not yet in settlement DB, IsM0Standard() returns
        // true incorrectly. When both are mined, M0_vaulted increases without real M0.
        //
        // Fix: Check if any TX_LOCK input comes from a mempool TX_LOCK's receipt output.
        // ═══════════════════════════════════════════════════════════════════════════
        if (tx.nType == CTransaction::TxType::TX_LOCK) {
            LOCK(pool.cs);
            for (const CTxIn& txin : tx.vin) {
                // Check if this input's prevout is from a mempool transaction
                auto it = pool.mapTx.find(txin.prevout.hash);
                if (it != pool.mapTx.end()) {
                    const CTransaction& parentTx = it->GetTx();
                    // If parent is TX_LOCK and we're spending index 1 (the receipt), reject
                    if (parentTx.nType == CTransaction::TxType::TX_LOCK && txin.prevout.n == 1) {
                        return state.DoS(10, error("AcceptToMemoryPool: TX_LOCK cannot spend M1 receipt from mempool TX_LOCK"),
                                        REJECT_INVALID, "bad-lock-spends-mempool-receipt");
                    }
                }
            }
        }

        // Bring the best block into scope
        view.GetBestBlock();

        nValueIn = view.GetValueIn(tx);

        // ═══════════════════════════════════════════════════════════════════════════
        // BP30 Settlement: Track M1 inputs for settlement accounting (NOT fee calc)
        // ═══════════════════════════════════════════════════════════════════════════
        // nM1InputTotal tracks M1 receipt values for settlement validation.
        // This does NOT affect fee calculation - fees use raw sat values.
        // nValueIn is NOT modified - it stays as sum(all input sats) for fee calc.
        // ═══════════════════════════════════════════════════════════════════════════
        CAmount nM1InputTotal = 0;  // Track total M1 inputs for settlement logic
        if (tx.nType == CTransaction::TxType::TX_UNLOCK) {
            // TX_UNLOCK: Track M1 receipt inputs for settlement validation
            for (const CTxIn& txin : tx.vin) {
                bool isM1 = g_settlementdb && g_settlementdb->IsM1Receipt(txin.prevout);
                if (isM1) {
                    const Coin& inputCoin = view.AccessCoin(txin.prevout);
                    if (!inputCoin.IsSpent()) {
                        nM1InputTotal += inputCoin.out.nValue;
                    }
                }
            }
        }
        // NOTE: nValueIn is NOT modified - it remains sum(all input sats) for fee calc

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        unsigned int nSigOps = GetLegacySigOpCount(tx);
        unsigned int nMaxSigOps = MAX_TX_SIGOPS_CURRENT;
        nSigOps += GetP2SHSigOpCount(tx, view);
        if(nSigOps > nMaxSigOps)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d > %d", nSigOps, nMaxSigOps));

        CAmount nValueOut = tx.GetValueOut();

        // ═══════════════════════════════════════════════════════════════════════════
        // FEE CALCULATION for MEMPOOL ACCEPTANCE
        // ═══════════════════════════════════════════════════════════════════════════
        //
        // For MOST transactions: fee = sum(input sats) - sum(output sats)
        //
        // SPECIAL CASE - TX_LOCK:
        //   TX_LOCK creates M1 (receipt) which has a sat value in the UTXO, but this
        //   value is conceptually "new" M1, not drawn from M0 inputs. The receipt
        //   is created by the settlement layer, backed by the vault.
        //
        //   Structure: Input(M0) → Vault(M0) + Receipt(M1) + Change(M0)
        //   - Vault = lockAmount (M0 locked)
        //   - Receipt = lockAmount (M1 created, same sat value as vault)
        //   - Change = inputs - vault - fee (leftover M0)
        //
        //   From UTXO perspective: outputs = vault + receipt + change > inputs
        //   This is intentional - M1 is being created.
        //
        //   For fee calculation: fee = inputs - vault - change (EXCLUDE receipt)
        //   The receipt is NOT counted because it's M1 being created, not M0 being spent.
        //
        //   IMPORTANT: This fee goes to coinbase (recycled), preserving A5 invariant.
        //   The M1 receipt creation is balanced by M0 being locked in vault.
        //
        // For TX_UNLOCK (BP30 v3.1): fee = M1_in - M0_out - M1_change, recomputed from
        //   the settlement-DB receipt inputs — real vault M0 released to the coinbase
        //   (see GetSettlementTxFee / CheckUnlock).
        // For TX_TRANSFER_M1: fee = inputs - outputs (standard)
        // ═══════════════════════════════════════════════════════════════════════════

        // Settlement-aware M0/coinbase fee. Shared with ConnectBlock via
        // GetSettlementTxFee so the two can never diverge (see settlement_logic.h).
        CAmount nFees = GetSettlementTxFee(tx, nValueIn, nValueOut);
        // Debug logging for settlement transactions
        if (tx.nType == CTransaction::TxType::TX_LOCK) {
            LogPrintf("MEMPOOL-FEE: TX_LOCK nValueIn=%lld nValueOut=%lld nFees=%lld\n",
                     nValueIn, nValueOut, nFees);
        }
        bool fSpendsCoinbase = false;

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        for (const CTxIn &txin : tx.vin) {
            const Coin &coin = view.AccessCoin(txin.prevout);
            if (coin.IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }

        CTxMemPoolEntry entry(_tx, nFees, nAcceptTime, chainHeight,
                              fSpendsCoinbase, nSigOps);
        unsigned int nSize = entry.GetTxSize();

        // Don't accept it if it can't get into a block
        // BP30 v3.0/v3.1: min-relay-fee exempt transactions
        // TX_UNLOCK: pays a REAL M0 coinbase fee since v3.1 (min enforced by
        //   CheckUnlock at the same 50 sat/kB rate) — kept exempt so a fee=0 full
        //   unlock stays relayable and to avoid double-gating under mempool pressure
        // TX_TRANSFER_M1: M1 fee deducted from transfer amount (OP_TRUE output)
        // HTLC transactions: Fee exempt for strict conservation (atomic swap integrity)
        // HTLC3S transactions: 3-secret HTLCs for FlowSwap (same fee exemption)
        bool isM1FeeExempt = (tx.nType == CTransaction::TxType::TX_UNLOCK ||
                              tx.nType == CTransaction::TxType::TX_TRANSFER_M1 ||
                              tx.nType == CTransaction::TxType::HTLC_CREATE_M1 ||
                              tx.nType == CTransaction::TxType::HTLC_CLAIM ||
                              tx.nType == CTransaction::TxType::HTLC_REFUND ||
                              tx.nType == CTransaction::TxType::HTLC_CREATE_3S ||
                              tx.nType == CTransaction::TxType::HTLC_CLAIM_3S ||
                              tx.nType == CTransaction::TxType::HTLC_REFUND_3S);

        if (!ignoreFees && !isM1FeeExempt) {
            const CAmount txMinFee = GetMinRelayFee(tx, pool, nSize);
            if (fLimitFree && nFees < txMinFee) {
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                    strprintf("%d < %d", nFees, txMinFee));
            }

            // No transactions are allowed below minRelayTxFee except from disconnected blocks
            if (fLimitFree && nFees < ::minRelayTxFee.GetFee(nSize)) {
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "min relay fee not met");
            }

            // DoS defense (Bitcoin-Core parity, previously unwired): once the mempool
            // fills and TrimToSize evicts the cheapest txs, the ROLLING minimum fee
            // rises. Enforce it at accept — otherwise a flooder just re-fills the pool
            // at the static min-relay floor after each eviction, defeating the
            // eviction backpressure entirely. The machinery (GetMinFee / TrimToSize /
            // rollingMinimumFeeRate) existed but was never consulted here.
            const CAmount mempoolRejectFee = pool.GetMinFee(
                gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
            if (fLimitFree && mempoolRejectFee > 0 && nFees < mempoolRejectFee) {
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false,
                    strprintf("%d < %d", nFees, mempoolRejectFee));
            }
        }

        if (fRejectAbsurdFee) {
            const CAmount nMaxFee = tx.IsShieldedTx() ? GetShieldedTxMinFee(tx) * 100 :
                                                        GetMinRelayFee(nSize) * 10000;
            if (nFees > nMaxFee)
                return state.Invalid(false, REJECT_HIGHFEE, "absurdly-high-fee",
                                     strprintf("%d > %d", nFees, nMaxFee));
        }

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, error("%s : %s", __func__, errString), REJECT_NONSTANDARD, "too-long-mempool-chain", false);
        }

        // BIP68: only accept transactions whose sequence locks can be satisfied
        // in the NEXT block (mirrors the CheckFinalTx policy above for
        // nLockTime; no-op until UPGRADE_CSV). Re-checked after reorgs in
        // CTxMemPool::removeForReorg. Needs the mempool view (unconfirmed
        // parents count as confirming in the next block) — hence here, under
        // pool.cs, and not next to CheckFinalTx.
        if (!CheckSequenceLocks(pool, tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");

        bool fCLTVIsActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_BIP65);
        bool templateVerifyActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_V7_0);
        bool btcStateActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_BTCSTATE);
        bool csfsActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_CSFS);
        bool csvActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_CSV);
        bool opCatActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_OPCAT);
        bool outputValueActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_OUTPUTVALUE);
        bool outputScriptActivated = consensus.NetworkUpgradeActive(chainHeight, Consensus::UPGRADE_OUTPUTSCRIPT);
        // A1: snapshot = current confirmed tip (policy view; re-anchored per
        // block at ConnectBlock). Under cs_main here.
        if (btcStateActivated) BtcStateCaptureSnapshot();
        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        int flags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (fCLTVIsActivated)
            flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        if (templateVerifyActivated)
            flags |= SCRIPT_VERIFY_TEMPLATEVERIFY;
        if (btcStateActivated)
            flags |= SCRIPT_VERIFY_BTCSTATE;
        if (csfsActivated)
            flags |= SCRIPT_VERIFY_CHECKSIGFROMSTACK;
        if (csvActivated)
            flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        if (opCatActivated)
            flags |= SCRIPT_VERIFY_OPCAT;
        if (outputValueActivated)
            flags |= SCRIPT_VERIFY_CHECKOUTPUTVALUE;
        if (outputScriptActivated)
            flags |= SCRIPT_VERIFY_CHECKOUTPUTSCRIPT;

        PrecomputedTransactionData precomTxData(tx);
        if (!CheckInputs(tx, state, view, true, flags, true, precomTxData)) {
            return false;
        }

        // Check again against just the consensus-critical mandatory script
        // verification flags, in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks, however allowing such transactions into the mempool
        // can be exploited as a DoS attack.
        flags = MANDATORY_SCRIPT_VERIFY_FLAGS;
        if (fCLTVIsActivated)
            flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
        if (templateVerifyActivated)
            flags |= SCRIPT_VERIFY_TEMPLATEVERIFY;
        if (btcStateActivated)
            flags |= SCRIPT_VERIFY_BTCSTATE;
        if (csfsActivated)
            flags |= SCRIPT_VERIFY_CHECKSIGFROMSTACK;
        if (csvActivated)
            flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
        if (opCatActivated)
            flags |= SCRIPT_VERIFY_OPCAT;
        if (outputValueActivated)
            flags |= SCRIPT_VERIFY_CHECKOUTPUTVALUE;
        if (outputScriptActivated)
            flags |= SCRIPT_VERIFY_CHECKOUTPUTSCRIPT;
        if (!CheckInputs(tx, state, view, true, flags, true, precomTxData)) {
            return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against MANDATORY but not STANDARD flags %s, %s",
                    __func__, hash.ToString(), FormatStateMessage(state));
        }
        // todo: pool.removeStaged for all conflicting entries

        // This transaction should only count for fee estimation if
        // the node is not behind and it is not dependent on any other
        // transactions in the mempool
        bool validForFeeEstimation = IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, validForFeeEstimation);

        // trim mempool and check if tx was trimmed
        if (!fOverrideMempoolLimit) {
            LimitMempoolSize(pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }

        pool.TrimToSize(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000);
        if (!pool.exists(tx.GetHash()))
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
    }

    GetMainSignals().TransactionAddedToMempool(_tx);

    return true;
}

bool AcceptToMemoryPoolWithTime(CTxMemPool& pool, CValidationState &state, const CTransactionRef& tx, bool fLimitFree,
                        bool* pfMissingInputs, int64_t nAcceptTime, bool fOverrideMempoolLimit, bool fRejectAbsurdFee, bool fIgnoreFees)
{
    AssertLockHeld(cs_main);

    std::vector<COutPoint> coins_to_uncache;
    bool res = AcceptToMemoryPoolWorker(pool, state, tx, fLimitFree, pfMissingInputs, nAcceptTime, fOverrideMempoolLimit, fRejectAbsurdFee, fIgnoreFees, coins_to_uncache);
    if (!res) {
        for (const COutPoint& outpoint: coins_to_uncache)
            pcoinsTip->Uncache(outpoint);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(stateDummy, FLUSH_STATE_PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx,
                        bool fLimitFree, bool* pfMissingInputs, bool fOverrideMempoolLimit,
                        bool fRejectInsaneFee, bool ignoreFees)
{
    return AcceptToMemoryPoolWithTime(pool, state, tx, fLimitFree, pfMissingInputs, GetTime(), fOverrideMempoolLimit, fRejectInsaneFee, ignoreFees);
}

/** Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, uint256& hashBlock, bool fAllowSlow, CBlockIndex* blockIndex)
{
    CBlockIndex* pindexSlow = blockIndex;

    LOCK(cs_main);

    if (!blockIndex) {

        CTransactionRef ptx = mempool.get(hash);
        if (ptx) {
            txOut = ptx;
            return true;
        }

        if (fTxIndex) {
            CDiskTxPos postx;
            if (pblocktree->ReadTxIndex(hash, postx)) {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
                if (file.IsNull())
                    return error("%s: OpenBlockFile failed", __func__);
                CBlockHeader header;
                try {
                    file >> header;
                    fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                    file >> txOut;
                } catch (const std::exception& e) {
                    return error("%s : Deserialize or I/O error - %s", __func__, e.what());
                }
                hashBlock = header.GetHash();
                if (txOut->GetHash() != hash)
                    return error("%s : txid mismatch", __func__);
                return true;
            }

            // transaction not found in the index, nothing more can be done
            return false;
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            const Coin& coin = AccessByTxid(*pcoinsTip, hash);
            if (!coin.IsSpent()) pindexSlow = chainActive[coin.nHeight];
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

bool WriteBlockToDisk(const CBlock& block, FlatFilePos& pos)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk : OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(block, fileout.GetVersion());
    fileout << Params().MessageStart() << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk : ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const FlatFilePos& pos)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk : OpenBlockFile failed");

    // Read block
    try {
        filein >> block;
    } catch (const std::exception& e) {
        return error("%s : Deserialize or I/O error - %s", __func__, e.what());
    }

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex)
{
    FlatFilePos blockPos = WITH_LOCK(cs_main, return pindex->GetBlockPos(); );
    if (!ReadBlockFromDisk(block, blockPos)) {
        return false;
    }
    if (block.GetHash() != pindex->GetBlockHash()) {
        LogPrintf("%s : block=%s index=%s\n", __func__, block.GetHash().GetHex(), pindex->GetBlockHash().GetHex());
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*) : GetHash() doesn't match index");
    }
    return true;
}


CAmount GetBlockValue(int nHeight)
{
    // ═══════════════════════════════════════════════════════════════════════════
    // BATHRON M0 Supply Policy: ZERO block rewards on ALL networks
    // ═══════════════════════════════════════════════════════════════════════════
    // All M0 supply comes ONLY from TX_MINT_M0BTC (BTC burn claims).
    // Block 1: TX_BTC_HEADERS only. Burns detected by daemon after network starts.
    // Same K_FINALITY for all burns (20 testnet, 100 mainnet).
    // This is invariant A5: M0_total(N) = M0_total(N-1) + Σ(TX_MINT_M0BTC in block N)
    // Consensus rule C1: Coinbase outputs must sum to 0, always, all heights.
    // ═══════════════════════════════════════════════════════════════════════════
    (void)nHeight;  // Unused - same policy for all heights
    return 0;
}


bool IsInitialBlockDownload()
{
    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
         return false;
    const int chainHeight = chainActive.Height();
    if (fImporting || fReindex || chainHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;
    bool state = (chainHeight < pindexBestHeader->nHeight - 24 * 6 ||
            pindexBestHeader->GetBlockTime() < GetTime() - nMaxTipAge);
    if (!state) {
        LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
        latchToFalse.store(true, std::memory_order_relaxed);
    }
    return state;
}

CBlockIndex *pindexBestForkTip = nullptr, *pindexBestForkBase = nullptr;

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    std::thread t(runCommand, strCmd);
    t.detach(); // thread runs free
}

void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before the last checkpoint)
    if (IsInitialBlockDownload())
        return;

    const CBlockIndex* pChainTip = chainActive.Tip();
    if (!pChainTip)
        return;

    // If our best fork is no longer within 72 blocks (+/- 3 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && pChainTip->nHeight - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = nullptr;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > pChainTip->nChainWork + (GetBlockWeight(*pChainTip) * 6))) {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase) {
            if (pindexBestForkBase->phashBlock) {
                std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                                      pindexBestForkBase->phashBlock->ToString() + std::string("'");
                AlertNotify(warning);
            }
        }
        if (pindexBestForkTip && pindexBestForkBase) {
            if (pindexBestForkBase->phashBlock) {
                LogPrintf("CheckForkWarningConditions: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n",
                    pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                    pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
                SetfLargeWorkForkFound(true);
            }
        } else {
            LogPrintf("CheckForkWarningConditions: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n");
            SetfLargeWorkInvalidChainFound(true);
        }
    } else {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger) {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition which we should warn the user about as a fork of at least 7 blocks
    // who's tip is within 72 blocks (+/- 3 hours if no one mines it) of ours
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || (pindexBestForkTip && pindexNewForkTip->nHeight > pindexBestForkTip->nHeight)) &&
        pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockWeight(*pfork) * 7) &&
        chainActive.Height() - pindexNewForkTip->nHeight < 72) {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("InvalidChainFound: invalid block=%s  height=%d  log2_work=%.16f  date=%s\n",
        pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
        log(pindexNew->nChainWork.getdouble()) / log(2.0), FormatISO8601DateTime(pindexNew->GetBlockTime()));

    const CBlockIndex* pChainTip = chainActive.Tip();
    assert(pChainTip);
    LogPrintf("InvalidChainFound:  current best=%s  height=%d  log2_work=%.16f  date=%s\n",
        pChainTip->GetBlockHash().GetHex(), pChainTip->nHeight, log(pChainTip->nChainWork.getdouble()) / log(2.0),
        FormatISO8601DateTime(pChainTip->GetBlockTime()));

    CheckForkWarningConditions();
}

void static InvalidBlockFound(CBlockIndex* pindex, const CValidationState& state)
{
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo& txundo, int nHeight)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn& txin : tx.vin) {
            txundo.vprevout.emplace_back();
            inputs.SpendCoin(txin.prevout, &txundo.vprevout.back());
        }
    }

    // update spent nullifiers
    inputs.SetNullifiers(tx, true);

    // add outputs
    AddCoins(inputs, tx, nHeight, false);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache &inputs, int nHeight)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight);
}

bool CScriptCheck::operator()()
{
    const CScript& scriptSig = ptxTo->vin[nIn].scriptSig;
    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *precomTxData), ptxTo->GetRequiredSigVersion(), &error);
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = LookupBlockIndex(inputs.GetBestBlock());
    return pindexPrev->nHeight + 1;
}

namespace Consensus {
bool CheckTxInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight)
{
    // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
    // for an attacker to attempt to split the network.
    if (!inputs.HaveInputs(tx))
        return state.Invalid(false, 0, "", "Inputs unavailable");

    // are the Sapling's requirements met?
    if (!inputs.HaveShieldedRequirements(tx))
        return state.Invalid(error("CheckInputs(): %s Sapling requirements not met", tx.GetHash().ToString()));

    const Consensus::Params& consensus = ::Params().GetConsensus();
    CAmount nValueIn = 0;
    CAmount nFees = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++) {
        const COutPoint &prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        if (coin.IsCoinBase()) {
            // ═══════════════════════════════════════════════════════════════════════════
            // BATHRON Bootstrap: skip coinbase maturity for the early bootstrap window
            // ═══════════════════════════════════════════════════════════════════════════
            // NOTE: there is NO premine — block-1 coinbase value is 0. This exception only
            // lets the burn-backed minted M0 (and MN collaterals funded from it) be spent
            // for ProRegTx during bootstrap without waiting the full coinbase maturity.
            // ═══════════════════════════════════════════════════════════════════════════
            bool bSkipMaturity = false;
            if (::Params().IsRegTestNet() && coin.nHeight <= 1) {
                bSkipMaturity = true;  // Regtest: Genesis (0) and Block 1 immediately spendable
            } else if (::Params().IsTestnet() && coin.nHeight == 1) {
                bSkipMaturity = true;  // Testnet: block-1 coinbase exempt (bootstrap; NO premine — value is 0)
            }
            if (!bSkipMaturity && (signed long)nSpendHeight - coin.nHeight < (signed long)Consensus::Params::HU_COINBASE_MATURITY)
                return state.Invalid(false, REJECT_INVALID, "bad-txns-premature-spend-of-coinbase",
                        strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!consensus.MoneyRange(coin.out.nValue) || !consensus.MoneyRange(nValueIn))
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputvalues-outofrange");
    }

    // Sapling
    nValueIn += tx.GetShieldedValueIn();

    // ═══════════════════════════════════════════════════════════════════════════
    // FEE CALCULATION: Always use raw sat values - NO M0/M1 adjustments!
    // ═══════════════════════════════════════════════════════════════════════════
    // Fee = sum(input sats) - sum(output sats)
    //
    // The M0/M1 token type distinction is for SETTLEMENT ACCOUNTING only,
    // not for fee calculation. The miner receives actual sats left over,
    // regardless of what token type the inputs/outputs represent.
    //
    // TX_LOCK:       fee = inputs - (vault + receipt + change) = actual fee
    // TX_UNLOCK:     fee = inputs - outputs = actual fee
    // TX_TRANSFER_M1: fee = inputs - outputs = actual fee
    //
    // WRONG (old code): Subtract M1 receipts from outputs, inflating "fee".
    //   This created phantom M0 when coinbase received inflated fees.
    // ═══════════════════════════════════════════════════════════════════════════
    CAmount nValueOut = tx.GetValueOut();

    // ═══════════════════════════════════════════════════════════════════════════
    // TX_LOCK SPECIAL HANDLING:
    // TX_LOCK creates M1 (receipt at vout[1]) with sat value = lockAmount.
    // This means outputs > inputs from a pure sat perspective, which is intentional.
    // For input/output validation, we exclude the receipt (M1 creation is valid).
    // ═══════════════════════════════════════════════════════════════════════════
    CAmount nValueOutForValidation = nValueOut;
    if (tx.nType == CTransaction::TxType::TX_LOCK && tx.vout.size() >= 2) {
        // Exclude receipt (vout[1]) from validation check
        nValueOutForValidation = 0;
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            if (i != 1) {  // Skip receipt at index 1
                nValueOutForValidation += tx.vout[i].nValue;
            }
        }
    }

    // All transactions must have value_in >= value_out (fee >= 0)
    // For TX_LOCK: we check against nValueOutForValidation (excluding receipt)
    if (nValueIn < nValueOutForValidation)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-in-belowout", false,
                strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(nValueOutForValidation)));

    // Tally transaction fees
    // For TX_LOCK: fee = inputs - vault - change (excluding receipt)
    CAmount nTxFee = nValueIn - nValueOutForValidation;
    if (nTxFee < 0)
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-negative");
    nFees += nTxFee;
    if (!consensus.MoneyRange(nFees))
        return state.DoS(100, false, REJECT_INVALID, "bad-txns-fee-outofrange");

    return true;
}
}// namespace Consensus

bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheStore, PrecomputedTransactionData& precomTxData, std::vector<CScriptCheck> *pvChecks)
{
    if (!tx.IsCoinBase()) {
        // ═══════════════════════════════════════════════════════════════════════════
        // BP11: TX_MINT_M0BTC bypasses normal input validation
        // It has empty vin (no inputs) and creates new M0BTC from verified burn claims.
        // Full validation is done in CheckMintM0BTC called from CheckSpecialTx.
        // ═══════════════════════════════════════════════════════════════════════════
        if (tx.nType == CTransaction::TxType::TX_MINT_M0BTC) {
            // TX_MINT_M0BTC has no inputs to validate - it's money creation
            // The mint transaction validity is verified in CheckSpecialTx/ConnectBlock
            return true;
        }

        if (!Consensus::CheckTxInputs(tx, state, inputs, GetSpendHeight(inputs)))
            return false;

        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last block chain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (fScriptChecks) {
            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint& prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed to by tx' witness hash. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.

                // Verify signature
                CScriptCheck check(coin.out, tx, i, flags, cacheStore, &precomTxData);
                if (pvChecks) {
                    pvChecks->emplace_back();
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(coin.out, tx, i,
                            flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheStore, &precomTxData);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. a invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after a soft-fork
                    // super-majority vote has passed.
                    return state.DoS(100, false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }
        }
    }

    return true;
}

/** Abort with a message */
static bool AbortNode(const std::string& strMessage, const std::string& userMessage="")
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

static bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

namespace {

bool UndoWriteToDisk(const CBlockUndo& blockundo, FlatFilePos& pos, const uint256& hashBlock)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s : OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(blockundo, fileout.GetVersion());
    fileout << Params().MessageStart() << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s : ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo& blockundo, const FlatFilePos& pos, const uint256& hashBlock)
{
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s : OpenBlockFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << hashBlock;
        verifier >> blockundo;
        filein >> hashChecksum;
    } catch (const std::exception& e) {
        return error("%s : Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s : Checksum mismatch", __func__);

    return true;
}

} // anon namespace

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output

    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}


/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult DisconnectBlock(CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view, bool fJustCheck = false)
{
    AssertLockHeld(cs_main);

    bool fDIP3Active = Params().GetConsensus().NetworkUpgradeActive(pindex->nHeight, Consensus::UPGRADE_V6_0);
    bool fHasBestBlock = evoDb->VerifyBestBlock(pindex->GetBlockHash());

    if (fDIP3Active && !fHasBestBlock) {
        AbortNode("Found EvoDB inconsistency, you must reindex to continue");
        return DISCONNECT_FAILED;
    }

    bool fClean = true;

    CBlockUndo blockUndo;
    FlatFilePos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        error("%s: no undo data available", __func__);
        return DISCONNECT_FAILED;
    }
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash())) {
        error("%s: failure reading undo data", __func__);
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("%s: block and undo data inconsistent", __func__);
        return DISCONNECT_FAILED;
    }

    if (!UndoSpecialTxsInBlock(block, pindex, fJustCheck)) {
        return DISCONNECT_FAILED;
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction& tx = *block.vtx[i];


        const uint256& hash = tx.GetHash();


        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                view.SpendCoin(out, &coin);
                if (tx.vout[o] != coin.out) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        // not coinbases because they dont have traditional inputs
        if (tx.IsCoinBase())
            continue;

        // Sapling, update unspent nullifiers
        view.SetNullifiers(tx, false);

        // restore inputs
        CTxUndo& txundo = blockUndo.vtxundo[i - 1];
        if (txundo.vprevout.size() != tx.vin.size()) {
            error("%s: transaction and undo data inconsistent - txundo.vprevout.siz=%d tx.vin.siz=%d",
                    __func__, txundo.vprevout.size(), tx.vin.size());
            return DISCONNECT_FAILED;
        }
        for (unsigned int j = tx.vin.size(); j-- > 0;) {
            const COutPoint& out = tx.vin[j].prevout;
            int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
            if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
            fClean = fClean && res != DISCONNECT_UNCLEAN;
        }
        // At this point, all of txundo.vprevout should have been moved out.
    }

    const Consensus::Params& consensus = Params().GetConsensus();

    // set the old best Sapling anchor back
    // We can get this from the `hashFinalSaplingRoot` of the last block
    // However, this is only reliable if the last block was on or after
    // the Sapling activation height. Otherwise, the last anchor was the
    // empty root.
    if (consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_V5_0)) {
        view.PopAnchor(pindex->pprev->hashFinalSaplingRoot);
    } else {
        view.PopAnchor(SaplingMerkleTree::empty_root());
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());
    evoDb->WriteBestBlock(pindex->pprev->GetBlockHash());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    FlatFilePos block_pos_old(nLastBlockFile, vinfoBlockFile[nLastBlockFile].nSize);
    FlatFilePos undo_pos_old(nLastBlockFile, vinfoBlockFile[nLastBlockFile].nUndoSize);

    bool status = true;
    status &= BlockFileSeq().Flush(block_pos_old, fFinalize);
    status &= UndoFileSeq().Flush(undo_pos_old, fFinalize);
    if (!status) {
        AbortNode("Flushing block file to disk failed. This is likely the result of an I/O error.");
    }
}

bool FindUndoPos(CValidationState& state, int nFile, FlatFilePos& pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck()
{
    util::ThreadRename("bathron-scriptch");
    scriptcheckqueue.Thread();
}

static int64_t nTimeVerify = 0;
static int64_t nTimeProcessSpecial = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeTotal = 0;

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
static bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& view, bool fJustCheck = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    LogPrintf("DEBUG-HANG: ConnectBlock ENTER height=%d block=%s nTx=%d\n",
              pindex ? pindex->nHeight : -1, block.GetHash().ToString().substr(0, 16), block.vtx.size());
    AssertLockHeld(cs_main);
    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(block, state, !fJustCheck, !fJustCheck, !fJustCheck)) {
        if (state.CorruptionPossible()) {
            // We don't write down blocks to disk if they may have been
            // corrupted, so this should be impossible unless we're having hardware
            // problems.
            return AbortNode(state, "Corrupt block found indicating potential hardware failure; shutting down");
        }
        return error("%s: CheckBlock failed for %s: %s", __func__, block.GetHash().ToString(), FormatStateMessage(state));
    }

    // HU Finality: Check for conflicting finalized blocks
    if (pindex->pprev && pindex->phashBlock && hu::finalityHandler &&
        hu::finalityHandler->HasConflictingFinality(pindex->nHeight, pindex->GetBlockHash())) {
        return state.DoS(10, error("%s: conflicting with HU finality", __func__), REJECT_INVALID, "bad-hu-finality");
    }
    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? UINT256_ZERO : pindex->pprev->GetBlockHash();
    if (hashPrevBlock != view.GetBestBlock())
        LogPrintf("%s: hashPrev=%s view=%s\n", __func__, hashPrevBlock.GetHex(), view.GetBestBlock().GetHex());
    assert(hashPrevBlock == view.GetBestBlock());

    const Consensus::Params& consensus = Params().GetConsensus();
    const bool isV5UpgradeEnforced = consensus.NetworkUpgradeActive(pindex->nHeight, Consensus::UPGRADE_V5_0);
    const bool isV6UpgradeEnforced = consensus.NetworkUpgradeActive(pindex->nHeight, Consensus::UPGRADE_V6_0);

    // HU V6.0: FINALITY VIA MASTERNODES (independent from DMM block production)
    //
    // ARCHITECTURE: DMM and HU are COMPLETELY INDEPENDENT systems:
    //   - DMM: Produces blocks deterministically (never blocked by HU)
    //   - HU: Finalizes blocks via quorum (prevents reorgs on finalized blocks)
    //
    // The nHuMaxReorgDepth parameter is used ONLY for reorg protection, NOT for
    // blocking new block production. A block with HU finality cannot be reorged.
    //
    // This check only LOGS warnings for missing finality - it never rejects blocks.
    // Reorg protection is handled separately in DisconnectBlock/InvalidateBlock.
    const int nHuFinalityDepth = consensus.nHuMaxReorgDepth;
    if (isV6UpgradeEnforced && pindex->pprev && hu::finalityHandler) {
        CBlockIndex* pindexCheck = pindex->pprev;
        int depth = 0;

        while (pindexCheck && depth < nHuFinalityDepth) {
            pindexCheck = pindexCheck->pprev;
            depth++;
        }

        // Log warning if block at depth lacks finality (informational only)
        if (pindexCheck && depth == nHuFinalityDepth &&
            consensus.NetworkUpgradeActive(pindexCheck->nHeight, Consensus::UPGRADE_V6_0)) {
            if (!hu::finalityHandler->HasFinality(pindexCheck->nHeight, pindexCheck->GetBlockHash())) {
                LogPrint(BCLog::STATE, "Quorum: Block at depth %d (height %d) awaiting finality\n",
                         nHuFinalityDepth, pindexCheck->nHeight);
            }
        }
    }


    if (pindex->pprev) {
        bool fHasBestBlock = evoDb->VerifyBestBlock(hashPrevBlock);

        bool fPrevIsGenesis = (hashPrevBlock == consensus.hashGenesisBlock);

        if (isV6UpgradeEnforced && !fHasBestBlock && !fPrevIsGenesis) {
            return AbortNode(state, "Found EvoDB inconsistency, you must reindex to continue");
        }
    }

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable on mainnet/testnet — burn-only, empty premine).
    if (block.GetHash() == consensus.hashGenesisBlock) {
        if (!fJustCheck) {
            // REGTEST-ONLY: credit the genesis coinbase to the UTXO set so the
            // "convenience premine" (P2PKH outputs with known WIFs, see
            // CreateBathronRegtestGenesisBlock) is actually SPENDABLE for local
            // automated multi-node tests. Without this the wallet scans the
            // premine and shows a balance, but the outpoints are never in the
            // coins view -> spends fail "Missing inputs" (the genesis coinbase is
            // never connected). Gated to regtest, so mainnet/testnet — whose
            // genesis is burn-only with no premine — are byte-identical. Premine
            // spends are NORMAL txs, outside the M0/M1 settlement accounting
            // (A5/A6/A7), so no invariant is affected. Regtest maturity for
            // genesis-height coins is already skipped (see the bSkipMaturity
            // "Genesis (0) ... immediately spendable" paths).
            if (Params().NetworkIDString() == CBaseChainParams::REGTEST && !block.vtx.empty()) {
                AddCoins(view, *block.vtx[0], 0, /*check=*/false);
            }
            view.SetBestBlock(pindex->GetBlockHash());
        }
        return true;
    }

    if (!CheckBlockMNOnly(block, pindex->pprev, state)) {
        // state already set by CheckBlockMNOnly
        return false;
    }

    // Sapling
    // Reject a block that results in a negative shielded value pool balance.
    // Description under ZIP209 turnstile violation.

    // If we've reached ConnectBlock, we have all transactions of
    // parents and can expect nChainSaplingValue not to be boost::none.
    // However, the miner and mining RPCs may not have populated this
    // value and will call `TestBlockValidity`. So, we act
    // conditionally.
    if (pindex->nChainSaplingValue) {
        if (*pindex->nChainSaplingValue < 0) {
            return state.DoS(100, error("%s: turnstile violation in Sapling shielded value pool: val: %d", __func__, *pindex->nChainSaplingValue),
                             REJECT_INVALID, "turnstile-violation-sapling-shielded-pool");
        }
    }

    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    // If scripts won't be checked anyways, don't bother seeing if CLTV is activated
    bool fCLTVIsActivated = false;
    bool btcStateActivated = false;
    bool csfsActivated = false;
    bool templateVerifyActivated = false;
    if (fScriptChecks && pindex->pprev) {
        fCLTVIsActivated = consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_BIP65);
        templateVerifyActivated = consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_V7_0);
        btcStateActivated = consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_BTCSTATE);
        csfsActivated = consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_CSFS);
        // NOTE: unlike the script-flag gates above, the CSV/BIP68 gate is NOT
        // tied to fScriptChecks — sequence locks are a tx-level consensus rule
        // (like nLockTime finality), enforced below even under checkpoints.
        // A1 determinism anchor: OP_BTCSTATEVERIFY answers against the
        // btcheaders tip AS OF THE PREVIOUS BLOCK — captured here, before any
        // tx of this block (incl. TX_BTC_HEADERS) applies. Order- and
        // thread-independent; parallel script checks read the atomic snapshot.
        if (btcStateActivated) BtcStateCaptureSnapshot();
    }

    // CSV/BIP68 (see NOTE above). TWO activation bases, each chosen to match
    // the mempool so a tx can never be valid in one and not the other:
    //  - the OP_CHECKSEQUENCEVERIFY SCRIPT FLAG activates like the sibling
    //    opcodes (CLTV/BTCSTATE) on the PREVIOUS block's height, matching the
    //    mempool which gates the flag on the current tip (chainHeight);
    //  - the tx-level BIP68 sequence-lock rule binds by the height of the
    //    block the tx lands IN (this block), matching the mempool's tip+1
    //    basis in CheckSequenceLocks. Gating it on pprev->nHeight instead
    //    would let the activation-height block escape the rule that the
    //    mempool already enforces for it (a policy/consensus split at that
    //    single boundary block).
    const bool csvScriptFlag =
        pindex->pprev && consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_CSV);
    const bool csvSeqLockActivated =
        consensus.NetworkUpgradeActive(pindex->nHeight, Consensus::UPGRADE_CSV);
    const bool opCatActivated =
        pindex->pprev && consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_OPCAT);
    const bool outputValueActivated =
        pindex->pprev && consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_OUTPUTVALUE);
    const bool outputScriptActivated =
        pindex->pprev && consensus.NetworkUpgradeActive(pindex->pprev->nHeight, Consensus::UPGRADE_OUTPUTSCRIPT);

    // CVE-2024-52911: precomTxData MUST be declared before `control` so that,
    // on stack unwind (including the early `return error()` below when CheckInputs
    // fails), `control` is destroyed FIRST. Its destructor runs Wait(), draining
    // the parallel script-check workers, before precomTxData is freed. The queued
    // CScriptCheck objects hold raw pointers into precomTxData (see CheckInputs);
    // freeing it while workers are still running would be a use-after-free.
    std::vector<PrecomputedTransactionData> precomTxData;
    precomTxData.reserve(block.vtx.size()); // Required so that pointers to individual precomTxData don't get invalidated

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : nullptr);

    int64_t nTimeStart = GetTimeMicros();
    CAmount nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    CBlockUndo blockundo;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    unsigned int nMaxBlockSigOps = MAX_BLOCK_SIGOPS_CURRENT;

    // Sapling
    SaplingMerkleTree sapling_tree;
    uint256 saplingAnchor = view.GetBestAnchor();
    if (!view.GetSaplingAnchorAt(saplingAnchor, sapling_tree)) {
        // The best anchor must ALWAYS be retrievable from the view. If it is not,
        // the local Sapling anchor DB is corrupt. Substituting an empty tree (the
        // previous behaviour) would compute a wrong hashFinalSaplingRoot below and
        // make this node silently reject otherwise-valid blocks -> consensus
        // fork/halt specific to this node. Fail hard so the operator reindexes,
        // mirroring upstream's hard failure on this "impossible" internal state.
        return AbortNode(state, strprintf("%s: best Sapling anchor %s not found in view; anchor DB likely corrupt, you must reindex to continue", __func__, saplingAnchor.ToString()));
    }

    // BATHRON: Sapling is always active - no maintenance mode (SPORK_20 removed)
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *block.vtx[i];

        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);
        if (nSigOps > nMaxBlockSigOps)
            return state.DoS(100, error("ConnectBlock() : too many sigops"), REJECT_INVALID, "bad-blk-sigops");

        // After v5 enforcement, ContextualCheckTransaction rejects legacy transactions.
        // ═══════════════════════════════════════════════════════════════════════════
        // BP11: TX_MINT_M0BTC has no inputs - skip input validation like coinbase
        // It creates M0BTC from verified BTC burn proofs. Full validation done in
        // CheckSpecialTx and ConnectMintM0BTC.
        // ═══════════════════════════════════════════════════════════════════════════
        const bool isMintM0BTC = (tx.nType == CTransaction::TxType::TX_MINT_M0BTC);

        if (!tx.IsCoinBase() && !isMintM0BTC) {
            if (!view.HaveInputs(tx)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-missingorspent");
            }
            // Sapling: are the sapling spends' requirements met in tx(valid anchors/nullifiers)?
            if (!view.HaveShieldedRequirements(tx))
                return state.DoS(100, error("%s: spends requirements not met", __func__),
                                 REJECT_INVALID, "bad-txns-sapling-requirements-not-met");

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += GetP2SHSigOpCount(tx, view);
            if (nSigOps > nMaxBlockSigOps)
                return state.DoS(100, error("ConnectBlock() : too many sigops"), REJECT_INVALID, "bad-blk-sigops");

        }

        // Cache the sig ser hashes
        precomTxData.emplace_back(tx);

        CAmount txValueOut = tx.GetValueOut();

        // ═══════════════════════════════════════════════════════════════════════════
        // FEE CALCULATION for ConnectBlock
        // ═══════════════════════════════════════════════════════════════════════════
        //
        // SPECIAL CASE - TX_LOCK:
        //   TX_LOCK creates M1 (receipt at vout[1]) with sat value = lockAmount.
        //   This M1 is conceptually "new" value created by settlement layer.
        //
        //   For fee calculation: EXCLUDE receipt (vout[1])
        //   fee = inputs - vault - change = actual fee user paid
        //
        //   This fee goes to coinbase, preserving A5 invariant.
        //   The M1 creation is balanced by M0 being locked in vault.
        //
        // For all other TX types: fee = inputs - outputs (standard)
        // ═══════════════════════════════════════════════════════════════════════════

        if (!tx.IsCoinBase() && !isMintM0BTC) {
            // BIP68: relative lock-times, evaluated against the heights of the
            // spent coins as seen by THIS block (in-block parents count as
            // this height — UpdateCoins hasn't run for tx i yet but has for
            // i-1, so same-block ancestors read back pindex->nHeight).
            // HaveInputs above guarantees every AccessCoin hit is live.
            if (csvSeqLockActivated) {
                std::vector<int> prevheights;
                prevheights.resize(tx.vin.size());
                for (size_t j = 0; j < tx.vin.size(); j++) {
                    prevheights[j] = (int)view.AccessCoin(tx.vin[j].prevout).nHeight;
                }
                if (!SequenceLocks(tx, LOCKTIME_VERIFY_SEQUENCE, &prevheights, *pindex)) {
                    return state.DoS(100, error("%s: contains a non-BIP68-final transaction %s", __func__, tx.GetHash().ToString()),
                                     REJECT_INVALID, "bad-txns-nonfinal");
                }
            }

            CAmount txValueIn = view.GetValueIn(tx);

            // Settlement-aware M0/coinbase fee. Shared with mempool acceptance via
            // GetSettlementTxFee so the two can never diverge (see settlement_logic.h).
            // A divergence here previously made TX_UNLOCK blocks fail bad-cb-amount
            // (honest producer) / mint un-backed M0 into the coinbase (malicious one).
            CAmount txFee = GetSettlementTxFee(tx, txValueIn, txValueOut);

            nFees += txFee;

            std::vector<CScriptCheck> vChecks;
            unsigned int flags = SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_DERSIG;
            if (fCLTVIsActivated)
                flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
            if (templateVerifyActivated)
                flags |= SCRIPT_VERIFY_TEMPLATEVERIFY;
            if (btcStateActivated)
                flags |= SCRIPT_VERIFY_BTCSTATE;
            if (csfsActivated)
                flags |= SCRIPT_VERIFY_CHECKSIGFROMSTACK;
            if (csvScriptFlag)
                flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
            if (opCatActivated)
                flags |= SCRIPT_VERIFY_OPCAT;
            if (outputValueActivated)
                flags |= SCRIPT_VERIFY_CHECKOUTPUTVALUE;
            if (outputScriptActivated)
                flags |= SCRIPT_VERIFY_CHECKOUTPUTSCRIPT;

            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, precomTxData[i], nScriptCheckThreads ? &vChecks : nullptr))
                return error("%s: Check inputs on %s failed with %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.emplace_back();
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

        // Sapling update tree
        if (tx.IsShieldedTx() && !tx.sapData->vShieldedOutput.empty()) {
            for(const OutputDescription &outputDescription : tx.sapData->vShieldedOutput) {
                sapling_tree.append(outputDescription.cmu);
            }
        }

        vPos.emplace_back(tx.GetHash(), pos);
        pos.nTxOffset += ::GetSerializeSize(tx, CLIENT_VERSION);
    }

    // Push new tree anchor
    view.PushAnchor(sapling_tree);

    // Verify header correctness
    if (isV5UpgradeEnforced) {
        // If Sapling is active, block.hashFinalSaplingRoot must be the
        // same as the root of the Sapling tree
        if (block.hashFinalSaplingRoot != sapling_tree.root()) {
            return state.DoS(100,
                             error("ConnectBlock(): block's hashFinalSaplingRoot is incorrect (should be Sapling tree root)"),
                             REJECT_INVALID, "bad-sapling-root-in-block");
        }
    }

    assert(nFees >= 0);

    int64_t nTime1 = GetTimeMicros();
    nTimeConnect += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCHMARK, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n", (unsigned)block.vtx.size(), 0.001 * (nTime1 - nTimeStart), 0.001 * (nTime1 - nTimeStart) / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * (nTime1 - nTimeStart) / (nInputs - 1), nTimeConnect * 0.000001);

    // Coinbase value check: after v6 enforcement, the coinbase must equal the
    // recycled fees (block_reward = 0). This is the sole block-level money check;
    // overmint is otherwise impossible (CheckTxInputs caps out<=in) and A5/A6 are
    // enforced by the settlement layer. The legacy budget/MN-payee validators
    // (IsBlockValueValid/IsBlockPayeeValid) were no-op stubs and are removed.
    if (isV6UpgradeEnforced && !IsCoinbaseValueValid(block.vtx[0], nFees, state)) {
        // pass the state returned by the function above
        return false;
    }

    if (!control.Wait())
        return state.DoS(100, error("%s: CheckQueue failed", __func__), REJECT_INVALID, "block-validation-failed");
    int64_t nTime2 = GetTimeMicros();
    nTimeVerify += nTime2 - nTimeStart;
    LogPrint(BCLog::BENCHMARK, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime2 - nTimeStart), nInputs <= 1 ? 0 : 0.001 * (nTime2 - nTimeStart) / (nInputs - 1), nTimeVerify * 0.000001);

    LogPrintf("DEBUG-HANG: ConnectBlock calling ProcessSpecialTxsInBlock (nTx=%d)...\n", block.vtx.size());
    if (!ProcessSpecialTxsInBlock(block, pindex, &view, state, fJustCheck)) {
        LogPrintf("DEBUG-HANG: ProcessSpecialTxsInBlock FAILED: %s\n", FormatStateMessage(state));
        return error("%s: Special tx processing failed with %s", __func__, FormatStateMessage(state));
    }
    LogPrintf("DEBUG-HANG: ProcessSpecialTxsInBlock OK\n");

    int64_t nTime3 = GetTimeMicros();
    nTimeProcessSpecial += nTime3 - nTime2;
    LogPrint(BCLog::BENCHMARK, "    - Process special tx: %.2fms [%.2fs]\n", 0.001 * (nTime3 - nTime2), nTimeProcessSpecial * 0.000001);

    //IMPORTANT NOTE: Nothing before this point should actually store to disk (or even memory)
    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        if (pindex->GetUndoPos().IsNull()) {
            FlatFilePos diskPosBlock;
            if (!FindUndoPos(state, pindex->nFile, diskPosBlock, ::GetSerializeSize(blockundo, CLIENT_VERSION) + 40))
                return error("ConnectBlock() : FindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, diskPosBlock, pindex->pprev->GetBlockHash()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = diskPosBlock.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }


    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return AbortNode(state, "Failed to write transaction index");

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());
    evoDb->WriteBestBlock(pindex->GetBlockHash());

    int64_t nTime4 = GetTimeMicros();
    nTimeIndex += nTime4 - nTime3;
    LogPrint(BCLog::BENCHMARK, "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime4 - nTime3), nTimeIndex * 0.000001);

    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed if either they're too large, forceWrite is set, or
 * fast is not set and it's been a while since the last write.
 * Full flush also updates the money supply from disk (except during shutdown)
 */
bool static FlushStateToDisk(CValidationState& state, FlushStateMode mode)
{
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    try {
        int64_t nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        if (nLastSetChain == 0) {
            nLastSetChain = nNow;
        }
        int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
        int64_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now
        // (not in the middle of a block processing).
        bool fCacheLarge = mode == FLUSH_STATE_PERIODIC &&
                cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && (unsigned) cacheSize > nCoinCacheUsage;
        // The evoDB cache is too large, time to write
        bool fEvoDbCacheCritical = mode == FLUSH_STATE_IF_NEEDED && evoDb != nullptr && evoDb->GetMemoryUsage() >= (64 << 20);
        // It's been a while since we wrote the block index to disk.
        // Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        bool fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fEvoDbCacheCritical || fPeriodicFlush;
        // Write blocks and block index to disk.
        if (fDoFullFlush || fPeriodicWrite) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(GetBlocksDir())) {
                return AbortNode(state, "Disk space is low!", _("Error: Disk space is low!"));
            }
            // First make sure all block and undo data is flushed to disk.
            FlushBlockFile();
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.emplace_back(*it, &vinfoBlockFile[*it]);
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Files to write to block index database");
                }
            }

            nLastWrite = nNow;
        }

        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush && !pcoinsTip->GetBestBlock().IsNull()) {
            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(GetDataDir(), 48 * 2 * 2 * pcoinsTip->GetCacheSize())) {
                return AbortNode(state, "Disk space is low!", _("Error: Disk space is low!"));
            }
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");
            if (!evoDb->CommitRootTransaction()) {
                return AbortNode(state, "Failed to commit EvoDB");
            }
            nLastFlush = nNow;
            // Update money supply on memory, reading data from disk
            if (!ShutdownRequested() && !IsInitialBlockDownload()) {
                MoneySupply.Update(pcoinsTip->GetTotalAmount(), chainActive.Height());
            }
        }
        if ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000) {
            // Update best block in wallet (so we can detect restored wallets).
            GetMainSignals().SetBestChain(chainActive.GetLocator());
            nLastSetChain = nNow;
        }

    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk()
{
    CValidationState state;
    FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
}

/** Update chainActive and related internal data structures. */
void static UpdateTip(CBlockIndex* pindexNew)
{
    AssertLockHeld(cs_main);
    chainActive.SetTip(pindexNew);

    // New best block
    mempool.AddTransactionsUpdated(1);

    // BATHRON: Update sync state based on chain height and HU finality
    g_tiertwo_sync_state.SetChainHeight(pindexNew->nHeight);

    // Check if this block is finalized (has HU quorum)
    // No bootstrap phase - quorum required from block 1
    bool isFinalized = hu::PreviousBlockHasQuorum(pindexNew);
    if (isFinalized) {
        g_tiertwo_sync_state.OnFinalizedBlock(GetTime());
    }

    // Monitor finality lag and warn if too high
    const Consensus::Params& consensus = Params().GetConsensus();
    if (!IsInitialBlockDownload() && hu::finalityHandler) {
        int finalityLag = hu::finalityHandler->GetFinalityLag(pindexNew->nHeight);
        // Warn at 2x the diagnostic lag-warning window
        int warningThreshold = consensus.nHuFinalityLagWarning * 2;
        if (finalityLag > warningThreshold) {
            LogPrintf("WARNING: Finality lag is %d blocks (threshold: %d). Network may be under stress.\n",
                     finalityLag, warningThreshold);
        }
    }

    const CBlockIndex* pChainTip = chainActive.Tip();
    assert(pChainTip != nullptr);
    LogPrintf("%s: new best=%s  height=%d version=%d  log2_work=%.16f  tx=%lu  date=%s progress=%f  cache=%.1fMiB(%utxo)  evodb_cache=%.1fMiB\n",
              __func__,
              pChainTip->GetBlockHash().GetHex(), pChainTip->nHeight, pChainTip->nVersion, log(pChainTip->nChainWork.getdouble()) / log(2.0), (unsigned long)pChainTip->nChainTx,
              FormatISO8601DateTime(pChainTip->GetBlockTime()),
              Checkpoints::GuessVerificationProgress(pChainTip), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize(),
              evoDb->GetMemoryUsage() * (1.0 / (1<<20)));

    // Check the version of the last 100 blocks to see if we need to upgrade:
    static bool fWarned = false;
    if (!IsInitialBlockDownload() && !fWarned) {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pChainTip;
        for (int i = 0; i < 100 && pindex != nullptr; i++) {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, (int)CBlock::CURRENT_VERSION);
        if (nUpgraded > 100 / 2) {
            std::string strWarning = _("Warning: This version is obsolete, upgrade required!");
            SetMiscWarning(strWarning);
            if (!fWarned) {
                AlertNotify(strWarning);
                fWarned = true;
            }
        }
    }
}

/** Disconnect chainActive's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool static DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);
    CBlockIndex* pindexDelete = chainActive.Tip();
    assert(pindexDelete);

    // HU FINALITY PROTECTION: Cannot disconnect blocks with HU finality
    if (hu::finalityHandler && hu::finalityHandler->HasFinality(pindexDelete->nHeight, pindexDelete->GetBlockHash())) {
        return state.DoS(100, error("%s: Cannot disconnect block %s at height %d - has HU finality",
                                    __func__, pindexDelete->GetBlockHash().ToString(), pindexDelete->nHeight),
                         REJECT_INVALID, "hu-finality-protected");
    }

    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete))
        return error("%s: Failed to read block", __func__);
    // Apply the block atomically to the chain state.
    const uint256& saplingAnchorBeforeDisconnect = pcoinsTip->GetBestAnchor();
    int64_t nStart = GetTimeMicros();
    {
        auto dbTx = evoDb->BeginTransaction();

        CCoinsViewCache view(pcoinsTip.get());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip() : DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
        dbTx->Commit();
    }
    LogPrint(BCLog::BENCHMARK, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    const uint256& saplingAnchorAfterDisconnect = pcoinsTip->GetBestAnchor();
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    // Evict from mempool if the anchor changes
    if (saplingAnchorBeforeDisconnect != saplingAnchorAfterDisconnect) {
        // The anchor may not change between block disconnects,
        // in which case we don't want to evict from the mempool yet!
        mempool.removeWithAnchor(saplingAnchorBeforeDisconnect);
    }
    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock, pindexDelete->GetBlockHash(), pindexDelete->nHeight, pindexDelete->GetBlockTime());

    // Update MN manager cache
    deterministicMNManager->SetTipIndex(pindexDelete->pprev);
    // BATHRON: mnodeman.CacheBlockHash/UncacheBlockHash removed - DMN system doesn't need this

    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    PerBlockConnectTrace() {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;

public:
    ConnectTrace() : blocksConnected(1) {}

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        blocksConnected.pop_back();
        return blocksConnected;
    }
};

/**
 * Connect a new block to chainActive. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool static ConnectTip(CValidationState& state, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    LogPrintf("DEBUG-HANG: ConnectTip ENTER height=%d block=%s\n",
              pindexNew ? pindexNew->nHeight : -1, pindexNew ? pindexNew->GetBlockHash().ToString().substr(0, 16) : "null");
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);
    assert(pindexNew->pprev == chainActive.Tip());

    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;

    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros();
    nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCHMARK, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        LogPrintf("DEBUG-HANG: ConnectTip evoDb->BeginTransaction...\n");
        auto dbTx = evoDb->BeginTransaction();
        LogPrintf("DEBUG-HANG: ConnectTip got evoDB transaction\n");

        CCoinsViewCache view(pcoinsTip.get());
        LogPrintf("DEBUG-HANG: ConnectTip calling ConnectBlock...\n");
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, false);
        LogPrintf("DEBUG-HANG: ConnectTip ConnectBlock returned %d\n", rv);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("%s: ConnectBlock %s failed, %s", __func__, pindexNew->GetBlockHash().ToString(), FormatStateMessage(state));
        }
        nTime3 = GetTimeMicros();
        nTimeConnectTotal += nTime3 - nTime2;
        LogPrint(BCLog::BENCHMARK, "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        LogPrintf("DEBUG-HANG: ConnectTip calling view.Flush...\n");
        bool flushed = view.Flush();
        LogPrintf("DEBUG-HANG: ConnectTip view.Flush returned %d\n", flushed);
        assert(flushed);
        LogPrintf("DEBUG-HANG: ConnectTip calling dbTx->Commit...\n");
        dbTx->Commit();
        LogPrintf("DEBUG-HANG: ConnectTip dbTx->Commit OK\n");
    }
    int64_t nTime4 = GetTimeMicros();
    nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCHMARK, "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);

    // Write the chain state to disk, if necessary. Always write to disk if this is the first of a new file.
    FlushStateMode flushMode = FLUSH_STATE_IF_NEEDED;
    if (pindexNew->pprev && (pindexNew->GetBlockPos().nFile != pindexNew->pprev->GetBlockPos().nFile))
        flushMode = FLUSH_STATE_ALWAYS;
    if (!FlushStateToDisk(state, flushMode))
        return false;
    int64_t nTime5 = GetTimeMicros();
    nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCHMARK, "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);

    // Remove conflicting transactions from the mempool.
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);
    // F-HTLC-2 rollover-liveness: the tip advanced, so evict any special tx a
    // height-monotonic-tightening rule now rejects permanently for the NEXT
    // block (pindexNew->nHeight + 1). Without this a min-margin HTLC_CLAIM that
    // rolled over one block would linger and poison future templates.
    mempool.removeForSpecialTxHeightChange(*pcoinsTip, pindexNew->nHeight + 1);
    // Update chainActive & related variables.
    UpdateTip(pindexNew);
    // BATHRON: Legacy mnodeman calls removed - DMN system handles all MN state
    deterministicMNManager->SetTipIndex(pindexNew);

    int64_t nTime6 = GetTimeMicros();
    nTimePostConnect += nTime6 - nTime5;
    nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCHMARK, "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint(BCLog::BENCHMARK, "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));

    // HU Signaling: Notify that block was connected (triggers MN signing if in quorum)
    if (g_connman) {
        hu::NotifyBlockConnected(pindexNew, g_connman.get());
    }

    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
static CBlockIndex* FindMostWorkChain()
{
    do {
        CBlockIndex* pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex* pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex* pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.emplace(pindexFailed->pprev, pindexFailed);
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while (true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
static void PruneBlockIndexCandidates()
{
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 */
static bool ActivateBestChainStep(CValidationState& state, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);
    const CBlockIndex* pindexOldTip = chainActive.Tip();
    const CBlockIndex* pindexFork = chainActive.FindFork(pindexMostWork);

    // BATHRON HU FINALITY: Check if this reorg would violate finality (BFT guarantee)
    // Per BLUEPRINT: NEVER reorg below lastFinalizedHeight
    if (pindexFork && chainActive.Tip() && pindexFork != chainActive.Tip()) {
        if (hu::WouldViolateHuFinality(pindexMostWork, pindexFork)) {
            return state.DoS(100, error("%s: HU Finality violation - cannot reorg past finalized block",
                                        __func__), REJECT_INVALID, "bad-hu-finality-reorg");
        }
    }

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, Params(), &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);

            // If we're unable to disconnect a block during normal operation,
            // then that is a failure of our local system -- we should abort
            // rather than stay on a less work chain.
            return AbortNode(state, "Failed to disconnect block; see debug.log for details");
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex* pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        LogPrintf("DEBUG-HANG: ActivateBestChainStep connecting %d blocks\n", vpindexToConnect.size());
        for (CBlockIndex* pindexConnect : reverse_iterate(vpindexToConnect)) {
            LogPrintf("DEBUG-HANG: ActivateBestChainStep calling ConnectTip for height=%d\n", pindexConnect->nHeight);
            if (!ConnectTip(state, pindexConnect, (pindexConnect == pindexMostWork) ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible()) {
                        InvalidChainFound(vpindexToConnect.front());
                    }
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);
    }
    mempool.check(pcoinsTip.get());

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either nullptr or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */

bool ActivateBestChain(CValidationState& state, std::shared_ptr<const CBlock> pblock)
{
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);
    LogPrintf("DEBUG-HANG: ActivateBestChain ENTER block=%s\n", pblock ? pblock->GetHash().ToString().substr(0, 16) : "null");

    // Increment counter to prevent DMM from producing while we're syncing
    // Uses counter to handle recursive/nested calls correctly
    g_activating_best_chain.fetch_add(1);

    // ABC maintains a fair degree of expensive-to-calculate internal state
    // because this function periodically releases cs_main so that it does not lock up other threads for too long
    // during large connects - and to allow for e.g. the callback queue to drain
    // we use m_cs_chainstate to enforce mutual exclusion so that only one caller may execute this function at a time
    LogPrintf("DEBUG-HANG: ActivateBestChain acquiring m_cs_chainstate...\n");
    LOCK(m_cs_chainstate);
    LogPrintf("DEBUG-HANG: ActivateBestChain got m_cs_chainstate\n");

    CBlockIndex* pindexNewTip = nullptr;
    CBlockIndex* pindexMostWork = nullptr;
    do {
        LogPrintf("DEBUG-HANG: ActivateBestChain loop iteration start\n");
        boost::this_thread::interruption_point();

        int pending = GetMainSignals().CallbacksPending();
        if (pending > 10) {
            LogPrintf("DEBUG-HANG: ActivateBestChain SyncWithValidationInterfaceQueue (pending=%d)...\n", pending);
            // Block until the validation queue drains. This should largely
            // never happen in normal operation, however may happen during
            // reindex, causing memory blowup  if we run too far ahead.
            SyncWithValidationInterfaceQueue();
            LogPrintf("DEBUG-HANG: ActivateBestChain SyncWithValidationInterfaceQueue DONE\n");
        }

        {
            LogPrintf("DEBUG-HANG: ActivateBestChain acquiring cs_main...\n");
            LOCK(cs_main);
            LogPrintf("DEBUG-HANG: ActivateBestChain got cs_main, acquiring mempool.cs...\n");
            LOCK(mempool.cs); // Lock transaction pool for at least as long as it takes for connectTrace to be consumed
            LogPrintf("DEBUG-HANG: ActivateBestChain got mempool.cs\n");
            CBlockIndex* starting_tip = chainActive.Tip();
            bool blocks_connected = false;
            do {
                // We absolutely may not unlock cs_main until we've made forward progress
                // (with the exception of shutdown due to hardware issues, low disk space, etc).
                ConnectTrace connectTrace; // Destructed before cs_main is unlocked

                if (pindexMostWork == nullptr) {
                    pindexMostWork = FindMostWorkChain();
                }

                // Whether we have anything to do at all.
                if (pindexMostWork == nullptr || pindexMostWork == chainActive.Tip()) {
                    break;
                }

                bool fInvalidFound = false;
                std::shared_ptr<const CBlock> nullBlockPtr;
                LogPrintf("DEBUG-HANG: Calling ActivateBestChainStep (mostWork=%d)...\n", pindexMostWork ? pindexMostWork->nHeight : -1);
                if (!ActivateBestChainStep(state, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace)) {
                    LogPrintf("DEBUG-HANG: ActivateBestChainStep FAILED\n");
                    return false;
                }
                LogPrintf("DEBUG-HANG: ActivateBestChainStep returned OK\n");
                blocks_connected = true;

                if (fInvalidFound) {
                    // Wipe cache, we may need another branch now.
                    pindexMostWork = nullptr;
                }
                pindexNewTip = chainActive.Tip();

                for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                    assert(trace.pblock && trace.pindex);
                    GetMainSignals().BlockConnected(trace.pblock, trace.pindex);
                }
            } while (!chainActive.Tip() || (starting_tip && CBlockIndexWorkComparator()(chainActive.Tip(), starting_tip)));
            if (!blocks_connected) {
                g_activating_best_chain.store(false);
                return true;
            }

            const CBlockIndex* pindexFork = chainActive.FindFork(starting_tip);
            bool fInitialDownload = IsInitialBlockDownload();

            // Notify external listeners about the new tip.
            // Enqueue while holding cs_main to ensure that UpdatedBlockTip is called in the order in which blocks are connected
            if (pindexFork != pindexNewTip) {
                // Notify ValidationInterface subscribers
                GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

                // Always notify the UI if a new block tip was connected
                uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
            }
        }

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested())
            break;
    } while (pindexMostWork != chainActive.Tip());

    CheckBlockIndex();

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC)) {
        g_activating_best_chain.fetch_sub(1);
        return false;
    }

    g_activating_best_chain.fetch_sub(1);
    return true;
}

bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    // HU FINALITY PROTECTION: Cannot invalidate/reorg blocks with HU finality
    // This is the ONLY place where HU prevents chain changes - block production is never blocked
    if (hu::finalityHandler && hu::finalityHandler->HasFinality(pindex->nHeight, pindex->GetBlockHash())) {
        return state.DoS(100, error("%s: Cannot invalidate block %s at height %d - has HU finality",
                                    __func__, pindex->GetBlockHash().ToString(), pindex->nHeight),
                         REJECT_INVALID, "hu-finality-protected");
    }

    // hu-finality-4: the in-memory check above only covers `pindex` itself. Invalidating
    // it disconnects the WHOLE span [pindex .. tip], so guard the full span against the
    // authoritative finality DB (pFinalityDB) — this also catches the post-restart case
    // where the in-memory handler is empty but the DB still records the finality.
    if (chainActive.Contains(pindex) &&
        hu::WouldViolateHuFinality(pindex, pindex->pprev)) {
        return state.DoS(100, error("%s: Cannot invalidate block %s at height %d - disconnect "
                                    "span contains an HU-finalized block",
                                    __func__, pindex->GetBlockHash().ToString(), pindex->nHeight),
                         REJECT_INVALID, "hu-finality-protected");
    }

    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);

    LOCK(mempool.cs); // Lock for as long as disconnectpool is in scope to make sure UpdateMempoolForReorg is called after DisconnectTip without unlocking in between
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Contains(pindex)) {
        CBlockIndex* pindexWalk = chainActive.Tip();
        pindexWalk->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(pindexWalk);
        setBlockIndexCandidates.erase(pindexWalk);
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // It's probably hopeless to try to make the mempool consistent
            // here if DisconnectTip failed, but we can try.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
    }

    // DisconnectTip will add transactions to disconnectpool; try to add these
    // back to the mempool.
    UpdateMempoolForReorg(disconnectpool, true);

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    return true;
}

bool ReconsiderBlock(CValidationState& state, CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}

static CBlockIndex* AddToBlockIndex(const CBlock& block) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    // Check for duplicate
    uint256 hash = block.GetHash();
    CBlockIndex* pindex = LookupBlockIndex(hash);
    if (pindex)
        return pindex;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.emplace(hash, pindexNew).first;

    pindexNew->phashBlock = &((*mi).first);
    CBlockIndex* pprev = LookupBlockIndex(block.hashPrevBlock);
    if (pprev) {
        pindexNew->pprev = pprev;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockWeight(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool ReceivedBlockTransactions(const CBlock& block, CValidationState& state, CBlockIndex* pindexNew, const FlatFilePos& pos)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;

    // Sapling
    CAmount saplingValue = 0;
    for (const auto& tx : block.vtx) {
        if (tx->IsShieldedTx()) {
            // Negative valueBalance "takes" money from the transparent value pool
            // and adds it to the Sapling value pool. Positive valueBalance "gives"
            // money to the transparent value pool, removing from the Sapling value
            // pool. So we invert the sign here.
            saplingValue += -tx->sapData->valueBalance;
        }
    }
    pindexNew->nSaplingValue = saplingValue;
    pindexNew->nChainSaplingValue = nullopt;

    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->nChainTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex* pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;

            // Sapling, update chain value
            pindex->SetChainSaplingValue();

            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.emplace(pindexNew->pprev, pindexNew);
        }
    }

    return true;
}

bool FindBlockPos(CValidationState& state, FlatFilePos& pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nFile, vinfoBlockFile[nFile].ToString());
        }
        FlushBlockFile(!fKnown);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        bool out_of_space;
        BlockFileSeq().Allocate(pos, nAddSize, out_of_space);
        if (out_of_space) {
            return AbortNode("Disk space is low!", _("Error: Disk space is low!"));
        }
        // future: add prunning flag check
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

bool FindUndoPos(CValidationState& state, int nFile, FlatFilePos& pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    bool out_of_space;
    UndoFileSeq().Allocate(pos, nAddSize, out_of_space);
    if (out_of_space) {
        return AbortNode(state, "Disk space is low!", _("Error: Disk space is low!"));
    }
    // future: add prunning flag check

    return true;
}

// cumulative size of all shielded txes inside a block
static unsigned int GetTotalShieldedTxSize(const CBlock& block)
{
    unsigned int nSizeShielded = 0;
    for (const auto& tx : block.vtx) {
        if (tx->IsShieldedTx()) nSizeShielded += tx->GetTotalSize();
    }
    return nSizeShielded;
}

bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig)
{
    AssertLockHeld(cs_main);

    if (block.fChecked)
        return true;

    // These are checks that are independent of context.
    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // Size limits
    unsigned int nMaxBlockSize = MAX_BLOCK_SIZE_CURRENT;
    const unsigned int nBlockSize = ::GetSerializeSize(block, PROTOCOL_VERSION);
    if (block.vtx.empty() || block.vtx.size() > nMaxBlockSize || nBlockSize > nMaxBlockSize)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // Check shielded txes limits (no need to check if the block size is already under 750kB)
    if (nBlockSize > MAX_BLOCK_SHIELDED_TXES_SIZE && GetTotalShieldedTxSize(block) > MAX_BLOCK_SHIELDED_TXES_SIZE)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-shielded-size", false, "shielded size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // BP-SPVMNPUB R8: at most ONE *published* (MN, non-null publisher)
    // TX_BTC_HEADERS per block. The genesis seed (block 1) carries the whole BTC
    // header history split into several NULL-publisher TX_BTC_HEADERS (chunks of
    // BTCHEADERS_GENESIS_MAX_COUNT) — those are exempt: a null publisher only
    // passes full validation during genesis/bootstrap (CheckBtcHeadersTx rejects
    // a null publisher otherwise), so they cannot be used to spam a normal block.
    {
        int publishedBtcHeadersTx = 0;
        for (const auto& tx : block.vtx) {
            if (tx->nType == CTransaction::TxType::TX_BTC_HEADERS) {
                BtcHeadersPayload r8Payload;
                if (!GetBtcHeadersPayload(*tx, r8Payload) || r8Payload.publisherProTxHash.IsNull()) {
                    continue;  // genesis/bootstrap seed tx — exempt from the per-block cap
                }
                publishedBtcHeadersTx++;
                if (publishedBtcHeadersTx > 1) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-block-multiple-btcheaders",
                                     false, "more than one published TX_BTC_HEADERS in block");
                }
            }
        }
    }

    // Reject a block that does not build on our tip and whose parent we have
    // never indexed (out of order). Payee/DMM validation happens later in
    // ConnectBlock, not here.
    CBlockIndex* pindexPrev = chainActive.Tip();
    if (pindexPrev != nullptr && block.hashPrevBlock != UINT256_ZERO) {
        if (pindexPrev->GetBlockHash() != block.hashPrevBlock) {
            //out of order
            CBlockIndex* pindexPrev = LookupBlockIndex(block.hashPrevBlock);
            if (!pindexPrev) {
                return state.Error("blk-out-of-order");
            }
        }
    }

    // Check transactions
    for (const auto& txIn : block.vtx) {
        const CTransaction& tx = *txIn;
        if (!CheckTransaction(tx, state)) {
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                    strprintf("Transaction check failed (tx hash %s) %s", tx.GetHash().ToString(), state.GetDebugMessage()));
        }

        // Non-contextual checks for special txes
        if (!CheckSpecialTxNoContext(tx, state)) {
            // pass the state returned by the function above
            return false;
        }
    }

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx) {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    unsigned int nMaxBlockSigOps = MAX_BLOCK_SIGOPS_CURRENT;
    if (nSigOps > nMaxBlockSigOps)
        return state.DoS(100, error("%s : out-of-bounds SigOpCount", __func__),
            REJECT_INVALID, "bad-blk-sigops", true);

    // Check block signature.
    if (fCheckSig && !CheckBlockSignature(block)) {
        return state.DoS(100, error("%s : bad block signature", __func__),
                         REJECT_INVALID, "bad-block-sig", true);
    }

    if (fCheckPOW && fCheckMerkleRoot && fCheckSig)
        block.fChecked = true;

    return true;
}

bool CheckWork(const CBlock& block, const CBlockIndex* const pindexPrev)
{
    if (pindexPrev == nullptr)
        return error("%s : null pindexPrev for block %s", __func__, block.GetHash().GetHex());

    unsigned int nBitsRequired = GetBlockDifficultyBits(pindexPrev, &block);

    if (block.nBits != nBitsRequired) {
        return error("%s : incorrect proof of work at %d", __func__, pindexPrev->nHeight + 1);
    }

    return true;
}

bool CheckBlockTime(const CBlockHeader& block, CValidationState& state, CBlockIndex* const pindexPrev)
{
    // Not enforced on RegTest
    if (Params().IsRegTestNet())
        return true;

    const int64_t blockTime = block.GetBlockTime();
    const int blockHeight = pindexPrev->nHeight + 1;

    // BATHRON: Relax time checks during bootstrap phase (blocks 1..nDMMBootstrapHeight)
    // During bootstrap, blocks are generated rapidly via generatebootstrap RPC.
    // DMM takes over timing enforcement after bootstrap is complete.
    if (blockHeight <= Params().GetConsensus().nDMMBootstrapHeight) {
        // Only enforce basic time slot alignment during bootstrap
        if (!Params().GetConsensus().IsValidBlockTimeStamp(blockTime, blockHeight))
            return state.DoS(100, error("%s : block timestamp mask not valid", __func__), REJECT_INVALID, "invalid-time-mask");
        return true;
    }

    // Check blocktime against future drift (WANT: blk_time <= Now + MaxDrift)
    if (blockTime > pindexPrev->MaxFutureBlockTime())
        return state.Invalid(error("%s : block timestamp too far in the future", __func__), REJECT_INVALID, "time-too-new");

    // dmm-production-1: lower bound on block time. The block timestamp must be
    // strictly greater than the median of the previous 11 blocks (BIP113-style).
    // Without it a producer can sign a non-monotonic / backdated timestamp that all
    // nodes accept, corrupting the DMM slot math (which derives the slot from
    // blockTime) and time-based locks. (The old "blockTime > MinPastBlockTime"
    // check was dropped for DMM; median-time-past is the correct, spacing-agnostic
    // replacement — it never rejects a forward-moving block.)
    if (blockTime <= pindexPrev->GetMedianTimePast())
        return state.Invalid(error("%s : block timestamp too old (<= median-time-past)", __func__), REJECT_INVALID, "time-too-old");

    // Check blocktime mask
    if (!Params().GetConsensus().IsValidBlockTimeStamp(blockTime, blockHeight))
        return state.DoS(100, error("%s : block timestamp mask not valid", __func__), REJECT_INVALID, "invalid-time-mask");

    // All good
    return true;
}

//! Returns last CBlockIndex* that is a checkpoint
static const CBlockIndex* GetLastCheckpoint() EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    if (!Checkpoints::fEnabled)
        return nullptr;

    const MapCheckpoints& checkpoints = *Params().Checkpoints().mapCheckpoints;

    for (const auto& i : reverse_iterate(checkpoints)) {
        const uint256& hash = i.second;
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex)
            return pindex;
    }
    return nullptr;
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex* const pindexPrev)
{
    AssertLockHeld(cs_main);

    const Consensus::Params& consensus = Params().GetConsensus();
    uint256 hash = block.GetHash();

    if (hash == consensus.hashGenesisBlock)
        return true;

    assert(pindexPrev);

    const int nHeight = pindexPrev->nHeight + 1;
    const int chainHeight = chainActive.Height();

    //If this is a reorg, check that it is not too deep
    int nMaxReorgDepth = gArgs.GetArg("-maxreorg", DEFAULT_MAX_REORG_DEPTH);
    if (chainHeight - nHeight >= nMaxReorgDepth)
        return state.DoS(1, error("%s: forked chain older than max reorganization depth (height %d)", __func__, chainHeight - nHeight));

    // Check blocktime (past limit, future limit and mask)
    if (!CheckBlockTime(block, state, pindexPrev))
        return false;

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckBlock(nHeight, hash))
        return state.DoS(100, error("%s : rejected by checkpoint lock-in at %d", __func__, nHeight),
            REJECT_CHECKPOINT, "checkpoint mismatch");

    // Don't accept any forks from the main chain prior to last checkpoint
    const CBlockIndex* pcheckpoint = GetLastCheckpoint();
    if (pcheckpoint && nHeight < pcheckpoint->nHeight)
        return state.DoS(0, error("%s : forked chain older than last checkpoint (height %d)", __func__, nHeight));

    // Reject outdated version blocks
    if ((block.nVersion < 3 && nHeight >= 1) ||
        (block.nVersion < 5 && consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BIP65)) ||
        (block.nVersion < 6 && consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_V3_4)) ||
        (block.nVersion < 7 && consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_V4_0)) ||
        (block.nVersion < 8 && consensus.NetworkUpgradeActive(nHeight, Consensus::UPGRADE_V5_0)))
    {
        std::string stringErr = strprintf("rejected block version %d at height %d", block.nVersion, nHeight);
        return state.Invalid(false, REJECT_OBSOLETE, "bad-version", stringErr);
    }

    return true;
}

bool ContextualCheckBlock(const CBlock& block, CValidationState& state, CBlockIndex* const pindexPrev)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;
    const CChainParams& chainparams = Params();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {

        // Check transaction contextually against consensus rules at block height
        if (!ContextualCheckTransaction(tx, state, chainparams, nHeight, true /* isMined */, IsInitialBlockDownload())) {
            return false;
        }

        if (!IsFinalTx(tx, nHeight, block.GetBlockTime())) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
    if (pindexPrev) { // pindexPrev is only null on the first block which is a version 1 block.
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // DAEMON-ONLY BURN FLOW
    // ═══════════════════════════════════════════════════════════════════════════
    // Block 1: TX_BTC_HEADERS only (BTC headers from checkpoint)
    // Burns: Detected by burn_claim_daemon after network starts
    // All burns use same K_FINALITY (20 testnet, 100 mainnet)
    // ═══════════════════════════════════════════════════════════════════════════
    if (nHeight == 1) {
        // Count TX_BURN_CLAIM and TX_BTC_HEADERS for logging
        size_t claimCount = 0;
        size_t headerCount = 0;
        for (const auto& tx : block.vtx) {
            if (tx->nType == CTransaction::TxType::TX_BURN_CLAIM) {
                claimCount++;
            } else if (tx->nType == CTransaction::TxType::TX_BTC_HEADERS) {
                headerCount++;
            }
        }
        LogPrintf("GENESIS: Block 1 contains %zu TX_BTC_HEADERS and %zu TX_BURN_CLAIM\n",
            headerCount, claimCount);
    }

    return true;
}

// Get the index of previous block of given CBlock
static bool GetPrevIndex(const CBlock& block, CBlockIndex** pindexPrevRet, CValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    CBlockIndex*& pindexPrev = *pindexPrevRet;
    pindexPrev = nullptr;
    if (block.GetHash() != Params().GetConsensus().hashGenesisBlock) {
        pindexPrev = LookupBlockIndex(block.hashPrevBlock);
        if (!pindexPrev) {
            return state.DoS(0, error("%s : prev block %s not found", __func__, block.hashPrevBlock.GetHex()), 0,
                             "prevblk-not-found");
        }
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK) {
            //If this "invalid" block is an exact match from the checkpoints, then reconsider it
            if (Checkpoints::CheckBlock(pindexPrev->nHeight, block.hashPrevBlock, true)) {
                LogPrintf("%s : Reconsidering block %s height %d\n", __func__, block.hashPrevBlock.ToString(), pindexPrev->nHeight);
                CValidationState statePrev;
                ReconsiderBlock(statePrev, pindexPrev);
                if (statePrev.IsValid()) {
                    ActivateBestChain(statePrev);
                    return true;
                }
            }
            return state.DoS(100, error("%s : prev block %s is invalid, unable to add block %s", __func__, block.hashPrevBlock.GetHex(), block.GetHash().GetHex()),
                             REJECT_INVALID, "bad-prevblk");
        }
    }
    return true;
}

bool AcceptBlockHeader(const CBlock& block, CValidationState& state, CBlockIndex** ppindex, CBlockIndex* pindexPrev)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    const uint256& hash = block.GetHash();
    CBlockIndex* pindex = LookupBlockIndex(hash);

    // TODO : ENABLE BLOCK CACHE IN SPECIFIC CASES
    if (pindex) {
        // Block header is already known.
        if (ppindex)
            *ppindex = pindex;
        if (pindex->nStatus & BLOCK_FAILED_MASK)
            return state.Invalid(error("%s : block is marked invalid", __func__), 0, "duplicate");
        return true;
    }

    // Get prev block index
    if (pindexPrev == nullptr && !GetPrevIndex(block, &pindexPrev, state)) {
        return false;
    }

    if (!ContextualCheckBlockHeader(block, state, pindexPrev))
        return error("%s: ContextualCheckBlockHeader failed for block %s: %s", __func__, hash.ToString(), FormatStateMessage(state));

    // Check for conflicting HU finality UNLESS that's the genesis block
    if (block.GetHash() != Params().GetConsensus().hashGenesisBlock && hu::finalityHandler) {
        if (hu::finalityHandler->HasConflictingFinality(pindexPrev->nHeight + 1, hash)) {
            return state.DoS(10, error("%s: conflicting with HU finality", __func__), REJECT_INVALID, "bad-hu-finality");
        }
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex();

    // Notify external listeners about accepted block header
    GetMainSignals().AcceptedBlockHeader(pindex);
    return true;
}

/*
 * Collect the sets of regular utxo inputs spent by in-block txes.
 * Also, check that there are no in-block double spends.
 */
static bool CheckInBlockDoubleSpends(const CBlock& block, int nHeight, CValidationState& state,
                                     std::unordered_set<COutPoint, SaltedOutpointHasher>& spent_outpoints)
{
    // First collect the tx inputs, and check double spends
    for (size_t i = 1; i < block.vtx.size(); i++) {
        // skip coinbase
        CTransactionRef tx = block.vtx[i];
        for (const CTxIn& in: tx->vin) {
            // regular utxo
            if (spent_outpoints.find(in.prevout) != spent_outpoints.end()) {
                return state.DoS(100, error("%s: inputs double spent in the same block", __func__));
            }
            spent_outpoints.insert(in.prevout);
        }
    }

    // Then remove from the coins_spent set, any coin that was created inside this block.
    // In fact, if a transaction inside this block spends an output generated by another in-block tx,
    // such output doesn't exist on chain yet, so we must not access the coins cache, or "walk the fork",
    // to ensure that it was unspent before this block.
    std::unordered_set<uint256> inblock_txes;
    for (size_t i = 1; i < block.vtx.size(); i++) {
        // coinbase outputs cannot be spent inside the same block
        inblock_txes.insert(block.vtx[i]->GetHash());
    }
    for (auto it = spent_outpoints.begin(); it != spent_outpoints.end(); /* no increment */) {
        if (inblock_txes.find(it->hash) != inblock_txes.end()) {
            // the input spent was created as output of another in-block tx - valid in-block spend
            it = spent_outpoints.erase(it);
        } else {
            it++;
        }
    }

    return true;
}

/*
 * Check whether ALL the provided inputs (outpoints) are UNSPENT on
 * a forked (non currently active) chain.
 * Start from startIndex and go backwards on the forked chain, down to the split block.
 * Return false if any block contains a tx spending an input included in the provided set.
 * Return false also when the fork is longer than -maxreorg.
 * Return true otherwise.
 * Save in pindexFork the index of the pre-split block (last common block with the active chain).
 * Remove from the outpoints set, any coin that was created in the fork (we don't
 * need to check that it was unspent on the active chain before the split).
 */
static bool IsUnspentOnFork(std::unordered_set<COutPoint, SaltedOutpointHasher>& outpoints,
                            const CBlockIndex* startIndex, CValidationState& state, const CBlockIndex*& pindexFork)
{
    // Go backwards on the forked chain up to the split
    int readBlock = 0;
    pindexFork = startIndex;
    for ( ; !chainActive.Contains(pindexFork); pindexFork = pindexFork->pprev) {
        // Check if the forked chain is longer than the max reorg limit
        if (++readBlock == gArgs.GetArg("-maxreorg", DEFAULT_MAX_REORG_DEPTH)) {
            // TODO: Remove this chain from disk.
            return error("%s: forked chain longer than maximum reorg limit", __func__);
        }
        if (pindexFork->pprev == nullptr) {
            return error("%s: null pprev for block %s", __func__, pindexFork->GetBlockHash().GetHex());
        }

        // if there are no coins left, don't read the block
        if (outpoints.empty()) continue;

        // read block
        CBlock bl;
        if (!ReadBlockFromDisk(bl, pindexFork)) {
            return error("%s: block %s not on disk", __func__, pindexFork->GetBlockHash().GetHex());
        }
        // Loop through every tx of this block
        // (reversed because we first check spent outpoints, and then remove created ones)
        for (auto it = bl.vtx.rbegin(); it != bl.vtx.rend(); ++it) {
            CTransactionRef tx = *it;
            // Loop through every input of this tx
            for (const CTxIn& in: tx->vin) {
                // check if any of the provided outpoints is being spent
                if (outpoints.find(in.prevout) != outpoints.end()) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-spent-fork-post-split");
                }
            }
            // Then remove from the outpoints set, any coin created by this tx
            const uint256& txid = tx->GetHash();
            for (size_t i = 0; i < tx->vout.size(); i++) {
                // erase if present (no-op if not)
                outpoints.erase(COutPoint(txid, i));
            }
        }
    }

    // All the provided outpoints are not spent on the fork,
    // and this fork is below the max reorg depth
    return true;
}

/*
 * Check whether ALL the provided inputs (regular utxos) are SPENT on the currently active chain.
 * Start from the block on top of pindexFork, and go upwards on the active chain, up to the tip.
 * Remove from the 'outpoints' set, all the inputs spent by transactions included in the scanned
 * blocks. At the end, return true if the set is empty (all outpoints are spent), and false
 * otherwise (some outpoint is unspent).
 */
static bool IsSpentOnActiveChain(std::unordered_set<COutPoint, SaltedOutpointHasher>& outpoints, const CBlockIndex* pindexFork)
{
    assert(chainActive.Contains(pindexFork));
    const int height_start = pindexFork->nHeight + 1;
    const int height_end = chainActive.Height();

    // Go upwards on the active chain till the tip
    for (int height = height_start; height <= height_end && !outpoints.empty(); height++) {
        // read block
        const CBlockIndex* pindex = mapBlockIndex.at(chainActive[height]->GetBlockHash());
        CBlock bl;
        if (!ReadBlockFromDisk(bl, pindex)) {
            return error("%s: block %s not on disk", __func__, pindex->GetBlockHash().GetHex());
        }
        // Loop through every tx of this block
        for (const auto& tx : bl.vtx) {
            // Loop through every input of this tx
            for (const CTxIn& in: tx->vin) {
                // erase if present (no-op if not)
                outpoints.erase(in.prevout);
            }
        }
    }

    return outpoints.empty();
}

static bool AcceptBlock(const CBlock& block, CValidationState& state, CBlockIndex** ppindex, const FlatFilePos* dbp) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    LogPrintf("DEBUG-HANG: AcceptBlock ENTER block=%s\n", block.GetHash().ToString().substr(0, 16));

    CBlockIndex* pindexDummy = nullptr;
    CBlockIndex*& pindex = ppindex ? *ppindex : pindexDummy;

    const Consensus::Params& consensus = Params().GetConsensus();

    // Get prev block index
    CBlockIndex* pindexPrev = nullptr;
    if (!GetPrevIndex(block, &pindexPrev, state))
        return false;
    LogPrintf("DEBUG-HANG: AcceptBlock GetPrevIndex OK (prev=%d)\n", pindexPrev ? pindexPrev->nHeight : -1);

    // Block validation via CheckWork (genesis and standard blocks)
    if (block.GetHash() != consensus.hashGenesisBlock && !CheckWork(block, pindexPrev))
        return state.DoS(100, false, REJECT_INVALID);
    LogPrintf("DEBUG-HANG: AcceptBlock CheckWork OK\n");

    if (!AcceptBlockHeader(block, state, &pindex, pindexPrev))
        return false;
    LogPrintf("DEBUG-HANG: AcceptBlock AcceptBlockHeader OK (height=%d)\n", pindex ? pindex->nHeight : -1);

    if (pindex->nStatus & BLOCK_HAVE_DATA) {
        // We already have this exact block (same hash). This is safe to skip.
        // Note: Different blocks at same height have different hashes, so they
        // would have different pindex entries and wouldn't hit this branch.
        LogPrint(BCLog::VALIDATION, "%s: already have block %d %s\n",
                 __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
        return true;
    }

    if (!CheckBlock(block, state) || !ContextualCheckBlock(block, state, pindex->pprev)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    int nHeight = pindex->nHeight;

    // EARLY MN SIGNATURE VALIDATION (before storing block to disk)
    // This prevents fork attacks where invalid blocks get stored first.
    // Invalid blocks signed by wrong producers are rejected BEFORE WriteBlockToDisk.
    // Also applies PoSe penalties for MNs that missed their production slot.
    // NOTE: Skip during IBD - evodb may not have data for previous blocks yet.
    // Full validation still happens in ConnectBlock -> ProcessSpecialTxsInBlock.
    //
    // CRITICAL FIX: Also skip if block is ahead of our chain tip. During P2P sync,
    // we receive blocks out of order. evodb only has data up to chainActive.Tip(),
    // so blocks beyond that height cannot be validated yet.
    int chainHeight = chainActive.Height();
    bool blockAheadOfTip = pindexPrev && (pindexPrev->nHeight > chainHeight);
    if (!Params().IsRegTestNet() && pindexPrev && !IsInitialBlockDownload() && !blockAheadOfTip) {
        // Skip genesis (has no prev) and bootstrap phase blocks
        if (nHeight > consensus.nDMMBootstrapHeight) {
            // Get DMN list at previous block
            if (deterministicMNManager) {
                CDeterministicMNList mnList = deterministicMNManager->GetListForBlock(pindexPrev);

                // Validate against the SAME bootstrap-aware eligible producer set the
                // scheduler uses (CalculateBlockProducerScores: bootstrap-trust +
                // confirmed MNs), not GetConfirmedMNsCount() — the confirmed-only gate
                // skipped the producer check for the whole post-bootstrap-pre-confirmation
                // window (~1440 blocks on mainnet). Empty set → no producer to check.
                if (!mn_consensus::CalculateBlockProducerScores(pindexPrev, mnList).empty()) {
                    std::vector<uint256> skippedMNs;
                    int producerIndex = 0;

                    // Use extended verification that also identifies skipped MNs
                    // PoSe penalties are applied in CDeterministicMNManager::BuildNewListFromBlock
                    if (!mn_consensus::VerifyBlockProducerSignatureWithPoSe(block, pindexPrev, mnList, state, skippedMNs, producerIndex)) {
                        // Mark as invalid and reject BEFORE storing
                        pindex->nStatus |= BLOCK_FAILED_VALID;
                        setDirtyBlockIndex.insert(pindex);
                        LogPrintf("%s: REJECTED block %d - early MN signature validation failed: %s\n",
                                  __func__, nHeight, FormatStateMessage(state));
                        return false;
                    }

                    // Log fallback usage (actual PoSe penalties applied in BuildNewListFromBlock)
                    if (producerIndex > 0) {
                        LogPrint(BCLog::VALIDATION, "%s: Block %d used fallback producer #%d (%d MN(s) missed slot)\n",
                                 __func__, nHeight, producerIndex, (int)skippedMNs.size());
                    }

                    LogPrint(BCLog::VALIDATION, "%s: Early MN signature validation PASSED for block %d\n",
                             __func__, nHeight);
                }
            }
        }
    }
    LogPrintf("DEBUG-HANG: AcceptBlock MN signature validation complete\n");

    // MN-only - these checks apply to all blocks
    {
        // Blocks arrives in order, so if prev block is not the tip then we are on a fork.
        // Extra info: duplicated blocks are skipping this checks, so we don't have to worry about those here.
        //
        // CRITICAL FIX: If pindexPrev is ahead of our chain tip, it's NOT a fork - we're just
        // behind during initial sync. Only consider it a fork if pindexPrev is at or below our tip
        // but not in our active chain.
        bool isBlockFromFork = pindexPrev != nullptr &&
                               chainActive.Tip() != pindexPrev &&
                               pindexPrev->nHeight <= chainActive.Height();

        // Collect spent_outpoints and check for in-block double spends
        std::unordered_set<COutPoint, SaltedOutpointHasher> spent_outpoints;
        if (!CheckInBlockDoubleSpends(block, nHeight, state, spent_outpoints)) {
            return false;
        }

        // If this is a fork, check if all the tx inputs were spent in the fork
        // Start at the block we're adding on to.
        // Also remove from spent_outpoints any coin that was created in the fork
        const CBlockIndex* pindexFork{nullptr}; // index of the split block (last common block between fork and active chain)
        if (isBlockFromFork && !IsUnspentOnFork(spent_outpoints, pindexPrev, state, pindexFork)) {
            return false;
        }
        assert(!isBlockFromFork || pindexFork != nullptr);

        // Reject forks below maxdepth
        if (isBlockFromFork && chainActive.Height() - pindexFork->nHeight > gArgs.GetArg("-maxreorg", DEFAULT_MAX_REORG_DEPTH)) {
            // TODO: Remove this chain from disk.
            return error("%s: forked chain longer than maximum reorg limit", __func__);
        }

        // Check that all tx inputs were unspent on the active chain before the fork
        for (auto it = spent_outpoints.begin(); it != spent_outpoints.end(); /* no increment */) {
            const Coin& coin = pcoinsTip->AccessCoin(*it);
            if (!coin.IsSpent()) {
                // if this is on a fork, then the coin must be created before the split
                if (isBlockFromFork && (int) coin.nHeight > pindexFork->nHeight) {
                    return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-created-post-split");
                }
                // unspent on active chain
                it = spent_outpoints.erase(it);
            } else {
                // spent on active chain
                if (!isBlockFromFork)
                    return error("%s: tx inputs spent/not-available on main chain (%s)", __func__, it->ToString());
                it++;
            }
        }
        if (isBlockFromFork && !spent_outpoints.empty()) {
            // Some coins are not spent on the fork post-split, but cannot be found in the coins cache.
            // So they were either created on the fork, or spent on the active chain.
            // Since coins created in the fork are removed by IsUnspentOnFork(), if there are some coins left,
            // they were spent on the active chain.
            // If some of them was not spent after the split, then the block is invalid.
            // Walk the active chain, starting from pindexFork, going upwards till the chain tip, and check if
            // all of these coins were spent by transactions included in the scanned blocks.
            // If ALL of them are spent, then accept the block.
            // Otherwise reject it, as it means that this blocks includes a transaction with an input that is
            // either already spent before the chain split, or non-existent.
            if (!IsSpentOnActiveChain(spent_outpoints, pindexFork)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-txns-inputs-spent-fork-pre-split");
            }
        }


    }
    LogPrintf("DEBUG-HANG: AcceptBlock fork/double-spend checks complete\n");

    // Write block to history file
    try {
        unsigned int nBlockSize = ::GetSerializeSize(block, CLIENT_VERSION);
        FlatFilePos blockPos;
        if (dbp != nullptr)
            blockPos = *dbp;
        LogPrintf("DEBUG-HANG: AcceptBlock calling FindBlockPos...\n");
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, block.GetBlockTime(), dbp != nullptr))
            return error("%s : FindBlockPos failed", __func__);
        LogPrintf("DEBUG-HANG: AcceptBlock FindBlockPos OK, calling WriteBlockToDisk...\n");
        if (dbp == nullptr)
            if (!WriteBlockToDisk(block, blockPos))
                return AbortNode(state, "Failed to write block");
        LogPrintf("DEBUG-HANG: AcceptBlock WriteBlockToDisk OK, calling ReceivedBlockTransactions...\n");
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
            return error("%s : ReceivedBlockTransactions failed", __func__);
        LogPrintf("DEBUG-HANG: AcceptBlock ReceivedBlockTransactions OK\n");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    LogPrintf("DEBUG-HANG: AcceptBlock EXIT success\n");
    return true;
}

bool ProcessNewBlock(const std::shared_ptr<const CBlock>& pblock, const FlatFilePos* dbp)
{
    AssertLockNotHeld(cs_main);

    // Preliminary checks
    int64_t nStartTime = GetTimeMillis();
    int newHeight = 0;

    {
        // CheckBlock requires cs_main lock
        LOCK(cs_main);
        CValidationState state;
        LogPrintf("DEBUG-HANG: ProcessNewBlock ENTER block=%s\n", pblock->GetHash().ToString().substr(0, 16));
        if (!CheckBlock(*pblock, state)) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error ("%s : CheckBlock FAILED for block %s, %s", __func__, pblock->GetHash().GetHex(), FormatStateMessage(state));
        }
        LogPrintf("DEBUG-HANG: CheckBlock PASSED\n");

        // Store to disk
        CBlockIndex* pindex = nullptr;
        LogPrintf("DEBUG-HANG: Calling AcceptBlock...\n");
        bool ret = AcceptBlock(*pblock, state, &pindex, dbp);
        LogPrintf("DEBUG-HANG: AcceptBlock returned %d\n", ret);
        CheckBlockIndex();
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s : AcceptBlock FAILED", __func__);
        }
        newHeight = pindex->nHeight;
    }

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    LogPrintf("DEBUG-HANG: Calling ActivateBestChain for height=%d\n", newHeight);
    if (!ActivateBestChain(state, pblock))
        return error("%s : ActivateBestChain failed", __func__);

    LogPrintf("%s : ACCEPTED Block %ld in %ld milliseconds with size=%d\n", __func__, newHeight, GetTimeMillis() - nStartTime,
              GetSerializeSize(*pblock, CLIENT_VERSION));

    return true;
}

bool TestBlockValidity(CValidationState& state, const CBlock& block, CBlockIndex* const pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckBlockSig)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev);
    if (pindexPrev != chainActive.Tip()) {
        LogPrintf("%s : No longer working on chain tip\n", __func__);
        return false;
    }
    // HU Finality: Check for conflicting finalized blocks
    if (hu::finalityHandler && hu::finalityHandler->HasConflictingFinality(pindexPrev->nHeight + 1, block.GetHash())) {
        return state.DoS(10, error("%s: conflicting with HU finality", __func__), REJECT_INVALID, "bad-hu-finality");
    }

    CCoinsViewCache viewNew(pcoinsTip.get());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // begin tx and let it rollback
    auto dbTx = evoDb->BeginTransaction();

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, pindexPrev))
        return error("%s: ContextualCheckBlockHeader failed: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, fCheckPOW, fCheckMerkleRoot, fCheckBlockSig))
        return error("%s: CheckBlock failed: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, pindexPrev))
        return error("%s: ContextualCheckBlock failed: %s", __func__, FormatStateMessage(state));
    if (!ConnectBlock(block, state, &indexDummy, viewNew, true))
        return false;
    assert(state.IsValid());

    return true;
}

static FlatFileSeq BlockFileSeq()
{
    return FlatFileSeq(GetBlocksDir(), "blk", BLOCKFILE_CHUNK_SIZE);
}

static FlatFileSeq UndoFileSeq()
{
    return FlatFileSeq(GetBlocksDir(), "rev", UNDOFILE_CHUNK_SIZE);
}

FILE* OpenBlockFile(const FlatFilePos& pos, bool fReadOnly)
{
    return BlockFileSeq().Open(pos, fReadOnly);
}

FILE* OpenUndoFile(const FlatFilePos& pos, bool fReadOnly)
{
    return UndoFileSeq().Open(pos, fReadOnly);
}

fs::path GetBlockPosFilename(const FlatFilePos &pos)
{
    return BlockFileSeq().FileName(pos);
}

CBlockIndex* InsertBlockIndex(const uint256& hash)
{
    AssertLockHeld(cs_main);

    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    mi = mapBlockIndex.emplace(hash, pindexNew).first;

    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool static LoadBlockIndexDB(std::string& strError) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    if (!pblocktree->LoadBlockIndexGuts(InsertBlockIndex))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex) {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.emplace_back(pindex->nHeight, pindex);
    }
    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex*>& item : vSortedByHeight) {
        // Stop if shutdown was requested
        if (ShutdownRequested()) return false;

        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockWeight(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                    // Sapling, calculate chain index value
                    if (pindex->pprev->nChainSaplingValue) {
                        pindex->nChainSaplingValue = *pindex->pprev->nChainSaplingValue + pindex->nSaplingValue;
                    } else {
                        pindex->nChainSaplingValue = nullopt;
                    }

                } else {
                    pindex->nChainTx = 0;
                    pindex->nChainSaplingValue = nullopt;
                    mapBlocksUnlinked.emplace(pindex->pprev, pindex);
                }
            } else {
                pindex->nChainTx = pindex->nTx;
                pindex->nChainSaplingValue = pindex->nSaplingValue;
            }
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == nullptr))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<const uint256, CBlockIndex*>& item : mapBlockIndex) {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++) {
        FlatFilePos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    //Check if the shutdown procedure was followed on last client exit
    bool fLastShutdownWasPrepared = true;
    pblocktree->ReadFlag("shutdown", fLastShutdownWasPrepared);
    LogPrintf("%s: Last shutdown was prepared: %s\n", __func__, fLastShutdownWasPrepared);

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if (fReindexing) fReindex = true;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("LoadBlockIndexDB(): transaction index %s\n", fTxIndex ? "enabled" : "disabled");

    // If this is written true before the next client init, then we know the shutdown process failed
    pblocktree->WriteFlag("shutdown", false);

    return true;
}

bool LoadChainTip(const CChainParams& chainparams)
{
    AssertLockHeld(cs_main);

    if (chainActive.Tip() && chainActive.Tip()->GetBlockHash() == pcoinsTip->GetBestBlock()) return true;

    if (pcoinsTip->GetBestBlock().IsNull() && mapBlockIndex.size() == 1) {
        // In case we just added the genesis block, connect it now, so
        // that we always have a chainActive.Tip() when we return.
        LogPrintf("%s: Connecting genesis block...\n", __func__);
        CValidationState state;
        if (!ActivateBestChain(state)) {
            return false;
        }
    }

    // Load pointer to end of best chain
    CBlockIndex* pindex = LookupBlockIndex(pcoinsTip->GetBestBlock());
    if (!pindex) {
        return false;
    }
    chainActive.SetTip(pindex);

    PruneBlockIndexCandidates();

    const CBlockIndex* pChainTip = chainActive.Tip();

    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
            pChainTip->GetBlockHash().GetHex(), pChainTip->nHeight,
            FormatISO8601DateTime(pChainTip->GetBlockTime()),
            Checkpoints::GuessVerificationProgress(pChainTip));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks..."), 0);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100);
}

bool CVerifyDB::VerifyDB(CCoinsView* coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr)
        return true;

    const int chainHeight = chainActive.Height();

    // begin tx and let it rollback
    auto dbTx = evoDb->BeginTransaction();

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainHeight)
        nCheckDepth = chainHeight;
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    int reportDone = 0;
    LogPrintf("[0%%]...");
    CValidationState state;
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev) {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone);
        if (pindex->nHeight < chainHeight - nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex))
            return error("%s: *** ReadBlockFromDisk failed at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__, pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            FlatFilePos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBlockHash()))
                    return error("%s: *** found bad undo data at %d, hash=%s\n", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        // IMPORTANT: fJustCheck=true to avoid modifying BP30 LevelDB state during verification
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            DisconnectResult res = DisconnectBlock(block, pindex, coins, /*fJustCheck=*/true);
            if (res == DISCONNECT_FAILED) {
                return error("%s: *** irrecoverable inconsistency in block data at %d, hash=%s", __func__,
                             pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            pindexState = pindex->pprev;
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("%s: *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", __func__, chainHeight - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex* pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainHeight - pindex->nHeight)) / (double)nCheckDepth * 50))));
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex))
                return error("%s: *** ReadBlockFromDisk failed at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!ConnectBlock(block, state, pindex, coins, false))
                return error("%s: *** found unconnectable block at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }
    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainHeight - pindexState->nHeight, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
static bool RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);

    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex)) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout);
            }
        }

        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }

    CValidationState state;
    if (!ProcessSpecialTxsInBlock(block, pindex, &inputs, state, false /*fJustCheck*/)) {
        return error("%s: Special tx processing failed for block %s with %s",
                     __func__, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
    }

    return true;
}

bool ReplayBlocks(const CChainParams& params, CCoinsView* view)
{
    LOCK(cs_main);

    CCoinsViewCache cache(view);

    std::vector<uint256> hashHeads = view->GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("%s: unknown inconsistent state", __func__);

    uiInterface.ShowProgress(_("Replaying blocks..."), 0);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    pindexNew = LookupBlockIndex(hashHeads[0]);
    if (!pindexNew) {
        return error("%s: reorganization to unknown block requested", __func__);
    }

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        pindexOld = LookupBlockIndex(hashHeads[1]);
        if (!pindexOld) {
            return error("%s: reorganization from unknown block requested", __func__);
        }
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld)) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        if (!RollforwardBlock(pindex, cache, params)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    evoDb->WriteBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100);
    return true;
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    setBlockIndexCandidates.clear();
    chainActive.SetTip(nullptr);
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();

    for (BlockMap::value_type& entry : mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
}

bool LoadBlockIndex(std::string& strError)
{
    AssertLockHeld(cs_main);

    bool needs_init = fReindex;
    if (!fReindex) {
        if (!LoadBlockIndexDB(strError))
            return false;
        needs_init = mapBlockIndex.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        // Use the provided setting for -txindex in the new database
        fTxIndex = gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX);
        pblocktree->WriteFlag("txindex", fTxIndex);
    }
    return true;
}


bool LoadGenesisBlock()
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // mapBlockIndex. Note that we can't use chainActive here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (mapBlockIndex.count(Params().GenesisBlock().GetHash()))
        return true;

    try {
        CBlock& block = const_cast<CBlock&>(Params().GenesisBlock());
        // Start new block file
        unsigned int nBlockSize = ::GetSerializeSize(block, CLIENT_VERSION);
        FlatFilePos blockPos;
        CValidationState state;
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, 0, block.GetBlockTime()))
            return error("%s: FindBlockPos failed", __func__);
        if (!WriteBlockToDisk(block, blockPos))
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = AddToBlockIndex(block);
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
            return error("%s: genesis block not accepted", __func__);
    } catch (const std::runtime_error& e) {
         return error("%s: failed to write genesis block: %s", __func__, e.what());
     }

    return true;
}


bool LoadExternalBlockFile(FILE* fileIn, FlatFilePos* dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, FlatFilePos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    // Block checked event listener
    BlockStateCatcherWrapper stateCatcher(UINT256_ZERO);
    stateCatcher.registerEvent();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2 * MAX_BLOCK_SIZE_CURRENT, MAX_BLOCK_SIZE_CURRENT + 8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++;         // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(Params().MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> buf;
                if (memcmp(buf, Params().MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SIZE_CURRENT)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();
                CBlockIndex* pindex{nullptr};
                {
                    LOCK(cs_main);
                    // detect out of order blocks, and store them for later
                    if (hash != Params().GetConsensus().hashGenesisBlock && !LookupBlockIndex(block.hashPrevBlock)) {
                        LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__,
                                hash.ToString(), block.hashPrevBlock.ToString());
                        if (dbp)
                            mapBlocksUnknownParent.emplace(block.hashPrevBlock, *dbp);
                        continue;
                    }

                    pindex = LookupBlockIndex(hash);
                }

                // process in case the block isn't known yet
                if (!pindex || (pindex->nStatus & BLOCK_HAVE_DATA) == 0) {
                    std::shared_ptr<const CBlock> block_ptr = std::make_shared<const CBlock>(block);
                    stateCatcher.get().setBlockHash(block_ptr->GetHash());
                    if (ProcessNewBlock(block_ptr, dbp)) {
                        nLoaded++;
                    }
                    if (stateCatcher.get().stateErrorFound()) {
                        break;
                    }
                } else if (hash != Params().GetConsensus().hashGenesisBlock && pindex->nHeight % 1000 == 0) {
                    LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), pindex->nHeight);
                }

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, FlatFilePos>::iterator, std::multimap<uint256, FlatFilePos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, FlatFilePos>::iterator it = range.first;
                        if (ReadBlockFromDisk(block, it->second)) {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, block.GetHash().ToString(),
                                head.ToString());
                            std::shared_ptr<const CBlock> block_ptr = std::make_shared<const CBlock>(block);
                            if (ProcessNewBlock(block_ptr, &it->second)) {
                                nLoaded++;
                                queue.emplace_back(block.GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s : Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void static CheckBlockIndex()
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*, CBlockIndex*> forward;
    for (auto& entry : mapBlockIndex) {
        forward.emplace(entry.second->pprev, entry.second);
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex* pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr;         // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr;         // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNotTreeValid = nullptr;    // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr;   // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == Params().GetConsensus().hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis());                       // The current active chain's genesis block must be this block.
        }
        // HAVE_DATA is equivalent to VALID_TRANSACTIONS and equivalent to nTx > 0 (we stored the number of transactions in the block)
        assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0));
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId == 0); // nSequenceId can't be set for blocks that aren't linked
        // All parents having data is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstMissing != nullptr) == (pindex->nChainTx == 0));                                             // nChainTx == 0 is used to signal that all parent block's transaction data is available.
        assert(pindex->nHeight == nHeight);                                                                          // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork);                            // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight)));                                // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr);                                                                     // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr);       // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr);     // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstMissing == nullptr) {
            if (pindexFirstInvalid == nullptr) { // If this block sorts at least as good as the current tip and is valid, it must be in setBlockIndexCandidates.
                assert(setBlockIndexCandidates.count(pindex));
            }
        } else { // If this block sorts worse than the current tip, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && pindex->nStatus & BLOCK_HAVE_DATA && pindexFirstMissing != nullptr) {
            if (pindexFirstInvalid == nullptr) { // If this block has block data available, some parent doesn't, and has no invalid parents, it must be in mapBlocksUnlinked.
                assert(foundInUnlinked);
            }
        } else { // If this block does not have block data available, or all parents do, it cannot be in mapBlocksUnlinked.
            assert(!foundInUnlinked);
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

// HU: Active protocol version (enforced from genesis)
int ActiveProtocol()
{
    return MIN_PEER_PROTO_VERSION_AFTER_ENFORCEMENT;
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, FormatISO8601Date(nTimeFirst), FormatISO8601Date(nTimeLast));
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(CTxMemPool& pool)
{
    int64_t nExpiryTimeout = gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fopen((GetDataDir() / "mempool.dat").string().c_str(), "r");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t skipped = 0;
    int64_t failed = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                pool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(pool, state, tx, true, nullptr, nTime);
                if (state.IsValid()) {
                    ++count;
                } else {
                    ++failed;
                }
            } else {
                ++skipped;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            pool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i successes, %i failed, %i expired\n", count, failed, skipped);
    return true;
}

bool DumpMempool(const CTxMemPool& pool)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    static Mutex dump_mutex;
    LOCK(dump_mutex);

    {
        LOCK(pool.cs);
        for (const auto &i : pool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = pool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fopen((GetDataDir() / "mempool.dat.new").string().c_str(), "w");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << i.tx;
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        if (!FileCommit(file.Get()))
            throw std::runtime_error("FileCommit failed");
        file.fclose();
        if (!RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat")) {
            throw std::runtime_error("Rename failed");
        }
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*0.000001, (last-mid)*0.000001);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup()
    {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;

