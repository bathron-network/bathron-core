// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013-2014 The NovaCoin Developers
// Copyright (c) 2014-2018 The BlackCoin Developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BATHRON_VALIDATION_H
#define BATHRON_VALIDATION_H

#if defined(HAVE_CONFIG_H)
#include "config/bathron-config.h"
#endif

#include "amount.h"
#include "chain.h"
#include "coins.h"
#include "consensus/validation.h"
#include "fs.h"
#include "moneysupply.h"
#include "policy/feerate.h"
#include "script/script_error.h"
#include "sync.h"
#include "txmempool.h"

#include <algorithm>
#include <atomic>
#include <functional>
#include <exception>
#include <map>
#include <memory>
#include <set>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CBlockIndex;
class CBlockTreeDB;
class CCoinsViewDB;
class CBloomFilter;
class CInv;
class CConnman;
class CNode;
class CScriptCheck;

struct PrecomputedTransactionData;

/** Default for -limitancestorcount, max number of in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_LIMIT = 25;
/** Default for -limitancestorsize, maximum kilobytes of tx + all in-mempool ancestors */
static const unsigned int DEFAULT_ANCESTOR_SIZE_LIMIT = 101;
/** Default for -banscore */
static const int DEFAULT_BANSCORE_THRESHOLD = 100;
/** Default for -persistmempool */
static const bool DEFAULT_PERSIST_MEMPOOL = true;
/** Default for -limitdescendantcount, max number of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_LIMIT = 25;
/** Default for -limitdescendantsize, maximum kilobytes of in-mempool descendants */
static const unsigned int DEFAULT_DESCENDANT_SIZE_LIMIT = 101;
/** Default for -mempoolexpiry, expiration time for mempool transactions in hours */
static const unsigned int DEFAULT_MEMPOOL_EXPIRY = 72;
/** Default for -txindex */
static const bool DEFAULT_TXINDEX = true;
static const bool DEFAULT_CHECKPOINTS_ENABLED = true;
/** The maximum size for transactions we're willing to relay/mine */
static const unsigned int MAX_STANDARD_TX_SIZE = 100000;
/** Maximum kilobytes for transactions to store for processing during reorg */
static const unsigned int MAX_DISCONNECTED_TX_POOL_SIZE = 20000;
/** Default for -checkblocks */
static const signed int DEFAULT_CHECKBLOCKS = 6;
static const unsigned int DEFAULT_CHECKLEVEL = 3;
/** The maximum size of a blk?????.dat file (since 0.8) */
static const unsigned int MAX_BLOCKFILE_SIZE = 0x8000000; // 128 MiB
/** The pre-allocation chunk size for blk?????.dat files (since 0.8) */
static const unsigned int BLOCKFILE_CHUNK_SIZE = 0x1000000; // 16 MiB
/** The pre-allocation chunk size for rev?????.dat files (since 0.8) */
static const unsigned int UNDOFILE_CHUNK_SIZE = 0x100000; // 1 MiB
/** Maximum number of script-checking threads allowed */
static const int MAX_SCRIPTCHECK_THREADS = 16;
/** -par default (number of script-checking threads, 0 = auto) */
static const int DEFAULT_SCRIPTCHECK_THREADS = 0;
/** Number of blocks that can be requested at any given time from a single peer. */
static const int MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16;
/** Timeout in seconds during which a peer must stall block download progress before being disconnected. */
static const unsigned int BLOCK_STALLING_TIMEOUT = 2;
/** Size of the "block download window": how far ahead of our current height do we fetch?
 *  Larger windows tolerate larger download speed differences between peer, but increase the potential
 *  degree of disordering of blocks on disk (which make reindexing and in the future perhaps pruning
 *  harder). We'll probably want to make this a per-peer adaptive value at some point. */
static const unsigned int BLOCK_DOWNLOAD_WINDOW = 1024;
/** Time to wait (in seconds) between writing blocks/block index to disk. */
static const unsigned int DATABASE_WRITE_INTERVAL = 60 * 60;
/** Time to wait (in seconds) between flushing chainstate to disk. */
static const unsigned int DATABASE_FLUSH_INTERVAL = 24 * 60 * 60;
/** Average delay between local address broadcasts */
static constexpr std::chrono::hours AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL{24};
/** Average delay between peer address broadcasts */
static constexpr std::chrono::seconds AVG_ADDRESS_BROADCAST_INTERVAL{30};
/** Default multiplier used in the computation for shielded txes min fee */
static const unsigned int DEFAULT_SHIELDEDTXFEE_K = 10;
/** Enable bloom filter */
 static const bool DEFAULT_PEERBLOOMFILTERS = true;
/** If the tip is older than this (in seconds), the node is considered to be in initial block download. */
static const int64_t DEFAULT_MAX_TIP_AGE = 24 * 60 * 60;
/** Maximum age of our tip in seconds for us to be considered current for fee estimation */
static const int64_t MAX_FEE_ESTIMATION_TIP_AGE = 3 * 60 * 60;

struct BlockHasher {
    size_t operator()(const uint256& hash) const { return hash.GetCheapHash(); }
};

extern RecursiveMutex cs_main;
extern CTxMemPool mempool;
typedef std::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;
extern BlockMap mapBlockIndex;

extern std::atomic<bool> fImporting;
extern std::atomic<bool> fReindex;
extern int nScriptCheckThreads;
extern bool fTxIndex;
extern bool fRequireStandard;
extern bool fCheckBlockIndex;
extern size_t nCoinCacheUsage;
extern CFeeRate minRelayTxFee;
extern int64_t nMaxTipAge;

extern bool fLargeWorkForkFound;
extern bool fLargeWorkInvalidChainFound;

extern CMoneySupply MoneySupply;

/** Best header we've seen so far (used for getheaders queries' starting points). */
extern CBlockIndex* pindexBestHeader;

/**
 * Process an incoming block. This only returns after the best known valid
 * block is made active. Note that it does not, however, guarantee that the
 * specific block passed to it has been checked for validity!
 *
 * If you want to *possibly* get feedback on whether pblock is valid, you must
 * install a CValidationInterface (see validationinterface.h) - this will have
 * its BlockChecked method called whenever *any* block completes validation.
 *
 * Note that we guarantee that either the proof-of-work is valid on pblock, or
 * (and possibly also) BlockChecked will have been called.
 *
 * @param[in]   pblock     The block we want to process.
 * @param[out]  dbp        The already known disk position of pblock, or nullptr if not yet stored.
 * @return True if state.IsValid()
 */
bool ProcessNewBlock(const std::shared_ptr<const CBlock>& pblock, const FlatFilePos* dbp);

/** Open a block file (blk?????.dat) */
FILE* OpenBlockFile(const FlatFilePos& pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE* OpenUndoFile(const FlatFilePos& pos, bool fReadOnly = false);
/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const FlatFilePos &pos);
/** Import blocks from an external file */
bool LoadExternalBlockFile(FILE* fileIn, FlatFilePos* dbp = nullptr);
/** Ensures we have a genesis block in the block tree, possibly writing one to disk. */
bool LoadGenesisBlock();
/** Load the block tree and coins database from disk,
 * initializing state if we're running with -reindex. */
bool LoadBlockIndex(std::string& strError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
/** Update the chain tip based on database information. */
bool LoadChainTip(const CChainParams& chainparams) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
/** Unload database information */
void UnloadBlockIndex();
/** See whether the protocol update is enforced for connected nodes */
int ActiveProtocol();
/** Run an instance of the script checking thread */
void ThreadScriptCheck();

/** Check whether we are doing an initial block download (synchronizing from disk or network) */
bool IsInitialBlockDownload();
/** Retrieve a transaction (from memory pool, or from disk, if possible) */
bool GetTransaction(const uint256& hash, CTransactionRef& tx, uint256& hashBlock, bool fAllowSlow = false, CBlockIndex* blockIndex = nullptr);

/** Find the best known block, and make it the tip of the block chain */
bool ActivateBestChain(CValidationState& state, std::shared_ptr<const CBlock> pblock = std::shared_ptr<const CBlock>());

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 1 round 15 — consensus-DB fatal latch (AUD-017).
//
// When a consensus-DB commit fails mid-sequence, some LevelDB instances may be
// ahead of the others: the local storage is torn. From that instant NOTHING may
// connect or disconnect blocks in this process — a retry re-runs the whole apply
// phase on top of the committed prefix and can convert a purely LOCAL storage
// failure into a bogus consensus rejection of a VALID block (e.g. re-applying a
// TX_BTC_HEADERS batch that is already durable fails "bad-btcheaders-not-heavier").
// The only exit is a process restart: the startup consistency gate then reports
// the torn state and instructs -reindex.
// ═══════════════════════════════════════════════════════════════════════════════

/** First-failure context preserved by the latch (diagnostic, operator-facing). */
struct ConsensusDBFatalContext {
    bool fConnect{true};        //!< direction: true = connect, false = disconnect
    int nStep{0};               //!< failing commit step (1 settlement, 2 btcheaders, 3 htlc, 4 burnclaim, 5 marker)
    std::string strDB;          //!< human name of the failing commit
    bool fPartial{false};       //!< true iff at least one earlier commit already succeeded
    int nHeight{0};
    uint256 blockHash;
    std::string strMessage;     //!< full operator message
};

/** True iff a consensus-DB commit has failed in this process. Latched: once set it
 *  stays set for the lifetime of the process — no RPC, argument or config can clear
 *  it; only a restart (through the startup consistency gate) can. */
bool IsConsensusDBFatal();

/** Copy the FIRST failure's context. Returns false if the latch is not set. */
bool GetConsensusDBFatalContext(ConsensusDBFatalContext& out);

/** THE single fatal-abort primitive for consensus-DB commit failures (LOT 1 r15).
 *
 *  Order of effects (deliberate): (1) atomically latch `consensus_db_fatal` BEFORE
 *  anything else; (2) preserve the FIRST failure's context (later calls do NOT
 *  overwrite it); (3) invoke the real AbortNode mechanism — misc warning + fatal
 *  log + UI message + StartShutdown — exactly ONCE, on the first call; (4) return
 *  false, with `state` carrying a non-invalid Error(): a storage failure is NEVER
 *  block invalidity, so no caller may derive BLOCK_FAILED_VALID from it.
 *
 *  Not reachable from any RPC, argument or config. Idempotent by construction.
 *  `stateOut` may be null (disconnect side has no CValidationState). */
bool AbortConsensusDBState(bool fConnect, int nStep, const std::string& strDB, bool fPartial,
                           int nHeight, const uint256& blockHash, CValidationState* stateOut = nullptr);

/** TEST-ONLY: clear the latch between unit-test cases. Compiled into the daemon but
 *  called from nowhere in it (verified structurally); there is deliberately no RPC,
 *  argument or config path to reach it. */
void ResetConsensusDBFatalForTests();

/** Counter for nested ActivateBestChain calls - used by DMM to avoid block production during sync */
extern std::atomic<int> g_activating_best_chain;

#ifdef BATHRON_ENABLE_LAB_FINALITY_HOOK
/**
 * LAB/TEST-ONLY seam (LOT 6 r3, blocker B1) — PHASED.
 *
 * The three local-finality backstops inside ActivateBestChainStep exist for a REAL
 * race: the finality write path (ProcessHuSignature -> AddSignature) is deliberately
 * lock-free — net_processing.cpp says so, and AddSignature avoids cs_main to keep the
 * UpdateTip lock order — so the local view CAN change while ActivateBestChain holds
 * cs_main, after its candidate filter has run.
 *
 * ONE hook at the top of the step cannot reach all three, because each backstop reads
 * a DIFFERENT view at a DIFFERENT moment:
 *   AFTER_FILTER        -> WouldViolateHuFinality, which reads the finality DB ONLY;
 *   BEFORE_DISCONNECT   -> DisconnectTip, which reads the in-memory handler ONLY, and
 *                          is only reached when the DB check above did NOT fire;
 *   BEFORE_CONNECT      -> ConnectBlock's HasConflictingFinality, which needs a height
 *                          finalized to a DIFFERENT hash, and is only reached after
 *                          the disconnect loop completed.
 * That is why an r2 test that finalized once at the top could not cover the last two.
 *
 * The callback may change the REAL finality view (handler/DB) at that instant. It must
 * never set fLocalFinalityRefused nor dictate an outcome — the production code decides.
 *
 * Phase counters increment whenever a phase is REACHED, hook installed or not, so a
 * test can assert mechanically that the branch it claims to cover really executed.
 * A test whose name claims a branch without such a counter is forbidden: in r2 exactly
 * such a test passed while never reaching its branch.
 *
 * Compiled in ONLY with ./configure --enable-lab-finality-hook (default off): the
 * declaration, the definitions and every call site are compiled out otherwise, so a
 * release binary contains neither the symbols nor the calls (verified with nm/strings).
 * Settable only from C++ test code — no RPC, config or environment path exists.
 */
enum class LabFinalityPhase {
    AFTER_FILTER = 0,        //!< top of ActivateBestChainStep, before the reorg backstop
    BEFORE_DISCONNECT = 1,   //!< immediately before the disconnect loop
    BEFORE_CONNECT = 2,      //!< immediately before the connect loop
    // r4 / B3 — InvalidateBlock. Its span guard runs once, then the disconnect loop
    // does N disk reads and flushes while the finality writer runs lock-free, so the
    // race has to be injectable at each of these four points to prove the
    // all-or-nothing marking really holds.
    INV_AFTER_PREFLIGHT = 3,     //!< after the span guard passed, before anything else
    INV_BEFORE_FIRST_DISCONNECT = 4,
    INV_BETWEEN_DISCONNECTS = 5,
    INV_BEFORE_MARKING = 6,      //!< all disconnects done, just before the status write
    COUNT = 7
};
extern std::function<void(LabFinalityPhase)> g_lab_finality_hook;
extern std::atomic<int> g_lab_finality_phase_hits[static_cast<size_t>(LabFinalityPhase::COUNT)];
void LabFinalityPhaseReached(LabFinalityPhase phase);

/**
 * Per-BACKSTOP refusal counters. The phase counters above prove a phase was REACHED,
 * which is NOT the same as the refusal branch having EXECUTED — a final independent
 * review showed a phase counter is satisfied by any activation at all, so a test can
 * still claim a branch it never entered. These increment at the exact lines that set
 * fLocalFinalityRefused, so `Refusals(x) > 0` is proof the branch ran.
 */
enum class LabFinalityBackstop { REORG = 0, DISCONNECT = 1, CONNECT = 2, COUNT = 3 };

/**
 * LAB/TEST-ONLY READ-ONLY observers (r6). setBlockIndexCandidates and
 * FindMostWorkChain are file-local to validation.cpp, so a test cannot otherwise
 * assert the candidate-set invariant that ReAddBlockIndexCandidates exists to
 * restore — and r5 could neither prove nor disprove that helper because of it.
 * Both are strictly READ-ONLY, and that had to be FIXED: the first version of
 * LabFindMostWorkChainHash called FindMostWorkChain(), which is NOT a pure function —
 * it writes pindexBestInvalid, sets BLOCK_FAILED_CHILD, inserts into mapBlocksUnlinked
 * and ERASES from setBlockIndexCandidates whenever the best candidate has a failed or
 * data-missing ancestor. A probe that can mark blocks invalid in the very set it is
 * measuring is not a measuring instrument; an independent review caught it. It now
 * peeks at the same element FindMostWorkChain would start from, without any of that.
 *
 * Behind the same compile-time gate as the rest of the seam (absent from release:
 * nm/strings report zero, no RPC/config/env path).
 */
std::vector<uint256> LabGetBlockIndexCandidates() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
uint256 LabBestCandidateHash() EXCLUSIVE_LOCKS_REQUIRED(cs_main);
extern std::atomic<int> g_lab_finality_backstop_hits[static_cast<size_t>(LabFinalityBackstop::COUNT)];
#endif

CAmount GetBlockValue(int nHeight);

/** BATHRON consensus rule C1: coinbase value must equal exactly the block's
 *  collected fees (block_reward=0, no inflation). Exposed for unit testing;
 *  rejects with "bad-cb-amount". */
bool IsCoinbaseValueValid(const CTransactionRef& tx, CAmount nFees, CValidationState& _state);

/** Create a new block index entry for a given block hash */
CBlockIndex* InsertBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
/** Flush all state, indexes and buffers to disk. */
void FlushStateToDisk();


/** (try to) add transaction to memory pool **/
bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState& state, const CTransactionRef& tx, bool fLimitFree,
                        bool* pfMissingInputs, bool fOverrideMempoolLimit = false,
                        bool fRejectInsaneFee = false, bool ignoreFees = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** (try to) add transaction to memory pool with a specified acceptance time **/
bool AcceptToMemoryPoolWithTime(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx, bool fLimitFree,
                                bool* pfMissingInputs, int64_t nAcceptTime, bool fOverrideMempoolLimit = false,
                                bool fRejectInsaneFee = false, bool ignoreFees = false) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

CAmount GetMinRelayFee(const CTransaction& tx, const CTxMemPool& pool, unsigned int nBytes);
CAmount GetMinRelayFee(unsigned int nBytes);
/**
 * Return the minimum fee for a shielded tx.
 */
CAmount GetShieldedTxMinFee(const CTransaction& tx);

/**
 * Check transaction inputs, and make sure any
 * pay-to-script-hash transactions are evaluating IsStandard scripts
 *
 * Why bother? To avoid denial-of-service attacks; an attacker
 * can submit a standard HASH... OP_EQUAL transaction,
 * which will get accepted into blocks. The redemption
 * script can be anything; an attacker could use a very
 * expensive-to-check-upon-redemption script like:
 *   DUP CHECKSIG DROP ... repeated 100 times... OP_1
 */

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set. If pvChecks is not nullptr, script checks are pushed onto it
 * instead of being performed inline.
 */
bool CheckInputs(const CTransaction& tx, CValidationState& state, const CCoinsViewCache& view, bool fScriptChecks, unsigned int flags, bool cacheStore, PrecomputedTransactionData& precomTxData, std::vector<CScriptCheck>* pvChecks = nullptr);

/** Apply the effects of this transaction on the UTXO set represented by view */
void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight);

/**
 * Check if transaction will be final in the next block to be created.
 *
 * Calls IsFinalTx() with current block height and appropriate block time.
 *
 * See consensus/consensus.h for flag definitions.
 */
bool CheckFinalTx(const CTransactionRef& tx, int flags = -1);

/**
 * BIP68 — relative lock-times (gate UPGRADE_CSV).
 *
 * Check if a transaction's sequence locks are satisfied for inclusion in the
 * block described by `block` (inside ConnectBlock: the actual index; for the
 * next block: a dummy CBlockIndex with nHeight = tip+1 and pprev = tip).
 * `prevHeights` holds, for each input, the height of the block containing the
 * spent coin (the evaluation height itself for in-block/mempool parents).
 * Only binds for tx.nVersion >= 2 when `flags` carries LOCKTIME_VERIFY_SEQUENCE.
 */
bool SequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);

/** Pieces of SequenceLocks, exposed for unit tests. */
std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction& tx, int flags, std::vector<int>* prevHeights, const CBlockIndex& block);
bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair);

/**
 * Mempool variant: check sequence locks against the NEXT block (tip+1), with
 * prev heights resolved through the mempool view (unconfirmed parents are
 * assumed to confirm in the next block). Returns true when UPGRADE_CSV is not
 * yet active at tip+1. Requires cs_main and pool.cs held.
 */
bool CheckSequenceLocks(CTxMemPool& pool, const CTransaction& tx, int flags);


/**
 * Closure representing one script verification
 * Note that this stores references to the spending transaction
 */
class CScriptCheck
{
private:
    CTxOut m_tx_out;
    const CTransaction* ptxTo;
    unsigned int nIn;
    unsigned int nFlags;
    bool cacheStore;
    ScriptError error;
    PrecomputedTransactionData *precomTxData;

public:
    CScriptCheck() : ptxTo(0), nIn(0), nFlags(0), cacheStore(false), error(SCRIPT_ERR_UNKNOWN_ERROR), precomTxData(nullptr) {}
    CScriptCheck(const CTxOut& outIn, const CTransaction& txToIn, unsigned int nInIn, unsigned int nFlagsIn, bool cacheIn, PrecomputedTransactionData* cachedHashesIn) :
        m_tx_out(outIn),
        ptxTo(&txToIn),
        nIn(nInIn),
        nFlags(nFlagsIn),
        cacheStore(cacheIn),
        error(SCRIPT_ERR_UNKNOWN_ERROR),
        precomTxData(cachedHashesIn) {}

    bool operator()();

    void swap(CScriptCheck& check)
    {
        std::swap(ptxTo, check.ptxTo);
        std::swap(m_tx_out, check.m_tx_out);
        std::swap(nIn, check.nIn);
        std::swap(nFlags, check.nFlags);
        std::swap(cacheStore, check.cacheStore);
        std::swap(error, check.error);
        std::swap(precomTxData, check.precomTxData);
    }

    ScriptError GetScriptError() const { return error; }
};


/** Functions for disk access for blocks */
bool WriteBlockToDisk(const CBlock& block, FlatFilePos& pos);
bool ReadBlockFromDisk(CBlock& block, const FlatFilePos& pos);
bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex);


/** Functions for validating blocks and updating the block tree */

/** Context-independent validity checks */
bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW = true, bool fCheckMerkleRoot = true, bool fCheckSig = true) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool CheckWork(const CBlock& block, const CBlockIndex* const pindexPrev);

/** Context-dependent validity checks */
bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, CBlockIndex* pindexPrev) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
bool ContextualCheckBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindexPrev);

/** Check a block is completely valid from start to finish (only works on top of our current best block, with cs_main held) */
bool TestBlockValidity(CValidationState& state, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW = true, bool fCheckMerkleRoot = true, bool fCheckBlockSig = true) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

bool AcceptBlockHeader(const CBlock& block, CValidationState& state, CBlockIndex** ppindex = nullptr, CBlockIndex* pindexPrev = nullptr) EXCLUSIVE_LOCKS_REQUIRED(cs_main);


/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB
{
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(CCoinsView* coinsview, int nCheckLevel, int nCheckDepth);
};

/** Replay blocks that aren't fully applied to the database. */
bool ReplayBlocks(const CChainParams& params, CCoinsView* view);

inline CBlockIndex* LookupBlockIndex(const uint256& hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    AssertLockHeld(cs_main);
    BlockMap::const_iterator it = mapBlockIndex.find(hash);
    return it == mapBlockIndex.end() ? nullptr : it->second;
}

/** Find the last common block between the parameter chain and a locator. */
CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Mark a block as invalid. */
bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindex) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

/** Remove invalidity status from a block and its descendants. */
bool ReconsiderBlock(CValidationState& state, CBlockIndex* pindex);

/** The currently-connected chain of blocks (protected by cs_main). */
extern CChain chainActive;

/** Global variable that points to the coins database (protected by cs_main) */
extern std::unique_ptr<CCoinsViewDB> pcoinsdbview;

/** Global variable that points to the active CCoinsView (protected by cs_main) */
extern std::unique_ptr<CCoinsViewCache> pcoinsTip;

/** Global variable that points to the active block tree (protected by cs_main) */
extern std::unique_ptr<CBlockTreeDB> pblocktree;


// BATHRON: pSporkDB removed - spork system eliminated

/**
 * Return a reliable pointer (in mapBlockIndex) to the chain's tip index
 */
CBlockIndex* GetChainTip();

/**
 * Return the spend height, which is one more than the inputs.GetBestBlock().
 * While checking, GetBestBlock() refers to the parent block. (protected by cs_main)
 * This is also true for mempool checks.
 */
int GetSpendHeight(const CCoinsViewCache& inputs);

/** Reject codes greater or equal to this can be returned by AcceptToMemPool
 * for transactions, to signal internal conditions. They cannot and should not
 * be sent over the P2P network.
 */
static const unsigned int REJECT_INTERNAL = 0x100;
/** Too high fee. Can not be triggered by P2P transactions */
static const unsigned int REJECT_HIGHFEE = 0x100;
/** Transaction is already known (either in mempool or blockchain) */
static const unsigned int REJECT_ALREADY_KNOWN = 0x101;
/** Transaction conflicts with a transaction already known */
static const unsigned int REJECT_CONFLICT = 0x102;

/** Get block file info entry for one block file */

/** Dump the mempool to disk. */
bool DumpMempool(const CTxMemPool& pool);

/** Load the mempool from disk. */
bool LoadMempool(CTxMemPool& pool);

#endif // BATHRON_VALIDATION_H
