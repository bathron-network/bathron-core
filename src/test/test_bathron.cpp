// Copyright (c) 2011-2013 The Bitcoin Core developers
// Copyright (c) 2017-2022 The BATHRON Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Bathron Test Suite

#include "test/test_bathron.h"

#include "blockassembler.h"
#include "btcheaders/btcheadersdb.h"   // LOT 2 sentinel: consensus-DB globals
#include "burnclaim/burnclaimdb.h"
#include "consensus/merkle.h"
#include "htlc/htlcdb.h"
#include "state/settlementdb.h"
#include "guiinterface.h"
#include "masternode/deterministicmns.h"
#include "masternode/evodb.h"
#include "masternode/evonotificationinterface.h"
#include "net/net_processing.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "bathron_chainwork.h"
#include "script/sigcache.h"
#include "streams.h"
#include "txmempool.h"
#include "validation.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>

#include <boost/test/unit_test.hpp>

// Block assembly print priority (for tests)
static const bool DEFAULT_PRINTPRIORITY = false;

std::unique_ptr<CConnman> g_connman;

CClientUIInterface uiInterface;  // Declared but not defined in guiinterface.h

FastRandomContext g_insecure_rand_ctx;
/** Random context to get unique temp data dirs. Separate from g_insecure_rand_ctx, which can be seeded from a const env var */
static FastRandomContext g_insecure_rand_ctx_temp_path;

/** Return the unsigned from the environment var if available, otherwise 0 */
static uint256 GetUintFromEnv(const std::string& env_name)
{
    const char* num = std::getenv(env_name.c_str());
    if (!num) return {};
    return uint256S(num);
}

void Seed(FastRandomContext& ctx)
{
    // Should be enough to get the seed once for the process
    static uint256 seed{};
    static const std::string RANDOM_CTX_SEED{"RANDOM_CTX_SEED"};
    if (seed.IsNull()) seed = GetUintFromEnv(RANDOM_CTX_SEED);
    if (seed.IsNull()) seed = GetRandHash();
    LogPrintf("%s: Setting random seed for current tests to %s=%s\n", __func__, RANDOM_CTX_SEED, seed.GetHex());
    ctx = FastRandomContext(seed);
}

extern bool fPrintToConsole;
extern void noui_connect();

std::ostream& operator<<(std::ostream& os, const uint256& num)
{
    os << num.ToString();
    return os;
}

BasicTestingSetup::BasicTestingSetup(const std::string& chainName)
    : m_path_root{fs::temp_directory_path() / "test_bathron" / std::to_string(g_insecure_rand_ctx_temp_path.rand32())}
{
    ECC_Start();
    SetupEnvironment();
    InitSignatureCache();
    // LOT 1 r15: AbortNode -> uiInterface.ThreadSafeMessageBox uses a last_value<bool>
    // combiner, which THROWS no_slots_error with no slot connected. The daemon always
    // connects one (noui_connect); tests must too, or the real abort path becomes
    // untestable. Connected once per process.
    static bool uiSlotConnected = false;
    if (!uiSlotConnected) {
        uiSlotConnected = true;
        uiInterface.ThreadSafeMessageBox.connect(
            [](const std::string&, const std::string&, unsigned int) { return false; });
    }
    fCheckBlockIndex = true;
    SelectParams(chainName);
    SeedInsecureRand();
    evoDb.reset(new CEvoDB(1 << 20, true, true));
    deterministicMNManager.reset(new CDeterministicMNManager(*evoDb));
}

BasicTestingSetup::~BasicTestingSetup()
{
    // LOT 1 r15 (Phase H) — SENTINEL: if the real shutdown path or the consensus-DB
    // fatal latch was reached during this test case and not explicitly acknowledged,
    // the case must FAIL — the old exit(0) stub used to turn exactly this situation
    // into a false green. Tests that legitimately exercise the abort path must assert
    // it and then call test_shutdown::Reset() + ResetConsensusDBFatalForTests().
    BOOST_CHECK_MESSAGE(test_shutdown::Requests() == 0,
        "SENTINEL: StartShutdown() was requested " << test_shutdown::Requests()
        << " time(s) during this test case and never consumed — the real shutdown "
           "path was reached. Assert it explicitly, then test_shutdown::Reset().");
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(),
        "SENTINEL: the consensus-DB fatal latch is still set at teardown — assert it "
        "explicitly, then ResetConsensusDBFatalForTests().");
    test_shutdown::Reset();
    ResetConsensusDBFatalForTests();

    // LOT 2 — no consensus-DB global may outlive its fixture, ENFORCED BY
    // CONSTRUCTION rather than by assertion. This runs AFTER the derived destructor,
    // so a well-behaved fixture has already reset what it created; this catches the
    // rest. A survivor would otherwise be destroyed later, by the *next* fixture's
    // assignment, pointing at the datadir this destructor is about to delete — which
    // is precisely the `dbwrapper_error: Database I/O error` in an unrelated case
    // that was hit while writing the LOT 2 tests.
    //
    // Measured, not assumed: 110 existing cases across 10 suites (settlement_tests,
    // htlc3s_*, specialtx_rollover_*, ...) leave a global behind — they call
    // InitSettlementDB()/InitHtlcDB() inside the case and never reset. Those DBs are
    // in-memory, so they were harmless in practice; only an ON-DISK survivor can
    // trigger the failure above. An assertion here would therefore condemn a
    // pre-existing style far outside AUD-003's scope, so this resets silently
    // instead. Verified: with this reset in place the full suite is unchanged.
    g_burnclaimdb.reset();
    g_settlementdb.reset();
    g_htlcdb.reset();
    g_btcheadersdb.reset();

    fs::remove_all(m_path_root);
    ECC_Stop();
    deterministicMNManager.reset();
    evoDb.reset();
}

fs::path BasicTestingSetup::SetDataDir(const std::string& name)
{
    fs::path ret = m_path_root / name;
    fs::create_directories(ret);
    gArgs.ForceSetArg("-datadir", ret.string());
    // NOTE (LOT 2): deliberately NO ClearDatadirCache() here. Callers such as
    // wallet_tests/importwallet_rescan use SetDataDir mid-test only to obtain a
    // *path* for a file, and must NOT have the effective datadir relocated under
    // them (doing so moves GetDataDir() away from the chain the fixture built and
    // breaks the rescan). A fixture that genuinely wants to switch the effective
    // datadir before opening on-disk DBs calls ClearDatadirCache() itself — see
    // TestingSetup and P0AtomicitySetup.
    return ret;
}

TestingSetup::TestingSetup(const std::string& chainName) : BasicTestingSetup(chainName)
{
        SetDataDir("tempdir");
        ClearDatadirCache();

        // Start the lightweight task scheduler thread
        CScheduler::Function serviceLoop = std::bind(&CScheduler::serviceQueue, &scheduler);
        threadGroup.create_thread(std::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));

        // Note that because we don't bother running a scheduler thread here,
        // callbacks via CValidationInterface are unreliable, but that's OK,
        // our unit tests aren't testing multiple parts of the code at once.
        GetMainSignals().RegisterBackgroundSignalScheduler(scheduler);

        g_connman = std::make_unique<CConnman>(0x1337, 0x1337); // Deterministic randomness for tests.
        connman = g_connman.get();

        // Register EvoNotificationInterface
        pEvoNotificationInterface = new EvoNotificationInterface();
        RegisterValidationInterface(pEvoNotificationInterface);

        // Ideally we'd move all the RPC tests to the functional testing framework
        // instead of unit tests, but for now we need these here.
        RegisterAllCoreRPCCommands(tableRPC);
        // BATHRON: pSporkDB removed - spork system eliminated
        pblocktree.reset(new CBlockTreeDB(1 << 20, true));
        pcoinsdbview.reset(new CCoinsViewDB(1 << 23, true));
        pcoinsTip.reset(new CCoinsViewCache(pcoinsdbview.get()));
        if (!LoadGenesisBlock()) {
            throw std::runtime_error("Error initializing block database");
        }
        {
            CValidationState state;
            bool ok = ActivateBestChain(state);
            BOOST_CHECK(ok);
        }
        nScriptCheckThreads = 3;
        for (int i=0; i < nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
        peerLogic.reset(new PeerLogicValidation(connman));
}

TestingSetup::~TestingSetup()
{
        scheduler.stop();
        threadGroup.interrupt_all();
        threadGroup.join_all();
        GetMainSignals().FlushBackgroundCallbacks();
        UnregisterAllValidationInterfaces();
        GetMainSignals().UnregisterBackgroundSignalScheduler();
        g_connman.reset();
        peerLogic.reset();
        UnloadBlockIndex();
        delete pEvoNotificationInterface;
        pcoinsTip.reset();
        pcoinsdbview.reset();
        pblocktree.reset();
        // BATHRON: pSporkDB.reset() removed - spork system eliminated
}

// Test chain only available on regtest
TestChainSetup::TestChainSetup(int blockCount) : TestingSetup(CBaseChainParams::REGTEST)
{
    // HU: No PoS activation check needed - DMM-only chain

    // Generate a blockCount-block chain:
    coinbaseKey.MakeNewKey(true);
    CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey()) << OP_CHECKSIG;
    for (int i = 0; i < blockCount; i++)
    {
        std::vector<CMutableTransaction> noTxns;
        CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey);
        coinbaseTxns.push_back(*b.vtx[0]);
    }
}

// Create a new block with coinbase paying to scriptPubKey, and try to add it to the current chain.
// Include given transactions, and, if fNoMempoolTx=true, remove transactions coming from the mempool.
CBlock TestChainSetup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey, bool fNoMempoolTx)
{
    CBlock block = CreateBlock(txns, scriptPubKey, fNoMempoolTx);
    ProcessNewBlock(std::make_shared<const CBlock>(block), nullptr);
    return block;
}

CBlock TestChainSetup::CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CKey& scriptKey)
{
    CScript scriptPubKey = CScript() <<  ToByteVector(scriptKey.GetPubKey()) << OP_CHECKSIG;
    return CreateAndProcessBlock(txns, scriptPubKey);
}

CBlock TestChainSetup::CreateBlock(const std::vector<CMutableTransaction>& txns,
                                   const CScript& scriptPubKey,
                                   bool fNoMempoolTx,
                                   bool fTestBlockValidity,
                                   bool fIncludeQfc,
                                   CBlockIndex* customPrevBlock)
{
    std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(
            Params(), DEFAULT_PRINTPRIORITY).CreateNewBlock(scriptPubKey,
                                                            nullptr,       // wallet
                                                            false,   // fMNBlock
                                                            nullptr, // availableCoins
                                                            fNoMempoolTx,
                                                            fTestBlockValidity,
                                                            customPrevBlock,
                                                            true,
                                                            fIncludeQfc);
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>(pblocktemplate->block);

    // Add passed-in txns:
    for (const CMutableTransaction& tx : txns) {
        pblock->vtx.push_back(MakeTransactionRef(tx));
    }

    const int nHeight = (customPrevBlock != nullptr ? customPrevBlock->nHeight + 1
                                                    : WITH_LOCK(cs_main, return chainActive.Height()) + 1);

    // Re-compute sapling root
    pblock->hashFinalSaplingRoot = CalculateSaplingTreeRoot(pblock.get(), nHeight, Params());

    // Find valid PoW
    assert(SolveBlock(pblock, nHeight));
    return *pblock;
}

CBlock TestChainSetup::CreateBlock(const std::vector<CMutableTransaction>& txns, const CKey& scriptKey,
                                   bool fTestBlockValidity)
{
    CScript scriptPubKey = CScript() <<  ToByteVector(scriptKey.GetPubKey()) << OP_CHECKSIG;
    return CreateBlock(txns, scriptPubKey, fTestBlockValidity);
}

std::shared_ptr<CBlock> FinalizeBlock(std::shared_ptr<CBlock> pblock)
{
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
    // MN-only consensus - set random nonce for tests
    pblock->nNonce = GetRand(std::numeric_limits<uint32_t>::max());
    return pblock;
}

TestChainSetup::~TestChainSetup()
{
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CMutableTransaction& tx)
{
    CTransaction txn(tx);
    return FromTx(txn);
}

CTxMemPoolEntry TestMemPoolEntryHelper::FromTx(const CTransaction& txn)
{
    return CTxMemPoolEntry(MakeTransactionRef(txn), nFee, nTime, nHeight,
                           spendsCoinbase, sigOpCount);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 1 round 15 (Phase H) — the shutdown stubs must NEVER exit(0).
//
// The old stubs were `std::exit(0)`: any test that reached the REAL shutdown path
// (e.g. AbortNode -> StartShutdown on a consensus-DB commit failure) terminated the
// whole suite with rc 0 — a FALSE GREEN. StartShutdown now records the request in a
// counter; the sentinel in ~BasicTestingSetup fails the current test case if the
// request was not explicitly consumed via test_shutdown::ExpectAndClear()/Reset().
// Shutdown(void*) (the full init teardown, which no unit test may legitimately
// reach) aborts loudly with a NON-ZERO exit instead of a clean-looking rc 0.
// ═══════════════════════════════════════════════════════════════════════════════

static std::atomic<int> g_test_shutdown_requests{0};

namespace test_shutdown {
int Requests() { return g_test_shutdown_requests.load(); }
void Reset() { g_test_shutdown_requests.store(0); }
} // namespace test_shutdown

[[noreturn]] void Shutdown(void* parg)
{
    std::fprintf(stderr,
        "FATAL: unit test reached the real Shutdown() teardown path — this must never "
        "happen in test_bathron. Aborting with a non-zero status so the run cannot "
        "read as green.\n");
    std::abort();
}

void StartShutdown()
{
    g_test_shutdown_requests.fetch_add(1);
}

bool ShutdownRequested()
{
    return g_test_shutdown_requests.load() > 0;
}
