// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Regression test for CVE-2024-52911 (Bitcoin Core, fixed in 29.0): a
// use-after-free in ConnectBlock's parallel script verification.
//
// In ConnectBlock, each queued CScriptCheck holds a raw pointer into the
// local `std::vector<PrecomputedTransactionData> precomTxData`. The bug is a
// destruction-order hazard: if `precomTxData` is declared AFTER the
// `CCheckQueueControl control`, then on an EARLY `return error(...)` (e.g. when
// CheckInputs fails for a later tx, before the explicit control.Wait()) the
// stack unwinds destroying `precomTxData` FIRST, then `~CCheckQueueControl`
// runs Wait() and drains worker threads that are still dereferencing the
// now-freed precomputed data -> heap-use-after-free.
//
// The fix (src/validation.cpp) declares `precomTxData` BEFORE `control`, so
// `control` is destroyed first: its destructor joins/drains the workers before
// the precomputed data is freed.
//
// This test reproduces the same pattern with the REAL CCheckQueue /
// CCheckQueueControl: worker threads execute checks that hold raw pointers into
// a heap buffer, the buffer is declared before the control, and the scope is
// left WITHOUT calling Wait() (simulating the early `return error`). Built with
// `--with-sanitizers=address`, this exercise must remain clean; reverting the
// declaration order (here or in ConnectBlock) makes AddressSanitizer report a
// heap-use-after-free. Without ASan it is a smoke test of the parallel path.

#include "test/test_bathron.h"

#include "checkqueue.h"

#include <atomic>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <boost/thread/thread.hpp>

BOOST_FIXTURE_TEST_SUITE(connectblock_uaf_tests, BasicTestingSetup)

namespace {

// Sentinels written into a payload's canary across its lifetime. A worker that
// reads CANARY_DEAD has observed a use-after-free.
constexpr int CANARY_LIVE = 0x0A11FE;
constexpr int CANARY_DEAD = 0x0DEAD0;

// Analog of one PrecomputedTransactionData entry: lives in the `precomData`
// vector that the checks point into. Its destructor flips the canary so any
// post-destruction read is detectable (in addition to being caught by ASan).
struct Payload {
    std::atomic<int> canary{CANARY_LIVE};
    ~Payload() { canary.store(CANARY_DEAD, std::memory_order_relaxed); }
};

// Analog of CScriptCheck: holds a RAW pointer into the `precomData` vector,
// exactly like CScriptCheck holds `&precomTxData[i]`.
struct PtrCheck {
    const Payload* payload = nullptr;
    std::atomic<int>* sawDead = nullptr;
    std::atomic<int>* ran = nullptr;

    PtrCheck() = default;
    PtrCheck(const Payload* p, std::atomic<int>* sawDeadIn, std::atomic<int>* ranIn)
        : payload(p), sawDead(sawDeadIn), ran(ranIn) {}

    bool operator()()
    {
        // Stay in-flight briefly so the master leaves scope (and ~control
        // begins draining) while workers are mid-execution -- this is the race
        // window the UAF needs.
        for (volatile int spin = 0; spin < 200000; ++spin) { /* busy wait */ }
        // Dereference the pointer into precomData -- the load that becomes a
        // use-after-free if precomData was freed before this worker finished.
        if (payload->canary.load(std::memory_order_relaxed) == CANARY_DEAD)
            sawDead->fetch_add(1, std::memory_order_relaxed);
        ran->fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    void swap(PtrCheck& x)
    {
        std::swap(payload, x.payload);
        std::swap(sawDead, x.sawDead);
        std::swap(ran, x.ran);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(precom_data_outlives_checkqueue_on_early_exit)
{
    const int N = 256; // saturate the workers so several are in-flight at scope exit

    CCheckQueue<PtrCheck> queue(128);

    // Start worker threads, mirroring ThreadScriptCheck on the global queue.
    boost::thread_group workers;
    const int nWorkers = 3;
    for (int i = 0; i < nWorkers; ++i)
        workers.create_thread([&queue] { queue.Thread(); });

    std::atomic<int> sawDead{0};
    std::atomic<int> ran{0};

    {
        // ---- This block mirrors the relevant locals of ConnectBlock. ----
        // ORDER MATTERS: precomData is declared BEFORE control, so on scope
        // exit `control` is destroyed first and drains the workers before
        // `precomData` is freed. This is the fixed ordering from validation.cpp.
        std::vector<Payload> precomData(N);

        CCheckQueueControl<PtrCheck> control(&queue);

        std::vector<PtrCheck> checks;
        checks.reserve(N);
        for (int i = 0; i < N; ++i)
            checks.emplace_back(&precomData[i], &sawDead, &ran);
        control.Add(checks);

        // Simulate ConnectBlock's early `return error(...)`: leave the scope
        // WITHOUT calling control.Wait(). The ~CCheckQueueControl destructor
        // (declared after precomData, destroyed before it) must drain the
        // workers here, before precomData's destructors run.
    }

    // All checks must have completed, and none may have observed freed memory.
    BOOST_CHECK_EQUAL(ran.load(), N);
    BOOST_CHECK_EQUAL(sawDead.load(), 0);

    workers.interrupt_all();
    workers.join_all();
}

#ifdef SAPLING_UAF_REPRO
// Buggy-ordering reproducer, EXCLUDED from normal builds. Compile the test
// binary with `-DSAPLING_UAF_REPRO` under AddressSanitizer
// (`--with-sanitizers=address`) and run this case to observe the
// CVE-2024-52911 heap-use-after-free: here `control` is declared BEFORE
// `precomData`, so on the early scope exit `precomData` is freed FIRST and
// ~CCheckQueueControl then drains workers still reading it. This is the
// pre-fix ordering; it MUST abort under ASan (proof that the fixed ordering
// above is what prevents the UAF). Verified standalone against the real
// checkqueue.h: ASan reports heap-use-after-free in PtrCheck::operator()
// via CCheckQueue::Loop.
BOOST_AUTO_TEST_CASE(precom_data_freed_before_drain_is_uaf)
{
    const int N = 256;
    CCheckQueue<PtrCheck> queue(128);
    boost::thread_group workers;
    for (int i = 0; i < 3; ++i)
        workers.create_thread([&queue] { queue.Thread(); });
    std::atomic<int> sawDead{0};
    std::atomic<int> ran{0};
    {
        // BUGGY: control declared before precomData -> precomData destroyed
        // first (use-after-free when ~control drains in-flight workers).
        CCheckQueueControl<PtrCheck> control(&queue);
        std::vector<Payload> precomData(N);
        std::vector<PtrCheck> checks;
        checks.reserve(N);
        for (int i = 0; i < N; ++i)
            checks.emplace_back(&precomData[i], &sawDead, &ran);
        control.Add(checks);
    }
    workers.interrupt_all();
    workers.join_all();
    BOOST_CHECK_EQUAL(ran.load(), N);
}
#endif // SAPLING_UAF_REPRO

BOOST_AUTO_TEST_SUITE_END()
