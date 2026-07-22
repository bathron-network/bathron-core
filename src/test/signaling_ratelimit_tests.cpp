// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Regression for the HUSIG per-peer rate-limit map DoS (hard-test campaign #1).
//
// mapPeerRateLimit was insert-only: ProcessHuSignature does
// `mapPeerRateLimit[pfrom->GetId()]` (operator[] = insert) keyed on a MONOTONIC
// NodeId, and NOTHING ever erased it. The husig message is unauthenticated, and the
// insert happens BEFORE any signature validation, so any peer could connect → send
// one trivially-formed husig → disconnect, repeat, and leave a permanent entry each
// cycle → unbounded map growth = remote memory-exhaustion DoS.
//
// Fix: Cleanup() (run every block) now evicts entries whose rate-limit window has
// fully expired. That is behavior-preserving — such an entry would reset its counter
// to 0 on next access anyway — and bounds the map to peers active within the last few
// windows. This test proves the map stays bounded.

#include "state/signaling.h"
#include "test/test_bathron.h"
#include "utiltime.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(signaling_ratelimit_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stale_peer_ratelimit_entries_are_swept)
{
    hu::CHuSignalingManager mgr;
    const int64_t T = 1'000'000'000;
    SetMockTime(T);

    // 1000 stale peers (window long expired) + 5 fresh peers (active "now").
    const int STALE = 1000, FRESH = 5;
    for (int i = 0; i < STALE; ++i) mgr.InjectPeerRateLimitForTest(i, T - 1000);   // >> 2*RATE_LIMIT_WINDOW
    for (int i = 0; i < FRESH; ++i) mgr.InjectPeerRateLimitForTest(10'000 + i, T); // active
    BOOST_CHECK_EQUAL(mgr.PeerRateLimitEntryCount(), (size_t)(STALE + FRESH));

    // Cleanup(1): height < 100 so only the every-block cheap sweep runs (the
    // 100-block sig-cache pass is skipped), isolating the rate-limit eviction.
    mgr.Cleanup(1);

    // Only the fresh entries survive -> the map is bounded, the DoS is closed.
    BOOST_CHECK_EQUAL(mgr.PeerRateLimitEntryCount(), (size_t)FRESH);

    // Advance past the fresh entries' window: a later sweep reclaims them too, so an
    // idle-then-gone peer leaves nothing behind.
    SetMockTime(T + 1000);
    mgr.Cleanup(2);
    BOOST_CHECK_EQUAL(mgr.PeerRateLimitEntryCount(), (size_t)0);

    SetMockTime(0);
}

// R2: a malformed finality sig (null block/proTx or empty vchSig) must set the
// out-flag so the P2P handler can Misbehaving()/ban a peer flooding garbage husig.
BOOST_AUTO_TEST_CASE(malformed_husig_flags_misbehave)
{
    hu::CHuSignalingManager mgr;
    hu::CHuSignature bad;  // default-constructed: null hashes, empty vchSig
    bool misbehave = false;
    BOOST_CHECK(!mgr.ProcessHuSignature(bad, nullptr, nullptr, &misbehave));
    BOOST_CHECK(misbehave);  // malformed = punishable
    // The internal replay path passes no out-flag (default nullptr) — must not crash.
    BOOST_CHECK(!mgr.ProcessHuSignature(bad, nullptr, nullptr));
}

BOOST_AUTO_TEST_SUITE_END()
