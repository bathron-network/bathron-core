// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Non-regression guard for LAB-DEPENDS-LIBEVENT-1.
//
// libevent 2.1.8-stable calls arc4random_addrandom() unconditionally in
// evutil_rand.c. Every libc that provides arc4random() but NOT
// arc4random_addrandom() — glibc >= 2.36 — then fails: the compiler sees an
// implicit declaration (an error under GCC >= 14) and, even with that error
// silenced, the link fails because the symbol does not exist in libc.
//
// Upstream fixed this in 2.1.12-stable by guarding the call:
//
//   evutil_rand.c:193
//   #if !defined(EVENT__HAVE_ARC4RANDOM) || defined(EVENT__HAVE_ARC4RANDOM_ADDRANDOM)
//
// This test pins the OUTCOME rather than the recipe: whatever libevent the
// build links against — depends or system — it must be one that carries the
// guard. Downgrading depends/packages/libevent.mk below 2.1.12 makes this fail.
//
// It is deliberately NOT conditional on the host libc: a build that links an
// unfixed libevent is unqualified everywhere, not merely on glibc >= 2.36.

#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

#include <event2/event.h>

BOOST_FIXTURE_TEST_SUITE(libevent_version_tests, BasicTestingSetup)

//! 2.1.12-stable == 0x02010c00 in libevent's packed version encoding.
static constexpr ev_uint32_t MIN_LIBEVENT_WITH_ARC4RANDOM_GUARD = 0x02010c00;

BOOST_AUTO_TEST_CASE(LinkedLibeventGuardsArc4RandomAddrandom)
{
    const ev_uint32_t linked = event_get_version_number();
    BOOST_CHECK_MESSAGE(linked >= MIN_LIBEVENT_WITH_ARC4RANDOM_GUARD,
                        "linked libevent is " << event_get_version() << " (0x" << std::hex << linked
                        << "), older than 2.1.12-stable: it calls arc4random_addrandom() without a "
                        "guard and cannot build against a libc that lacks that symbol");
}

BOOST_AUTO_TEST_SUITE_END()
