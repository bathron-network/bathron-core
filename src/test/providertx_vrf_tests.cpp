// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for the v3 ProRegTx/ProUpRegTx VRF key (pubKeyVRF).
// v3 is the ONLY supported version: it carries a dedicated ECVRF sortition key, and legacy
// v2 (ECDSA operator key without a VRF key) is rejected by consensus (bad-protx-version).

#include "masternode/providertx.h"
#include "masternode/deterministicmns.h"

#include "consensus/validation.h"
#include "key.h"
#include "pubkey.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(providertx_vrf_tests, BasicTestingSetup)

namespace {
CPubKey NewPubKey()
{
    CKey k;
    k.MakeNewKey(/*fCompressed=*/true);
    return k.GetPubKey();
}

// A ProRegPL that satisfies every IsTriviallyValid check (owner/voting/operator/
// vrf keys all distinct, P2PKH payout to a fourth key).
ProRegPL MakeValidProRegPL(uint16_t version)
{
    ProRegPL pl;
    pl.nVersion = version;
    pl.keyIDOwner = NewPubKey().GetID();
    pl.keyIDVoting = NewPubKey().GetID();
    pl.pubKeyOperator = NewPubKey();
    if (version >= 3) pl.pubKeyVRF = NewPubKey();
    pl.scriptPayout = GetScriptForDestination(NewPubKey().GetID());
    return pl;
}

template <typename T>
T SerRoundTrip(const T& in)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << in;
    T out;
    ss >> out;
    return out;
}
} // namespace

// v3 ProRegPL round-trips with the VRF key intact.
BOOST_AUTO_TEST_CASE(proregpl_v3_serialization_roundtrip)
{
    ProRegPL pl = MakeValidProRegPL(3);
    BOOST_REQUIRE(pl.pubKeyVRF.IsValid());

    ProRegPL out = SerRoundTrip(pl);
    BOOST_CHECK_EQUAL(out.nVersion, 3);
    BOOST_CHECK(out.pubKeyVRF == pl.pubKeyVRF);
    BOOST_CHECK(out.pubKeyOperator == pl.pubKeyOperator);
    // payload hash (covers the VRF key) is stable across the round-trip
    BOOST_CHECK(::SerializeHash(out) == ::SerializeHash(pl));
}

// v3 is the only version: pubKeyVRF is ALWAYS part of the wire format (no conditional
// serialization). A round-trip preserves the VRF key.
BOOST_AUTO_TEST_CASE(proregpl_vrf_always_serialized)
{
    ProRegPL pl = MakeValidProRegPL(3);
    ProRegPL out = SerRoundTrip(pl);
    BOOST_CHECK_EQUAL(out.nVersion, 3);
    BOOST_CHECK(out.pubKeyVRF == pl.pubKeyVRF);
    BOOST_CHECK(out.pubKeyVRF.IsFullyValid());
}

// Validation: finality is VRF-only, so a valid v3 with a real VRF key is REQUIRED;
// v2 (and anything below v3) is rejected — a v2 operator has no VRF key and would be
// silently finality-dead (audit F5) while still raising the ceil(2/3·N) threshold.
BOOST_AUTO_TEST_CASE(proregpl_validation_vrf_key)
{
    {   // v3, valid VRF key → accepted
        ProRegPL pl = MakeValidProRegPL(3);
        CValidationState state;
        BOOST_CHECK(pl.IsTriviallyValid(state));
    }
    {   // v3, missing VRF key → rejected with the specific code
        ProRegPL pl = MakeValidProRegPL(3);
        pl.pubKeyVRF = CPubKey();  // null
        CValidationState state;
        BOOST_CHECK(!pl.IsTriviallyValid(state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-vrf-key-invalid");
    }
    {   // v2 → REJECTED: v3 is the only supported version (legacy v2 removed)
        ProRegPL pl = MakeValidProRegPL(2);
        CValidationState state;
        BOOST_CHECK(!pl.IsTriviallyValid(state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-version");
    }
    {   // v1 → rejected (only v3 accepted)
        ProRegPL pl = MakeValidProRegPL(3);
        pl.nVersion = 1;
        CValidationState state;
        BOOST_CHECK(!pl.IsTriviallyValid(state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-version");
    }
    {   // version 0 → rejected
        ProRegPL pl = MakeValidProRegPL(3);
        pl.nVersion = 0;
        CValidationState state;
        BOOST_CHECK(!pl.IsTriviallyValid(state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-version");
    }
    {   // version above CURRENT_VERSION → rejected
        ProRegPL pl = MakeValidProRegPL(3);
        pl.nVersion = 4;
        CValidationState state;
        BOOST_CHECK(!pl.IsTriviallyValid(state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-protx-version");
    }
}

// ProUpRegPL v3 carries + round-trips the VRF key and validates it.
BOOST_AUTO_TEST_CASE(proupregpl_v3_vrf)
{
    ProUpRegPL pl;
    pl.nVersion = 3;
    pl.nMode = 0;
    pl.pubKeyOperator = NewPubKey();
    pl.pubKeyVRF = NewPubKey();
    pl.keyIDVoting = NewPubKey().GetID();
    pl.scriptPayout = GetScriptForDestination(NewPubKey().GetID());

    ProUpRegPL out = SerRoundTrip(pl);
    BOOST_CHECK_EQUAL(out.nVersion, 3);
    BOOST_CHECK(out.pubKeyVRF == pl.pubKeyVRF);

    CValidationState state;
    BOOST_CHECK(pl.IsTriviallyValid(state));

    pl.pubKeyVRF = CPubKey();
    CValidationState state2;
    BOOST_CHECK(!pl.IsTriviallyValid(state2));
    BOOST_CHECK_EQUAL(state2.GetRejectReason(), "bad-protx-vrf-key-invalid");

    // v2 ProUpRegTx → rejected: v3 is the only version (legacy v2 removed).
    ProUpRegPL v2;
    v2.nVersion = 2;
    v2.pubKeyOperator = NewPubKey();
    v2.keyIDVoting = NewPubKey().GetID();
    v2.scriptPayout = GetScriptForDestination(NewPubKey().GetID());
    CValidationState state3;
    BOOST_CHECK(!v2.IsTriviallyValid(state3));
    BOOST_CHECK_EQUAL(state3.GetRejectReason(), "bad-protx-version");
}

// CDeterministicMNState carries the VRF key from the payload and round-trips it.
BOOST_AUTO_TEST_CASE(dmnstate_carries_vrf_key)
{
    ProRegPL pl = MakeValidProRegPL(3);
    CDeterministicMNState st(pl);
    BOOST_CHECK(st.pubKeyVRF == pl.pubKeyVRF);

    CDeterministicMNState out = SerRoundTrip(st);
    BOOST_CHECK(out.pubKeyVRF == pl.pubKeyVRF);

    // ResetOperatorFields clears the VRF key (part of operator identity).
    st.ResetOperatorFields();
    BOOST_CHECK(!st.pubKeyVRF.IsValid());
}

BOOST_AUTO_TEST_SUITE_END()
