// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Regression test for the network-wide halt caused by the pubKeyOperator
// unique-property asymmetry in the multi-MN deterministic list.
//
// In the multi-MN model, AddMN intentionally does NOT track pubKeyOperator as a
// unique property (duplicate operator keys are allowed). The bug: UpdateMN and
// RemoveMN still called UpdateUniqueProperty/DeleteUniqueProperty on
// pubKeyOperator, so removing or operator-rekeying any normally-registered MN
// called DeleteUniqueProperty on a key absent from mnUniquePropertyMap, tripping
// `assert(p && ...)` (deterministicmns.h:485) -> abort() on every validating
// node. Reachable by spending any MN collateral (BuildNewListFromBlock ->
// RemoveMN). NDEBUG is forbidden, so the assert always fires.
//
// These cases construct a MN through the normal add path (operator key NOT
// tracked) and then remove it / change its operator key. Before the fix each
// case abort()s the test binary; after the fix (pubKeyOperator handling dropped
// from UpdateMN/RemoveMN, symmetric with AddMN) they complete cleanly.

#include "test/test_bathron.h"

#include "key.h"
#include "masternode/deterministicmns.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dmn_operator_key_tests, BasicTestingSetup)

namespace {

// Build a MN added through the normal ProReg path: collateral + owner key are
// tracked as unique properties; operator key is NOT (multi-MN allows dupes).
CDeterministicMNCPtr MakeMN(const uint256& proTxHash, const COutPoint& collateral,
                            const CKeyID& ownerKeyID, const CPubKey& operatorKey)
{
    auto state = std::make_shared<CDeterministicMNState>();
    state->keyIDOwner = ownerKeyID;
    state->pubKeyOperator = operatorKey;
    auto dmn = std::make_shared<CDeterministicMN>(uint64_t(0));
    dmn->proTxHash = proTxHash;
    dmn->collateralOutpoint = collateral;
    dmn->pdmnState = state;
    return dmn;
}

CPubKey FreshPubKey()
{
    CKey k;
    k.MakeNewKey(true);
    return k.GetPubKey();
}

} // namespace

// Spending a MN's collateral -> RemoveMN must not abort.
BOOST_AUTO_TEST_CASE(remove_mn_does_not_abort_on_untracked_operator_key)
{
    CDeterministicMNList list;
    const uint256 proTxHash = uint256S("0000000000000000000000000000000000000000000000000000000000000a01");
    const COutPoint collateral(uint256S("0000000000000000000000000000000000000000000000000000000000000b02"), 0);
    const CPubKey ownerKey = FreshPubKey();
    const CPubKey operatorKey = FreshPubKey();

    list.AddMN(MakeMN(proTxHash, collateral, ownerKey.GetID(), operatorKey));
    BOOST_CHECK(list.HasMN(proTxHash));

    // Pre-fix: DeleteUniqueProperty(pubKeyOperator) -> assert -> abort().
    BOOST_CHECK_NO_THROW(list.RemoveMN(proTxHash));
    BOOST_CHECK(!list.HasMN(proTxHash));
}

// Operator-key ProUpReg -> UpdateMN must not abort.
BOOST_AUTO_TEST_CASE(update_mn_operator_key_change_does_not_abort)
{
    CDeterministicMNList list;
    const uint256 proTxHash = uint256S("0000000000000000000000000000000000000000000000000000000000000c03");
    const COutPoint collateral(uint256S("0000000000000000000000000000000000000000000000000000000000000d04"), 0);
    const CPubKey ownerKey = FreshPubKey();
    const CPubKey operatorKey1 = FreshPubKey();
    const CPubKey operatorKey2 = FreshPubKey();

    list.AddMN(MakeMN(proTxHash, collateral, ownerKey.GetID(), operatorKey1));

    // New state with a different operator key (the ProUpReg case).
    auto newState = std::make_shared<CDeterministicMNState>();
    newState->keyIDOwner = ownerKey.GetID();
    newState->pubKeyOperator = operatorKey2;

    // Pre-fix: UpdateUniqueProperty(old,new) -> DeleteUniqueProperty(old) -> assert -> abort().
    BOOST_CHECK_NO_THROW(list.UpdateMN(proTxHash, newState));
    BOOST_CHECK(list.HasMN(proTxHash));
}

BOOST_AUTO_TEST_SUITE_END()
