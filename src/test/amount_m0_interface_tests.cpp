// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// LAB-BATHRON-TX-AMOUNT-COHERENCE-1
//
// Contrat d'interface des montants : un montant est un ENTIER d'unités minimales,
// 1 unité minimale = 1 satoshi d'origine.
//
// util_tests/util_ParseMoney couvre déjà l'analyseur lui-même. Ce fichier couvre la
// COMPOSITION effectivement employée aux points d'entrée d'interface :
//
//     ParseMoney(littéral, n)  &&  Params().GetConsensus().MoneyRange(n)
//
// C'est exactement ce que font désormais, à l'identique :
//   - src/bathron-tx.cpp  ExtractAndValidateValue()   (outaddr/outscript/outpubkey/outdata)
//   - src/bathron-tx.cpp  AmountFromValue()           (set=prevtxs:[{"amount":…}])
//   - src/rpc/server.cpp  AmountFromValue()           (RPC)
//
// Avant correction, le deuxième divergeait : il lisait un double, multipliait par COIN et
// refusait toute valeur > 21000000.0 avant mise à l'échelle. Le montant de prevtxs entrant
// dans le calcul de la signature, l'écart n'était pas cosmétique.

#include "test/test_bathron.h"

#include "amount.h"
#include "chainparams.h"
#include "utilmoneystr.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(amount_m0_interface_tests, BasicTestingSetup)

namespace {
//! Reproduit la composition employée aux points d'entrée d'interface.
bool AcceptAmount(const std::string& literal, CAmount& out)
{
    if (!ParseMoney(literal, out)) return false;
    return Params().GetConsensus().MoneyRange(out);
}
} // namespace

BOOST_AUTO_TEST_CASE(accepts_integer_minimal_units)
{
    CAmount n = -1;

    BOOST_CHECK(AcceptAmount("0", n));           BOOST_CHECK_EQUAL(n, 0);
    BOOST_CHECK(AcceptAmount("1", n));           BOOST_CHECK_EQUAL(n, 1);

    // 4 vaut QUATRE unités minimales — surtout pas 4 * COIN.
    BOOST_CHECK(AcceptAmount("4", n));           BOOST_CHECK_EQUAL(n, 4);
    BOOST_CHECK(n != 4 * COIN);

    BOOST_CHECK(AcceptAmount("21000000", n));    BOOST_CHECK_EQUAL(n, 21000000);
}

//! Garde de non-régression du défaut corrigé.
//!
//! L'ancienne AmountFromValue locale de bathron-tx refusait toute valeur > 21000000.0
//! AVANT de multiplier par COIN, ce qui rendait 100000000 inacceptable. Sous la convention
//! en unités minimales, 100000000 est une valeur parfaitement ordinaire.
BOOST_AUTO_TEST_CASE(old_bitcoin_cap_no_longer_applies)
{
    CAmount n = 0;
    BOOST_CHECK(AcceptAmount("100000000", n));
    BOOST_CHECK_EQUAL(n, 100000000);
    BOOST_CHECK_EQUAL(n, COIN);

    // Très au-dessus de l'ancien plafond, très en dessous du vrai maximum.
    BOOST_CHECK(AcceptAmount("999999999999", n));
    BOOST_CHECK_EQUAL(n, 999999999999LL);
}

BOOST_AUTO_TEST_CASE(range_bounds)
{
    const CAmount max_money = Params().GetConsensus().nMaxMoneyOut;
    BOOST_CHECK_EQUAL(max_money, 21000000LL * COIN);   // 2 100 000 000 000 000

    CAmount n = 0;
    BOOST_CHECK(AcceptAmount(std::to_string(max_money), n));
    BOOST_CHECK_EQUAL(n, max_money);

    // Maximum + 1 : analysé sans erreur, mais hors MoneyRange.
    CAmount parsed = 0;
    BOOST_CHECK(ParseMoney(std::to_string(max_money + 1), parsed));
    BOOST_CHECK_EQUAL(parsed, max_money + 1);
    BOOST_CHECK(!Params().GetConsensus().MoneyRange(parsed));
    BOOST_CHECK(!AcceptAmount(std::to_string(max_money + 1), n));
}

//! Les décimaux sont refusés BRUYAMMENT — jamais tronqués, jamais arrondis.
//! C'est la garantie qui empêche qu'un montant soit silencieusement déformé.
BOOST_AUTO_TEST_CASE(rejects_decimals_loudly)
{
    CAmount n = 12345;
    const CAmount sentinel = n;

    BOOST_CHECK(!AcceptAmount("0.5", n));
    BOOST_CHECK(!AcceptAmount("1.3782", n));
    BOOST_CHECK(!AcceptAmount("0.18", n));
    BOOST_CHECK(!AcceptAmount("4.0", n));

    // Aucun de ces refus ne doit avoir écrit une valeur partielle.
    BOOST_CHECK_EQUAL(n, sentinel);
}

BOOST_AUTO_TEST_CASE(rejects_negative_and_non_numeric)
{
    CAmount n = 0;
    BOOST_CHECK(!AcceptAmount("-1", n));
    BOOST_CHECK(!AcceptAmount("abc", n));
    BOOST_CHECK(!AcceptAmount("", n));
    BOOST_CHECK(!AcceptAmount("12abc", n));    // pas de préfixe numérique toléré
    BOOST_CHECK(!AcceptAmount("1e8", n));      // pas de notation scientifique
}

BOOST_AUTO_TEST_SUITE_END()
