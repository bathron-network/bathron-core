// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Non-regression test for LAB-SQLITE-INIT-1.
//
// depends builds SQLite with -DSQLITE_OMIT_AUTOINIT (depends/packages/sqlite.mk). Under
// that option sqlite3_open*() no longer calls sqlite3_initialize() implicitly, and
// sqlite3.h states that "the application must call sqlite3_initialize() directly prior to
// using any other SQLite interface". When the application does not, the memory allocator
// vector reached through sqlite3Malloc() is still null and openDatabase() jumps to
// address 0 — an EXC_BAD_ACCESS with no diagnostic.
//
// This test pins BOTH halves of that contract, so it cannot be satisfied by weakening the
// build recipe instead of fixing the code:
//
//   1. the linked SQLite really is compiled with OMIT_AUTOINIT — removing the option from
//      sqlite.mk to dodge the crash makes this test fail;
//   2. a file-backed wallet database opens, writes and reads back correctly.
//
// On unpatched 32ca174e, part 2 crashes exactly like
// wallet_zkeys_tests/WriteCryptedSaplingZkeyDirectToDb.

#include "test/test_bathron.h"

#include "test/util/lab_wallet_testdir.h"
#include "util/system.h"
#include "wallet/db.h"
#include "wallet/walletutil.h"

#include <boost/test/unit_test.hpp>

#include <sqlite3.h>

BOOST_FIXTURE_TEST_SUITE(sqlite_init_tests, BasicTestingSetup)

//! The build recipe must keep SQLITE_OMIT_AUTOINIT. If this ever fails, the crash was
//! papered over by changing depends rather than by initialising SQLite in the code.
BOOST_AUTO_TEST_CASE(SqliteBuiltWithoutAutoinit)
{
    BOOST_CHECK_MESSAGE(sqlite3_compileoption_used("OMIT_AUTOINIT") == 1,
                        "linked SQLite is NOT built with SQLITE_OMIT_AUTOINIT: the depends "
                        "recipe changed, and this test no longer proves anything");
}

// NOTE — do not add a test case here that calls sqlite3_initialize() itself.
//
// A first version of this file had one, placed before the case below. It made the whole
// suite USELESS as a regression test: Boost runs cases in declaration order within a
// process, so that call performed the "effective" initialisation (sqlite3.h) and the
// file-backed open that follows then succeeded even on unpatched 32ca174e. The suite
// passed against the very defect it was written to catch.
//
// Nothing in this suite may touch SQLite before the case below.

//! The regression itself: a real, file-backed database round-trip.
//! Unpatched, this dies inside openDatabase() at address 0x0.
BOOST_AUTO_TEST_CASE(OpenFileBackedDatabaseWithoutAutoinit)
{
    // LAB-WALLET-TEST-ISOLATION-1 — même garde partagée que wallet_zkeys_tests.
    // Redirige -datadir vers une racine temporaire propre à ce cas, purge le cache, et
    // refuse fail-closed tout chemin qui sortirait de cette racine ou toucherait un
    // datadir persistant connu.
    const fs::path path = fs::absolute("sqlite_init_testWallet",
                                       lab_test::SetupIsolatedWalletDir(*this, "sqlite_init_tests"));

    // SQLiteDatabase::Create is what WalletDatabase::Create resolves to
    // (wallet/walletdb.h: using WalletDatabase = SQLiteDatabase). Calling it directly
    // keeps this test's includes to wallet/db.h and avoids pulling in the whole wallet.
    std::unique_ptr<SQLiteDatabase> db = SQLiteDatabase::Create(path);
    BOOST_REQUIRE(db != nullptr);
    BOOST_CHECK(!db->IsDummy());

    // Prove the connection is usable, not merely constructed.
    const std::string key = "lab_sqlite_init_1";
    const std::string written = "value-written-through-a-real-sqlite-file";

    {
        SQLiteBatch batch(*db, "cw+");
        BOOST_CHECK(batch.Write(key, written));
    }

    {
        SQLiteBatch batch(*db, "r");
        std::string read_back;
        BOOST_CHECK(batch.Read(key, read_back));
        BOOST_CHECK_EQUAL(read_back, written);
    }

    // The database file must exist on disk: this was a file-backed open, not a fallback
    // to :memory: or to a dummy.
    BOOST_CHECK(fs::exists(path / "wallet.sqlite") || fs::exists(path));
}

BOOST_AUTO_TEST_SUITE_END()
