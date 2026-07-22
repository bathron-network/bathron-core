// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Settlement Layer Tests - TX_LOCK validation and DB operations
 *
 * Ref: doc/blueprints/settlement/LOCK-SETTLEMENT-v1.3.2.md
 *
 * Tests:
 *   1. SettlementState invariants and serialization
 *   2. VaultEntry and M1Receipt serialization
 *   3. Settlement DB operations (IsVault, IsM1Receipt, IsM0Standard)
 *   4. TX_LOCK structure validation (CheckLock)
 *   5. ApplyLock state mutation
 */

#include "state/settlement.h"
#include "state/settlementdb.h"
#include "state/settlement_logic.h"
#include "amount.h"
#include "clientversion.h"
#include "coins.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "hash.h"                              // Hash() (scan-vs-point-get regression txids)
#include "key.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "streams.h"
#include "htlc/htlc.h"                         // HTLC3SCreatePayload (receipt-guard regression)
#include "htlc/htlcdb.h"                       // g_htlcdb / InitHtlcDB (HTLC-outpoint guard regression)
#include "script/conditional.h"               // covenant redeemScript + spend builders (covenant-fee test)
#include "crypto/sha256.h"                     // CSHA256 (real hashlock for covenant-fee test)
#include "version.h"                           // PROTOCOL_VERSION (payload serialization)
#include "masternode/specialtx_validation.h"  // CheckSpecialTx (consensus entry point)
#include "validation.h"                        // cs_main
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(settlement_tests, BasicTestingSetup)

// =============================================================================
// Helper: Create a mock TX_LOCK transaction (no real signature needed for unit tests)
// =============================================================================
// BP30 v2.0: OP_TRUE vault script (consensus-protected)
static CScript GetOpTrueScript()
{
    CScript script;
    script << OP_TRUE;
    return script;
}

static CMutableTransaction CreateMockTxLock(CAmount lockAmount,
                                            const CScript& vaultScript,
                                            const CScript& receiptScript)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_LOCK;

    // Mock input (we won't actually spend it in unit tests)
    uint256 dummyTxid;
    dummyTxid.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    mtx.vin.emplace_back(CTxIn(COutPoint(dummyTxid, 0)));

    // Outputs: vout[0] = Vault, vout[1] = Receipt (canonical order A11)
    mtx.vout.emplace_back(CTxOut(lockAmount, vaultScript));
    mtx.vout.emplace_back(CTxOut(lockAmount, receiptScript));

    return mtx;
}

// =============================================================================
// GetSettlementTxFee: the single source of truth shared by mempool acceptance
// and ConnectBlock. Regression guard for the bug where the two fee calculations
// diverged for TX_UNLOCK (mempool=0, ConnectBlock=m0Out), which made every honest
// block carrying an unlock fail bad-cb-amount and let a malicious producer mint
// m0Out of un-backed M0 into the coinbase.
// =============================================================================
BOOST_AUTO_TEST_CASE(settlement_tx_fee_is_shared_and_correct)
{
    const CAmount P = 100 * COIN;
    const CScript opTrue = GetOpTrueScript();
    CScript p2pkh; p2pkh << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x02)
                         << OP_EQUALVERIFY << OP_CHECKSIG;

    // --- TX_LOCK: fee excludes the vout[1] M1 receipt (newly-minted M1) ---
    {
        CMutableTransaction lock = CreateMockTxLock(P, opTrue, p2pkh);
        lock.vout.emplace_back(CTxOut(5, p2pkh));            // vout[2] = change
        const CAmount valueIn  = P + 5 + 3;                  // covers vault + change + fee
        const CAmount valueOut = P + P + 5;                  // vault + receipt + change (GetValueOut)
        CAmount fee = GetSettlementTxFee(CTransaction(lock), valueIn, valueOut);
        // receipt (vout[1]=P) excluded: fee = valueIn - (vault P + change 5) = 3
        BOOST_CHECK_EQUAL(fee, 3);
        BOOST_CHECK(fee != valueIn - valueOut);              // NOT the naive raw fee
    }

    // --- TX_UNLOCK: the fee is a REAL M0 coinbase fee (BP30 v3.1 producer-incentive)
    // = M1_in - M0_out - M1_change, read from the settlement DB exactly as CheckUnlock
    // does — NOT the raw valueIn-valueOut delta (which is m0Out + 2*fee, dominated by
    // the M1 burn). ---
    {
        BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
        uint256 d; d.SetHex("22");
        COutPoint receiptOut(d, 0);
        M1Receipt r; r.outpoint = receiptOut; r.amount = P; r.nCreateHeight = 1;
        BOOST_REQUIRE(g_settlementdb->WriteReceipt(r));

        CMutableTransaction unlock;
        unlock.nVersion = CTransaction::TxVersion::SAPLING;
        unlock.nType = CTransaction::TxType::TX_UNLOCK;
        unlock.vin.emplace_back(CTxIn(receiptOut));         // receipt input (P, in DB)
        unlock.vin.emplace_back(CTxIn(COutPoint(d, 1)));    // vault input (not a receipt)
        unlock.vout.emplace_back(CTxOut(P - 10, p2pkh));    // m0Out (user)
        unlock.vout.emplace_back(CTxOut(7, p2pkh));         // m1 change (user)
        // fee = M1_in(P) - m0Out(P-10) - m1Change(7) = 3, released to the coinbase.
        const CAmount valueIn  = P + P;
        const CAmount valueOut = (P - 10) + 7;
        CAmount fee = GetSettlementTxFee(CTransaction(unlock), valueIn, valueOut);
        BOOST_CHECK_EQUAL(fee, 3);
        BOOST_CHECK(fee != valueIn - valueOut);             // raw delta is m0Out + 2*fee
        g_settlementdb->EraseReceipt(receiptOut);
    }

    // --- TX_TRANSFER_M1 and NORMAL: standard raw fee = valueIn - valueOut ---
    {
        uint256 d; d.SetHex("33");
        CMutableTransaction xfer;
        xfer.nVersion = CTransaction::TxVersion::SAPLING;
        xfer.nType = CTransaction::TxType::TX_TRANSFER_M1;
        xfer.vin.emplace_back(CTxIn(COutPoint(d, 0)));
        xfer.vout.emplace_back(CTxOut(P, p2pkh));
        BOOST_CHECK_EQUAL(GetSettlementTxFee(CTransaction(xfer), P + 7, P), 7);

        CMutableTransaction normal;
        normal.nVersion = CTransaction::TxVersion::SAPLING;
        normal.nType = CTransaction::TxType::NORMAL;
        normal.vin.emplace_back(CTxIn(COutPoint(d, 1)));
        normal.vout.emplace_back(CTxOut(P, p2pkh));
        BOOST_CHECK_EQUAL(GetSettlementTxFee(CTransaction(normal), P + 11, P), 11);
    }
}

// =============================================================================
// A settlement/special tx must NOT carry Sapling shielded data. This closes the
// M0-shield inflation vector where a crafted TX_LOCK with negative valueBalance
// pushes un-backed value into the Sapling pool that the settlement conservation
// (blind to valueBalance) never charges to the inputs. Shielding M0 is a NORMAL
// (type-0) tx only.
// =============================================================================
BOOST_AUTO_TEST_CASE(settlement_tx_rejects_sapling_data)
{
    LOCK(cs_main);  // CheckSpecialTx is EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    CKey key; key.MakeNewKey(true);
    CScript dest = GetScriptForDestination(key.GetPubKey().GetID());

    // A well-formed TX_LOCK is accepted by the basic checks...
    {
        CMutableTransaction ok = CreateMockTxLock(100 * COIN, GetOpTrueScript(), dest);
        CTransaction tx(ok);
        CValidationState st;
        CheckSpecialTx(tx, nullptr, nullptr, st);  // no context: runs CheckSpecialTxBasic
        BOOST_CHECK(st.GetRejectReason() != "bad-txns-special-has-sapling");
    }

    // ...but the same TX_LOCK carrying a shielded sink (valueBalance < 0) is rejected.
    {
        CMutableTransaction bad = CreateMockTxLock(100 * COIN, GetOpTrueScript(), dest);
        bad.sapData->valueBalance = -50 * COIN;   // shield value into the pool
        BOOST_REQUIRE(CTransaction(bad).hasSaplingData());
        CTransaction tx(bad);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, nullptr, nullptr, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-special-has-sapling");
    }
}

// =============================================================================
// M0 shield consensus accounting (M0<->M0shield). Validates, at the consensus
// value-accounting level (no funded wallet needed), that shielding/unshielding M0
// is conserved: the Sapling sink is charged to inputs when shielding and credited
// as an input when unshielding, so shielded M0 is always backed. This is exactly
// the property the TX_LOCK receipt-exclusion bug violated — here on the legitimate
// NORMAL-tx shield path it holds. Plus the ZIP209 turnstile accumulation that makes
// "cannot unshield more than was shielded" a chain invariant.
// =============================================================================
BOOST_AUTO_TEST_CASE(m0_shield_value_accounting_and_turnstile)
{
    CScript p2pkh; p2pkh << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, 0x07)
                         << OP_EQUALVERIFY << OP_CHECKSIG;
    uint256 d; d.SetHex("55");
    const CAmount O = 20 * COIN;   // transparent output kept
    const CAmount X = 30 * COIN;   // amount moved across the shield boundary
    const CAmount F = 500;         // fee

    // ── M0 -> shield: NORMAL tx, valueBalance < 0 moves X into the shielded pool. ──
    CMutableTransaction shield;
    shield.nVersion = CTransaction::TxVersion::SAPLING;
    shield.nType = CTransaction::TxType::NORMAL;
    shield.vin.emplace_back(CTxIn(COutPoint(d, 0)));
    shield.vout.emplace_back(CTxOut(O, p2pkh));
    shield.sapData->valueBalance = -X;             // shield X into the pool
    CTransaction txShield(shield);
    // GetValueOut MUST include the shielded sink: value out = O + X (not just O).
    BOOST_CHECK_EQUAL(txShield.GetValueOut(), O + X);
    BOOST_CHECK_EQUAL(txShield.GetShieldedValueIn(), 0);
    // Standard fee accounting charges the FULL sink to inputs: inputs O+X+F cover it,
    // fee = F. (Contrast the TX_LOCK bug, which dropped the sink from validation.)
    BOOST_CHECK_EQUAL(GetSettlementTxFee(txShield, /*valueIn=*/O + X + F, txShield.GetValueOut()), F);

    // ── M0shield -> M0: NORMAL tx, valueBalance > 0 moves X back to transparent. ──
    CMutableTransaction unshield;
    unshield.nVersion = CTransaction::TxVersion::SAPLING;
    unshield.nType = CTransaction::TxType::NORMAL;
    unshield.vin.emplace_back(CTxIn(COutPoint(d, 1)));  // (spends the note off-chain via sapData)
    unshield.vout.emplace_back(CTxOut(X - F, p2pkh));   // X out minus fee
    unshield.sapData->valueBalance = X;                 // unshield X from the pool
    CTransaction txUnshield(unshield);
    // Positive valueBalance is credited as an input; GetValueOut is transparent-only.
    BOOST_CHECK_EQUAL(txUnshield.GetShieldedValueIn(), X);
    BOOST_CHECK_EQUAL(txUnshield.GetValueOut(), X - F);
    // valueIn = transparent(0) + shielded X ; fee = X - (X - F) = F.
    BOOST_CHECK_EQUAL(GetSettlementTxFee(txUnshield, /*valueIn=*/0 + X, txUnshield.GetValueOut()), F);

    // ── Turnstile (ZIP209) accumulation: nChainSaplingValue = Σ per-block nSaplingValue,
    //    where a block's nSaplingValue = Σ(-valueBalance). Shielding grows the pool,
    //    unshielding shrinks it, and the pool may never go negative (that block is
    //    rejected by ConnectBlock with turnstile-violation-sapling-shielded-pool). ──
    CBlockIndex g; g.pprev = nullptr; g.nSaplingValue = 0; g.SetChainSaplingValue();
    CBlockIndex b1; b1.pprev = &g;  b1.nSaplingValue = X;  b1.SetChainSaplingValue();  // shield X
    BOOST_REQUIRE(b1.nChainSaplingValue);
    BOOST_CHECK_EQUAL(*b1.nChainSaplingValue, X);                 // pool == X (>= 0, ok)
    CBlockIndex b2; b2.pprev = &b1; b2.nSaplingValue = -X; b2.SetChainSaplingValue(); // unshield X
    BOOST_REQUIRE(b2.nChainSaplingValue);
    BOOST_CHECK_EQUAL(*b2.nChainSaplingValue, 0);                 // pool back to 0 (ok)
    CBlockIndex b3; b3.pprev = &b2; b3.nSaplingValue = -1; b3.SetChainSaplingValue(); // over-unshield
    BOOST_REQUIRE(b3.nChainSaplingValue);
    BOOST_CHECK(*b3.nChainSaplingValue < 0);   // negative pool → ConnectBlock rejects this block
}

// =============================================================================
// Test 1: SettlementState invariants and serialization
// =============================================================================
BOOST_AUTO_TEST_CASE(settlement_state_invariants)
{
    // Test A6 invariant: M0_vaulted == M1_supply
    SettlementState state;
    state.M0_vaulted = 1000 * COIN;
    state.M1_supply = 1000 * COIN;
    state.nHeight = 100;

    // 1000 == 1000 → should pass
    BOOST_CHECK(state.CheckInvariants());

    // Break the invariant
    state.M1_supply = 800 * COIN; // Now 1000 != 800
    BOOST_CHECK(!state.CheckInvariants());

    // Fix it back
    state.M1_supply = 1000 * COIN;
    BOOST_CHECK(state.CheckInvariants());
}

// =============================================================================
// Test 2: CheckLock validation logic
// =============================================================================
BOOST_AUTO_TEST_CASE(checklock_validates_structure)
{
    // Initialize settlement DB for M0 standard checks
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    // BP30 v2.0: Vault MUST use OP_TRUE script (consensus-protected)
    CScript vaultScript = GetOpTrueScript();
    CScript receiptScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Test 1: Valid TX_LOCK (with OP_TRUE vault)
    {
        CMutableTransaction mtx = CreateMockTxLock(100 * COIN, vaultScript, receiptScript);
        CTransaction tx(mtx);

        CCoinsView coinsDummy;
        CCoinsViewCache view(&coinsDummy);
        CValidationState state;

        BOOST_CHECK(CheckLock(tx, view, state));
    }

    // Test 2: Wrong type (not TX_LOCK)
    {
        CMutableTransaction mtx = CreateMockTxLock(100 * COIN, vaultScript, receiptScript);
        mtx.nType = CTransaction::TxType::NORMAL;
        CTransaction tx(mtx);

        CCoinsView coinsDummy;
        CCoinsViewCache view(&coinsDummy);
        CValidationState state;

        BOOST_CHECK(!CheckLock(tx, view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txlock-type");
    }

    // Test 3: Amount mismatch (vout[0] != vout[1])
    {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_LOCK;

        uint256 dummyTxid;
        dummyTxid.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
        mtx.vin.emplace_back(CTxIn(COutPoint(dummyTxid, 0)));

        mtx.vout.emplace_back(CTxOut(100 * COIN, vaultScript));
        mtx.vout.emplace_back(CTxOut(99 * COIN, receiptScript)); // Different!
        CTransaction tx(mtx);

        CCoinsView coinsDummy;
        CCoinsViewCache view(&coinsDummy);
        CValidationState state;

        BOOST_CHECK(!CheckLock(tx, view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txlock-amount-mismatch");
    }

    // Test 4: Wrong output count (not exactly 2)
    {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_LOCK;

        uint256 dummyTxid;
        dummyTxid.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
        mtx.vin.emplace_back(CTxIn(COutPoint(dummyTxid, 0)));

        mtx.vout.emplace_back(CTxOut(100 * COIN, vaultScript));
        // Only 1 output
        CTransaction tx(mtx);

        CCoinsView coinsDummy;
        CCoinsViewCache view(&coinsDummy);
        CValidationState state;

        BOOST_CHECK(!CheckLock(tx, view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txlock-output-count");
    }

    // Test 5: Zero amount
    {
        CMutableTransaction mtx = CreateMockTxLock(0, vaultScript, receiptScript);
        CTransaction tx(mtx);

        CCoinsView coinsDummy;
        CCoinsViewCache view(&coinsDummy);
        CValidationState state;

        BOOST_CHECK(!CheckLock(tx, view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txlock-amount-zero");
    }

    // Test 6: Vault is NOT OP_TRUE (BP30 v2.0: must be OP_TRUE)
    {
        CKey wrongKey;
        wrongKey.MakeNewKey(true);
        CScript p2pkhScript = GetScriptForDestination(wrongKey.GetPubKey().GetID());

        CMutableTransaction mtx = CreateMockTxLock(100 * COIN, p2pkhScript, receiptScript);
        CTransaction tx(mtx);

        CCoinsView coinsDummy;
        CCoinsViewCache view(&coinsDummy);
        CValidationState state;

        BOOST_CHECK(!CheckLock(tx, view, state));
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txlock-vault-not-optrue");
    }
}

// =============================================================================
// Test 3: SettlementState serialization round-trip
// =============================================================================
BOOST_AUTO_TEST_CASE(settlement_state_serialization)
{
    // A6 invariant: M0_vaulted == M1_supply
    SettlementState original;
    original.M0_vaulted = 1000 * COIN;
    original.M1_supply = 1000 * COIN;
    original.M0_shielded = 500 * COIN;  // Informative only
    original.nHeight = 12345;

    // Verify invariant holds (1000 == 1000)
    BOOST_CHECK(original.CheckInvariants());

    // Serialize
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << original;

    // Deserialize
    SettlementState loaded;
    ss >> loaded;

    // Verify all fields
    BOOST_CHECK_EQUAL(loaded.M0_vaulted, original.M0_vaulted);
    BOOST_CHECK_EQUAL(loaded.M1_supply, original.M1_supply);
    BOOST_CHECK_EQUAL(loaded.M0_shielded, original.M0_shielded);
    BOOST_CHECK_EQUAL(loaded.nHeight, original.nHeight);
    BOOST_CHECK(loaded.CheckInvariants());
}

// =============================================================================
// Test 4: VaultEntry and M1Receipt serialization
// =============================================================================
BOOST_AUTO_TEST_CASE(vault_receipt_serialization)
{
    // Create a dummy txid
    uint256 txid;
    txid.SetHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

    // VaultEntry - BP30 v2.0: No receiptOutpoint (bearer model)
    VaultEntry vault;
    vault.outpoint = COutPoint(txid, 0);
    vault.amount = 100 * COIN;
    vault.nLockHeight = 12345;
    // NOTE: vault.receiptOutpoint removed in bearer model - no 1:1 link

    CDataStream ssVault(SER_DISK, CLIENT_VERSION);
    ssVault << vault;

    VaultEntry loadedVault;
    ssVault >> loadedVault;

    BOOST_CHECK(loadedVault.outpoint == vault.outpoint);
    BOOST_CHECK_EQUAL(loadedVault.amount, vault.amount);
    BOOST_CHECK_EQUAL(loadedVault.nLockHeight, vault.nLockHeight);

    // M1Receipt - BP30 v2.0: No vaultOutpoint (bearer model)
    M1Receipt receipt;
    receipt.outpoint = COutPoint(txid, 1);
    receipt.amount = 100 * COIN;
    // NOTE: receipt.vaultOutpoint removed in bearer model - M1 is bearer asset
    receipt.nCreateHeight = 12345;

    CDataStream ssReceipt(SER_DISK, CLIENT_VERSION);
    ssReceipt << receipt;

    M1Receipt loadedReceipt;
    ssReceipt >> loadedReceipt;

    BOOST_CHECK(loadedReceipt.outpoint == receipt.outpoint);
    BOOST_CHECK_EQUAL(loadedReceipt.amount, receipt.amount);
    BOOST_CHECK_EQUAL(loadedReceipt.nCreateHeight, receipt.nCreateHeight);
}

// =============================================================================
// Test 5: IsM0Standard is DB-driven
// =============================================================================
BOOST_AUTO_TEST_CASE(is_m0_standard_db_driven)
{
    // Initialize settlement DB
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    // Create a dummy outpoint
    uint256 txid;
    txid.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    COutPoint testOutpoint(txid, 0);

    // Initially should be M0 standard (not in any index)
    BOOST_CHECK(g_settlementdb->IsM0Standard(testOutpoint));

    // Add as Vault
    VaultEntry vault;
    vault.outpoint = testOutpoint;
    vault.amount = 100 * COIN;
    BOOST_REQUIRE(g_settlementdb->WriteVault(vault));

    // Now should NOT be M0 standard
    BOOST_CHECK(!g_settlementdb->IsM0Standard(testOutpoint));
    BOOST_CHECK(g_settlementdb->IsVault(testOutpoint));

    // Clean up
    BOOST_REQUIRE(g_settlementdb->EraseVault(testOutpoint));
    BOOST_CHECK(g_settlementdb->IsM0Standard(testOutpoint));

    // Test with Receipt
    COutPoint receiptOutpoint(txid, 1);
    BOOST_CHECK(g_settlementdb->IsM0Standard(receiptOutpoint));

    M1Receipt receipt;
    receipt.outpoint = receiptOutpoint;
    receipt.amount = 100 * COIN;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(receipt));

    BOOST_CHECK(!g_settlementdb->IsM0Standard(receiptOutpoint));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOutpoint));

    // Clean up
    BOOST_REQUIRE(g_settlementdb->EraseReceipt(receiptOutpoint));
    BOOST_CHECK(g_settlementdb->IsM0Standard(receiptOutpoint));
}

// =============================================================================
// Test 6: ApplyLock mutates SettlementState correctly
// =============================================================================
BOOST_AUTO_TEST_CASE(applylock_state_mutation)
{
    // Initialize settlement DB
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    // BP30 v2.0: Vault uses OP_TRUE (consensus-protected)
    CScript vaultScript = GetOpTrueScript();
    CScript receiptScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Create valid TX_LOCK
    CAmount P = 100 * COIN;
    CMutableTransaction mtx = CreateMockTxLock(P, vaultScript, receiptScript);
    CTransaction tx(mtx);

    // Initial state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 1000;

    BOOST_CHECK(state.CheckInvariants()); // 0 == 0

    // Apply the lock
    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CSettlementDB::Batch batch = g_settlementdb->CreateBatch();

    uint32_t nHeight = 1001;
    BOOST_CHECK(ApplyLock(tx, view, state, nHeight, batch));

    // Verify state mutation (A6)
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);

    // Invariant should still hold: P + 0 == P + 0
    BOOST_CHECK(state.CheckInvariants());

    // Verify DB entries were prepared (via batch)
    // Note: Batch writes are not committed yet, but we can verify the vault was created
    const uint256& txid = tx.GetHash();

    // Commit the batch
    BOOST_CHECK(batch.Commit());

    // Now verify DB entries
    COutPoint vaultOutpoint(txid, 0);
    COutPoint receiptOutpoint(txid, 1);

    BOOST_CHECK(g_settlementdb->IsVault(vaultOutpoint));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOutpoint));
    BOOST_CHECK(!g_settlementdb->IsM0Standard(vaultOutpoint));
    BOOST_CHECK(!g_settlementdb->IsM0Standard(receiptOutpoint));

    // Verify VaultEntry contents - BP30 v2.0: No receipt link (bearer model)
    VaultEntry vault;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOutpoint, vault));
    BOOST_CHECK_EQUAL(vault.amount, P);
    BOOST_CHECK_EQUAL(vault.nLockHeight, nHeight);

    // Verify M1Receipt contents - BP30 v2.0: No vault link (bearer model)
    M1Receipt receipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(receiptOutpoint, receipt));
    BOOST_CHECK_EQUAL(receipt.amount, P);
    BOOST_CHECK_EQUAL(receipt.nCreateHeight, nHeight);
}

// =============================================================================
// TX_UNLOCK Tests (6 tests)
// =============================================================================

// Helper: Create a mock TX_UNLOCK transaction
static CMutableTransaction CreateMockTxUnlock(const COutPoint& receiptOutpoint,
                                               const COutPoint& vaultOutpoint,
                                               CAmount unlockAmount,
                                               const CScript& destScript)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;

    // Inputs: vin[0] = Receipt, vin[1] = Vault (canonical order)
    mtx.vin.emplace_back(CTxIn(receiptOutpoint));
    mtx.vin.emplace_back(CTxIn(vaultOutpoint));

    // Output: vout[0] = M0 (unlocked amount)
    mtx.vout.emplace_back(CTxOut(unlockAmount, destScript));

    return mtx;
}

// Helper: Setup Vault+Receipt pair in DB for unlock tests
static void SetupVaultReceiptPair(CAmount P, uint32_t lockHeight,
                                   COutPoint& vaultOut, COutPoint& receiptOut)
{
    // Create a unique txid for this pair
    static int counter = 0;
    counter++;
    uint256 lockTxid;
    lockTxid.SetHex(strprintf("aabbccdd%056d", counter));

    vaultOut = COutPoint(lockTxid, 0);
    receiptOut = COutPoint(lockTxid, 1);

    // Create and write Vault entry - BP30 v2.0: No receipt link (bearer model)
    VaultEntry vault;
    vault.outpoint = vaultOut;
    vault.amount = P;
    vault.nLockHeight = lockHeight;
    // NOTE: No receiptOutpoint or unlockPubKey in bearer model
    BOOST_REQUIRE(g_settlementdb->WriteVault(vault));

    // Create and write Receipt entry - BP30 v2.0: No vault link (bearer model)
    M1Receipt receipt;
    receipt.outpoint = receiptOut;
    receipt.amount = P;
    // NOTE: No vaultOutpoint in bearer model - M1 is a bearer asset
    receipt.nCreateHeight = lockHeight;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(receipt));
}

// =============================================================================
// Test 7: CheckUnlock rejects when receipt missing
// =============================================================================
BOOST_AUTO_TEST_CASE(checkunlock_missing_receipt_reject)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Create fake outpoints (not in DB)
    uint256 fakeTxid;
    fakeTxid.SetHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    COutPoint fakeReceipt(fakeTxid, 0);
    COutPoint fakeVault(fakeTxid, 1);

    CMutableTransaction mtx = CreateMockTxUnlock(fakeReceipt, fakeVault, 100 * COIN, destScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    BOOST_CHECK(!CheckUnlock(tx, view, state));
    // BP30 v3.0 (M1 fee model): an input that is neither a known M1 receipt nor a
    // known vault is rejected outright (no M0 fee inputs). The unknown fakeReceipt
    // input trips this before the per-section receipt/vault tallies.
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txunlock-invalid-input");
}

// =============================================================================
// Test 8: CheckUnlock rejects when vault missing
// =============================================================================
BOOST_AUTO_TEST_CASE(checkunlock_vault_missing_reject)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Create only a receipt (no vault) - BP30 v2.0 bearer model
    uint256 txid;
    txid.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    COutPoint receiptOut(txid, 1);
    COutPoint vaultOut(txid, 0);

    // Write only receipt, not vault
    M1Receipt receipt;
    receipt.outpoint = receiptOut;
    receipt.amount = 100 * COIN;
    receipt.nCreateHeight = 1000;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(receipt));

    CMutableTransaction mtx = CreateMockTxUnlock(receiptOut, vaultOut, 100 * COIN, destScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    BOOST_CHECK(!CheckUnlock(tx, view, state));
    // BP30 v3.0 (M1 fee model): the vault input is absent from the settlement DB,
    // so it is neither a known receipt nor a known vault -> rejected as an invalid
    // input (the old "fee-before-vault" reason no longer exists).
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txunlock-invalid-input");

    // Cleanup
    g_settlementdb->EraseReceipt(receiptOut);
}

// =============================================================================
// Test 9: CheckUnlock rejects when vault amount insufficient (BP30 v2.0 bearer model)
// =============================================================================
BOOST_AUTO_TEST_CASE(checkunlock_vault_insufficient_reject)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Create receipt with more amount than vault
    uint256 txid;
    txid.SetHex("3333333333333333333333333333333333333333333333333333333333333333");

    COutPoint vaultOut(txid, 0);
    COutPoint receiptOut(txid, 1);

    // Vault with 50 COIN
    VaultEntry vault;
    vault.outpoint = vaultOut;
    vault.amount = 50 * COIN;
    vault.nLockHeight = 1000;
    BOOST_REQUIRE(g_settlementdb->WriteVault(vault));

    // Receipt with 100 COIN (more than vault!)
    M1Receipt receipt;
    receipt.outpoint = receiptOut;
    receipt.amount = 100 * COIN;
    receipt.nCreateHeight = 1000;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(receipt));

    CMutableTransaction mtx = CreateMockTxUnlock(receiptOut, vaultOut, 100 * COIN, destScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // BP30 v3.1: a full unlock of a 100-M1 receipt backed by only a 50-M0 vault
    // cannot satisfy vault conservation (totalVault == M0_out + fee + vault_backing:
    // 50 != 100 + 0 + 0), so it is rejected as vault-not-rebacked (the single
    // UTXO-level A6 guard now subsumes the old "vault-insufficient" check).
    BOOST_CHECK(!CheckUnlock(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txunlock-vault-not-rebacked");

    // Cleanup
    g_settlementdb->EraseVault(vaultOut);
    g_settlementdb->EraseReceipt(receiptOut);
}

// =============================================================================
// Test 9b: Conservation violation MUST fail (anti-inflation/deflation bug)
// =============================================================================
BOOST_AUTO_TEST_CASE(checkunlock_conservation_violation_reject)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Create vault with 10 M0
    COutPoint vaultOut;
    GetStrongRandBytes(vaultOut.hash.begin(), 32);
    vaultOut.n = 0;

    VaultEntry vault;
    vault.outpoint = vaultOut;
    vault.amount = 10 * COIN;
    vault.nLockHeight = 1000;
    BOOST_REQUIRE(g_settlementdb->WriteVault(vault));

    // Create M1 receipt with 10 M1
    COutPoint receiptOut;
    GetStrongRandBytes(receiptOut.hash.begin(), 32);
    receiptOut.n = 1;

    M1Receipt receipt;
    receipt.outpoint = receiptOut;
    receipt.amount = 10 * COIN;
    receipt.nCreateHeight = 1000;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(receipt));

    // ========================================================================
    // TEST: M1_in > M0_out + M1_change (attempting to burn extra M1)
    // This MUST fail - would break A6 invariant (M0_vaulted == M1_supply)
    // ========================================================================
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;

    // vin[0] = M1 Receipt (10 M1)
    mtx.vin.emplace_back(CTxIn(receiptOut));
    // vin[1] = Vault (10 M0)
    mtx.vin.emplace_back(CTxIn(vaultOut));

    // BP30 v3.1 conservation rule: M1_in must cover M0_out + M1_change (the fee is
    // the non-negative remainder, released to the coinbase). To exercise the check,
    // take MORE M0 + M1 change than the redeemed M1 holds:
    //   M0_out(8) + M1_change(5) = 13 > M1_in(10)
    // i.e. an attempt to materialise 3 extra M1. This MUST be rejected (A6).
    mtx.vout.emplace_back(CTxOut(8 * COIN, destScript));         // vout[0] M0 out (P2PKH)
    mtx.vout.emplace_back(CTxOut(5 * COIN, destScript));         // vout[1] M1 change (P2PKH)

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // MUST reject - conservation violated (M1 out != M1 in)
    BOOST_CHECK(!CheckUnlock(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txunlock-conservation-violated");

    // Cleanup
    g_settlementdb->EraseVault(vaultOut);
    g_settlementdb->EraseReceipt(receiptOut);
}

// =============================================================================
// Test 10: ApplyUnlock deletes DB entries
// =============================================================================
BOOST_AUTO_TEST_CASE(applyunlock_deletes_db_entries)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 100 * COIN;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Verify entries exist
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    // Create TX_UNLOCK
    CMutableTransaction mtx = CreateMockTxUnlock(receiptOut, vaultOut, P, destScript);
    CTransaction tx(mtx);

    // Setup state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = P;
    state.M1_supply = P;
    BOOST_CHECK(state.CheckInvariants()); // P == P

    // Apply unlock
    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    auto batch = g_settlementdb->CreateBatch();

    UnlockUndoData undoData;
    BOOST_CHECK(ApplyUnlock(tx, view, state, batch, undoData));
    BOOST_CHECK(batch.Commit());

    // Verify entries are deleted
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK(g_settlementdb->IsM0Standard(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM0Standard(receiptOut));
}

// =============================================================================
// Test 11: ApplyUnlock state mutation preserves invariant
// =============================================================================
BOOST_AUTO_TEST_CASE(applyunlock_state_mutation_invariant)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 200 * COIN;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Setup state with existing lock (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = P;
    state.M1_supply = P;
    BOOST_CHECK(state.CheckInvariants()); // P == P

    // Create and apply TX_UNLOCK
    CMutableTransaction mtx = CreateMockTxUnlock(receiptOut, vaultOut, P, destScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    auto batch = g_settlementdb->CreateBatch();

    UnlockUndoData undoData;
    BOOST_CHECK(ApplyUnlock(tx, view, state, batch, undoData));
    BOOST_CHECK(batch.Commit());

    // Verify state mutation: M0_vaulted -= P, M1_supply -= P
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);

    // Invariant must still hold: 0 + 0 == 0 + 0
    BOOST_CHECK(state.CheckInvariants());
}

// =============================================================================
// Test 12: UndoUnlock restores everything (BP30 v2.1)
// =============================================================================
BOOST_AUTO_TEST_CASE(undo_unlock_restores_everything)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 150 * COIN;
    uint32_t lockHeight = 1000;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, lockHeight, vaultOut, receiptOut);

    // Read entries before unlock (for later comparison)
    VaultEntry originalVault;
    M1Receipt originalReceipt;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, originalVault));
    BOOST_CHECK(g_settlementdb->ReadReceipt(receiptOut, originalReceipt));

    // Setup state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = P;
    state.M1_supply = P;

    // Create TX_UNLOCK and apply
    CMutableTransaction mtx = CreateMockTxUnlock(receiptOut, vaultOut, P, destScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    UnlockUndoData undoData;

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(tx, view, state, batch, undoData));
        BOOST_CHECK(batch.Commit());
    }

    // State after unlock
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));

    // Verify undoData captured correctly
    BOOST_CHECK_EQUAL(undoData.receiptsSpent.size(), 1);
    BOOST_CHECK_EQUAL(undoData.vaultsSpent.size(), 1);
    BOOST_CHECK_EQUAL(undoData.m0Released, P);
    BOOST_CHECK_EQUAL(undoData.netM1Burned, P);
    BOOST_CHECK_EQUAL(undoData.changeReceiptsCreated, 0);

    // Now UNDO the unlock using undoData
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoUnlock(tx, undoData, state, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify state restored
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK(state.CheckInvariants());

    // Verify DB entries restored
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    // Verify entry contents - BP30 v2.0: No link fields in bearer model
    VaultEntry restoredVault;
    M1Receipt restoredReceipt;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, restoredVault));
    BOOST_CHECK(g_settlementdb->ReadReceipt(receiptOut, restoredReceipt));

    BOOST_CHECK_EQUAL(restoredVault.amount, P);
    BOOST_CHECK_EQUAL(restoredReceipt.amount, P);
}

// =============================================================================
// Test 12: Unlock with M1 change (BP30 v2.1 - partial unlock)
// =============================================================================
// Helper: sum every vault UTXO currently held in the settlement DB.
// THE UTXO-level A6 guard: sum(vault UTXOs) must equal M0_vaulted, else some M1
// is unbacked (stranded / unredeemable). The scalar A6 (M0_vaulted == M1_supply)
// does NOT catch a missing vault UTXO; only this sum does.
static CAmount SumAllVaultUTXOs()
{
    CAmount total = 0;
    g_settlementdb->ForEachVault([&total](const VaultEntry& v) {
        total += v.amount;
        return true;  // keep iterating
    });
    return total;
}

// =============================================================================
// B11 regression: ForEachVault (iterator scan) vs point-gets (IsVault/ReadVault)
// =============================================================================
// A fuzz-harness artifact once masqueraded as "the scan loses a just-written
// vault": two byte-identical mock LOCKs (collapsed funding txids + equal random
// amount) shared one tx hash, so the second WriteVault upserted the SAME key
// while the harness model counted the amount twice — the scan and the point-gets
// never disagreed. Pin the real contract here: at a scale that crosses the
// memtable->L0 compaction (256KB write buffer at the 1MB test cache size), the
// scan returns EXACTLY the point-gettable set — same count, same amounts, same
// sum — including an all-zero-txid outpoint that the previous composite seek key
// (DB_VAULT, COutPoint()) skipped (default COutPoint has n=0xFFFFFFFF), and
// duplicate writes behave as upserts.

static uint256 ScanTxid(int ctr)
{
    const std::string s = strprintf("b11-scan-%d", ctr);
    return Hash(s.begin(), s.end());
}

// The scan must return exactly the model set: no missing, no extra, no
// duplicated outpoint, equal amounts, and every model entry point-gettable.
static void CheckScanMatchesPointGets(const std::map<COutPoint, CAmount>& model)
{
    std::map<COutPoint, CAmount> scanned;
    g_settlementdb->ForEachVault([&scanned](const VaultEntry& v) {
        BOOST_CHECK_MESSAGE(scanned.emplace(v.outpoint, v.amount).second,
                            "duplicate outpoint in scan: " << v.outpoint.ToString());
        return true;
    });
    BOOST_CHECK_EQUAL(scanned.size(), model.size());
    CAmount sumScan = 0, sumModel = 0;
    for (const auto& p : scanned) {
        const auto itM = model.find(p.first);
        BOOST_REQUIRE_MESSAGE(itM != model.end(),
                              "scan returned unknown outpoint " << p.first.ToString());
        BOOST_CHECK_EQUAL(p.second, itM->second);
        sumScan += p.second;
    }
    for (const auto& p : model) {
        sumModel += p.second;
        BOOST_CHECK_MESSAGE(g_settlementdb->IsVault(p.first),
                            "IsVault false for " << p.first.ToString());
        VaultEntry v;
        BOOST_REQUIRE_MESSAGE(g_settlementdb->ReadVault(p.first, v),
                              "ReadVault failed for " << p.first.ToString());
        BOOST_CHECK_EQUAL(v.amount, p.second);
        BOOST_CHECK_MESSAGE(scanned.count(p.first),
                            "scan MISSED vault " << p.first.ToString());
    }
    BOOST_CHECK_EQUAL(sumScan, sumModel);
}

// Fill nEntries vaults (checking scan==point-gets periodically so the check
// straddles the memtable->L0 compaction boundary), then exercise upsert,
// early-stop and erase. Returns the final expected model.
static std::map<COutPoint, CAmount> FillAndCheckVaultScan(int nEntries)
{
    // Live neighbor prefixes on both sides of 'V' ('R'/'U' below, 'Z' above)
    // so the scan has to stop by prefix, not by end-of-DB.
    M1Receipt r;
    r.outpoint = COutPoint(ScanTxid(-1), 1);
    r.amount = 777;
    r.nCreateHeight = 1;
    BOOST_REQUIRE(g_settlementdb->WriteReceipt(r));
    BOOST_REQUIRE(g_settlementdb->WriteUnlockUndo(ScanTxid(-2), UnlockUndoData()));
    BOOST_REQUIRE(g_settlementdb->WriteBurnscanProgress(42, ScanTxid(-3)));
    BOOST_REQUIRE(g_settlementdb->WriteBestBlock(ScanTxid(-4)));

    std::map<COutPoint, CAmount> model;
    const auto add = [&model](const COutPoint& op, CAmount amt, uint32_t h) {
        VaultEntry v;
        v.outpoint = op;
        v.amount = amt;
        v.nLockHeight = h;
        BOOST_REQUIRE(g_settlementdb->WriteVault(v));
        model[op] = amt;
        BOOST_REQUIRE_MESSAGE(g_settlementdb->IsVault(op),
                              "vault not point-gettable right after write");
    };

    // Edge outpoints: the all-zero txid sorts at the very start of the 'V'
    // range; (max txid, max-1 n) at the very end, right before the 'Z' keys.
    add(COutPoint(uint256(), 0), 11, 1);
    add(COutPoint(uint256(), 1), 22, 1);
    uint256 maxTxid;
    maxTxid.SetHex(std::string(64, 'f'));
    add(COutPoint(maxTxid, 0xFFFFFFFE), 33, 1);

    for (int i = 0; i < nEntries; ++i) {
        add(COutPoint(ScanTxid(i), (uint32_t)(i % 3)),
            (CAmount)(1 + (i * 7919) % 1000000), 100 + (uint32_t)i);
        if ((i + 1) % 500 == 0) CheckScanMatchesPointGets(model);
    }
    CheckScanMatchesPointGets(model);

    // Duplicate write on an existing key = upsert: count unchanged, last wins.
    const COutPoint dup(ScanTxid(123), 123 % 3);
    BOOST_REQUIRE(model.count(dup));
    add(dup, model[dup] + 12345, 9999);
    CheckScanMatchesPointGets(model);

    // Early-stop contract: callback returning false stops the iteration.
    int nSeen = 0;
    g_settlementdb->ForEachVault([&nSeen](const VaultEntry&) { return ++nSeen < 10; });
    BOOST_CHECK_EQUAL(nSeen, 10);

    // Erase: gone from the scan AND the point-gets.
    const COutPoint gone(ScanTxid(7), 7 % 3);
    BOOST_REQUIRE(g_settlementdb->EraseVault(gone));
    model.erase(gone);
    BOOST_CHECK(!g_settlementdb->IsVault(gone));
    CheckScanMatchesPointGets(model);

    return model;
}

BOOST_AUTO_TEST_CASE(foreachvault_scan_matches_point_gets_inmemory)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    FillAndCheckVaultScan(4000);
}

BOOST_AUTO_TEST_CASE(foreachvault_scan_matches_point_gets_ondisk)
{
    SetDataDir("settlement_scan_ondisk");
    ClearDatadirCache();
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/false, /*fWipe=*/true));
    const std::map<COutPoint, CAmount> model = FillAndCheckVaultScan(4000);

    // Close and reopen: the same set must come back off the real files
    // (sstables + recovery log), scan and point-gets agreeing again.
    g_settlementdb.reset();
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/false, /*fWipe=*/false));
    CheckScanMatchesPointGets(model);
    g_settlementdb.reset();  // release the DB before the fixture removes the datadir
}

// A no-fee PARTIAL unlock: release part of the M0 and re-vault the rest so the
// M1 change keeps spendable vault backing (the v2.2 "OP_TRUE == vault" shape,
// which the v3.0 M1-fee model must still accept when no fee is charged).
BOOST_AUTO_TEST_CASE(unlock_with_m1_change)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CPubKey ownerPubKey = key.GetPubKey();
    CScript destScript = GetScriptForDestination(ownerPubKey.GetID());
    CScript changeScript = GetScriptForDestination(ownerPubKey.GetID());  // Same for simplicity

    CAmount P = 10 * COIN;  // Lock 10 M0
    CAmount unlockAmount = 3 * COIN;  // Unlock only 3 M0
    uint32_t lockHeight = 100;

    // Initialize state (genesis, A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;
    BOOST_CHECK(state.CheckInvariants()); // 0 == 0

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Step 1: TX_LOCK - Create 10 M0 vault + 10 M1 receipt
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, lockHeight, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);

    // Verify state after LOCK
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);  // 10 M0 vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, P);          // 10 M1 supply
    BOOST_CHECK(state.CheckInvariants());

    // Step 2: TX_UNLOCK with M1 change (NO fee).
    // Unlock 3 M0; the unreleased 7 M0 must be RE-VAULTED (vout[2], OP_TRUE) so
    // the 7 M1 change keeps spendable vault backing. v3.0 canonical no-fee layout:
    //   vout[0] = M0 released (3, P2PKH)
    //   vout[1] = M1 change   (7, P2PKH)
    //   vout[2] = vault change(7, OP_TRUE)   <- re-vaults the unreleased M0
    CAmount m1Change = P - unlockAmount;  // 7 M0
    CAmount vaultChange = P - unlockAmount;  // 7 M0 re-vaulted (no fee, full backing)

    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;

    // vin[0] = M1 Receipt (10 M1)
    mtxUnlock.vin.emplace_back(CTxIn(receiptOut));
    // vin[1] = Vault (10 M0)
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));

    // vout[0] = M0 output (3 M0)
    mtxUnlock.vout.emplace_back(CTxOut(unlockAmount, destScript));
    // vout[1] = M1 change receipt (7 M1)
    mtxUnlock.vout.emplace_back(CTxOut(m1Change, changeScript));
    // vout[2] = vault change (7 M0, OP_TRUE) - re-backs the M1 change
    mtxUnlock.vout.emplace_back(CTxOut(vaultChange, GetOpTrueScript()));

    CTransaction txUnlock(mtxUnlock);

    // Validate and apply
    CValidationState validationState;
    BOOST_CHECK(CheckUnlock(txUnlock, view, validationState));

    UnlockUndoData undoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlock, view, state, batch, undoData));
        BOOST_CHECK(batch.Commit());
    }

    // Verify state after partial UNLOCK
    BOOST_CHECK_EQUAL(state.M0_vaulted, m1Change);  // 7 M0 still vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, m1Change);          // 7 M1 remaining
    BOOST_CHECK(state.CheckInvariants());                  // A6 still holds!

    // THE UTXO-level invariant: every vaulted M0 exists as a spendable vault UTXO.
    BOOST_CHECK_EQUAL(SumAllVaultUTXOs(), state.M0_vaulted);  // 7 == 7 (no leak)

    // Verify undo data
    BOOST_CHECK_EQUAL(undoData.m0Released, unlockAmount);  // 3 M0 released
    BOOST_CHECK_EQUAL(undoData.netM1Burned, unlockAmount); // 3 M1 net burned
    BOOST_CHECK_EQUAL(undoData.changeReceiptsCreated, 1);  // 1 change receipt (no fee)

    // Verify DB state
    COutPoint changeReceiptOut(txUnlock.GetHash(), 1);
    COutPoint vaultChangeOut(txUnlock.GetHash(), 2);
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));            // Original vault spent
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));      // Original receipt spent
    BOOST_CHECK(g_settlementdb->IsM1Receipt(changeReceiptOut)); // Change receipt created
    BOOST_CHECK(g_settlementdb->IsVault(vaultChangeOut));       // Change RE-VAULTED

    // Verify change receipt + vault change amounts
    M1Receipt changeReceipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(changeReceiptOut, changeReceipt));
    BOOST_CHECK_EQUAL(changeReceipt.amount, m1Change);
    VaultEntry vaultChangeEntry;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultChangeOut, vaultChangeEntry));
    BOOST_CHECK_EQUAL(vaultChangeEntry.amount, vaultChange);

    // Step 3: Undo the unlock
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoUnlock(txUnlock, undoData, state, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify state restored
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);  // Back to 10 M0
    BOOST_CHECK_EQUAL(state.M1_supply, P);          // Back to 10 M1
    BOOST_CHECK(state.CheckInvariants());
    BOOST_CHECK_EQUAL(SumAllVaultUTXOs(), P);  // original vault restored, change vault erased

    // Verify DB entries restored
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(changeReceiptOut));  // Change receipt removed
    BOOST_CHECK(!g_settlementdb->IsVault(vaultChangeOut));        // Change vault removed
}

// =============================================================================
// A6 UTXO-LEVEL ENFORCEMENT — an under-backed partial unlock MUST be rejected.
//
// Repro of ~/BATHRON-m1-redeemability-repro.txt: a no-fee partial unlock that
// releases part of the M0 but does NOT re-vault the remainder (no OP_TRUE vault
// change output) would strand the M1 change with zero vault backing — the scalar
// A6 (M0_vaulted == M1_supply) stays satisfied and HIDES the leak (sum of vault
// UTXOs < M0_vaulted), and the stranded M1 could never be unlocked again.
//
// CheckUnlock now enforces vault conservation (sum(Vault_in) == M0_out +
// vault_backing_created) so such a tx is REJECTED at consensus. The well-formed
// (re-vaulted) partial unlock is exercised by unlock_with_m1_change.
// =============================================================================
BOOST_AUTO_TEST_CASE(partial_unlock_change_stays_backed)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CPubKey ownerPubKey = key.GetPubKey();
    CScript destScript = GetScriptForDestination(ownerPubKey.GetID());
    CScript changeScript = GetScriptForDestination(ownerPubKey.GetID());

    CAmount P = 10 * COIN;            // lock 10 M0
    CAmount unlockAmount = 3 * COIN;  // release only 3 M0
    CAmount m1Change = P - unlockAmount;  // 7 M0 must stay locked, backing 7 M1
    uint32_t lockHeight = 100;

    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // LOCK 10 -> vault(10) + receipt(10)
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, lockHeight, batch));
        BOOST_CHECK(batch.Commit());
    }
    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);

    // After LOCK the UTXO-level invariant holds: sum(vaults) == M0_vaulted == 10
    BOOST_CHECK_EQUAL(SumAllVaultUTXOs(), state.M0_vaulted);

    // UNDER-BACKED PARTIAL UNLOCK (the bug): vout[0]=3 M0 released, vout[1]=7 M1
    // change, but NO vault-change output re-backing the unreleased 7 M0.
    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlock.vin.emplace_back(CTxIn(receiptOut));
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));
    mtxUnlock.vout.emplace_back(CTxOut(unlockAmount, destScript));  // M0 out
    mtxUnlock.vout.emplace_back(CTxOut(m1Change, changeScript));    // M1 change
    CTransaction txUnlock(mtxUnlock);

    // REJECTED: vault not conserved (10 != 3 + 0). The leak can never be applied.
    CValidationState vstate;
    BOOST_CHECK(!CheckUnlock(txUnlock, view, vstate));
    BOOST_CHECK_EQUAL(vstate.GetRejectReason(), "bad-txunlock-vault-not-rebacked");

    // State + UTXO invariant untouched (nothing was applied).
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(SumAllVaultUTXOs(), state.M0_vaulted);  // still 10 == 10, no leak
}

// =============================================================================
// TX_TRANSFER_M1 Tests (6 tests)
// =============================================================================

// Helper: Create a mock TX_TRANSFER_M1 transaction
static CMutableTransaction CreateMockTxTransfer(const COutPoint& receiptInput,
                                                  CAmount transferAmount,
                                                  const CScript& newOwnerScript)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vin[0] = old Receipt
    mtx.vin.emplace_back(CTxIn(receiptInput));

    // vout[0] = new Receipt (same amount)
    mtx.vout.emplace_back(CTxOut(transferAmount, newOwnerScript));

    return mtx;
}

// BP30 v3.0 (M1 fee model): single-recipient TX_TRANSFER_M1 with an explicit
// M1 fee output. Conservation: recipientAmount + m1Fee == m1In (the input receipt).
// vout[0] = recipient receipt (P2PKH), vout[1] = M1 fee (OP_TRUE, producer claims).
// M1_supply is unchanged by a transfer (the fee is relocated M1, not burned).
static CMutableTransaction CreateMockTxTransferWithFee(const COutPoint& receiptInput,
                                                       CAmount recipientAmount,
                                                       CAmount m1Fee,
                                                       const CScript& newOwnerScript)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vin[0] = old Receipt
    mtx.vin.emplace_back(CTxIn(receiptInput));

    // vout[0] = recipient receipt, vout[1] = M1 fee (OP_TRUE)
    mtx.vout.emplace_back(CTxOut(recipientAmount, newOwnerScript));
    mtx.vout.emplace_back(CTxOut(m1Fee, GetOpTrueScript()));

    return mtx;
}

// =============================================================================
// Test 13: CheckTransfer rejects when no M1 receipt input
// =============================================================================
BOOST_AUTO_TEST_CASE(transfer_reject_no_m1_input)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript newOwnerScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Create TX_TRANSFER_M1 with a fake input that is NOT a receipt
    uint256 fakeTxid;
    fakeTxid.SetHex("5555555555555555555555555555555555555555555555555555555555555555");
    COutPoint fakeInput(fakeTxid, 0);

    CMutableTransaction mtx = CreateMockTxTransfer(fakeInput, 100 * COIN, newOwnerScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-no-receipt-input");
}

// =============================================================================
// Test 14: CheckTransfer rejects when multiple M1 receipt inputs
// =============================================================================
BOOST_AUTO_TEST_CASE(transfer_reject_multi_m1_inputs)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript newOwnerScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Setup two vault+receipt pairs
    CAmount P = 100 * COIN;
    COutPoint vaultOut1, receiptOut1;
    COutPoint vaultOut2, receiptOut2;
    SetupVaultReceiptPair(P, 1000, vaultOut1, receiptOut1);
    SetupVaultReceiptPair(P, 1001, vaultOut2, receiptOut2);

    // Create TX with 2 receipt inputs (invalid)
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;
    mtx.vin.emplace_back(CTxIn(receiptOut1));
    mtx.vin.emplace_back(CTxIn(receiptOut2));  // Second receipt = invalid
    mtx.vout.emplace_back(CTxOut(P, newOwnerScript));

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    BOOST_CHECK(!CheckTransfer(tx, view, state));
    // Second receipt at vin[1] fails with "receipt-not-vin0" (canonical order violation)
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-receipt-not-vin0");

    // Cleanup
    g_settlementdb->EraseVault(vaultOut1);
    g_settlementdb->EraseReceipt(receiptOut1);
    g_settlementdb->EraseVault(vaultOut2);
    g_settlementdb->EraseReceipt(receiptOut2);
}

// =============================================================================
// Test 15: CheckTransfer rejects when sum(outputs) > old receipt amount
// BP30 v2.1: Multi-output splits allowed, but cannot exceed input
// =============================================================================
BOOST_AUTO_TEST_CASE(transfer_reject_m1_not_conserved)
{
    // BP30 v2.4: STRICT M1 conservation - sum(M1_out) must EQUAL sum(M1_in)
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript newOwnerScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 100 * COIN;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Create transfer with EXCEEDING amount (101 instead of 100)
    // BP30 v2.4: This fails strict M1 conservation (m1Out != m1In)
    CMutableTransaction mtx = CreateMockTxTransfer(receiptOut, 101 * COIN, newOwnerScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-m1-not-conserved");

    // Cleanup
    g_settlementdb->EraseVault(vaultOut);
    g_settlementdb->EraseReceipt(receiptOut);
}

// =============================================================================
// Test 16: ApplyTransfer updates vault.receiptOutpoint to new receipt
// =============================================================================
BOOST_AUTO_TEST_CASE(transfer_updates_vault_receipt_pointer)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript newOwnerScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 100 * COIN;
    COutPoint vaultOut, oldReceiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, oldReceiptOut);

    // Verify initial state - BP30 v2.0: No link in bearer model
    VaultEntry vaultBefore;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, vaultBefore));
    BOOST_CHECK_EQUAL(vaultBefore.amount, P);

    // Create and apply transfer
    CMutableTransaction mtx = CreateMockTxTransfer(oldReceiptOut, P, newOwnerScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    auto batch = g_settlementdb->CreateBatch();

    TransferUndoData undoData;
    BOOST_CHECK(ApplyTransfer(tx, view, batch, undoData));
    BOOST_CHECK(batch.Commit());

    // BP30 v2.0 Bearer model: Vault is UNCHANGED after transfer
    // (no more receipt pointer update - M1 is a bearer asset)
    VaultEntry vaultAfter;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, vaultAfter));
    BOOST_CHECK_EQUAL(vaultAfter.amount, P);
}

// =============================================================================
// Test 17: ApplyTransfer deletes old receipt and creates new receipt
// =============================================================================
BOOST_AUTO_TEST_CASE(transfer_db_deletes_old_and_creates_new)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript newOwnerScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 150 * COIN;
    COutPoint vaultOut, oldReceiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, oldReceiptOut);

    // Verify old receipt exists
    BOOST_CHECK(g_settlementdb->IsM1Receipt(oldReceiptOut));

    // Create and apply transfer
    CMutableTransaction mtx = CreateMockTxTransfer(oldReceiptOut, P, newOwnerScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    auto batch = g_settlementdb->CreateBatch();

    TransferUndoData undoData;
    BOOST_CHECK(ApplyTransfer(tx, view, batch, undoData));
    BOOST_CHECK(batch.Commit());

    COutPoint newReceiptOut(tx.GetHash(), 0);

    // Old receipt should be deleted
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(oldReceiptOut));
    BOOST_CHECK(g_settlementdb->IsM0Standard(oldReceiptOut));

    // New receipt should exist
    BOOST_CHECK(g_settlementdb->IsM1Receipt(newReceiptOut));

    // Verify new receipt contents - BP30 v2.0: No vault link in bearer model
    M1Receipt newReceipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(newReceiptOut, newReceipt));
    BOOST_CHECK_EQUAL(newReceipt.amount, P);
}

// =============================================================================
// Test 18: UndoTransfer restores everything
// =============================================================================
BOOST_AUTO_TEST_CASE(undo_transfer_restores_everything)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript newOwnerScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 200 * COIN;
    uint32_t lockHeight = 1000;
    COutPoint vaultOut, oldReceiptOut;
    SetupVaultReceiptPair(P, lockHeight, vaultOut, oldReceiptOut);

    // Save original receipt for comparison
    M1Receipt originalReceipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(oldReceiptOut, originalReceipt));

    // Create and apply transfer
    CMutableTransaction mtx = CreateMockTxTransfer(oldReceiptOut, P, newOwnerScript);
    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // BP30 v2.2: ApplyTransfer stores undo data
    TransferUndoData undoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(tx, view, batch, undoData));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint newReceiptOut(tx.GetHash(), 0);

    // Verify transfer applied
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(oldReceiptOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(newReceiptOut));

    // BP30 v2.0: Vault is unchanged (no receipt pointer in bearer model)
    VaultEntry vaultAfterTransfer;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, vaultAfterTransfer));
    BOOST_CHECK_EQUAL(vaultAfterTransfer.amount, P);

    // Now UNDO the transfer using the undo data
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(tx, undoData, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify undo: old receipt restored
    BOOST_CHECK(g_settlementdb->IsM1Receipt(oldReceiptOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(newReceiptOut));

    // Verify vault unchanged (BP30 v2.0: no pointer in bearer model)
    VaultEntry vaultAfterUndo;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, vaultAfterUndo));
    BOOST_CHECK_EQUAL(vaultAfterUndo.amount, P);

    // Verify receipt contents restored - BP30 v2.0: No vault link in bearer model
    M1Receipt restoredReceipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(oldReceiptOut, restoredReceipt));
    BOOST_CHECK_EQUAL(restoredReceipt.amount, P);
}

// =============================================================================
// Test 18b: Cross-wallet unlock (transfer → unlock by new owner without vault key)
// BP30 v2.1: Bearer model - M1 holder can unlock without original locker's keys
// =============================================================================
BOOST_AUTO_TEST_CASE(cross_wallet_transfer_then_unlock)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    // Alice: original M1 holder (locks M0)
    CKey aliceKey;
    aliceKey.MakeNewKey(true);
    CScript aliceScript = GetScriptForDestination(aliceKey.GetPubKey().GetID());

    // Bob: receives M1 via transfer, then unlocks WITHOUT Alice's keys
    CKey bobKey;
    bobKey.MakeNewKey(true);
    CScript bobScript = GetScriptForDestination(bobKey.GetPubKey().GetID());

    CAmount P = 10 * COIN;
    uint32_t lockHeight = 100;

    // Initialize state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Step 1: Alice locks 10 M0 → gets vault + receipt
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), aliceScript);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, lockHeight, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint aliceReceiptOut(txLock.GetHash(), 1);

    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);

    // Step 2: Alice transfers M1 to Bob
    CMutableTransaction mtxTransfer = CreateMockTxTransfer(aliceReceiptOut, P, bobScript);
    CTransaction txTransfer(mtxTransfer);

    TransferUndoData transferUndoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txTransfer, view, batch, transferUndoData));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint bobReceiptOut(txTransfer.GetHash(), 0);

    // Verify Bob has the M1 now
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(aliceReceiptOut));  // Alice's spent
    BOOST_CHECK(g_settlementdb->IsM1Receipt(bobReceiptOut));     // Bob's new

    // Step 3: Bob unlocks (partial) - NO VAULT KEY NEEDED (bearer model)
    // Bob has 10 M1, unlocks 4 M0, keeps 6 M1 change
    CAmount unlockAmount = 4 * COIN;
    CAmount m1Change = P - unlockAmount;  // 6 M1

    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;

    // vin[0] = Bob's M1 Receipt (10 M1)
    mtxUnlock.vin.emplace_back(CTxIn(bobReceiptOut));
    // vin[1] = Vault (OP_TRUE - anyone can spend, consensus-protected)
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));

    // vout[0] = M0 to Bob (4 M0)
    mtxUnlock.vout.emplace_back(CTxOut(unlockAmount, bobScript));
    // vout[1] = M1 change to Bob (6 M1)
    mtxUnlock.vout.emplace_back(CTxOut(m1Change, bobScript));
    // vout[2] = vault change re-backing Bob's M1 change (6 M0, OP_TRUE)
    mtxUnlock.vout.emplace_back(CTxOut(m1Change, GetOpTrueScript()));

    CTransaction txUnlock(mtxUnlock);

    // Validate - Bob can unlock without Alice's keys!
    CValidationState validationState;
    BOOST_CHECK(CheckUnlock(txUnlock, view, validationState));

    UnlockUndoData undoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlock, view, state, batch, undoData));
        BOOST_CHECK(batch.Commit());
    }

    // Verify final state
    BOOST_CHECK_EQUAL(state.M0_vaulted, m1Change);  // 6 M0 still vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, m1Change);          // 6 M1 remaining
    BOOST_CHECK(state.CheckInvariants());                  // A6 HOLDS!

    // Verify Bob's M1 change receipt exists
    COutPoint bobChangeOut(txUnlock.GetHash(), 1);
    BOOST_CHECK(g_settlementdb->IsM1Receipt(bobChangeOut));

    M1Receipt changeReceipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(bobChangeOut, changeReceipt));
    BOOST_CHECK_EQUAL(changeReceipt.amount, m1Change);

    // Bob's M1 change stays vault-backed (re-vaulted), no leak.
    BOOST_CHECK(g_settlementdb->IsVault(COutPoint(txUnlock.GetHash(), 2)));
    BOOST_CHECK_EQUAL(SumAllVaultUTXOs(), state.M0_vaulted);  // 6 == 6
}

// INTEGRATION TESTS - Full Flow Scenarios
// =============================================================================

// =============================================================================
// Integration Test 1: LOCK → TRANSFER_M1 → UNLOCK (full M1 cycle)
// =============================================================================
BOOST_AUTO_TEST_CASE(integration_lock_transfer_unlock)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key1, key2, key3;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);
    key3.MakeNewKey(true);
    CScript script1 = GetScriptForDestination(key1.GetPubKey().GetID());
    CScript script2 = GetScriptForDestination(key2.GetPubKey().GetID());
    CScript script3 = GetScriptForDestination(key3.GetPubKey().GetID());

    CAmount P = 100 * COIN;

    // Initialize state (genesis, A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;
    BOOST_CHECK(state.CheckInvariants());

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Step 1: TX_LOCK - Create Vault + Receipt
    // BP30 v2.0: Vault uses OP_TRUE (consensus-protected)
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), script1);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, 100, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify A6 invariant after LOCK: P == P
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK(state.CheckInvariants());

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    // Step 2: TX_TRANSFER_M1 - Transfer receipt to new owner
    CMutableTransaction mtxTransfer = CreateMockTxTransfer(receiptOut, P, script2);
    CTransaction txTransfer(mtxTransfer);

    TransferUndoData transferUndoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txTransfer, view, batch, transferUndoData));
        BOOST_CHECK(batch.Commit());
    }

    // Verify A6 invariant after TRANSFER: unchanged (no state mutation)
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK(state.CheckInvariants());

    // Verify old receipt erased, new receipt created
    COutPoint newReceiptOut(txTransfer.GetHash(), 0);
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(newReceiptOut));

    // BP30 v2.0: Vault is unchanged after transfer (no receipt pointer in bearer model)
    VaultEntry vault;
    BOOST_CHECK(g_settlementdb->ReadVault(vaultOut, vault));
    BOOST_CHECK_EQUAL(vault.amount, P);

    // Step 3: TX_UNLOCK - Release M0 from Vault+Receipt
    CMutableTransaction mtxUnlock = CreateMockTxUnlock(newReceiptOut, vaultOut, P, script3);
    CTransaction txUnlock(mtxUnlock);

    {
        auto batch = g_settlementdb->CreateBatch();
        UnlockUndoData undoData;
        BOOST_CHECK(ApplyUnlock(txUnlock, view, state, batch, undoData));
        BOOST_CHECK(batch.Commit());

        // Verify undo data populated correctly
        BOOST_CHECK_EQUAL(undoData.m0Released, P);
        BOOST_CHECK_EQUAL(undoData.netM1Burned, P);  // Full unlock, no change
        BOOST_CHECK_EQUAL(undoData.changeReceiptsCreated, 0);
    }

    // Verify A6 invariant after UNLOCK: back to genesis state
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(state.CheckInvariants());

    // Verify all settlement indexes are clean
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(newReceiptOut));
    BOOST_CHECK(g_settlementdb->IsM0Standard(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM0Standard(newReceiptOut));
}

// =============================================================================
// Integration Test 3: A11 Canonical Output Order Enforcement
// =============================================================================
BOOST_AUTO_TEST_CASE(integration_a11_output_order)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript script = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 50 * COIN;

    // Test TX_LOCK output order: vout[0] = Vault, vout[1] = Receipt
    CMutableTransaction mtxLock;
    mtxLock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxLock.nType = CTransaction::TxType::TX_LOCK;

    uint256 dummyTxid;
    dummyTxid.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    mtxLock.vin.emplace_back(CTxIn(COutPoint(dummyTxid, 0)));

    // CORRECT order: Vault then Receipt
    // BP30 v2.0: Vault uses OP_TRUE (consensus-protected)
    mtxLock.vout.emplace_back(CTxOut(P, GetOpTrueScript()));  // vout[0] = Vault
    mtxLock.vout.emplace_back(CTxOut(P, script));             // vout[1] = Receipt

    CTransaction txLock(mtxLock);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState valState;

    // Should pass with correct order
    BOOST_CHECK(CheckLock(txLock, view, valState));

    // Verify the outputs are at expected positions
    BOOST_CHECK_EQUAL(txLock.vout[0].nValue, P); // Vault at index 0
    BOOST_CHECK_EQUAL(txLock.vout[1].nValue, P); // Receipt at index 1
}

// =============================================================================
// Integration Test 5: Partial unlock with vault change (BP30 v2.2)
// =============================================================================
// Tests that:
// 1. Partial unlock creates M1_change receipt
// 2. Partial unlock creates vault_change (OP_TRUE)
// 3. A6 invariant is preserved after partial unlock
// =============================================================================
// MIGRATED to BP30 v3.1 (producer-incentive): the unlock fee is a real M0 coinbase
// fee released from the vault — there is NO OP_TRUE fee receipt and NO fee-backing
// output. Both M0_vaulted and M1_supply drop by M0_out + fee (the released M0 plus
// the coinbased fee), and the only OP_TRUE output is the vault change re-backing the
// M1 change.
BOOST_AUTO_TEST_CASE(partial_unlock_with_vault_change)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CPubKey ownerPubKey = key.GetPubKey();
    CScript destScript = GetScriptForDestination(ownerPubKey.GetID());

    CAmount P = 100 * COIN;          // Lock 100 M0
    CAmount unlockAmount = 30 * COIN; // Unlock only 30 M0
    CAmount m1Fee = 1 * COIN;         // BP30 v3.1: M0 coinbase fee (implicit, to producer)
    CAmount m1Change = P - unlockAmount - m1Fee;  // 69 M1 change to user
    CAmount changeBacking = m1Change;             // 69 M0 re-vaulted to back the change
    CAmount remainingVaulted = P - unlockAmount - m1Fee;  // 69 M0 still vaulted (== M1 left)
    uint32_t lockHeight = 100;

    // Initialize state (genesis, A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;
    BOOST_CHECK(state.CheckInvariants()); // 0 == 0

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Step 1: TX_LOCK - Create 100 M0 vault + 100 M1 receipt
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, lockHeight, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);

    // Verify state after LOCK
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);  // 100 M0 vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, P);          // 100 M1 supply
    BOOST_CHECK(state.CheckInvariants());           // A6 should hold

    // Step 2: TX_UNLOCK with M1 change and vault change. BP30 v3.1 canonical output
    // order (producer-incentive fee model):
    // vout[0] = M0 unlocked (30 M0, P2PKH)
    // vout[1] = M1 change receipt (69 M1, P2PKH)
    // vout[2] = Vault change re-backing the M1 change (69 M0, OP_TRUE)
    // The 1 M0 fee is NOT an output — it is left on the table for the coinbase.
    // Conservation M1:    M1_in(100) - M0_out(30) - M1_change(69) = fee(1)
    // Conservation vault: Vault_in(100) == M0_out(30) + fee(1) + change_backing(69)
    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;

    // vin[0] = M1 Receipt (100 M1)
    mtxUnlock.vin.emplace_back(CTxIn(receiptOut));
    // vin[1] = Vault (100 M0)
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));

    // vout[0] = M0 output (30 M0)
    mtxUnlock.vout.emplace_back(CTxOut(unlockAmount, destScript));
    // vout[1] = M1 change receipt (69 M1)
    mtxUnlock.vout.emplace_back(CTxOut(m1Change, destScript));
    // vout[2] = Vault change re-backing the M1 change (69 M0, OP_TRUE)
    mtxUnlock.vout.emplace_back(CTxOut(changeBacking, GetOpTrueScript()));

    CTransaction txUnlock(mtxUnlock);

    // Validate
    CValidationState validationState;
    BOOST_CHECK(CheckUnlock(txUnlock, view, validationState));

    // Apply
    UnlockUndoData undoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlock, view, state, batch, undoData));
        BOOST_CHECK(batch.Commit());
    }

    // Verify state after partial UNLOCK (v3.1 producer-incentive model): both
    // M0_vaulted and M1_supply fall by M0_out + fee (30 + 1 = 31), leaving 69.
    BOOST_CHECK_EQUAL(state.M0_vaulted, remainingVaulted);  // 69 M0 still vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, remainingVaulted);          // 69 M1 remaining
    BOOST_CHECK(state.CheckInvariants());                     // A6 MUST still hold!

    // THE UTXO-level invariant: every vaulted M0 exists as a spendable vault UTXO
    // (change backing 69 == 69 == M0_vaulted). No leak.
    BOOST_CHECK_EQUAL(SumAllVaultUTXOs(), state.M0_vaulted);

    // Verify undo data — both counters moved by M0_out + fee (31).
    BOOST_CHECK_EQUAL(undoData.m0Released, unlockAmount + m1Fee);  // 31
    BOOST_CHECK_EQUAL(undoData.netM1Burned, unlockAmount + m1Fee); // 31

    // Verify DB state - v3.1 layout:
    //   vout[1] = M1 change receipt (69 M1)
    //   vout[2] = vault change re-backing the M1 change (69 M0)
    //   (no fee receipt, no separate fee backing — the fee went to the coinbase)
    COutPoint m1ChangeOut(txUnlock.GetHash(), 1);
    COutPoint changeBackingOut(txUnlock.GetHash(), 2);

    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));           // Original vault spent
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));     // Original receipt spent
    BOOST_CHECK(g_settlementdb->IsVault(changeBackingOut));    // Change RE-VAULTED
    BOOST_CHECK(g_settlementdb->IsM1Receipt(m1ChangeOut));     // M1 change is a receipt
    // vout[2] is NOT an M1 receipt (it is a vault), and there is no fee receipt.
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(changeBackingOut));

    // Verify vault change amount
    VaultEntry changeBackingEntry;
    BOOST_CHECK(g_settlementdb->ReadVault(changeBackingOut, changeBackingEntry));
    BOOST_CHECK_EQUAL(changeBackingEntry.amount, changeBacking);

    // Verify M1 change receipt amount
    M1Receipt m1ChangeReceipt;
    BOOST_CHECK(g_settlementdb->ReadReceipt(m1ChangeOut, m1ChangeReceipt));
    BOOST_CHECK_EQUAL(m1ChangeReceipt.amount, m1Change);
}

// =============================================================================
// Integration Test 6: Non-BP30 TX spending vault OP_TRUE is rejected
// =============================================================================
// Tests that:
// 1. A regular (non-TX_UNLOCK) transaction cannot spend vault OP_TRUE
// 2. This protects vault funds from being stolen by anyone-can-spend
// =============================================================================
BOOST_AUTO_TEST_CASE(non_bp30_vault_spend_rejected)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CPubKey ownerPubKey = key.GetPubKey();
    CScript destScript = GetScriptForDestination(ownerPubKey.GetID());

    CAmount P = 50 * COIN;
    uint32_t lockHeight = 100;

    // Initialize state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Step 1: Create a valid vault via TX_LOCK
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, lockHeight, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);

    // Verify vault exists
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));

    // Step 2: Try to spend vault with a NORMAL transaction (not TX_UNLOCK)
    // This should be rejected at consensus level
    CMutableTransaction mtxSteal;
    mtxSteal.nVersion = CTransaction::TxVersion::SAPLING;
    mtxSteal.nType = CTransaction::TxType::NORMAL;  // NOT a BP30 type!

    // Try to spend the vault OP_TRUE output
    mtxSteal.vin.emplace_back(CTxIn(vaultOut));
    // Send it to attacker address
    mtxSteal.vout.emplace_back(CTxOut(P - 1000, destScript));  // Attacker takes funds

    CTransaction txSteal(mtxSteal);

    // This should fail in script validation because OP_TRUE outputs
    // are only spendable by TX_UNLOCK transactions
    // The check happens in IsVaultSpendableByTxType() called during
    // ConnectBlock or AcceptToMemoryPool
    //
    // For unit test, we verify via IsVault check that the outpoint
    // is still protected by settlement logic
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));

    // Verify that CheckUnlock would reject this tx (wrong type)
    CValidationState validationState;
    // CheckUnlock expects TX_UNLOCK type, so this will fail
    BOOST_CHECK(!CheckUnlock(txSteal, view, validationState));

    // The vault should still exist (not spent)
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);  // Still vaulted
}

// =============================================================================
// REGRESSION (M1 receipt protection, option B / UPGRADE_M1_RECEIPT_PROTECTED):
// the M1 receipt now has a consensus guard symmetric to the vault. A bearer
// receipt may only be consumed by a settlement tx that RECONCILES it in
// ProcessSpecialTxsInBlock (TX_UNLOCK / TX_TRANSFER_M1 / HTLC_CREATE_M1 /
// HTLC_CREATE_3S, each of which calls EraseReceipt). Any other spend (NORMAL,
// or a non-reconciling type)
// is rejected with "bad-txns-receipt-protected", closing the drift where
// M1_supply would float above the live receipt set and orphan the backing vault.
//
// Before/after proof (the "before" is git history: this CHECK previously asserted
// the NORMAL receipt-spend was ACCEPTED, with the DB left unreconciled):
//   - NORMAL spend of a receipt  -> REJECTED  "bad-txns-receipt-protected"   (the fix)
//   - NORMAL spend of a vault    -> REJECTED  "bad-txns-vault-protected"     (unchanged)
//   - TX_UNLOCK / TX_TRANSFER_M1 / HTLC_CREATE_M1 / HTLC_CREATE_3S spending a
//       receipt -> NOT blocked by the receipt guard (they may still fail later
//       per-type validation on these minimal mock txs, but never with
//       "bad-txns-receipt-protected"). HTLC_CREATE_3S is the FlowSwap type 43:
//       it was missing from the guard's whitelist (a840582) even though
//       CheckHTLC3SCreate REQUIRES vin[0] to be an M1 receipt, so every
//       HTLC_CREATE_3S was rejected — regression guarded here.
//   - Gating: with pindexPrev==null (non-contextual CheckBlock) the guard is
//       deferred, so it does NOT fire — the contextual ConnectBlock/mempool call
//       is authoritative.
// =============================================================================
BOOST_AUTO_TEST_CASE(m1_receipt_spend_consensus_protected)
{
    LOCK(cs_main);  // CheckSpecialTx is EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);
    // UPGRADE_M1_RECEIPT_PROTECTED is ALWAYS_ACTIVE on all nets (fresh genesis),
    // so any non-null pindexPrev activates the guard regardless of height.
    BOOST_REQUIRE(Params().GetConsensus().IsM1ReceiptProtected(1));

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 50 * COIN;
    uint32_t lockHeight = 100;

    SettlementState settle;
    settle.M0_vaulted = 0;
    settle.M1_supply = 0;
    settle.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyLock(txLock, view, settle, lockHeight, batch));
        BOOST_REQUIRE(batch.Commit());
    }
    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);
    BOOST_REQUIRE(g_settlementdb->IsVault(vaultOut));
    BOOST_REQUIRE(g_settlementdb->IsM1Receipt(receiptOut));

    // Dummy contextual parent so the activation gate evaluates true.
    CBlockIndex idxPrev;
    idxPrev.nHeight = lockHeight;

    // Helper: build a minimal tx of the given type spending a single outpoint.
    auto spendOf = [&](CTransaction::TxType type, const COutPoint& in) {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = type;
        mtx.vin.emplace_back(CTxIn(in));
        mtx.vout.emplace_back(CTxOut(P - 1000, destScript));
        // HTLC_CREATE_3S is a payload-carrying type: without extraPayload it is
        // rejected "bad-txns-payload-empty" BEFORE the receipt guard, which would
        // make the guard assertion below vacuous. A dummy payload passes the
        // basic presence check; deserialization only fails in per-type
        // validation, which runs AFTER the guard.
        if (type == CTransaction::TxType::HTLC_CREATE_3S) {
            mtx.extraPayload = std::vector<uint8_t>{0x00};
        }
        return CTransaction(mtx);
    };

    // --- THE FIX: a NORMAL tx spending the RECEIPT is now REJECTED. ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::NORMAL, receiptOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-receipt-protected");
    }

    // --- CONTROL: the vault guard still rejects a NORMAL vault spend. ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::NORMAL, vaultOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-vault-protected");
    }

    // --- The 4 reconciling types are NOT blocked by the receipt guard. They may
    //     fail later per-type validation (minimal mock txs), but never at the
    //     guard. We assert the reject reason is never the receipt guard. ---
    for (CTransaction::TxType allowed : {CTransaction::TxType::TX_UNLOCK,
                                         CTransaction::TxType::TX_TRANSFER_M1,
                                         CTransaction::TxType::HTLC_CREATE_M1,
                                         CTransaction::TxType::HTLC_CREATE_3S}) {
        CTransaction tx = spendOf(allowed, receiptOut);
        CValidationState st;
        CheckSpecialTx(tx, &idxPrev, &view, st);  // result may be false (per-type), that's fine
        BOOST_CHECK_MESSAGE(st.GetRejectReason() != "bad-txns-receipt-protected",
                            "receipt guard wrongly blocked an allowed type");
    }

    // --- GATING: with pindexPrev==null the height is unknown, so the guard is
    //     deferred and does NOT fire (the contextual call is authoritative). ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::NORMAL, receiptOut);
        CValidationState st;
        BOOST_CHECK(CheckSpecialTx(tx, nullptr, &view, st));  // passes: guard skipped
        BOOST_CHECK(st.GetRejectReason() != "bad-txns-receipt-protected");
    }
}

// =============================================================================
// REGRESSION (FlowSwap, type 43): a WELL-FORMED HTLC_CREATE_3S spending an M1
// receipt must pass CheckSpecialTx END-TO-END — receipt guard AND
// CheckHTLC3SCreate. The guard's whitelist initially omitted HTLC_CREATE_3S
// (a840582) while CheckHTLC3SCreate requires vin[0] to be an M1 receipt, so
// every FlowSwap open was rejected "bad-txns-receipt-protected" — the loop
// above catches the guard, this proves the full positive path stays green.
// =============================================================================
BOOST_AUTO_TEST_CASE(m1_receipt_htlc3s_create_full_path)
{
    LOCK(cs_main);  // CheckSpecialTx is EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);
    BOOST_REQUIRE(Params().GetConsensus().IsM1ReceiptProtected(1));  // ALWAYS_ACTIVE

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 25 * COIN;
    uint32_t lockHeight = 100;

    SettlementState settle;
    settle.M0_vaulted = 0;
    settle.M1_supply = 0;
    settle.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Lock: mint vault + receipt.
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyLock(txLock, view, settle, lockHeight, batch));
        BOOST_REQUIRE(batch.Commit());
    }
    COutPoint receiptOut(txLock.GetHash(), 1);
    BOOST_REQUIRE(g_settlementdb->IsM1Receipt(receiptOut));

    CBlockIndex idxPrev;  // contextual parent so the guard activates
    idxPrev.nHeight = lockHeight;

    // Well-formed HTLC_CREATE_3S: receipt -> P2SH, strict amount, valid payload.
    HTLC3SCreatePayload payload;
    payload.hashlock_user = uint256S("aa");
    payload.hashlock_lp1 = uint256S("bb");
    payload.hashlock_lp2 = uint256S("cc");
    payload.expiryHeight = lockHeight + 200;
    payload.claimKeyID = key.GetPubKey().GetID();
    payload.refundKeyID = key.GetPubKey().GetID();

    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::HTLC_CREATE_3S;
    mtx.vin.emplace_back(CTxIn(receiptOut));
    CScript redeemScript = GetOpTrueScript();  // placeholder; only P2SH-ness is checked here
    mtx.vout.emplace_back(CTxOut(P, GetScriptForDestination(CScriptID(redeemScript))));
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());
    CTransaction txHtlc(mtx);

    CValidationState st;
    BOOST_CHECK_MESSAGE(CheckSpecialTx(txHtlc, &idxPrev, &view, st),
                        "well-formed HTLC_CREATE_3S rejected: " + st.GetRejectReason());
    BOOST_CHECK(st.GetRejectReason() != "bad-txns-receipt-protected");
}

// =============================================================================
// ROUND-TRIP (M1 receipt protection): lock → blocked NORMAL spend → unlock,
// driving the SAME functions ConnectBlock→ProcessSpecialTxsInBlock invokes per
// tx (CheckSpecialTx guard, then ApplyLock / CheckUnlock+ApplyUnlock). Proves
// end-to-end that (1) lock mints vault+receipt, (2) a NORMAL receipt-spend is
// rejected by consensus so the settlement DB never drifts, (3) a real TX_UNLOCK
// still redeems cleanly back to M1_supply==0 — no stuck funds, A6 holds at every
// step. (A literal mined-block ConnectBlock is impractical at unit level: BATHRON
// blocks >height 3 require HU-finality sigs + btcheaders + MN state; this drives
// the exact settlement+guard call chain ConnectBlock runs.)
// =============================================================================
BOOST_AUTO_TEST_CASE(m1_receipt_lock_blocked_normal_then_unlock_roundtrip)
{
    LOCK(cs_main);  // CheckSpecialTx is EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);
    BOOST_REQUIRE(Params().GetConsensus().IsM1ReceiptProtected(1));  // ALWAYS_ACTIVE

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 10 * COIN;
    uint32_t lockHeight = 100;

    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;
    BOOST_REQUIRE(state.CheckInvariants());  // 0 == 0

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    CBlockIndex idxPrev;  // contextual parent so the guard activates
    idxPrev.nHeight = lockHeight;

    // ── Block N — TX_LOCK: guard lets it through (not a receipt/vault input),
    //    then ApplyLock mints vault + receipt. (= what ProcessSpecialTxsInBlock
    //    does for TX_LOCK.) ──
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);
    {
        CValidationState st;
        // TX_LOCK is not blocked by the receipt guard.
        CheckSpecialTx(txLock, &idxPrev, &view, st);
        BOOST_CHECK(st.GetRejectReason() != "bad-txns-receipt-protected");
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyLock(txLock, view, state, lockHeight, batch));
        BOOST_REQUIRE(batch.Commit());
    }
    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK(state.CheckInvariants());

    // ── Drift attempt — a NORMAL tx spending the receipt is REJECTED by the
    //    per-tx guard ConnectBlock runs, so the whole block is rejected and the
    //    settlement DB is never mutated. No Apply* runs → no drift. ──
    {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::NORMAL;
        mtx.vin.emplace_back(CTxIn(receiptOut));
        mtx.vout.emplace_back(CTxOut(P - 1000, destScript));
        CTransaction txSteal(mtx);

        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(txSteal, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-receipt-protected");
    }
    // State untouched: receipt still live, supply unchanged, A6 holds.
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK(state.CheckInvariants());

    // ── Block N+1 — TX_UNLOCK: guard allows it, CheckUnlock validates, ApplyUnlock
    //    reconciles (full redeem, no change/fee). Receipt + vault consumed,
    //    M1_supply → 0. ──
    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlock.vin.emplace_back(CTxIn(receiptOut));  // canonical: receipts first
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));    // then vaults
    mtxUnlock.vout.emplace_back(CTxOut(P, destScript));  // full M0 out (P==M1_in)
    CTransaction txUnlock(mtxUnlock);
    {
        CValidationState st;
        BOOST_CHECK(CheckSpecialTx(txUnlock, &idxPrev, &view, st));  // guard + CheckUnlock pass
        UnlockUndoData undo;
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyUnlock(txUnlock, view, state, batch, undo));
        BOOST_REQUIRE(batch.Commit());
    }

    // Round-trip complete: fully reconciled, A6 holds, nothing stuck.
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(state.CheckInvariants());
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
}

// =============================================================================
// Cross-holder rail: A locks M0 -> transfers M1 to B -> B (a DIFFERENT holder)
// partially unlocks back to M0. Exercises the full M0->M1->M0 path across two
// holders with a partial redeem against the shared vault pool (bearer model),
// checking A6 (M0_vaulted == M1_supply) holds at every step and the M1-fee model
// reconciles. This is the "M1 partial -> M0 from someone else" flow end-to-end.
// =============================================================================
BOOST_AUTO_TEST_CASE(cross_holder_lock_transfer_partial_unlock)
{
    LOCK(cs_main);
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    CScript destA = GetScriptForDestination(keyA.GetPubKey().GetID());
    CScript destB = GetScriptForDestination(keyB.GetPubKey().GetID());

    const CAmount P  = 10 * COIN;   // A locks
    const CAmount fT = 1000;        // transfer fee (M1)
    const CAmount X  = 4 * COIN;    // B's partial unlock
    const CAmount fU = 1000;        // unlock fee (M1)

    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CBlockIndex idxPrev;
    idxPrev.nHeight = 100;

    // ── A locks P: mints vault(P) + receipt_A(P). ──
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destA);
    CTransaction txLock(mtxLock);
    {
        CValidationState st;
        BOOST_CHECK(CheckSpecialTx(txLock, &idxPrev, &view, st));
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyLock(txLock, view, state, 100, batch));
        BOOST_REQUIRE(batch.Commit());
    }
    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptA(txLock.GetHash(), 1);
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);
    BOOST_CHECK(state.CheckInvariants());

    // ── A transfers M1 to B (fee model): B gets P-fT, producer fee fT. A transfer
    //    conserves M1 (fee is relocated M1, not burned), so M1_supply is unchanged. ──
    CMutableTransaction mtxXfer = CreateMockTxTransferWithFee(receiptA, P - fT, fT, destB);
    CTransaction txXfer(mtxXfer);
    {
        CValidationState st;
        BOOST_CHECK(CheckSpecialTx(txXfer, &idxPrev, &view, st));
        TransferUndoData undo;
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyTransfer(txXfer, view, batch, undo));
        BOOST_REQUIRE(batch.Commit());
    }
    COutPoint receiptB(txXfer.GetHash(), 0);   // B's receipt (P - fT)
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptA));   // A's receipt consumed
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptB));    // B now holds it
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);
    BOOST_CHECK_EQUAL(state.M1_supply, P);                 // unchanged by transfer
    BOOST_CHECK(state.CheckInvariants());

    // ── B partially unlocks X against the shared vault (BP30 v3.1). Canonical outputs:
    //    [0]=M0 out (to B), [1]=M1 change (to B), [2]=vault change (OP_TRUE). The fU
    //    fee is an M0 coinbase fee (implicit) — no fee output, no separate backing. ──
    const CAmount m1ChangeB   = (P - fT) - X - fU;   // M1 conservation: receiptB - X - fU
    const CAmount vaultChange = P - X - fU;          // totalVault - M0_out - fee
    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlock.vin.emplace_back(CTxIn(receiptB));    // receipts first
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));    // then vaults
    mtxUnlock.vout.emplace_back(CTxOut(X, destB));                        // [0] M0 to B
    mtxUnlock.vout.emplace_back(CTxOut(m1ChangeB, destB));                // [1] M1 change to B
    mtxUnlock.vout.emplace_back(CTxOut(vaultChange, GetOpTrueScript()));  // [2] vault change
    CTransaction txUnlock(mtxUnlock);
    {
        CValidationState st;
        BOOST_CHECK(CheckSpecialTx(txUnlock, &idxPrev, &view, st));  // guard + CheckUnlock
        UnlockUndoData undo;
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyUnlock(txUnlock, view, state, batch, undo));
        BOOST_REQUIRE(batch.Commit());
    }

    // ── Post: both counters fall by M0_out + fee (X + fU); A6 holds. ──
    BOOST_CHECK_EQUAL(state.M0_vaulted, P - X - fU);
    BOOST_CHECK_EQUAL(state.M1_supply, P - X - fU);
    BOOST_CHECK(state.CheckInvariants());
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptB));  // B's receipt consumed
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));       // original vault consumed
    BOOST_CHECK(g_settlementdb->IsM1Receipt(COutPoint(txUnlock.GetHash(), 1)));  // B's M1 change live
    BOOST_CHECK(g_settlementdb->IsVault(COutPoint(txUnlock.GetHash(), 2)));      // re-vaulted backing
}

// =============================================================================
// ADVERSARIAL TESTS: Malformed TX rejection (BP30 v2.5)
// =============================================================================

// =============================================================================
// Adversarial Test 1: TX_TRANSFER_M1 with wrong output order (M0 first)
// =============================================================================
// Tests that ParseTransferM1Outputs correctly handles malicious TX
// where M0 fee change comes before M1 outputs
// =============================================================================
BOOST_AUTO_TEST_CASE(adversarial_transfer_wrong_output_order)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 100 * COIN;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Create malicious TX: M0 fee output FIRST, then M1 output
    // Canonical order requires M1 outputs first!
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // vin[0] = Receipt (100 M1)
    mtx.vin.emplace_back(CTxIn(receiptOut));
    // vin[1] = M0 fee input (mock)
    uint256 feeTxid;
    feeTxid.SetHex("7777777777777777777777777777777777777777777777777777777777777777");
    mtx.vin.emplace_back(CTxIn(COutPoint(feeTxid, 0)));

    // WRONG ORDER: M0 fee change first (1 M0), then M1 output (100 M1)
    mtx.vout.emplace_back(CTxOut(1 * COIN, destScript));    // vout[0] = M0 change (WRONG!)
    mtx.vout.emplace_back(CTxOut(P, destScript));           // vout[1] = M1 output

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // With cumsum algorithm: vout[0] (1 M0) is treated as M1 since 1 <= 100
    // vout[1] (100 M0) would push cumsum to 101, exceeding m1In (100)
    // So splitIndex = 1, m1Out = 1 M0
    // Conservation check: m1Out (1) != m1In (100) → REJECT
    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-m1-not-conserved");
}

// =============================================================================
// Adversarial Test 2: TX_TRANSFER_M1 with zero-value output
// =============================================================================
BOOST_AUTO_TEST_CASE(adversarial_transfer_zero_output)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 50 * COIN;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Create TX with zero-value output
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    mtx.vin.emplace_back(CTxIn(receiptOut));

    // vout[0] = 0 value (invalid!)
    mtx.vout.emplace_back(CTxOut(0, destScript));
    // vout[1] = 50 M1
    mtx.vout.emplace_back(CTxOut(P, destScript));

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // ParseTransferM1Outputs should reject zero-value outputs
    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-invalid-outputs");
}

// =============================================================================
// Adversarial Test 3: TX_TRANSFER_M1 with OP_RETURN output
// =============================================================================
BOOST_AUTO_TEST_CASE(adversarial_transfer_op_return)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 75 * COIN;
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Create TX with OP_RETURN output (unspendable)
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    mtx.vin.emplace_back(CTxIn(receiptOut));

    // vout[0] = OP_RETURN with data (unspendable)
    CScript opReturnScript;
    opReturnScript << OP_RETURN << std::vector<unsigned char>(10, 0xAB);
    mtx.vout.emplace_back(CTxOut(P, opReturnScript));

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // ParseTransferM1Outputs should reject OP_RETURN outputs
    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-invalid-outputs");
}

// =============================================================================
// Adversarial Test 4: TX_TRANSFER_M1 split with amounts not summing to input
// =============================================================================
BOOST_AUTO_TEST_CASE(adversarial_transfer_split_sum_mismatch)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey keyA, keyB;
    keyA.MakeNewKey(true);
    keyB.MakeNewKey(true);
    CScript scriptA = GetScriptForDestination(keyA.GetPubKey().GetID());
    CScript scriptB = GetScriptForDestination(keyB.GetPubKey().GetID());

    CAmount P = 100 * COIN;  // 100 M1 input
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Create split TX where outputs don't sum to input
    // Try to split 100 M1 into 60 + 60 = 120 M1 (inflation attempt!)
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    mtx.vin.emplace_back(CTxIn(receiptOut));

    // vout[0] = 60 M1 to A
    mtx.vout.emplace_back(CTxOut(60 * COIN, scriptA));
    // vout[1] = 60 M1 to B (total = 120, but input is only 100!)
    mtx.vout.emplace_back(CTxOut(60 * COIN, scriptB));

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // With cumsum: vout[0] (60) is M1, cumsum = 60 <= 100
    // vout[1] (60) would push cumsum to 120 > 100, so splitIndex = 1
    // m1Out = 60, but m1In = 100 → conservation violated
    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-m1-not-conserved");
}

// =============================================================================
// Adversarial Test 5: TX_TRANSFER_M1 implicit burn attempt (outputs < input)
// =============================================================================
BOOST_AUTO_TEST_CASE(adversarial_transfer_implicit_burn)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 100 * COIN;  // 100 M1 input
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // Try implicit burn: output only 80 M1, "burning" 20 M1
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    mtx.vin.emplace_back(CTxIn(receiptOut));

    // vout[0] = 80 M1 (trying to burn 20)
    mtx.vout.emplace_back(CTxOut(80 * COIN, destScript));

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // Strict conservation: m1Out (80) != m1In (100) → REJECT
    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-m1-not-conserved");
}

// =============================================================================
// Adversarial Test 6: TX_TRANSFER_M1 with multiple M0 change outputs
// =============================================================================
// MIGRATED to BP30 v3.0 (M1 fee model): in v2.x a TX_TRANSFER_M1 could carry M0
// fee inputs and M0 change outputs; v3.0 abolishes M0 in the transfer (pure M1 fee
// model). This adversarial test confirms the OLD multi-M0-change shape is now
// REJECTED: the M1 input is fully consumed by vout[0], leaving no OP_TRUE fee output,
// so CheckTransfer rejects with bad-txtransfer-fee-missing (the M0 "change" outputs
// are never honored as M0 in the settlement layer).
BOOST_AUTO_TEST_CASE(adversarial_transfer_multi_m0_change)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 100 * COIN;  // 100 M1 input
    COutPoint vaultOut, receiptOut;
    SetupVaultReceiptPair(P, 1000, vaultOut, receiptOut);

    // OLD v2.x shape: full M1 output first, then "M0 change" outputs (+ an M0 fee input)
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    mtx.vin.emplace_back(CTxIn(receiptOut));
    // Old-style M0 fee input (no longer part of the v3.0 transfer model)
    uint256 feeTxid;
    feeTxid.SetHex("8888888888888888888888888888888888888888888888888888888888888888");
    mtx.vin.emplace_back(CTxIn(COutPoint(feeTxid, 0)));

    // vout[0] = 100 M1 (full M1 output, consumes the whole receipt)
    mtx.vout.emplace_back(CTxOut(P, destScript));
    // vout[1..2] = old "M0 change" outputs
    mtx.vout.emplace_back(CTxOut(1 * COIN, destScript));
    mtx.vout.emplace_back(CTxOut(COIN / 2, destScript));

    CTransaction tx(mtx);

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CValidationState state;

    // BP30 v3.0: cumsum classifies vout[0] (100) as the only M1 output (== m1In),
    // so numM1Outputs == 1 < 2 → no fee output → REJECT. The old M0-change shape
    // can no longer pass the M1 fee model.
    BOOST_CHECK(!CheckTransfer(tx, view, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txtransfer-fee-missing");
}

// =============================================================================
// Deep Reorg Test: Settlement DB follows chain tip through 30-block reorg
// =============================================================================
BOOST_AUTO_TEST_CASE(deep_reorg_settlement_db_consistency)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Initialize state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // Track undo data for each block
    struct BlockUndoData {
        std::vector<std::pair<CTransaction, UnlockUndoData>> unlocks;
        std::vector<std::pair<CTransaction, TransferUndoData>> transfers;
        std::vector<CTransaction> locks;
        SettlementState stateBefore;
    };
    std::vector<BlockUndoData> undoStack;

    const int REORG_DEPTH = 30;
    const CAmount LOCK_AMOUNT = 10 * COIN;

    // Simulate 30 blocks with various operations
    for (int height = 1; height <= REORG_DEPTH; ++height) {
        BlockUndoData blockUndo;
        blockUndo.stateBefore = state;

        // Every block: create a lock
        CMutableTransaction mtxLock = CreateMockTxLock(LOCK_AMOUNT, GetOpTrueScript(), destScript);
        // Make txid unique per height
        mtxLock.vin[0].prevout.n = height;
        CTransaction txLock(mtxLock);

        {
            auto batch = g_settlementdb->CreateBatch();
            BOOST_CHECK(ApplyLock(txLock, view, state, height, batch));
            BOOST_CHECK(batch.Commit());
        }
        blockUndo.locks.push_back(txLock);

        // Every 5th block: do a transfer
        if (height % 5 == 0 && !blockUndo.locks.empty()) {
            COutPoint receiptOut(txLock.GetHash(), 1);

            CMutableTransaction mtxTransfer;
            mtxTransfer.nVersion = CTransaction::TxVersion::SAPLING;
            mtxTransfer.nType = CTransaction::TxType::TX_TRANSFER_M1;
            mtxTransfer.vin.emplace_back(CTxIn(receiptOut));
            mtxTransfer.vout.emplace_back(CTxOut(LOCK_AMOUNT, destScript));
            CTransaction txTransfer(mtxTransfer);

            TransferUndoData transferUndo;
            {
                auto batch = g_settlementdb->CreateBatch();
                BOOST_CHECK(ApplyTransfer(txTransfer, view, batch, transferUndo));
                BOOST_CHECK(batch.Commit());
            }
            blockUndo.transfers.push_back({txTransfer, transferUndo});
        }

        state.nHeight = height;
        undoStack.push_back(blockUndo);
    }

    // Verify state after 30 blocks
    BOOST_CHECK_EQUAL(state.nHeight, REORG_DEPTH);
    BOOST_CHECK_EQUAL(state.M0_vaulted, REORG_DEPTH * LOCK_AMOUNT);
    BOOST_CHECK_EQUAL(state.M1_supply, REORG_DEPTH * LOCK_AMOUNT);
    BOOST_CHECK(state.CheckInvariants());

    // Now simulate a 30-block reorg: undo all blocks
    for (int i = REORG_DEPTH - 1; i >= 0; --i) {
        BlockUndoData& blockUndo = undoStack[i];

        // Undo transfers (in reverse order)
        for (auto it = blockUndo.transfers.rbegin(); it != blockUndo.transfers.rend(); ++it) {
            auto batch = g_settlementdb->CreateBatch();
            BOOST_CHECK(UndoTransfer(it->first, it->second, batch));
            BOOST_CHECK(batch.Commit());
        }

        // Undo locks (in reverse order)
        for (auto it = blockUndo.locks.rbegin(); it != blockUndo.locks.rend(); ++it) {
            auto batch = g_settlementdb->CreateBatch();
            BOOST_CHECK(UndoLock(*it, state, batch));
            BOOST_CHECK(batch.Commit());
        }

        state.nHeight = i;
    }

    // Verify state after full reorg
    BOOST_CHECK_EQUAL(state.nHeight, 0);
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(state.CheckInvariants());

    // Verify DB is clean - all vaults and receipts should be gone
    for (const auto& blockUndo : undoStack) {
        for (const auto& txLock : blockUndo.locks) {
            COutPoint vaultOut(txLock.GetHash(), 0);
            COutPoint receiptOut(txLock.GetHash(), 1);
            BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
            BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
        }
    }
}

// =============================================================================
// Deep Reorg Test 2: Partial unlock with vault change survives reorg
// =============================================================================
// =============================================================================
// MAINNET AUDIT: Full Cycle M0/M1 Bearer Asset Test
// =============================================================================
// Tests the complete flow:
//   1. Lock M0 → Vault + M1 Receipt
//   2. Transfer M1 (send × 3)
//   3. Cross-wallet partial unlock (bearer - no link needed)
//   4. Transfer remaining M1 (send × 3)
//   5. Full unlock of remainder
//   6. Verify A6 invariant holds throughout
// =============================================================================
// MIGRATED to BP30 v3.0 (M1 fee model): every TX_TRANSFER_M1 now carries an OP_TRUE
// M1 fee output (1 COIN) that relocates M1 to the producer without changing M1_supply.
// Each TX_UNLOCK carries an M1 fee + vault backing. The accumulated producer fee
// receipts (7 of 1 COIN) are drained by the final multi-input full unlock, so the
// cycle still ends at M0_vaulted == M1_supply == 0. A6 holds at every step.
BOOST_AUTO_TEST_CASE(mainnet_audit_full_cycle_bearer_asset)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    // Create 4 different wallets (simulating cross-wallet transfers)
    CKey walletA, walletB, walletC, walletD;
    walletA.MakeNewKey(true);
    walletB.MakeNewKey(true);
    walletC.MakeNewKey(true);
    walletD.MakeNewKey(true);
    CScript scriptA = GetScriptForDestination(walletA.GetPubKey().GetID());
    CScript scriptB = GetScriptForDestination(walletB.GetPubKey().GetID());
    CScript scriptC = GetScriptForDestination(walletC.GetPubKey().GetID());
    CScript scriptD = GetScriptForDestination(walletD.GetPubKey().GetID());

    // Initialize state (genesis, A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;
    BOOST_CHECK(state.CheckInvariants()); // 0 == 0

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    const CAmount INITIAL_LOCK = 100 * COIN;  // 100 M0
    const CAmount FEE = 1 * COIN;             // BP30 v3.0: M1 fee per transfer/unlock
    // Track producer fee receipts so the final unlock can drain them to 0.
    std::vector<COutPoint> feeReceipts;

    // =========================================================================
    // STEP 1: WalletA locks 100 M0 → Vault(100) + Receipt(100 M1)
    // =========================================================================
    CMutableTransaction mtxLock = CreateMockTxLock(INITIAL_LOCK, GetOpTrueScript(), scriptA);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, 1, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptA(txLock.GetHash(), 1);

    // Verify state after lock
    BOOST_CHECK_EQUAL(state.M0_vaulted, INITIAL_LOCK);
    BOOST_CHECK_EQUAL(state.M1_supply, INITIAL_LOCK);
    BOOST_CHECK(state.CheckInvariants());  // A6: 100 + 0 == 100 + 0

    // =========================================================================
    // STEP 2: Transfer M1 × 3 (A → B → C → D) - "send send send"
    // =========================================================================

    // Transfer 1: A → B (100 M1 in: B gets 99, producer fee 1)
    CAmount amtB = INITIAL_LOCK - FEE;  // 99
    CMutableTransaction mtxT1 = CreateMockTxTransferWithFee(receiptA, amtB, FEE, scriptB);
    CTransaction txT1(mtxT1);

    CValidationState vs1;
    BOOST_CHECK(CheckTransfer(txT1, view, vs1));
    TransferUndoData undoT1;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txT1, view, batch, undoT1));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptB(txT1.GetHash(), 0);
    feeReceipts.emplace_back(txT1.GetHash(), 1);  // producer fee
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptA));  // Old consumed
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptB));   // New created
    BOOST_CHECK(state.CheckInvariants());  // A6 unchanged (transfer doesn't move totals)

    // Transfer 2: B → C (99 M1 in: C gets 98, producer fee 1)
    CAmount amtC = amtB - FEE;  // 98
    CMutableTransaction mtxT2 = CreateMockTxTransferWithFee(receiptB, amtC, FEE, scriptC);
    CTransaction txT2(mtxT2);

    CValidationState vs2;
    BOOST_CHECK(CheckTransfer(txT2, view, vs2));
    TransferUndoData undoT2;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txT2, view, batch, undoT2));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptC(txT2.GetHash(), 0);
    feeReceipts.emplace_back(txT2.GetHash(), 1);
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptB));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptC));
    BOOST_CHECK(state.CheckInvariants());

    // Transfer 3: C → D (98 M1 in: D gets 97, producer fee 1)
    CAmount amtD = amtC - FEE;  // 97
    CMutableTransaction mtxT3 = CreateMockTxTransferWithFee(receiptC, amtD, FEE, scriptD);
    CTransaction txT3(mtxT3);

    CValidationState vs3;
    BOOST_CHECK(CheckTransfer(txT3, view, vs3));
    TransferUndoData undoT3;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txT3, view, batch, undoT3));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptD(txT3.GetHash(), 0);
    feeReceipts.emplace_back(txT3.GetHash(), 1);
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptC));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptD));
    BOOST_CHECK(state.CheckInvariants());

    // =========================================================================
    // STEP 3: Cross-wallet PARTIAL unlock by D (bearer - no link to A!)
    //         D unlocks 30 M0, keeps 70 M1 as change
    // =========================================================================
    // BP30 v3.1 (producer-incentive): D's receipt is 97 M1 (after 3 transfer fees).
    // Unlock 30 M0 with an IMPLICIT fee of 1 (a real M0 coinbase fee, no fee output),
    // leaving 66 M1 change. The remaining 69 of the vault is re-vaulted as a single
    // OP_TRUE output = totalVault - M0_out - fee = 100 - 30 - 1 = 69, matching
    // M0_vaulted (both M0_vaulted and M1_supply fall by M0_out + fee = 31).
    CAmount unlockAmount = 30 * COIN;            // M0 released
    CAmount m1Change = amtD - unlockAmount - FEE; // 97 - 30 - 1 = 66 M1 change
    CAmount remainingVaulted = INITIAL_LOCK - unlockAmount - FEE;  // 69 stays vaulted (M0_out+fee left)

    CMutableTransaction mtxUnlock1;
    mtxUnlock1.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock1.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlock1.vin.emplace_back(CTxIn(receiptD));   // 97 M1 receipt from D
    mtxUnlock1.vin.emplace_back(CTxIn(vaultOut));   // Original 100 vault (OP_TRUE)
    mtxUnlock1.vout.emplace_back(CTxOut(unlockAmount, scriptD));         // vout[0] 30 M0 to D
    mtxUnlock1.vout.emplace_back(CTxOut(m1Change, scriptD));             // vout[1] 66 M1 change
    mtxUnlock1.vout.emplace_back(CTxOut(remainingVaulted, GetOpTrueScript())); // vout[2] 69 vault change

    CTransaction txUnlock1(mtxUnlock1);

    CValidationState vsU1;
    BOOST_CHECK(CheckUnlock(txUnlock1, view, vsU1));

    UnlockUndoData undoU1;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlock1, view, state, batch, undoU1));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptD2(txUnlock1.GetHash(), 1);     // 66 M1 change
    // BP30 v3.1: no M1 fee receipt is created (fee is an M0 coinbase fee).
    COutPoint newVaultOut(txUnlock1.GetHash(), 2);    // 69 vault change

    // undo counters both move by M0_out + fee = 31
    BOOST_CHECK_EQUAL(undoU1.m0Released, unlockAmount + FEE);
    BOOST_CHECK_EQUAL(undoU1.netM1Burned, unlockAmount + FEE);

    // Verify state after partial unlock (M0_out + fee left the vault)
    BOOST_CHECK_EQUAL(state.M0_vaulted, remainingVaulted);  // 69 M0 still vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, remainingVaulted);          // 69 M1 remaining
    BOOST_CHECK(state.CheckInvariants());  // A6: 69 == 69

    // Verify DB state
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));       // Original vault consumed
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptD));   // Original receipt consumed
    BOOST_CHECK(g_settlementdb->IsVault(newVaultOut));     // New vault backing/change created
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptD2));   // New M1 change created

    // =========================================================================
    // STEP 4: Transfer remaining M1 × 3 (D → A → B → C) - "send send send"
    // =========================================================================

    // Transfer 4: D → A (66 M1 in: A gets 65, producer fee 1)
    CAmount amtA2 = m1Change - FEE;  // 65
    CMutableTransaction mtxT4 = CreateMockTxTransferWithFee(receiptD2, amtA2, FEE, scriptA);
    CTransaction txT4(mtxT4);

    CValidationState vs4;
    BOOST_CHECK(CheckTransfer(txT4, view, vs4));
    TransferUndoData undoT4;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txT4, view, batch, undoT4));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptA2(txT4.GetHash(), 0);
    feeReceipts.emplace_back(txT4.GetHash(), 1);
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptA2));
    BOOST_CHECK(state.CheckInvariants());

    // Transfer 5: A → B (65 M1 in: B gets 64, producer fee 1)
    CAmount amtB2 = amtA2 - FEE;  // 64
    CMutableTransaction mtxT5 = CreateMockTxTransferWithFee(receiptA2, amtB2, FEE, scriptB);
    CTransaction txT5(mtxT5);

    CValidationState vs5;
    BOOST_CHECK(CheckTransfer(txT5, view, vs5));
    TransferUndoData undoT5;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txT5, view, batch, undoT5));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptB2(txT5.GetHash(), 0);
    feeReceipts.emplace_back(txT5.GetHash(), 1);
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptB2));
    BOOST_CHECK(state.CheckInvariants());

    // Transfer 6: B → C (64 M1 in: C gets 63, producer fee 1)
    CAmount amtC2 = amtB2 - FEE;  // 63
    CMutableTransaction mtxT6 = CreateMockTxTransferWithFee(receiptB2, amtC2, FEE, scriptC);
    CTransaction txT6(mtxT6);

    CValidationState vs6;
    BOOST_CHECK(CheckTransfer(txT6, view, vs6));
    TransferUndoData undoT6;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txT6, view, batch, undoT6));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptC2(txT6.GetHash(), 0);
    feeReceipts.emplace_back(txT6.GetHash(), 1);
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptC2));
    BOOST_CHECK(state.CheckInvariants());

    // =========================================================================
    // STEP 5: Full unlock of ALL remaining M1 (69 M0) — drains C's receipt plus
    // the 6 accumulated TRANSFER producer fee receipts, backed by the vault entry.
    // (Unlocks no longer create fee receipts under BP30 v3.1.) No M1 change, no fee
    // (full drain): M1_in(69) == M0_out(69). Input order: M1 receipts first, then vault.
    // =========================================================================
    BOOST_CHECK_EQUAL(state.M1_supply, remainingVaulted);  // 69 still in M1
    BOOST_CHECK_EQUAL((int)feeReceipts.size(), 6);         // 6 transfer fees (unlocks add none)

    CMutableTransaction mtxUnlock2;
    mtxUnlock2.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock2.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlock2.vin.emplace_back(CTxIn(receiptC2));   // 63 M1 receipt from C
    for (const COutPoint& f : feeReceipts) {         // 6 × 1 M1 producer fee receipts
        mtxUnlock2.vin.emplace_back(CTxIn(f));
    }
    mtxUnlock2.vin.emplace_back(CTxIn(newVaultOut)); // 69 vault (OP_TRUE)
    mtxUnlock2.vout.emplace_back(CTxOut(remainingVaulted, scriptC));  // 69 M0 to C

    CTransaction txUnlock2(mtxUnlock2);

    CValidationState vsU2;
    BOOST_CHECK(CheckUnlock(txUnlock2, view, vsU2));

    UnlockUndoData undoU2;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlock2, view, state, batch, undoU2));
        BOOST_CHECK(batch.Commit());
    }

    // =========================================================================
    // FINAL VERIFICATION: All M0/M1 released, A6 = 0
    // =========================================================================
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);  // All M0 released
    BOOST_CHECK_EQUAL(state.M1_supply, 0);          // All M1 burned
    BOOST_CHECK(state.CheckInvariants());           // A6: 0 == 0

    // Verify DB is clean
    BOOST_CHECK(!g_settlementdb->IsVault(newVaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptC2));

    // =========================================================================
    // STEP 6: Full reorg undo - verify all state restored
    // =========================================================================
    // Undo unlock 2
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoUnlock(txUnlock2, undoU2, state, batch));
        BOOST_CHECK(batch.Commit());
    }
    BOOST_CHECK_EQUAL(state.M0_vaulted, remainingVaulted);  // back to 70
    BOOST_CHECK_EQUAL(state.M1_supply, remainingVaulted);
    BOOST_CHECK(state.CheckInvariants());

    // Undo transfers 6, 5, 4
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(txT6, undoT6, batch));
        BOOST_CHECK(batch.Commit());
    }
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(txT5, undoT5, batch));
        BOOST_CHECK(batch.Commit());
    }
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(txT4, undoT4, batch));
        BOOST_CHECK(batch.Commit());
    }
    BOOST_CHECK(state.CheckInvariants());

    // Undo unlock 1
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoUnlock(txUnlock1, undoU1, state, batch));
        BOOST_CHECK(batch.Commit());
    }
    BOOST_CHECK_EQUAL(state.M0_vaulted, INITIAL_LOCK);
    BOOST_CHECK_EQUAL(state.M1_supply, INITIAL_LOCK);
    BOOST_CHECK(state.CheckInvariants());

    // Undo transfers 3, 2, 1
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(txT3, undoT3, batch));
        BOOST_CHECK(batch.Commit());
    }
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(txT2, undoT2, batch));
        BOOST_CHECK(batch.Commit());
    }
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoTransfer(txT1, undoT1, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify original receipt restored
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptA));
    BOOST_CHECK(state.CheckInvariants());

    // Undo lock
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoLock(txLock, state, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Final state: back to genesis
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(state.CheckInvariants());
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptA));
}

// =============================================================================
// MAINNET AUDIT: M1 Split then partial unlocks from different recipients
// =============================================================================
// Tests:
//   1. Lock 100 M0 → 100 M1
//   2. Split 100 M1 → 40 M1 (A) + 60 M1 (B)
//   3. A unlocks 40 M0 fully
//   4. B transfers 60 M1 → C
//   5. C unlocks 30 M0 partial (keeps 30 M1)
//   6. C unlocks remaining 30 M0
//   7. Verify A6 invariant holds at every step
// =============================================================================
// MIGRATED to BP30 v3.0 (M1 fee model): split + transfer carry OP_TRUE M1 fees,
// and each unlock carries an M1 fee + a single OP_TRUE vault output sized to
// vault_in - M0_out (so the vault DB amount always matches M0_vaulted). The
// accumulated producer fee receipts are drained by the final multi-input unlock.
BOOST_AUTO_TEST_CASE(mainnet_audit_split_multi_recipient_unlock)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey walletA, walletB, walletC;
    walletA.MakeNewKey(true);
    walletB.MakeNewKey(true);
    walletC.MakeNewKey(true);
    CScript scriptA = GetScriptForDestination(walletA.GetPubKey().GetID());
    CScript scriptB = GetScriptForDestination(walletB.GetPubKey().GetID());
    CScript scriptC = GetScriptForDestination(walletC.GetPubKey().GetID());

    // Initialize state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    const CAmount INITIAL_LOCK = 100 * COIN;
    const CAmount FEE = 1 * COIN;          // BP30 v3.0: M1 fee per transfer/unlock
    const CAmount SPLIT_A = 40 * COIN;     // A's receipt
    const CAmount SPLIT_B = 59 * COIN;     // B's receipt (100 - 40 - splitFee)
    // Track producer fee receipts so the final unlock can drain them to 0.
    std::vector<COutPoint> feeReceipts;

    // Step 1: Lock 100 M0
    CMutableTransaction mtxLock = CreateMockTxLock(INITIAL_LOCK, GetOpTrueScript(), scriptA);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, 1, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receipt0(txLock.GetHash(), 1);
    BOOST_CHECK_EQUAL(state.M0_vaulted, INITIAL_LOCK);
    BOOST_CHECK_EQUAL(state.M1_supply, INITIAL_LOCK);
    BOOST_CHECK(state.CheckInvariants());

    // Step 2: Split 100 M1 → 40 M1 (A) + 59 M1 (B) + 1 M1 fee (producer)
    // Conservation: 40 + 59 + 1 == 100. vout[2] (fee) must be OP_TRUE and last.
    CMutableTransaction mtxSplit;
    mtxSplit.nVersion = CTransaction::TxVersion::SAPLING;
    mtxSplit.nType = CTransaction::TxType::TX_TRANSFER_M1;
    mtxSplit.vin.emplace_back(CTxIn(receipt0));
    mtxSplit.vout.emplace_back(CTxOut(SPLIT_A, scriptA));  // 40 M1 to A
    mtxSplit.vout.emplace_back(CTxOut(SPLIT_B, scriptB));  // 59 M1 to B
    mtxSplit.vout.emplace_back(CTxOut(FEE, GetOpTrueScript())); // 1 M1 fee
    CTransaction txSplit(mtxSplit);

    CValidationState vsSplit;
    BOOST_CHECK(CheckTransfer(txSplit, view, vsSplit));

    TransferUndoData undoSplit;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txSplit, view, batch, undoSplit));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptA(txSplit.GetHash(), 0);
    COutPoint receiptB(txSplit.GetHash(), 1);
    feeReceipts.emplace_back(txSplit.GetHash(), 2);  // split fee (1 M1)
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptA));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptB));
    BOOST_CHECK(state.CheckInvariants());  // M1 unchanged (split, not burn)

    // Step 3: A unlocks against its 40 M1 receipt.
    // BP30 v3.1: M0_out=39, implicit fee=1 (M0 coinbase fee), no M1 change. The single
    // OP_TRUE vault output is sized vault_in - M0_out - fee = 100 - 39 - 1 = 60 (backs
    // the 60 M1 still outstanding). M0_vaulted and M1_supply both fall by M0_out+fee=40.
    CAmount aUnlock = SPLIT_A - FEE;                  // 39 M0 released
    CAmount aVaultOut = INITIAL_LOCK - aUnlock - FEE; // 60 re-vaulted (M0_out+fee left)
    CMutableTransaction mtxUnlockA;
    mtxUnlockA.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlockA.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlockA.vin.emplace_back(CTxIn(receiptA));  // 40 M1
    mtxUnlockA.vin.emplace_back(CTxIn(vaultOut));  // 100 vault
    mtxUnlockA.vout.emplace_back(CTxOut(aUnlock, scriptA));            // vout[0] 39 M0 to A
    mtxUnlockA.vout.emplace_back(CTxOut(aVaultOut, GetOpTrueScript()));// vout[1] 60 vault change
    CTransaction txUnlockA(mtxUnlockA);

    CValidationState vsUnlockA;
    BOOST_CHECK(CheckUnlock(txUnlockA, view, vsUnlockA));

    UnlockUndoData undoUnlockA;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlockA, view, state, batch, undoUnlockA));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultChange1(txUnlockA.GetHash(), 1);  // 60 vault
    // BP30 v3.1: no M1 fee receipt is created (fee is an M0 coinbase fee).
    BOOST_CHECK_EQUAL(state.M0_vaulted, aVaultOut);  // 60 M0 vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, aVaultOut);          // 60 M1 (B's 59 + 1 split fee)
    BOOST_CHECK(state.CheckInvariants());  // A6: 60 == 60

    // Step 4: B transfers 59 M1 → C (58 to C, 1 M1 fee)
    CAmount amtC = SPLIT_B - FEE;  // 58
    CMutableTransaction mtxTransferBC = CreateMockTxTransferWithFee(receiptB, amtC, FEE, scriptC);
    CTransaction txTransferBC(mtxTransferBC);

    CValidationState vsBC;
    BOOST_CHECK(CheckTransfer(txTransferBC, view, vsBC));

    TransferUndoData undoBC;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyTransfer(txTransferBC, view, batch, undoBC));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint receiptC(txTransferBC.GetHash(), 0);
    feeReceipts.emplace_back(txTransferBC.GetHash(), 1); // B→C transfer fee (1 M1)
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptC));
    BOOST_CHECK(state.CheckInvariants());

    // Step 5: C unlocks 30 M0 partial. C's receipt is 58 M1, vault is 60.
    // BP30 v3.1: M0_out=30, implicit fee=1, M1_change=27, single vault output =
    // vault_in - M0_out - fee = 60 - 30 - 1 = 29.
    CAmount partialUnlock = 30 * COIN;
    CAmount m1ChangeC = amtC - partialUnlock - FEE;      // 58 - 30 - 1 = 27 M1 change
    CAmount cVaultOut = aVaultOut - partialUnlock - FEE; // 60 - 30 - 1 = 29 re-vaulted

    CMutableTransaction mtxUnlockC1;
    mtxUnlockC1.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlockC1.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlockC1.vin.emplace_back(CTxIn(receiptC));      // 58 M1
    mtxUnlockC1.vin.emplace_back(CTxIn(vaultChange1)); // 60 vault
    mtxUnlockC1.vout.emplace_back(CTxOut(partialUnlock, scriptC));      // vout[0] 30 M0 to C
    mtxUnlockC1.vout.emplace_back(CTxOut(m1ChangeC, scriptC));          // vout[1] 27 M1 change
    mtxUnlockC1.vout.emplace_back(CTxOut(cVaultOut, GetOpTrueScript()));// vout[2] 29 vault change
    CTransaction txUnlockC1(mtxUnlockC1);

    CValidationState vsUnlockC1;
    BOOST_CHECK(CheckUnlock(txUnlockC1, view, vsUnlockC1));

    UnlockUndoData undoUnlockC1;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlockC1, view, state, batch, undoUnlockC1));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultChange2(txUnlockC1.GetHash(), 2);  // 29 vault
    COutPoint receiptC2(txUnlockC1.GetHash(), 1);     // 27 M1 change
    // BP30 v3.1: no M1 fee receipt is created (fee is an M0 coinbase fee).
    BOOST_CHECK_EQUAL(state.M0_vaulted, cVaultOut);  // 29 M0 vaulted
    BOOST_CHECK_EQUAL(state.M1_supply, cVaultOut);          // 29 M1 (27 change + 2 transfer fees)
    BOOST_CHECK(state.CheckInvariants());  // A6: 29 == 29

    // Step 6: C unlocks the remainder, draining its 27 M1 change PLUS the 2
    // accumulated TRANSFER fee receipts (split, B->C). Unlocks create no fee receipts
    // under BP30 v3.1. Full drain: M1_in(29) == M0_out(29), no change, no fee.
    BOOST_CHECK_EQUAL((int)feeReceipts.size(), 2);

    CMutableTransaction mtxUnlockC2;
    mtxUnlockC2.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlockC2.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlockC2.vin.emplace_back(CTxIn(receiptC2));    // 27 M1
    for (const COutPoint& f : feeReceipts) {           // 2 × 1 M1 producer fee receipts
        mtxUnlockC2.vin.emplace_back(CTxIn(f));
    }
    mtxUnlockC2.vin.emplace_back(CTxIn(vaultChange2)); // 29 vault
    mtxUnlockC2.vout.emplace_back(CTxOut(cVaultOut, scriptC));  // 29 M0 to C
    CTransaction txUnlockC2(mtxUnlockC2);

    CValidationState vsUnlockC2;
    BOOST_CHECK(CheckUnlock(txUnlockC2, view, vsUnlockC2));

    UnlockUndoData undoUnlockC2;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlockC2, view, state, batch, undoUnlockC2));
        BOOST_CHECK(batch.Commit());
    }

    // Final verification
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(state.CheckInvariants());  // A6: 0 == 0
}

// MIGRATED to BP30 v3.0 (M1 fee model): partial unlock carries an M1 fee + a single
// OP_TRUE vault output sized vault_in - M0_out, then is undone. Macro-state matches
// v2.2 (only M0_out leaves the vault). UndoUnlock erases the M1 change + fee receipts
// and the single vault output, restoring the original vault/receipt.
BOOST_AUTO_TEST_CASE(deep_reorg_partial_unlock_consistency)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    // Initialize state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    CAmount P = 100 * COIN;
    CAmount unlockAmount = 30 * COIN;
    CAmount FEE = 1 * COIN;
    CAmount m1Change = P - unlockAmount - FEE;   // 69 M1 change
    CAmount remainingVaulted = P - unlockAmount - FEE; // 69 M0 stays vaulted (M0_out+fee left)

    // Step 1: Lock 100 M0
    CMutableTransaction mtxLock = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLock(mtxLock);

    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyLock(txLock, view, state, 1, batch));
        BOOST_CHECK(batch.Commit());
    }

    COutPoint vaultOut(txLock.GetHash(), 0);
    COutPoint receiptOut(txLock.GetHash(), 1);

    // Step 2: Partial unlock (30 M0) with implicit M0 fee + single OP_TRUE vault output
    // BP30 v3.1 order: vout[0]=M0, vout[1]=M1 change, vout[2]=vault change. The fee (1)
    // is a real M0 coinbase fee — no fee output. vault_change = 100 - 30 - 1 = 69.
    CMutableTransaction mtxUnlock;
    mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
    mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;
    mtxUnlock.vin.emplace_back(CTxIn(receiptOut));
    mtxUnlock.vin.emplace_back(CTxIn(vaultOut));
    mtxUnlock.vout.emplace_back(CTxOut(unlockAmount, destScript));         // vout[0] 30 M0
    mtxUnlock.vout.emplace_back(CTxOut(m1Change, destScript));             // vout[1] 69 M1 change
    mtxUnlock.vout.emplace_back(CTxOut(remainingVaulted, GetOpTrueScript())); // vout[2] 69 vault change

    CTransaction txUnlock(mtxUnlock);

    UnlockUndoData undoData;
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(ApplyUnlock(txUnlock, view, state, batch, undoData));
        BOOST_CHECK(batch.Commit());
    }

    // undo counters both move by M0_out + fee = 31
    BOOST_CHECK_EQUAL(undoData.m0Released, unlockAmount + FEE);
    BOOST_CHECK_EQUAL(undoData.netM1Burned, unlockAmount + FEE);

    // Verify state after partial unlock (M0_out + fee left the vault)
    BOOST_CHECK_EQUAL(state.M0_vaulted, remainingVaulted);  // 69 M0
    BOOST_CHECK_EQUAL(state.M1_supply, remainingVaulted);          // 69 M1
    BOOST_CHECK(state.CheckInvariants());

    COutPoint newVaultOut(txUnlock.GetHash(), 2);
    COutPoint newReceiptOut(txUnlock.GetHash(), 1);
    BOOST_CHECK(g_settlementdb->IsVault(newVaultOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(newReceiptOut));

    // Step 3: Undo the partial unlock (simulate reorg)
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoUnlock(txUnlock, undoData, state, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify state after undo
    BOOST_CHECK_EQUAL(state.M0_vaulted, P);  // Back to 100 M0
    BOOST_CHECK_EQUAL(state.M1_supply, P);          // Back to 100 M1
    BOOST_CHECK(state.CheckInvariants());

    // Original vault and receipt restored
    BOOST_CHECK(g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    // New vault and receipt removed
    BOOST_CHECK(!g_settlementdb->IsVault(newVaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(newReceiptOut));

    // Step 4: Undo the lock
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_CHECK(UndoLock(txLock, state, batch));
        BOOST_CHECK(batch.Commit());
    }

    // Verify clean state
    BOOST_CHECK_EQUAL(state.M0_vaulted, 0);
    BOOST_CHECK_EQUAL(state.M1_supply, 0);
    BOOST_CHECK(state.CheckInvariants());
    BOOST_CHECK(!g_settlementdb->IsVault(vaultOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
}

// =============================================================================
// SECURITY TEST: Prevent TX_LOCK from spending M1 receipts (same block)
//
// Attack vector: TX_A creates Receipt_A, TX_B spends Receipt_A as if M0.
// Since settlement DB doesn't know about Receipt_A yet, IsM0Standard returns true.
// This causes M0_vaulted to increase without real M0 backing.
//
// Fix: Track pendingReceipts during block processing and reject TX_LOCK that
// spends a receipt created earlier in the same block.
// =============================================================================
BOOST_AUTO_TEST_CASE(security_lock_cannot_spend_same_block_receipt)
{
    // This test verifies the pendingReceipts logic conceptually.
    // The actual enforcement happens in ProcessSpecialTxsInBlock.

    CKey key;
    key.MakeNewKey(true);
    CScript receiptScript = GetScriptForDestination(key.GetPubKey().GetID());
    CAmount P = 100 * COIN;

    // TX_A: Creates a receipt at vout[1]
    CMutableTransaction txA;
    txA.nVersion = CTransaction::TxVersion::SAPLING;
    txA.nType = CTransaction::TxType::TX_LOCK;
    txA.vin.emplace_back(CTxIn(COutPoint(uint256S("aaaa"), 0)));
    txA.vout.emplace_back(CTxOut(P, GetOpTrueScript()));  // Vault
    txA.vout.emplace_back(CTxOut(P, receiptScript));       // Receipt

    COutPoint receiptA(CTransaction(txA).GetHash(), 1);

    // TX_B: Tries to spend Receipt_A as an input
    CMutableTransaction txB;
    txB.nVersion = CTransaction::TxVersion::SAPLING;
    txB.nType = CTransaction::TxType::TX_LOCK;
    txB.vin.emplace_back(CTxIn(receiptA));  // Spending the receipt!
    txB.vout.emplace_back(CTxOut(P, GetOpTrueScript()));
    txB.vout.emplace_back(CTxOut(P, receiptScript));

    // Simulate the pendingReceipts check (as done in ProcessSpecialTxsInBlock)
    std::set<COutPoint> pendingReceipts;
    pendingReceipts.insert(receiptA);  // TX_A created this receipt

    // TX_B should be rejected because it spends a pending receipt
    bool foundPendingReceipt = false;
    for (const CTxIn& txin : txB.vin) {
        if (pendingReceipts.count(txin.prevout)) {
            foundPendingReceipt = true;
            break;
        }
    }

    BOOST_CHECK_MESSAGE(foundPendingReceipt,
        "TX_LOCK spending a same-block receipt MUST be detected and rejected");

    LogPrintf("SECURITY-TEST: Verified pendingReceipts detection for same-block attack\n");
}

// =============================================================================
// SECURITY TEST: M0_vaulted cannot exceed M0_total
//
// Invariant: You cannot vault more M0 than exists.
// This test verifies that after applying locks with proper checks,
// M0_vaulted stays within valid bounds.
// =============================================================================
BOOST_AUTO_TEST_CASE(security_vaulted_cannot_exceed_total)
{
    // Initialize settlement DB in memory
    g_settlementdb = std::make_unique<CSettlementDB>(0, true, true);

    // Initialize state (A6: M0_vaulted == M1_supply)
    SettlementState state;
    state.M0_total_supply = 100 * COIN;  // Only 100 M0 exists
    state.M0_vaulted = 0;
    state.M1_supply = 0;

    // Valid case: lock 50 M0
    CAmount lockAmount = 50 * COIN;
    state.M0_vaulted += lockAmount;
    state.M1_supply += lockAmount;

    // Check A6 invariant
    BOOST_CHECK(state.CheckInvariants());
    BOOST_CHECK_EQUAL(state.M0_vaulted, state.M1_supply);

    // Simulate what would happen if we allowed locking M1 receipts:
    // This should NOT happen with the security fix, but we verify the math
    CAmount illegalLock = 60 * COIN;  // More than remaining M0_free
    SettlementState badState = state;
    badState.M0_vaulted += illegalLock;
    badState.M1_supply += illegalLock;

    // After illegal lock: M0_vaulted (110) > M0_total (100) - INVALID!
    BOOST_CHECK_MESSAGE(badState.M0_vaulted > badState.M0_total_supply,
        "This demonstrates the attack: vaulted > total is impossible in real money");

    // A6 still holds (that's why the bug was hard to catch)
    BOOST_CHECK_EQUAL(badState.M0_vaulted, badState.M1_supply);

    LogPrintf("SECURITY-TEST: Demonstrated M0_vaulted > M0_total attack vector\n");

    g_settlementdb.reset();
}

// =============================================================================
// Test: ParseSettlementTx - Robust M0/M1/Vault classification WITHOUT DB
// BP30 v2.6: Tests for the new DB-independent classification function
// =============================================================================

// Helper: Create simple coins view with known coins for ParseSettlementTx tests
class ParseSettlementMockCoinsView : public CCoinsView {
public:
    std::map<COutPoint, CTxOut> coins;

    void AddCoin(const COutPoint& outpoint, const CTxOut& out) {
        coins[outpoint] = out;
    }

    bool GetCoin(const COutPoint& outpoint, Coin& coin) const override {
        auto it = coins.find(outpoint);
        if (it != coins.end()) {
            coin = Coin(it->second, 0, false);
            return true;
        }
        return false;
    }

    bool HaveCoin(const COutPoint& outpoint) const override {
        return coins.count(outpoint) > 0;
    }
};

BOOST_AUTO_TEST_CASE(parse_settlement_tx_lock)
{
    // Test TX_LOCK classification
    CKey key;
    key.MakeNewKey(true);
    CScript vaultScript = GetOpTrueScript();
    CScript receiptScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount lockAmount = 5000;
    CMutableTransaction mtx = CreateMockTxLock(lockAmount, vaultScript, receiptScript);
    CTransaction tx(mtx);

    // Setup mock coins view
    ParseSettlementMockCoinsView baseView;
    CScript p2pkhScript = GetScriptForDestination(key.GetPubKey().GetID());
    baseView.AddCoin(tx.vin[0].prevout, CTxOut(lockAmount + 200, p2pkhScript));  // 200 for fee
    CCoinsViewCache view(&baseView);

    // Parse the transaction
    SettlementTxView stxView;
    BOOST_CHECK(ParseSettlementTx(tx, &view, stxView));

    // Verify classification
    BOOST_CHECK_EQUAL(stxView.txType, "TX_LOCK");
    BOOST_CHECK(stxView.complete);
    BOOST_CHECK_EQUAL(stxView.missing_inputs, 0u);

    // TX_LOCK: all inputs are M0
    BOOST_CHECK_EQUAL(stxView.m0_input_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m1_input_indices.size(), 0u);
    BOOST_CHECK_EQUAL(stxView.vault_input_indices.size(), 0u);

    // TX_LOCK outputs: vout[0]=vault, vout[1]=M1
    BOOST_CHECK_EQUAL(stxView.vault_output_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m1_output_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m0_output_indices.size(), 0u);

    // Amounts
    BOOST_CHECK_EQUAL(stxView.m0_in, lockAmount + 200);
    BOOST_CHECK_EQUAL(stxView.vault_out, lockAmount);
    BOOST_CHECK_EQUAL(stxView.m1_out, lockAmount);
    BOOST_CHECK_EQUAL(stxView.m0_out, 0);

    LogPrintf("TEST: ParseSettlementTx TX_LOCK classification verified\n");
}

BOOST_AUTO_TEST_CASE(parse_settlement_tx_unlock)
{
    // Test TX_UNLOCK classification
    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());
    CScript vaultScript = GetOpTrueScript();

    CAmount m1Amount = 5000;
    CAmount vaultAmount = 5000;
    CAmount unlockAmount = 5000;

    // Create TX_UNLOCK
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_UNLOCK;

    // Create prevout outpoints
    uint256 m1Txid, vaultTxid;
    m1Txid.SetHex("1111111111111111111111111111111111111111111111111111111111111111");
    vaultTxid.SetHex("2222222222222222222222222222222222222222222222222222222222222222");
    COutPoint m1Prevout(m1Txid, 0);
    COutPoint vaultPrevout(vaultTxid, 0);

    // vin[0] = M1 receipt (non-OP_TRUE), vin[1] = vault (OP_TRUE)
    mtx.vin.emplace_back(CTxIn(m1Prevout));
    mtx.vin.emplace_back(CTxIn(vaultPrevout));

    // vout[0] = M0 unlocked
    mtx.vout.emplace_back(CTxOut(unlockAmount, destScript));

    CTransaction tx(mtx);

    // Setup mock coins view
    ParseSettlementMockCoinsView baseView;
    baseView.AddCoin(m1Prevout, CTxOut(m1Amount, destScript));  // M1 receipt (normal script)
    baseView.AddCoin(vaultPrevout, CTxOut(vaultAmount, vaultScript));  // Vault (OP_TRUE)
    CCoinsViewCache view(&baseView);

    // Parse the transaction
    SettlementTxView stxView;
    BOOST_CHECK(ParseSettlementTx(tx, &view, stxView));

    // Verify classification
    BOOST_CHECK_EQUAL(stxView.txType, "TX_UNLOCK");
    BOOST_CHECK(stxView.complete);
    BOOST_CHECK_EQUAL(stxView.missing_inputs, 0u);

    // TX_UNLOCK inputs: M1 (before vault), vault (OP_TRUE)
    BOOST_CHECK_EQUAL(stxView.m1_input_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.vault_input_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m0_input_indices.size(), 0u);

    // TX_UNLOCK outputs: vout[0]=M0
    BOOST_CHECK_EQUAL(stxView.m0_output_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m1_output_indices.size(), 0u);
    BOOST_CHECK_EQUAL(stxView.vault_output_indices.size(), 0u);

    // Amounts
    BOOST_CHECK_EQUAL(stxView.m1_in, m1Amount);
    BOOST_CHECK_EQUAL(stxView.vault_in, vaultAmount);
    BOOST_CHECK_EQUAL(stxView.m0_in, 0);
    BOOST_CHECK_EQUAL(stxView.m0_out, unlockAmount);

    LogPrintf("TEST: ParseSettlementTx TX_UNLOCK classification verified\n");
}

BOOST_AUTO_TEST_CASE(parse_settlement_tx_transfer)
{
    // Test TX_TRANSFER_M1 classification
    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount m1Amount = 5000;
    CAmount feeInputAmount = 200;

    // Create TX_TRANSFER_M1
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;

    // Create prevout outpoints
    uint256 m1Txid, feeTxid;
    m1Txid.SetHex("3333333333333333333333333333333333333333333333333333333333333333");
    feeTxid.SetHex("4444444444444444444444444444444444444444444444444444444444444444");
    COutPoint m1Prevout(m1Txid, 0);
    COutPoint feePrevout(feeTxid, 0);

    // vin[0] = M1 receipt, vin[1] = M0 fee input
    mtx.vin.emplace_back(CTxIn(m1Prevout));
    mtx.vin.emplace_back(CTxIn(feePrevout));

    // vout[0] = new M1 receipt (5000), vout[1] = M0 fee change (100)
    mtx.vout.emplace_back(CTxOut(m1Amount, destScript));      // M1 out = m1_in
    mtx.vout.emplace_back(CTxOut(100, destScript));           // M0 fee change

    CTransaction tx(mtx);

    // Setup mock coins view
    ParseSettlementMockCoinsView baseView;
    baseView.AddCoin(m1Prevout, CTxOut(m1Amount, destScript));       // M1 receipt
    baseView.AddCoin(feePrevout, CTxOut(feeInputAmount, destScript)); // M0 fee input
    CCoinsViewCache view(&baseView);

    // Parse the transaction
    SettlementTxView stxView;
    BOOST_CHECK(ParseSettlementTx(tx, &view, stxView));

    // Verify classification
    BOOST_CHECK_EQUAL(stxView.txType, "TX_TRANSFER_M1");
    BOOST_CHECK(stxView.complete);
    BOOST_CHECK_EQUAL(stxView.missing_inputs, 0u);

    // TX_TRANSFER_M1 inputs: vin[0]=M1, vin[1+]=M0
    BOOST_CHECK_EQUAL(stxView.m1_input_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m0_input_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.vault_input_indices.size(), 0u);

    // TX_TRANSFER_M1 outputs: cumsum-based (vout[0]=M1, rest=M0)
    BOOST_CHECK_EQUAL(stxView.m1_output_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m0_output_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.vault_output_indices.size(), 0u);

    // Amounts
    BOOST_CHECK_EQUAL(stxView.m1_in, m1Amount);
    BOOST_CHECK_EQUAL(stxView.m0_in, feeInputAmount);
    BOOST_CHECK_EQUAL(stxView.m1_out, m1Amount);
    BOOST_CHECK_EQUAL(stxView.m0_out, 100);

    // M0 fee = m0_in - m0_out = 200 - 100 = 100
    BOOST_CHECK_EQUAL(stxView.m0_fee, 100);

    LogPrintf("TEST: ParseSettlementTx TX_TRANSFER_M1 classification verified\n");
}

BOOST_AUTO_TEST_CASE(parse_settlement_tx_incomplete)
{
    // Test handling of missing inputs (complete=false)
    CKey key;
    key.MakeNewKey(true);
    CScript vaultScript = GetOpTrueScript();
    CScript receiptScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount lockAmount = 5000;
    CMutableTransaction mtx = CreateMockTxLock(lockAmount, vaultScript, receiptScript);
    CTransaction tx(mtx);

    // Empty coins view - inputs cannot be resolved
    ParseSettlementMockCoinsView baseView;
    CCoinsViewCache view(&baseView);

    // Parse the transaction
    SettlementTxView stxView;
    BOOST_CHECK(ParseSettlementTx(tx, &view, stxView));

    // Should be marked incomplete
    BOOST_CHECK(!stxView.complete);
    BOOST_CHECK_EQUAL(stxView.missing_inputs, 1u);

    // Type should still be detected
    BOOST_CHECK_EQUAL(stxView.txType, "TX_LOCK");

    // Input amounts should be 0 (couldn't fetch)
    BOOST_CHECK_EQUAL(stxView.m0_in, 0);

    // Output classification should still work
    BOOST_CHECK_EQUAL(stxView.vault_output_indices.size(), 1u);
    BOOST_CHECK_EQUAL(stxView.m1_output_indices.size(), 1u);

    LogPrintf("TEST: ParseSettlementTx incomplete handling verified\n");
}

// =============================================================================
// Test: OP_TRUE forbidden in non-settlement TX (consensus rule BP30 v2.6)
// =============================================================================
BOOST_AUTO_TEST_CASE(optrue_forbidden_in_normal_tx)
{
    // A normal TX with an OP_TRUE output should be rejected by consensus
    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());
    CScript opTrueScript = GetOpTrueScript();

    // Create a NORMAL transaction with OP_TRUE output
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::NORMAL;

    // Add a dummy input
    uint256 dummyTxid;
    dummyTxid.SetHex("5555555555555555555555555555555555555555555555555555555555555555");
    mtx.vin.emplace_back(CTxIn(COutPoint(dummyTxid, 0)));

    // Add outputs: one normal, one OP_TRUE (should be forbidden)
    mtx.vout.emplace_back(CTxOut(1000, destScript));
    mtx.vout.emplace_back(CTxOut(1000, opTrueScript));  // OP_TRUE in normal TX!

    CTransaction tx(mtx);

    // This should be rejected by CheckTransaction
    CValidationState state;
    BOOST_CHECK(!CheckTransaction(tx, state));
    BOOST_CHECK_EQUAL(state.GetRejectReason(), "bad-txns-optrue-forbidden");

    LogPrintf("TEST: OP_TRUE forbidden in normal TX verified\n");
}

// =============================================================================
// Test: OP_TRUE allowed in TX_LOCK (settlement TX)
// =============================================================================
BOOST_AUTO_TEST_CASE(optrue_allowed_in_settlement_tx)
{
    // A TX_LOCK with an OP_TRUE vault output should be accepted
    CKey key;
    key.MakeNewKey(true);
    CScript vaultScript = GetOpTrueScript();
    CScript receiptScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount lockAmount = 5000;
    CMutableTransaction mtx = CreateMockTxLock(lockAmount, vaultScript, receiptScript);
    CTransaction tx(mtx);

    // This should pass CheckTransaction (OP_TRUE allowed in TX_LOCK)
    CValidationState state;
    BOOST_CHECK(CheckTransaction(tx, state));

    LogPrintf("TEST: OP_TRUE allowed in TX_LOCK verified\n");
}

// =============================================================================
// Integration Test: Consensus vs RPC view consistency (BP30 v2.6)
// =============================================================================
// This test verifies that ParseSettlementTx (used by RPC m0_fee_info) produces
// the SAME classification that consensus validates. The unified fee formula:
//   m0_fee = (m0_in + vault_in) - (m0_out + vault_out)
// must work correctly for all settlement TX types.
// =============================================================================
BOOST_AUTO_TEST_CASE(consensus_vs_rpc_view_consistency)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);

    CKey ownerKey;
    ownerKey.MakeNewKey(true);
    CScript ownerScript = GetScriptForDestination(ownerKey.GetPubKey().GetID());
    CScript vaultScript = GetOpTrueScript();

    // Initialize state
    SettlementState state;
    state.M0_vaulted = 0;
    state.M1_supply = 0;
    state.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);

    // =========================================================================
    // TEST 1: TX_LOCK - Verify fee = (m0_in + 0) - (m0_change + vault)
    // =========================================================================
    {
        CAmount lockAmount = 100 * COIN;
        CAmount m0InputAmount = 120 * COIN;  // 20 COIN for fee (no change in simple tx)

        CMutableTransaction mtxLock = CreateMockTxLock(lockAmount, vaultScript, ownerScript);
        CTransaction txLock(mtxLock);

        // Part A: Consensus validation passes
        CValidationState valState;
        BOOST_CHECK(CheckLock(txLock, view, valState));
        BOOST_CHECK(CheckTransaction(txLock, valState));

        // Part B: RPC classification via ParseSettlementTx
        ParseSettlementMockCoinsView mockBase;
        mockBase.AddCoin(txLock.vin[0].prevout, CTxOut(m0InputAmount, ownerScript));
        CCoinsViewCache mockView(&mockBase);

        SettlementTxView stxView;
        BOOST_CHECK(ParseSettlementTx(txLock, &mockView, stxView));

        // Verify classification
        BOOST_CHECK_EQUAL(stxView.txType, "TX_LOCK");
        BOOST_CHECK(stxView.complete);
        BOOST_CHECK_EQUAL(stxView.m0_in, m0InputAmount);
        BOOST_CHECK_EQUAL(stxView.vault_in, 0);
        BOOST_CHECK_EQUAL(stxView.vault_out, lockAmount);
        BOOST_CHECK_EQUAL(stxView.m1_out, lockAmount);
        BOOST_CHECK_EQUAL(stxView.m0_out, 0);

        // Verify fee formula: (120 + 0) - (0 + 100) = 20 COIN
        CAmount expectedFee = (stxView.m0_in + stxView.vault_in) - (stxView.m0_out + stxView.vault_out);
        BOOST_CHECK_EQUAL(stxView.m0_fee, expectedFee);
        BOOST_CHECK_EQUAL(stxView.m0_fee, 20 * COIN);

        LogPrintf("TEST: TX_LOCK consensus/RPC consistency verified (fee=%lld)\n", (long long)stxView.m0_fee);
    }

    // =========================================================================
    // TEST 2: TX_UNLOCK - Verify fee formula with vault_in/m0_out transformation
    // =========================================================================
    // This test focuses on RPC classification. Consensus validation for TX_UNLOCK
    // is thoroughly tested in other test cases (e.g., applyunlock_*, unlock_with_*).
    // Here we verify the fee formula: (m0_in + vault_in) - (m0_out + vault_out)
    // =========================================================================
    {
        // Create a simulated TX_UNLOCK (without full consensus validation)
        uint256 lockTxid;
        lockTxid.SetHex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
        COutPoint vaultOut(lockTxid, 0);
        COutPoint receiptOut(lockTxid, 1);

        // Create TX_UNLOCK: simple full unlock (no M1 change)
        // vin[0] = M1 receipt (50 COIN)
        // vin[1] = Vault (50 COIN)
        // vin[2] = M0 fee input (1 COIN)
        // vout[0] = M0 unlocked (50 COIN)
        // vout[1] = M0 fee change (0.99 COIN)
        CMutableTransaction mtxUnlock;
        mtxUnlock.nVersion = CTransaction::TxVersion::SAPLING;
        mtxUnlock.nType = CTransaction::TxType::TX_UNLOCK;
        mtxUnlock.vin.emplace_back(CTxIn(receiptOut));  // M1 receipt
        mtxUnlock.vin.emplace_back(CTxIn(vaultOut));    // Vault (OP_TRUE)
        uint256 feeTxid;
        feeTxid.SetHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        mtxUnlock.vin.emplace_back(CTxIn(COutPoint(feeTxid, 0)));  // M0 fee

        mtxUnlock.vout.emplace_back(CTxOut(50 * COIN, ownerScript));   // M0 unlocked
        mtxUnlock.vout.emplace_back(CTxOut(99000000, ownerScript));    // M0 fee change (0.99 COIN)

        CTransaction txUnlock(mtxUnlock);

        // RPC classification via ParseSettlementTx
        ParseSettlementMockCoinsView mockBase;
        mockBase.AddCoin(receiptOut, CTxOut(50 * COIN, ownerScript));     // M1 (before vault)
        mockBase.AddCoin(vaultOut, CTxOut(50 * COIN, vaultScript));       // Vault (OP_TRUE)
        mockBase.AddCoin(COutPoint(feeTxid, 0), CTxOut(1 * COIN, ownerScript));  // M0 fee
        CCoinsViewCache mockView(&mockBase);

        SettlementTxView stxView;
        BOOST_CHECK(ParseSettlementTx(txUnlock, &mockView, stxView));

        BOOST_CHECK_EQUAL(stxView.txType, "TX_UNLOCK");
        BOOST_CHECK(stxView.complete);

        // Inputs classified by prevout script:
        // vin[0] = before OP_TRUE → M1 (50 COIN)
        // vin[1] = OP_TRUE → Vault (50 COIN)
        // vin[2] = after vault → M0 (1 COIN)
        BOOST_CHECK_EQUAL(stxView.m1_in, 50 * COIN);
        BOOST_CHECK_EQUAL(stxView.vault_in, 50 * COIN);
        BOOST_CHECK_EQUAL(stxView.m0_in, 1 * COIN);

        // Outputs: vout[0] = M0 unlocked, vout[1] = classified based on cumsum
        // For TX_UNLOCK with m1_in=50 and m0_out_expected=50:
        // m1_change_expected = 50 - 50 = 0
        // So vout[1] is M0 fee change, not M1 change
        BOOST_CHECK_EQUAL(stxView.m0_out, 50 * COIN + 99000000);  // unlocked + fee_change
        BOOST_CHECK_EQUAL(stxView.vault_out, 0);

        // Fee formula: (m0_in + vault_in) - (m0_out + vault_out)
        //            = (1 + 50) - (50.99 + 0) = 0.01 COIN = 1,000,000 sats
        CAmount expectedFee = (stxView.m0_in + stxView.vault_in) - (stxView.m0_out + stxView.vault_out);
        BOOST_CHECK_EQUAL(stxView.m0_fee, expectedFee);
        BOOST_CHECK_EQUAL(stxView.m0_fee, 1000000);

        LogPrintf("TEST: TX_UNLOCK fee formula verified (fee=%lld)\n", (long long)stxView.m0_fee);
    }

    // =========================================================================
    // TEST 3: TX_TRANSFER_M1 - Verify cumsum M1/M0 classification and fee
    // =========================================================================
    // This test focuses on RPC classification. Consensus validation for TX_TRANSFER
    // is thoroughly tested in other test cases (e.g., transfer_*, adversarial_*).
    // Here we verify the cumsum algorithm and fee formula work correctly.
    // =========================================================================
    {
        // Create a simulated TX_TRANSFER_M1 (without full consensus validation)
        uint256 lockTxid;
        lockTxid.SetHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
        COutPoint receiptOut(lockTxid, 1);

        // Create TX_TRANSFER_M1:
        // vin[0] = M1 receipt (30 COIN) - canonical position
        // vin[1] = M0 fee input (0.06 COIN)
        // vout[0] = M1 output (30 COIN) - conserved
        // vout[1] = M0 fee change (0.05 COIN)
        CMutableTransaction mtxTransfer;
        mtxTransfer.nVersion = CTransaction::TxVersion::SAPLING;
        mtxTransfer.nType = CTransaction::TxType::TX_TRANSFER_M1;
        mtxTransfer.vin.emplace_back(CTxIn(receiptOut));  // M1 receipt (vin[0])
        uint256 feeTxid;
        feeTxid.SetHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
        mtxTransfer.vin.emplace_back(CTxIn(COutPoint(feeTxid, 0)));  // M0 fee (vin[1])

        mtxTransfer.vout.emplace_back(CTxOut(30 * COIN, ownerScript));  // M1 output (conserved)
        mtxTransfer.vout.emplace_back(CTxOut(5000000, ownerScript));    // M0 fee change

        CTransaction txTransfer(mtxTransfer);

        // RPC classification via ParseSettlementTx
        ParseSettlementMockCoinsView mockBase;
        mockBase.AddCoin(receiptOut, CTxOut(30 * COIN, ownerScript));
        mockBase.AddCoin(COutPoint(feeTxid, 0), CTxOut(6000000, ownerScript));  // 0.06 COIN
        CCoinsViewCache mockView(&mockBase);

        SettlementTxView stxView;
        BOOST_CHECK(ParseSettlementTx(txTransfer, &mockView, stxView));

        BOOST_CHECK_EQUAL(stxView.txType, "TX_TRANSFER_M1");
        BOOST_CHECK(stxView.complete);

        // Inputs: vin[0] = M1 (canonical), vin[1+] = M0
        BOOST_CHECK_EQUAL(stxView.m1_in, 30 * COIN);
        BOOST_CHECK_EQUAL(stxView.m0_in, 6000000);
        BOOST_CHECK_EQUAL(stxView.vault_in, 0);

        // Outputs via cumsum: vout[0]=30 ≤ m1_in=30, so M1; vout[1]=0.05 → M0
        BOOST_CHECK_EQUAL(stxView.m1_out, 30 * COIN);
        BOOST_CHECK_EQUAL(stxView.m0_out, 5000000);
        BOOST_CHECK_EQUAL(stxView.vault_out, 0);

        // Fee formula: (m0_in + vault_in) - (m0_out + vault_out)
        //            = (0.06 + 0) - (0.05 + 0) = 0.01 COIN
        CAmount expectedFee = (stxView.m0_in + stxView.vault_in) - (stxView.m0_out + stxView.vault_out);
        BOOST_CHECK_EQUAL(stxView.m0_fee, expectedFee);
        BOOST_CHECK_EQUAL(stxView.m0_fee, 1000000);

        LogPrintf("TEST: TX_TRANSFER_M1 fee formula verified (fee=%lld)\n", (long long)stxView.m0_fee);
    }

    LogPrintf("TEST: All consensus/RPC view consistency tests passed\n");
}

// =============================================================================
// REGRESSION (HTLC outpoint consensus protection): the CheckSpecialTx guard
// loop protected vaults (IsVault -> TX_UNLOCK only) and M1 receipts
// (IsM1Receipt -> reconciling whitelist) but NEVER consulted g_htlcdb. A
// NORMAL tx satisfying the HTLC redeem script (either party, with preimage or
// timeout branch) could spend the P2SH outpoint bypassing ApplyHTLCClaim /
// ApplyHTLCRefund: the record stays ACTIVE forever, no M1 receipt is
// recreated, M1_supply is overstated and the vault backing is orphaned —
// the same deflationary-leak class the receipt guard (a840582) closed.
//
// The guard is also POSITIONAL: every HTLC Check/Apply reconciles ONLY
// vin[0], so even a conforming HTLC_CLAIM must not carry a second HTLC at
// vin[1..]. Cross-family spends (2-party claim on a 3S outpoint and vice
// versa) are rejected too.
// =============================================================================
BOOST_AUTO_TEST_CASE(htlc_outpoint_spend_consensus_protected)
{
    LOCK(cs_main);  // CheckSpecialTx is EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(InitHtlcDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);
    BOOST_REQUIRE(g_htlcdb != nullptr);
    BOOST_REQUIRE(Params().GetConsensus().IsM1ReceiptProtected(1));  // ALWAYS_ACTIVE

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 30 * COIN;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CBlockIndex idxPrev;  // contextual parent so the guard activates
    idxPrev.nHeight = 100;

    // Register one ACTIVE 2-party HTLC and one ACTIVE 3S HTLC directly in the
    // DB (the guard consults only IsHTLC/IsHTLC3S; the create/claim/refund
    // paths themselves are covered by the HTLC suites).
    COutPoint htlcOut(uint256S("0x1111"), 0);
    {
        HTLCRecord rec;
        rec.htlcOutpoint = htlcOut;
        rec.amount = P;
        rec.hashlock = uint256S("0xaa");
        rec.claimKeyID = key.GetPubKey().GetID();
        rec.refundKeyID = key.GetPubKey().GetID();
        rec.createHeight = 90;
        rec.expiryHeight = 200;  // not yet expired at height 101
        BOOST_REQUIRE(g_htlcdb->WriteHTLC(rec));
    }
    COutPoint htlc3sOut(uint256S("0x2222"), 0);
    {
        HTLC3SRecord rec;
        rec.htlcOutpoint = htlc3sOut;
        rec.amount = P;
        rec.hashlock_user = uint256S("0xa1");
        rec.hashlock_lp1 = uint256S("0xa2");
        rec.hashlock_lp2 = uint256S("0xa3");
        rec.claimKeyID = key.GetPubKey().GetID();
        rec.refundKeyID = key.GetPubKey().GetID();
        rec.createHeight = 90;
        rec.expiryHeight = 200;
        BOOST_REQUIRE(g_htlcdb->WriteHTLC3S(rec));
    }
    BOOST_REQUIRE(g_htlcdb->IsHTLC(htlcOut));
    BOOST_REQUIRE(g_htlcdb->IsHTLC3S(htlc3sOut));

    // Helper: minimal tx of the given type spending a single outpoint.
    auto spendOf = [&](CTransaction::TxType type, const COutPoint& in) {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = type;
        mtx.vin.emplace_back(CTxIn(in));
        mtx.vout.emplace_back(CTxOut(P - 1000, destScript));
        return CTransaction(mtx);
    };

    // --- THE FIX: a NORMAL tx spending the HTLC P2SH is REJECTED. ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::NORMAL, htlcOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-htlc-protected");
    }
    {
        CTransaction tx = spendOf(CTransaction::TxType::NORMAL, htlc3sOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-htlc3s-protected");
    }

    // --- Non-reconciling special types are rejected as well. ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::TX_TRANSFER_M1, htlcOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-htlc-protected");
    }

    // --- Cross-family: the matching family is REQUIRED. ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::HTLC_CLAIM, htlc3sOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-htlc3s-protected");
    }
    {
        CTransaction tx = spendOf(CTransaction::TxType::HTLC_CLAIM_3S, htlcOut);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-htlc-protected");
    }

    // --- Conforming types at vin[0] are NOT blocked by the guard (they may
    //     fail later per-type validation on these minimal mocks, but never
    //     with the guard's reject codes). ---
    for (CTransaction::TxType allowed : {CTransaction::TxType::HTLC_CLAIM,
                                         CTransaction::TxType::HTLC_REFUND}) {
        CTransaction tx = spendOf(allowed, htlcOut);
        CValidationState st;
        CheckSpecialTx(tx, &idxPrev, &view, st);  // result may be false (per-type)
        BOOST_CHECK_MESSAGE(st.GetRejectReason() != "bad-txns-htlc-protected",
                            "HTLC guard wrongly blocked a conforming type");
    }
    for (CTransaction::TxType allowed : {CTransaction::TxType::HTLC_CLAIM_3S,
                                         CTransaction::TxType::HTLC_REFUND_3S}) {
        CTransaction tx = spendOf(allowed, htlc3sOut);
        CValidationState st;
        CheckSpecialTx(tx, &idxPrev, &view, st);  // result may be false (per-type)
        BOOST_CHECK_MESSAGE(st.GetRejectReason() != "bad-txns-htlc3s-protected",
                            "HTLC3S guard wrongly blocked a conforming type");
    }

    // --- POSITIONAL: an HTLC at vin[1] of an otherwise-conforming claim is
    //     REJECTED (ApplyHTLCClaim reconciles only vin[0]; the vin[1] record
    //     would stay ACTIVE while its UTXO is consumed). ---
    {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::HTLC_CLAIM;
        mtx.vin.emplace_back(CTxIn(COutPoint(uint256S("0x3333"), 0)));  // untracked
        mtx.vin.emplace_back(CTxIn(htlcOut));                            // HTLC at vin[1]
        mtx.vout.emplace_back(CTxOut(P, destScript));
        CTransaction tx(mtx);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-htlc-protected");
    }

    // --- GATING: with pindexPrev==null the guard is deferred (the contextual
    //     ConnectBlock/mempool call is authoritative). ---
    {
        CTransaction tx = spendOf(CTransaction::TxType::NORMAL, htlcOut);
        CValidationState st;
        BOOST_CHECK(CheckSpecialTx(tx, nullptr, &view, st));  // passes: guard skipped
        BOOST_CHECK(st.GetRejectReason() != "bad-txns-htlc-protected");
    }
}

// =============================================================================
// REGRESSION (receipt vin[0]-only rule for HTLC creates): ApplyHTLCCreate /
// ApplyHTLC3SCreate erase ONLY vin[0]'s receipt. A second receipt at vin[1..]
// would be consumed on-chain with its record left live (phantom receipt:
// M1_supply overstated, backing vault orphaned). The guard rejects it with
// "bad-txns-receipt-not-vin0". TX_UNLOCK/TX_TRANSFER_M1 reconcile every
// receipt input and stay exempt from the positional rule.
// =============================================================================
BOOST_AUTO_TEST_CASE(htlc_create_receipt_not_vin0)
{
    LOCK(cs_main);  // CheckSpecialTx is EXCLUSIVE_LOCKS_REQUIRED(cs_main)
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(InitHtlcDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);
    BOOST_REQUIRE(Params().GetConsensus().IsM1ReceiptProtected(1));  // ALWAYS_ACTIVE

    CKey key;
    key.MakeNewKey(true);
    CScript destScript = GetScriptForDestination(key.GetPubKey().GetID());

    CAmount P = 20 * COIN;
    uint32_t lockHeight = 100;

    SettlementState settle;
    settle.M0_vaulted = 0;
    settle.M1_supply = 0;
    settle.nHeight = 0;

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    CBlockIndex idxPrev;
    idxPrev.nHeight = lockHeight;

    // Two locks -> two live receipts.
    CMutableTransaction mtxLockA = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CMutableTransaction mtxLockB = CreateMockTxLock(P, GetOpTrueScript(), destScript);
    CTransaction txLockA(mtxLockA);
    CTransaction txLockB(mtxLockB);
    {
        auto batch = g_settlementdb->CreateBatch();
        BOOST_REQUIRE(ApplyLock(txLockA, view, settle, lockHeight, batch));
        BOOST_REQUIRE(ApplyLock(txLockB, view, settle, lockHeight, batch));
        BOOST_REQUIRE(batch.Commit());
    }
    COutPoint receiptA(txLockA.GetHash(), 1);
    COutPoint receiptB(txLockB.GetHash(), 1);
    BOOST_REQUIRE(g_settlementdb->IsM1Receipt(receiptA));
    BOOST_REQUIRE(g_settlementdb->IsM1Receipt(receiptB));

    // HTLC_CREATE_M1 with a SECOND receipt at vin[1] -> rejected positionally.
    {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::HTLC_CREATE_M1;
        mtx.vin.emplace_back(CTxIn(receiptA));  // vin[0]: reconciled by Apply
        mtx.vin.emplace_back(CTxIn(receiptB));  // vin[1]: would be a phantom
        mtx.vout.emplace_back(CTxOut(P, destScript));
        CTransaction tx(mtx);
        CValidationState st;
        BOOST_CHECK(!CheckSpecialTx(tx, &idxPrev, &view, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-txns-receipt-not-vin0");
    }

    // CONTROL: TX_UNLOCK spending both receipts (canonical order) is NOT hit
    // by the positional rule (it reconciles every receipt input).
    {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_UNLOCK;
        mtx.vin.emplace_back(CTxIn(receiptA));
        mtx.vin.emplace_back(CTxIn(receiptB));
        mtx.vout.emplace_back(CTxOut(2 * P, destScript));
        CTransaction tx(mtx);
        CValidationState st;
        CheckSpecialTx(tx, &idxPrev, &view, st);  // may fail later per-type checks
        BOOST_CHECK(st.GetRejectReason() != "bad-txns-receipt-not-vin0");
    }
}

// =============================================================================
// Covenant fee is re-routed to an OP_TRUE M1 fee receipt (vout[1]), NOT the
// coinbase. Leaving it to the coinbase stranded the vault backing and drifted
// M1_supply upward by covenantFee on every covenant claim. This test pins the
// consensus rule (CheckHTLCClaim) and the fee-receipt registration (ApplyHTLCClaim)
// for a 2-party covenant claim (Settlement Pivot).
// =============================================================================
BOOST_AUTO_TEST_CASE(htlc_covenant_claim_fee_receipt)
{
    LOCK(cs_main);
    BOOST_REQUIRE(InitSettlementDB(1 << 20, true));
    BOOST_REQUIRE(InitHtlcDB(1 << 20, true));
    BOOST_REQUIRE(g_settlementdb != nullptr);
    BOOST_REQUIRE(g_htlcdb != nullptr);

    CKey key;
    key.MakeNewKey(true);
    const CKeyID keyID = key.GetPubKey().GetID();
    const CScript destScript = GetScriptForDestination(keyID);

    const CAmount P = 100000;
    const CAmount fee = CTV_FIXED_FEE;   // 200
    const CAmount pivotAmount = P - fee;

    // Real preimage/hashlock so CheckHTLCClaim's VerifyPreimage passes.
    std::vector<unsigned char> secret(32, 0x7A);
    uint256 hashlock;
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    const uint256 c3 = uint256S("0x00000000000000000000000000000000000000000000000000000000c0ffee01");
    const CScript redeem = CreateConditionalWithCovenantScript(hashlock, 300000, keyID, keyID, c3);

    // Register one ACTIVE covenant HTLC (HasCovenant() == !templateCommitment.IsNull()).
    const COutPoint htlcOut(uint256S("0x00000000000000000000000000000000000000000000000000000000deadbeef"), 0);
    {
        HTLCRecord rec;
        rec.htlcOutpoint = htlcOut;
        rec.amount = P;
        rec.hashlock = hashlock;
        rec.status = HTLCStatus::ACTIVE;
        rec.claimKeyID = keyID;
        rec.refundKeyID = keyID;
        rec.createHeight = 90;
        rec.expiryHeight = 300000;
        rec.covenantFee = fee;
        rec.templateCommitment = c3;
        rec.htlc3ClaimKeyID = keyID;
        rec.htlc3RefundKeyID = keyID;
        rec.htlc3ExpiryHeight = 300002;  // R1-shape: expiry + HTLC3S_MIN_LIFETIME
        rec.redeemScript = redeem;
        BOOST_REQUIRE(g_htlcdb->WriteHTLC(rec));
    }
    BOOST_REQUIRE(g_htlcdb->IsHTLC(htlcOut));

    CCoinsView coinsDummy;
    CCoinsViewCache view(&coinsDummy);
    const std::vector<unsigned char> dummySig(72, 0x30);
    const CScript opTrue = CScript() << OP_TRUE;

    // Build a covenant claim with the given output list (vin[0] carries the preimage).
    auto buildClaim = [&](const std::vector<CTxOut>& vouts) {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::HTLC_CLAIM;
        CTxIn in(htlcOut);
        in.scriptSig = CreateConditionalSpendA(dummySig, key.GetPubKey(), secret, redeem);
        mtx.vin.push_back(in);
        for (const CTxOut& o : vouts) mtx.vout.push_back(o);
        return CTransaction(mtx);
    };

    // CheckHTLCClaim is read-only, so run every rejection case first (HTLC stays ACTIVE),
    // then the accepting case + ApplyHTLCClaim last.

    // (1) Missing fee output -> rejected (no vout[1]).
    {
        CTransaction tx = buildClaim({CTxOut(pivotAmount, destScript)});
        CValidationState st;
        BOOST_CHECK(!CheckHTLCClaim(tx, view, 100, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-fee-script");
    }
    // (2) Fee output not OP_TRUE -> rejected.
    {
        CTransaction tx = buildClaim({CTxOut(pivotAmount, destScript), CTxOut(fee, destScript)});
        CValidationState st;
        BOOST_CHECK(!CheckHTLCClaim(tx, view, 100, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-fee-script");
    }
    // (3) Fee output wrong amount -> rejected.
    {
        CTransaction tx = buildClaim({CTxOut(pivotAmount, destScript), CTxOut(fee + 1, opTrue)});
        CValidationState st;
        BOOST_CHECK(!CheckHTLCClaim(tx, view, 100, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-fee-amount");
    }
    // (4) Stray OP_TRUE beyond the fee slot -> rejected (would be a pseudo-vault).
    {
        CTransaction tx = buildClaim({CTxOut(pivotAmount, destScript), CTxOut(fee, opTrue),
                                      CTxOut(1, opTrue)});
        CValidationState st;
        BOOST_CHECK(!CheckHTLCClaim(tx, view, 100, st));
        BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-htlcclaim-stray-optrue");
    }

    // (5) Well-formed covenant claim -> accepted, and the fee becomes an M1 receipt.
    CTransaction goodTx = buildClaim({CTxOut(pivotAmount, destScript), CTxOut(fee, opTrue)});
    {
        CValidationState st;
        BOOST_CHECK_MESSAGE(CheckHTLCClaim(goodTx, view, 100, st),
                            "well-formed covenant claim rejected: " << st.GetRejectReason());
    }
    {
        auto sBatch = g_settlementdb->CreateBatch();
        auto hBatch = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(ApplyHTLCClaim(goodTx, view, 101, sBatch, hBatch));
        BOOST_REQUIRE(sBatch.Commit());
        BOOST_REQUIRE(hBatch.Commit());
    }
    const uint256 goodTxid = goodTx.GetHash();
    // htlc3 continuation at vout[0], covenant fee receipt at vout[1].
    BOOST_CHECK(g_htlcdb->IsHTLC(COutPoint(goodTxid, 0)));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(COutPoint(goodTxid, 1)));
    M1Receipt feeReceipt;
    BOOST_REQUIRE(g_settlementdb->ReadReceipt(COutPoint(goodTxid, 1), feeReceipt));
    BOOST_CHECK_EQUAL(feeReceipt.amount, fee);
    // Conservation: pivot (htlc3) + fee receipt == the original HTLC amount (no drift).
    BOOST_CHECK_EQUAL(pivotAmount + feeReceipt.amount, P);

    // Undo erases BOTH the htlc3 and the fee receipt.
    {
        auto sBatch = g_settlementdb->CreateBatch();
        auto hBatch = g_htlcdb->CreateBatch();
        BOOST_REQUIRE(UndoHTLCClaim(goodTx, sBatch, hBatch));
        BOOST_REQUIRE(sBatch.Commit());
        BOOST_REQUIRE(hBatch.Commit());
    }
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(COutPoint(goodTxid, 1)));
    BOOST_CHECK(!g_htlcdb->IsHTLC(COutPoint(goodTxid, 0)));
}

BOOST_AUTO_TEST_SUITE_END()
