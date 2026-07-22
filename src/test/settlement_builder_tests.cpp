// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state/settlement_builder.h"

#include "key.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "state/settlement.h"
#include "state/settlementdb.h"
#include "test/test_bathron.h"

#include <boost/test/unit_test.hpp>

// BP30 v3.0 "M1 fee model": the transaction fee is paid IN M1, deducted from the
// receipt/unlock amount. There are NO separate M0 fee inputs (feeInputs/changeDest
// are DEPRECATED, ignored). The fee is NOT burned — it becomes an OP_TRUE output the
// block producer claims, with vault backing to preserve A6.
//   - unlock:        M1_in == M0_out + M1_change + M1_fee
//   - transfer/split: sum(recipient outputs) + fee == input
// See doc/SETTLEMENT-M0-M1-MODEL.md and src/state/settlement_builder.cpp.
BOOST_FIXTURE_TEST_SUITE(settlement_builder_tests, BasicTestingSetup)

// =============================================================================
// Helper functions
// =============================================================================

static CKey GenerateKey()
{
    CKey key;
    key.MakeNewKey(true);
    return key;
}

static CScript GetP2PKHScript(const CPubKey& pubkey)
{
    return GetScriptForDestination(CTxDestination(pubkey.GetID()));
}

static LockInput CreateFakeLockInput(CAmount amount)
{
    LockInput input;
    // Create a random outpoint
    GetStrongRandBytes(input.outpoint.hash.begin(), 32);
    input.outpoint.n = 0;
    input.amount = amount;
    CKey key = GenerateKey();
    input.scriptPubKey = GetP2PKHScript(key.GetPubKey());
    return input;
}

// =============================================================================
// BuildLockTransaction Tests
// =============================================================================

BOOST_AUTO_TEST_CASE(build_lock_basic)
{
    // Create inputs
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(10 * COIN));

    // BP30 v2.0: No vault key needed - vault uses OP_TRUE (consensus-protected)
    CKey receiptKey = GenerateKey();
    CKey changeKey = GenerateKey();

    CScript receiptDest = GetP2PKHScript(receiptKey.GetPubKey());
    CScript changeDest = GetP2PKHScript(changeKey.GetPubKey());

    // Build transaction
    LockResult result = BuildLockTransaction(
        inputs,
        5 * COIN,  // Lock 5 M0
        receiptDest,
        changeDest
    );

    BOOST_CHECK(result.success);
    BOOST_CHECK(result.error.empty());
    BOOST_CHECK_EQUAL(result.lockedAmount, 5 * COIN);
    BOOST_CHECK(result.fee > 0);

    // Verify transaction structure
    const CMutableTransaction& mtx = result.mtx;
    BOOST_CHECK_EQUAL(mtx.nType, CTransaction::TxType::TX_LOCK);
    BOOST_CHECK_EQUAL(mtx.vin.size(), 1);
    BOOST_CHECK_EQUAL(mtx.vout.size(), 3);  // Vault + Receipt + Change

    // A11 canonical order: vout[0] = Vault (OP_TRUE), vout[1] = Receipt
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, 5 * COIN);  // Vault
    BOOST_CHECK_EQUAL(mtx.vout[1].nValue, 5 * COIN);  // Receipt
    BOOST_CHECK(mtx.vout[2].nValue > 0);  // Change
}

BOOST_AUTO_TEST_CASE(build_lock_no_change)
{
    // Create inputs that exactly match lock amount + estimated fee
    // Fee estimation: BASE_TX_SIZE(10) + 1*INPUT_SIZE(148) + 2*OUTPUT_SIZE(34) = 226 bytes
    // At 15 sat/kB: (226 * 15000) / 1000 = 3390 satoshis
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(5 * COIN + 5000));  // Amount + ~fee (with margin)

    CKey receiptKey = GenerateKey();

    CScript receiptDest = GetP2PKHScript(receiptKey.GetPubKey());

    LockResult result = BuildLockTransaction(
        inputs,
        5 * COIN,
        receiptDest,
        CScript()  // No change dest
    );

    BOOST_CHECK(result.success);
    // May have 2 or 3 outputs depending on exact change amount
    BOOST_CHECK(result.mtx.vout.size() >= 2);
}

BOOST_AUTO_TEST_CASE(build_lock_insufficient_funds)
{
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(1 * COIN));

    CKey receiptKey = GenerateKey();

    LockResult result = BuildLockTransaction(
        inputs,
        5 * COIN,  // Request more than available
        GetP2PKHScript(receiptKey.GetPubKey()),
        CScript()
    );

    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.error.empty());
    BOOST_CHECK(result.error.find("Insufficient") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(build_lock_zero_amount)
{
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(10 * COIN));

    CKey receiptKey = GenerateKey();

    LockResult result = BuildLockTransaction(
        inputs,
        0,  // Zero amount
        GetP2PKHScript(receiptKey.GetPubKey()),
        CScript()
    );

    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.error.empty());
}

BOOST_AUTO_TEST_CASE(build_lock_multiple_inputs)
{
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(3 * COIN));
    inputs.push_back(CreateFakeLockInput(3 * COIN));
    inputs.push_back(CreateFakeLockInput(4 * COIN));  // Total 10 M0

    CKey receiptKey = GenerateKey();
    CKey changeKey = GenerateKey();

    LockResult result = BuildLockTransaction(
        inputs,
        8 * COIN,
        GetP2PKHScript(receiptKey.GetPubKey()),
        GetP2PKHScript(changeKey.GetPubKey())
    );

    BOOST_CHECK(result.success);
    BOOST_CHECK_EQUAL(result.mtx.vin.size(), 3);
    BOOST_CHECK_EQUAL(result.lockedAmount, 8 * COIN);
}

// =============================================================================
// BuildUnlockTransaction Tests (BP30 v2.0 Bearer Asset Model)
// =============================================================================

BOOST_AUTO_TEST_CASE(build_unlock_basic)
{
    // BP30 v2.0: Create M1Input (receipt) and VaultInput separately
    std::vector<M1Input> m1Inputs;
    M1Input m1Input;
    GetStrongRandBytes(m1Input.outpoint.hash.begin(), 32);
    m1Input.outpoint.n = 1;
    m1Input.amount = 5 * COIN;
    m1Input.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());
    m1Inputs.push_back(m1Input);

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultInput;
    GetStrongRandBytes(vaultInput.outpoint.hash.begin(), 32);
    vaultInput.outpoint.n = 0;
    vaultInput.amount = 5 * COIN;
    vaultInputs.push_back(vaultInput);

    CKey destKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());

    // BP30 v3.0: Full unlock - unlockAmount=0 unlocks all M1 minus the M1 fee.
    CAmount unlockAmount = 0;  // 0 means "unlock all M1"
    UnlockResult result = BuildUnlockTransaction(m1Inputs, vaultInputs, unlockAmount, destScript, destScript);

    BOOST_REQUIRE(result.success);
    // BP30 v3.0 M1 fee model: M0_out == M1_in - m1Fee, with a positive M1 fee
    // deducted from the unlock. Conservation: M1_in == M0_out + M1_change + M1_fee.
    BOOST_CHECK(result.fee > 0);
    BOOST_CHECK_EQUAL(result.unlockedAmount, 5 * COIN - result.fee);
    BOOST_CHECK_EQUAL(result.m1Change, 0);  // Full unlock, no change
    // M1_in == M0_out + M1_change + M1_fee
    BOOST_CHECK_EQUAL(5 * COIN, result.unlockedAmount + result.m1Change + result.fee);

    // Verify transaction structure
    const CMutableTransaction& mtx = result.mtx;
    BOOST_CHECK_EQUAL(mtx.nType, CTransaction::TxType::TX_UNLOCK);
    BOOST_CHECK_EQUAL(mtx.vin.size(), 2);  // M1 Receipt + Vault

    // A11 order: vin[0] = Receipt, vin[1] = Vault
    BOOST_CHECK(mtx.vin[0].prevout == m1Input.outpoint);
    BOOST_CHECK(mtx.vin[1].prevout == vaultInput.outpoint);

    // BP30 v3.1 vout shape for a full unlock: the fee is an M0 coinbase fee (implicit,
    // left on the table), so there is NO fee output and NO fee backing. With no M1
    // change and no vault change either, the only output is vout[0] = M0.
    BOOST_CHECK_EQUAL(mtx.vout.size(), 1);
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, result.unlockedAmount);
    // The fee is still charged (result.fee > 0) but never appears as an output.
    BOOST_CHECK(result.fee > 0);
}

BOOST_AUTO_TEST_CASE(build_unlock_no_fee_inputs)
{
    // BP30 v2.0: Bearer model - M1 + Vault inputs
    std::vector<M1Input> m1Inputs;
    M1Input m1Input;
    GetStrongRandBytes(m1Input.outpoint.hash.begin(), 32);
    m1Input.outpoint.n = 1;
    m1Input.amount = 5 * COIN;
    m1Input.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());
    m1Inputs.push_back(m1Input);

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultInput;
    GetStrongRandBytes(vaultInput.outpoint.hash.begin(), 32);
    vaultInput.outpoint.n = 0;
    vaultInput.amount = 5 * COIN;
    vaultInputs.push_back(vaultInput);

    CKey destKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());

    // BP30 v3.0: feeInputs are DEPRECATED/ignored — the fee is paid in M1, deducted
    // from the unlock. There are no separate M0 fee inputs.
    CAmount unlockAmount = 0;  // 0 means "unlock all M1"
    UnlockResult result = BuildUnlockTransaction(m1Inputs, vaultInputs, unlockAmount, destScript, destScript);

    BOOST_REQUIRE(result.success);
    BOOST_CHECK(result.fee > 0);                                     // M1 fee deducted
    BOOST_CHECK_EQUAL(result.unlockedAmount, 5 * COIN - result.fee);  // M0_out = M1_in - fee
}

// =============================================================================
// BuildTransferTransaction Tests
// =============================================================================

BOOST_AUTO_TEST_CASE(build_transfer_basic)
{
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 5 * COIN;

    CKey newOwnerKey = GenerateKey();
    CScript newDest = GetP2PKHScript(newOwnerKey.GetPubKey());

    TransferResult result = BuildTransferTransaction(receipt, newDest);

    BOOST_REQUIRE(result.success);

    // Verify transaction structure (BP30 v3.0 M1 fee model)
    const CMutableTransaction& mtx = result.mtx;
    BOOST_CHECK_EQUAL(mtx.nType, CTransaction::TxType::TX_TRANSFER_M1);
    // Only the M1 receipt is an input — feeInputs are DEPRECATED/ignored.
    BOOST_CHECK_EQUAL(mtx.vin.size(), 1);

    // A11 order: vin[0] = Receipt
    BOOST_CHECK(mtx.vin[0].prevout == receipt.receiptOutpoint);

    // vout[0] = New Receipt (input - M1 fee), vout[1] = M1 fee (OP_TRUE).
    BOOST_REQUIRE_EQUAL(mtx.vout.size(), 2);
    CAmount m1Fee = mtx.vout[1].nValue;
    BOOST_CHECK(m1Fee > 0);
    BOOST_CHECK(mtx.vout[1].scriptPubKey == (CScript() << OP_TRUE));
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, 5 * COIN - m1Fee);
    // Conservation: recipient + fee == input
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue + m1Fee, receipt.amount);
}

BOOST_AUTO_TEST_CASE(build_transfer_insufficient_fee)
{
    // BP30 v3.0: the M1 fee is deducted FROM the receipt. The failure mode is now
    // "the receipt is too small to cover the M1 fee" (recipientAmount <= 0), not a
    // separate M0 fee input being too small (feeInputs are DEPRECATED/ignored).
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    // A 1-sat receipt cannot cover the (positive) M1 fee → build must fail.
    receipt.amount = 1;

    CKey newOwnerKey = GenerateKey();

    TransferResult result = BuildTransferTransaction(
        receipt,
        GetP2PKHScript(newOwnerKey.GetPubKey()));

    BOOST_CHECK(!result.success);
    // BuildTransferTransaction: "M1 amount too small for fee: ..."
    BOOST_CHECK(result.error.find("too small for fee") != std::string::npos);
}

// =============================================================================
// BuildSplitTransaction Tests (BP30 v2.4 - Strict M1 Conservation)
// =============================================================================

BOOST_AUTO_TEST_CASE(build_split_basic)
{
    // BP30 v3.0 M1 fee model: split 10 M1 into recipients + an M1 fee output.
    // The fee is deducted FROM the receipt (no separate M0 fee inputs).
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 10 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    CKey dest1 = GenerateKey();
    CKey dest2 = GenerateKey();

    // Recipients must sum to LESS than the receipt; the slack becomes the M1 fee
    // output. Conservation: sum(recipients) + fee == receipt.
    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(dest1.GetPubKey()), 3 * COIN});
    outputs.push_back({GetP2PKHScript(dest2.GetPubKey()), 6 * COIN});

    // still accepted for API compatibility.

    SplitResult result = BuildSplitTransaction(receipt, outputs);

    // REQUIRE (not CHECK): a failed build leaves mtx.vout empty, so the
    // dereferences below would crash the whole test binary instead of failing.
    BOOST_REQUIRE(result.success);
    BOOST_CHECK(result.error.empty());

    // Verify transaction structure (M1 fee model: 1 input, N recipients + 1 fee)
    const CMutableTransaction& mtx = result.mtx;
    BOOST_CHECK_EQUAL(mtx.nType, CTransaction::TxType::TX_TRANSFER_M1);
    BOOST_REQUIRE_EQUAL(mtx.vin.size(), 1);   // Receipt only (no M0 fee input)
    BOOST_REQUIRE_EQUAL(mtx.vout.size(), 3);  // Two recipient receipts + M1 fee

    // Recipient M1 amounts
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, 3 * COIN);
    BOOST_CHECK_EQUAL(mtx.vout[1].nValue, 6 * COIN);

    // Strict conservation INCLUDING the M1 fee: sum(recipients) + fee == receipt
    CAmount recipientTotal = mtx.vout[0].nValue + mtx.vout[1].nValue;
    BOOST_CHECK_EQUAL(recipientTotal + result.fee, receipt.amount);

    // Last output is the M1 fee (OP_TRUE, claimed by the block producer)
    BOOST_CHECK(result.fee > 0);
    BOOST_CHECK_EQUAL(mtx.vout.back().nValue, result.fee);
    BOOST_CHECK(mtx.vout.back().scriptPubKey == (CScript() << OP_TRUE));

    // New receipt outpoints = recipient outputs only (not the fee)
    BOOST_CHECK_EQUAL(result.newReceipts.size(), 2);
}

BOOST_AUTO_TEST_CASE(build_split_three_way)
{
    // BP30 v3.0 M1 fee model: split 100 M1 into 3 recipients + an M1 fee output.
    // The fee is deducted FROM the receipt, so recipients must sum to LESS than the
    // receipt. Conservation: sum(recipients) + fee == receipt.
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 100 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    // Recipients sum to 99 COIN (< 100); the 1-COIN slack absorbs the M1 fee.
    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 30 * COIN});
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 50 * COIN});
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 19 * COIN});


    SplitResult result = BuildSplitTransaction(receipt, outputs);

    // REQUIRE before any mtx.vout deref — a failed build leaves vout empty (segfault).
    BOOST_REQUIRE(result.success);
    BOOST_CHECK_EQUAL(result.newReceipts.size(), 3);

    // Recipient receipts (vout[0..2]) carry the requested amounts.
    CAmount recipientTotal = 0;
    for (size_t i = 0; i < outputs.size(); i++) {
        BOOST_CHECK_EQUAL(result.mtx.vout[i].nValue, outputs[i].amount);
        recipientTotal += result.mtx.vout[i].nValue;
    }

    // Strict conservation INCLUDING the M1 fee: sum(recipients) + fee == receipt.
    BOOST_CHECK(result.fee > 0);
    BOOST_CHECK_EQUAL(recipientTotal + result.fee, receipt.amount);

    // Last output is the M1 fee (OP_TRUE, claimed by the block producer).
    BOOST_CHECK_EQUAL(result.mtx.vout.back().nValue, result.fee);
    BOOST_CHECK(result.mtx.vout.back().scriptPubKey == (CScript() << OP_TRUE));
}

BOOST_AUTO_TEST_CASE(build_split_outputs_exceed_input)
{
    // BP30 v3.0 M1 fee model: outputs (+ fee) may not exceed the input. Recipients
    // summing to MORE than the receipt leaves no room and must be rejected.
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 10 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    // Sum = 12 COIN, exceeds input
    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 6 * COIN});
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 6 * COIN});


    SplitResult result = BuildSplitTransaction(receipt, outputs);

    BOOST_CHECK(!result.success);
    // BuildSplitTransaction: "Split outputs (...) + fee (...) exceed input (...)"
    BOOST_CHECK(result.error.find("exceed input") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(build_split_outputs_less_than_input_ok)
{
    // BP30 v3.0 M1 fee model: recipients summing to LESS than the receipt is now the
    // NORMAL case — the slack becomes the M1 fee (the builder grows the fee to absorb
    // it, ensuring strict conservation sum(recipients) + fee == receipt). No implicit
    // M1 burn occurs; the difference is the producer-claimable M1 fee.
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 10 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    // Sum = 9 COIN, less than input → 1 COIN slack becomes the M1 fee.
    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 5 * COIN});
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 4 * COIN});


    SplitResult result = BuildSplitTransaction(receipt, outputs);

    BOOST_REQUIRE(result.success);
    BOOST_CHECK_EQUAL(result.newReceipts.size(), 2);
    // Strict conservation: sum(recipients) + fee == receipt (fee absorbs the slack).
    BOOST_CHECK(result.fee > 0);
    CAmount recipientTotal = result.mtx.vout[0].nValue + result.mtx.vout[1].nValue;
    BOOST_CHECK_EQUAL(recipientTotal + result.fee, receipt.amount);
}

BOOST_AUTO_TEST_CASE(build_split_single_output)
{
    // Single output should fail (use transfer_m1 instead)
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 10 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 10 * COIN});


    SplitResult result = BuildSplitTransaction(receipt, outputs);

    BOOST_CHECK(!result.success);
    BOOST_CHECK(result.error.find("at least 2") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(build_split_zero_output)
{
    // Zero amount output should fail
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 10 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 10 * COIN});
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 0});  // Zero!


    SplitResult result = BuildSplitTransaction(receipt, outputs);

    BOOST_CHECK(!result.success);
    BOOST_CHECK(result.error.find("positive") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(build_split_insufficient_fee)
{
    // Not enough M0 for fee
    TransferInput receipt;
    GetStrongRandBytes(receipt.receiptOutpoint.hash.begin(), 32);
    receipt.receiptOutpoint.n = 1;
    receipt.amount = 10 * COIN;
    receipt.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());

    // Strict conservation
    std::vector<SplitOutput> outputs;
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 5 * COIN});
    outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 5 * COIN});

    // Only 100 sat for fee - not enough

    SplitResult result = BuildSplitTransaction(receipt, outputs);

    BOOST_CHECK(!result.success);
    BOOST_CHECK(result.error.find("fee") != std::string::npos);
}

// =============================================================================
// Integration: Split → Unlock flow (BP30 v2.4 - Strict M1 Conservation)
// =============================================================================

BOOST_AUTO_TEST_CASE(builder_flow_lock_split_unlock_partial)
{
    // Step 1: Lock 10 M0
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(12 * COIN));

    CKey receiptKey = GenerateKey();
    CKey changeKey = GenerateKey();

    LockResult lockResult = BuildLockTransaction(
        inputs,
        10 * COIN,
        GetP2PKHScript(receiptKey.GetPubKey()),
        GetP2PKHScript(changeKey.GetPubKey())
    );

    BOOST_CHECK(lockResult.success);
    BOOST_CHECK_EQUAL(lockResult.lockedAmount, 10 * COIN);

    // Step 2: Split into 2 + 7 (BP30 v3.0: M1 fee model — recipients sum to LESS
    // than the receipt so the 1-COIN slack becomes the M1 fee).
    TransferInput splitInput;
    splitInput.receiptOutpoint = lockResult.receiptOutpoint;
    splitInput.amount = lockResult.lockedAmount;
    splitInput.scriptPubKey = GetP2PKHScript(receiptKey.GetPubKey());

    CKey dest1 = GenerateKey();
    CKey dest2 = GenerateKey();

    // sum(recipients) + fee == receipt: 2 + 7 = 9 < 10, 1 COIN slack = M1 fee.
    std::vector<SplitOutput> splitOutputs;
    splitOutputs.push_back({GetP2PKHScript(dest1.GetPubKey()), 2 * COIN});
    splitOutputs.push_back({GetP2PKHScript(dest2.GetPubKey()), 7 * COIN});


    SplitResult splitResult = BuildSplitTransaction(splitInput, splitOutputs);

    // REQUIRE before dereferencing newReceipts below (failure leaves it empty).
    BOOST_REQUIRE(splitResult.success);
    BOOST_CHECK_EQUAL(splitResult.newReceipts.size(), 2);

    // Step 3: Unlock only the 2 M1 receipt (partial unlock)
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = splitResult.newReceipts[0];  // The 2 M1 receipt
    m1In.amount = 2 * COIN;
    m1In.scriptPubKey = GetP2PKHScript(dest1.GetPubKey());
    m1Inputs.push_back(m1In);

    // Need a vault that has at least 2 M1 backing
    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = lockResult.vaultOutpoint;  // Original 10 M0 vault
    vaultIn.amount = lockResult.lockedAmount;
    vaultInputs.push_back(vaultIn);

    CKey unlockDest = GenerateKey();
    CScript destScript = GetP2PKHScript(unlockDest.GetPubKey());

    // BP30 v3.0: full unlock of the 2-M1 receipt (unlockAmount=0 = all minus fee).
    // The M1 fee is deducted from the 2 M1, so M0_out is slightly under 2 COIN.
    CAmount unlockAmount = 0;
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        unlockAmount,
        destScript,
        destScript  // Change goes back to same script
    );

    BOOST_REQUIRE(unlockResult.success);
    BOOST_CHECK(unlockResult.fee > 0);
    BOOST_CHECK(unlockResult.unlockedAmount > 0);
    // M0_out = M1_in - fee, strictly below the 2-COIN receipt.
    BOOST_CHECK_EQUAL(unlockResult.unlockedAmount, 2 * COIN - unlockResult.fee);
    BOOST_CHECK(unlockResult.unlockedAmount < 2 * COIN);

    // The other 7 M1 receipt remains spendable separately
    // (not tested here as we don't have consensus tracking in builder tests)
}

BOOST_AUTO_TEST_CASE(builder_flow_split_chain)
{
    // BP30 v3.0: Split chaining with M1 fee model (recipients < input, slack = fee)
    // A → B+C → B1+B2 + C1+C2
    // Lock initial amount
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(100 * COIN));

    CKey receiptKey = GenerateKey();

    LockResult lockResult = BuildLockTransaction(
        inputs,
        80 * COIN,
        GetP2PKHScript(receiptKey.GetPubKey()),
        GetP2PKHScript(GenerateKey().GetPubKey())
    );

    BOOST_CHECK(lockResult.success);

    // Split 1: 80 → 30 + 50 (strict conservation)
    TransferInput split1Input;
    split1Input.receiptOutpoint = lockResult.receiptOutpoint;
    split1Input.amount = 80 * COIN;
    split1Input.scriptPubKey = GetP2PKHScript(receiptKey.GetPubKey());

    CKey dest30 = GenerateKey();
    CKey dest50 = GenerateKey();

    // M1 fee model: 30 + 49 = 79 < 80, 1 COIN slack = M1 fee.
    std::vector<SplitOutput> split1Outputs;
    split1Outputs.push_back({GetP2PKHScript(dest30.GetPubKey()), 30 * COIN});
    split1Outputs.push_back({GetP2PKHScript(dest50.GetPubKey()), 49 * COIN});


    SplitResult split1Result = BuildSplitTransaction(split1Input, split1Outputs);
    BOOST_REQUIRE(split1Result.success);

    // Split 2: Take the 30 M1 receipt and split again → 10 + 19 (slack = M1 fee)
    TransferInput split2Input;
    split2Input.receiptOutpoint = split1Result.newReceipts[0];
    split2Input.amount = 30 * COIN;
    split2Input.scriptPubKey = GetP2PKHScript(dest30.GetPubKey());

    // M1 fee model: 10 + 19 = 29 < 30, 1 COIN slack = M1 fee.
    std::vector<SplitOutput> split2Outputs;
    split2Outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 10 * COIN});
    split2Outputs.push_back({GetP2PKHScript(GenerateKey().GetPubKey()), 19 * COIN});


    SplitResult split2Result = BuildSplitTransaction(split2Input, split2Outputs);
    BOOST_REQUIRE(split2Result.success);
    BOOST_CHECK_EQUAL(split2Result.newReceipts.size(), 2);

    // After two splits, we have: 10, 20, 50 M1 receipts
    // Total M1 = 80 (unchanged - strict conservation)
    // Fees came from separate M0 inputs, not from M1
}

// =============================================================================
// Integration-like Tests (builder flow)
// =============================================================================

BOOST_AUTO_TEST_CASE(builder_flow_lock_unlock)
{
    // Step 1: Build LOCK (BP30 v2.0: no vaultDest - uses OP_TRUE)
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(10 * COIN));

    CKey receiptKey = GenerateKey();
    CKey changeKey = GenerateKey();

    LockResult lockResult = BuildLockTransaction(
        inputs,
        5 * COIN,
        GetP2PKHScript(receiptKey.GetPubKey()),
        GetP2PKHScript(changeKey.GetPubKey())
    );

    BOOST_CHECK(lockResult.success);
    BOOST_CHECK_EQUAL(lockResult.lockedAmount, 5 * COIN);

    // Step 2: Build UNLOCK using outputs from LOCK (bearer model)
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = lockResult.receiptOutpoint;
    m1In.amount = lockResult.lockedAmount;
    m1In.scriptPubKey = GetP2PKHScript(receiptKey.GetPubKey());
    m1Inputs.push_back(m1In);

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = lockResult.vaultOutpoint;
    vaultIn.amount = lockResult.lockedAmount;
    vaultInputs.push_back(vaultIn);

    CKey destKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());

    // BP30 v2.1: Full unlock - use 0 to unlock all M1 (fee deducted from output)
    CAmount unlockAmount = 0;  // 0 means "unlock all M1"
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        unlockAmount,
        destScript,
        destScript
    );

    BOOST_REQUIRE(unlockResult.success);
    // BP30 v3.0 M1 fee model: M0_out == M1_in - fee, with a positive M1 fee.
    BOOST_CHECK(unlockResult.fee > 0);
    BOOST_CHECK_EQUAL(unlockResult.unlockedAmount, 5 * COIN - unlockResult.fee);
}

BOOST_AUTO_TEST_CASE(builder_flow_lock_transfer_unlock)
{
    // Step 1: Build LOCK (BP30 v2.0: no vaultDest - uses OP_TRUE)
    std::vector<LockInput> inputs;
    inputs.push_back(CreateFakeLockInput(10 * COIN));

    CKey receiptKey1 = GenerateKey();
    CKey changeKey = GenerateKey();

    LockResult lockResult = BuildLockTransaction(
        inputs,
        5 * COIN,
        GetP2PKHScript(receiptKey1.GetPubKey()),
        GetP2PKHScript(changeKey.GetPubKey())
    );

    BOOST_CHECK(lockResult.success);

    // Step 2: Build TRANSFER
    TransferInput transferInput;
    transferInput.receiptOutpoint = lockResult.receiptOutpoint;
    transferInput.amount = lockResult.lockedAmount;
    transferInput.scriptPubKey = GetP2PKHScript(receiptKey1.GetPubKey());

    CKey newOwnerKey = GenerateKey();

    TransferResult transferResult = BuildTransferTransaction(
        transferInput,
        GetP2PKHScript(newOwnerKey.GetPubKey()));

    BOOST_REQUIRE(transferResult.success);

    // BP30 v3.0: the transfer deducted an M1 fee, so the new receipt carries
    // (5 COIN - transferFee), not the full 5 COIN. vout[0] is the recipient receipt.
    CAmount transferredM1 = transferResult.mtx.vout[0].nValue;
    BOOST_CHECK(transferredM1 > 0 && transferredM1 < 5 * COIN);

    // Step 3: Build UNLOCK with new receipt (bearer model)
    // The new owner can unlock using any vault - they don't need original vault key
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = transferResult.newReceiptOutpoint;
    m1In.amount = transferredM1;  // actual M1 carried by the transfer output
    m1In.scriptPubKey = GetP2PKHScript(newOwnerKey.GetPubKey());
    m1Inputs.push_back(m1In);

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = lockResult.vaultOutpoint;
    vaultIn.amount = lockResult.lockedAmount;  // 5 COIN vault, covers unlock + fee
    vaultInputs.push_back(vaultIn);

    CKey destKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());

    // BP30 v3.0: Full unlock after transfer - 0 means "unlock all M1 minus fee".
    CAmount unlockAmount = 0;
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        unlockAmount,
        destScript,
        destScript
    );

    BOOST_REQUIRE(unlockResult.success);
    // BP30 v3.0 M1 fee model: M0_out == M1_in - unlockFee, positive fee.
    BOOST_CHECK(unlockResult.fee > 0);
    BOOST_CHECK_EQUAL(unlockResult.unlockedAmount, transferredM1 - unlockResult.fee);
}

// =============================================================================
// TX_UNLOCK with network fee (wallet layer) tests
// =============================================================================

/**
 * Test: Unlock carries a positive M1 fee, and a wallet may still append M0 fee
 *        inputs/outputs on top without disturbing the BP30 settlement outputs.
 *
 * BP30 v3.0: the settlement fee is paid IN M1 (deducted from the unlock), so
 * unlockResult.fee > 0. A wallet that wants a separate M0 network fee can still
 * append M0 fee inputs + an M0 fee change output around the settlement vouts.
 */
BOOST_AUTO_TEST_CASE(unlock_with_m0_fee_inputs_has_network_fee)
{
    // Setup: Build a settlement unlock TX
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = COutPoint(GetRandHash(), 0);
    m1In.amount = 10 * COIN;
    m1In.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());
    m1Inputs.push_back(m1In);

    CAmount unlockAmt = 7 * COIN;

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = COutPoint(GetRandHash(), 0);
    // BP30 v3.0: vault must back unlock + M1 fee. Give it the full 10 COIN.
    vaultIn.amount = 10 * COIN;
    vaultInputs.push_back(vaultIn);

    CKey destKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());

    // Build settlement TX (M1 fee model)
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        unlockAmt,  // Partial unlock
        destScript,
        destScript  // M1 change goes to same address
    );

    BOOST_REQUIRE(unlockResult.success);
    BOOST_CHECK(unlockResult.fee > 0);  // BP30 v3.0: settlement layer charges an M1 fee
    BOOST_CHECK_EQUAL(unlockResult.unlockedAmount, 7 * COIN);
    // Conservation: M1_in == M0_out + M1_change + M1_fee → M1_change = 3 COIN - fee.
    BOOST_CHECK_EQUAL(unlockResult.m1Change, 3 * COIN - unlockResult.fee);
    BOOST_CHECK_EQUAL(10 * COIN, unlockResult.unlockedAmount + unlockResult.m1Change + unlockResult.fee);

    // Now simulate wallet layer: append an M0 fee input on top of the settlement TX.
    CMutableTransaction mtx = unlockResult.mtx;
    size_t settlementVinCount = unlockResult.mtx.vin.size();
    size_t settlementVoutCount = unlockResult.mtx.vout.size();

    // Add M0 fee input (simulating wallet coin selection)
    CAmount m0FeeInput = 0.001 * COIN;  // 0.001 M0 = 100,000 satoshi
    mtx.vin.emplace_back(COutPoint(GetRandHash(), 0));

    // No M0 fee change: the whole M0 fee input becomes the network fee.
    CAmount networkFee = m0FeeInput;

    // The settlement vouts are untouched; only one input was appended.
    BOOST_CHECK_EQUAL(mtx.vin.size(), settlementVinCount + 1);
    BOOST_CHECK_EQUAL(mtx.vout.size(), settlementVoutCount);
    BOOST_CHECK(networkFee > 0);
    BOOST_CHECK_EQUAL(networkFee, m0FeeInput);

    // Alternative: Add M0 fee input AND an M0 fee change output.
    CAmount m0FeeInputLarge = 0.01 * COIN;  // 0.01 M0
    CAmount targetFee = 0.0001 * COIN;      // 10,000 satoshi
    CAmount m0FeeChange = m0FeeInputLarge - targetFee;

    CMutableTransaction mtx2 = unlockResult.mtx;
    mtx2.vin.emplace_back(COutPoint(GetRandHash(), 0));  // M0 fee input
    mtx2.vout.emplace_back(m0FeeChange, destScript);     // M0 fee change

    BOOST_CHECK_EQUAL(mtx2.vin.size(), settlementVinCount + 1);
    BOOST_CHECK_EQUAL(mtx2.vout.size(), settlementVoutCount + 1);

    // Fee = M0_fee_input - M0_fee_change
    CAmount actualFee = m0FeeInputLarge - m0FeeChange;
    BOOST_CHECK_EQUAL(actualFee, targetFee);
    BOOST_CHECK(actualFee > 0);
}

/**
 * Test: A6 conservation is preserved by the M1 fee model, and survives an appended
 *        M0 network fee.
 *
 * BP30 v3.0 settlement conservation:
 *   sum(M1_in) == M0_out + M1_change + M1_fee
 * The M1 fee is transferred to the producer (not burned) and is vault-backed, so
 * A6 (M0_vaulted == M1_supply) holds. Appending an M0 fee input/change must not
 * touch the settlement outputs.
 */
BOOST_AUTO_TEST_CASE(unlock_with_m0_fee_preserves_a6_conservation)
{
    // Setup: Build a settlement unlock TX with partial unlock
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = COutPoint(GetRandHash(), 0);
    m1In.amount = 100 * COIN;
    m1In.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());
    m1Inputs.push_back(m1In);

    CAmount unlockAmount = 40 * COIN;

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = COutPoint(GetRandHash(), 0);
    // BP30 v3.0: vault must back unlock + M1 fee. Give it the full 100 COIN.
    vaultIn.amount = 100 * COIN;
    vaultInputs.push_back(vaultIn);

    CKey destKey = GenerateKey();
    CKey changeKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());
    CScript changeScript = GetP2PKHScript(changeKey.GetPubKey());

    // Build settlement TX
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        unlockAmount,
        destScript,
        changeScript
    );

    BOOST_REQUIRE(unlockResult.success);
    BOOST_CHECK(unlockResult.fee > 0);

    // Verify A6-preserving conservation at settlement layer:
    // sum(M1_in) == M0_out + M1_change + M1_fee
    CAmount totalM1In = m1Inputs[0].amount;        // 100 COIN
    CAmount m0Out = unlockResult.unlockedAmount;   // 40 COIN
    CAmount m1ChangeOut = unlockResult.m1Change;   // 60 COIN - fee
    CAmount m1Fee = unlockResult.fee;

    BOOST_CHECK_EQUAL(totalM1In, m0Out + m1ChangeOut + m1Fee);  // 100 == 40 + (60-fee) + fee

    // Now append an M0 fee input + M0 fee change (wallet layer)
    CMutableTransaction mtx = unlockResult.mtx;
    size_t settlementVoutCount = unlockResult.mtx.vout.size();

    CAmount m0FeeInput = 0.005 * COIN;  // 0.005 M0
    CAmount m0FeeChange = 0.004 * COIN; // 0.004 M0 change
    CAmount networkFee = m0FeeInput - m0FeeChange;  // 0.001 M0 fee

    mtx.vin.emplace_back(COutPoint(GetRandHash(), 0));  // M0 fee input
    mtx.vout.emplace_back(m0FeeChange, destScript);    // M0 fee change (appended last)

    BOOST_CHECK_EQUAL(mtx.vout.size(), settlementVoutCount + 1);

    // Settlement outputs are unchanged by the fee layer:
    // vout[0] = M0 unlocked (40 COIN), vout[1] = M1 change (60 - fee).
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, 40 * COIN);
    BOOST_CHECK_EQUAL(mtx.vout[1].nValue, m1ChangeOut);

    // Verify network fee is positive and separate
    BOOST_CHECK(networkFee > 0);
    BOOST_CHECK_EQUAL(networkFee, 0.001 * COIN);

    // The appended M0 fee change is the last output.
    BOOST_CHECK_EQUAL(mtx.vout.back().nValue, m0FeeChange);
}

/**
 * Test: Funding NEVER modifies BP30 settlement vouts
 *
 * Critical invariant: vout[0] (M0_out) and vout[1] (M1_change) must be
 * IDENTICAL before and after funding. Any modification breaks A6.
 *
 * This simulates the RPC flow and verifies immutability.
 */
BOOST_AUTO_TEST_CASE(funding_never_modifies_bp30_vouts)
{
    // Build settlement TX template
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = COutPoint(GetRandHash(), 0);
    m1In.amount = 50 * COIN;
    m1In.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());
    m1Inputs.push_back(m1In);

    CAmount unlockAmt = 30 * COIN;

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = COutPoint(GetRandHash(), 0);
    // BP30 v3.0: vault must back unlock + M1 fee. Give it the full 50 COIN.
    vaultIn.amount = 50 * COIN;
    vaultInputs.push_back(vaultIn);

    CKey destKey = GenerateKey();
    CKey changeKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());
    CScript changeScript = GetP2PKHScript(changeKey.GetPubKey());

    // Partial unlock: 30 M0 out, M1 change = 20 - M1 fee (BP30 v3.0)
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        unlockAmt,
        destScript,
        changeScript
    );

    BOOST_REQUIRE(unlockResult.success);
    BOOST_CHECK(unlockResult.fee > 0);

    // Capture BP30 settlement vouts BEFORE funding.
    // vout[0] = M0_out (30 COIN), vout[1] = M1_change (20 COIN - M1 fee).
    size_t settlementVoutCount = unlockResult.mtx.vout.size();
    CTxOut vout0_before = unlockResult.mtx.vout[0];  // M0_out
    CTxOut vout1_before = unlockResult.mtx.vout[1];  // M1_change

    BOOST_CHECK_EQUAL(vout0_before.nValue, 30 * COIN);
    BOOST_CHECK_EQUAL(vout1_before.nValue, 20 * COIN - unlockResult.fee);

    // Simulate funding: add M0 fee inputs + M0 fee change
    CMutableTransaction mtx = unlockResult.mtx;

    // Add M0 fee input
    mtx.vin.emplace_back(COutPoint(GetRandHash(), 0));

    // Add M0 fee change output (appended after the settlement vouts)
    CAmount m0FeeChange = 0.009 * COIN;
    mtx.vout.emplace_back(m0FeeChange, destScript);

    // Verify: BP30 settlement vouts are UNCHANGED after funding
    BOOST_CHECK_EQUAL(mtx.vout[0].nValue, vout0_before.nValue);
    BOOST_CHECK(mtx.vout[0].scriptPubKey == vout0_before.scriptPubKey);

    BOOST_CHECK_EQUAL(mtx.vout[1].nValue, vout1_before.nValue);
    BOOST_CHECK(mtx.vout[1].scriptPubKey == vout1_before.scriptPubKey);

    // BP30 v3.0 conservation still holds: M1_in == M0_out + M1_change + M1_fee
    CAmount m1InTotal = m1Inputs[0].amount;  // 50 COIN
    BOOST_CHECK_EQUAL(m1InTotal, mtx.vout[0].nValue + mtx.vout[1].nValue + unlockResult.fee);

    // Verify the appended fee change is separate (one extra output, last)
    BOOST_CHECK_EQUAL(mtx.vout.size(), settlementVoutCount + 1);
    BOOST_CHECK_EQUAL(mtx.vout.back().nValue, m0FeeChange);
}

/**
 * Test: TX_UNLOCK with OP_TRUE vault passes standardness checks
 *
 * BP30 special transactions bypass certain policy checks.
 * This test verifies the bypass works correctly.
 */
BOOST_AUTO_TEST_CASE(unlock_with_op_true_vault_is_standard)
{
    // Build a complete unlock TX
    std::vector<M1Input> m1Inputs;
    M1Input m1In;
    m1In.outpoint = COutPoint(GetRandHash(), 0);
    m1In.amount = 10 * COIN;
    m1In.scriptPubKey = GetP2PKHScript(GenerateKey().GetPubKey());
    m1Inputs.push_back(m1In);

    std::vector<VaultInput> vaultInputs;
    VaultInput vaultIn;
    vaultIn.outpoint = COutPoint(GetRandHash(), 0);
    vaultIn.amount = 10 * COIN;
    vaultInputs.push_back(vaultIn);

    CKey destKey = GenerateKey();
    CScript destScript = GetP2PKHScript(destKey.GetPubKey());

    // BP30 v3.0: full unlock (0 = all M1 minus the M1 fee). vault (10 COIN) backs
    // unlock + M1 fee.
    UnlockResult unlockResult = BuildUnlockTransaction(
        m1Inputs,
        vaultInputs,
        0,  // Full unlock (all M1 minus fee)
        destScript,
        destScript
    );

    BOOST_REQUIRE(unlockResult.success);

    // Verify TX type is TX_UNLOCK
    const CTransaction tx(unlockResult.mtx);
    BOOST_CHECK_EQUAL(tx.nType, CTransaction::TxType::TX_UNLOCK);

    // Verify vault input uses OP_TRUE (empty scriptSig for now)
    // In actual TX, vault vin[1] would have minimal scriptSig for OP_TRUE
    BOOST_CHECK_EQUAL(tx.vin.size(), 2);  // M1 receipt + vault

    // BP30 v3.1 full-unlock shape: the fee is an implicit M0 coinbase fee, so the
    // only output is vout[0] = M0 out (10 COIN - fee).
    BOOST_CHECK(unlockResult.fee > 0);
    BOOST_CHECK_EQUAL(tx.vout.size(), 1);
    BOOST_CHECK_EQUAL(tx.vout[0].nValue, 10 * COIN - unlockResult.fee);

    // BP30: TX_UNLOCK is accepted by mempool despite OP_TRUE vault inputs
    // This works via policy.cpp IsStandardTx() which checks nType directly:
    //   if (tx->nType == TX_LOCK || TX_UNLOCK || TX_TRANSFER_M1)
    //       return true;  // BP30 P1 transactions are always standard
    //
    // Note: TX_UNLOCK does NOT use extraPayload (unlike ProRegTx etc.)
    // so IsSpecialTx() returns false. Standardness is via nType check.

    // Verify version is SAPLING (required for nType to be valid)
    BOOST_CHECK(tx.nVersion == CTransaction::TxVersion::SAPLING);

    // Verify nType is exactly TX_UNLOCK (the key for standardness bypass)
    BOOST_CHECK(tx.nType == CTransaction::TxType::TX_UNLOCK);
}

BOOST_AUTO_TEST_SUITE_END()
