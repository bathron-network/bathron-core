// Copyright (c) 2026 The BATHRON Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
//
// Fuzz target for the REAL block-level settlement path (hard-test campaign #8).
//
// The deterministic counterpart is settlement_block_tests.cpp. This fuzzes the
// same entrypoint — `ProcessSpecialTxsInBlock(block, pindex, &view, state,
// /*fJustCheck=*/false, /*fSettlementOnly=*/true)` — with attacker-controlled
// bytes decoded into a block of arbitrary special transactions (TX_LOCK /
// TX_UNLOCK / TX_TRANSFER_M1 plus raw garbage special txs with hostile
// vin/vout). The in-memory settlement DB is pre-seeded with a handful of
// A6-consistent vault/receipt pairs so the fuzzer can reference real outpoints
// and actually reach the Apply* / ClassifyUnlockOutputs / ParseTransferM1Outputs
// paths (not only the early Check* rejections).
//
// Property under libFuzzer + ASan/UBSan:
//   (1) the settlement orchestrator NEVER crashes / OOMs / hits UB on hostile
//       bytes, and
//   (2) any block it ACCEPTS still satisfies the money invariants — A6
//       (M0_vaulted == M1_supply), the UTXO-level vault-sum == M0_vaulted guard,
//       and the A7 supply cap. A "valid" block that broke conservation would be
//       a consensus inflation/again bug; here it aborts.
//
//   ./configure --enable-fuzz --without-gui --disable-bench CC=clang CXX=clang++
//   make -C src test/fuzz/settlement_block \
//     CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1" \
//     LDFLAGS="-fsanitize=fuzzer,address,undefined"
//   ./src/test/fuzz/settlement_block corpus/

#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/validation.h"
#include "masternode/specialtx_validation.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "state/settlement.h"
#include "state/settlement_logic.h"
#include "state/settlementdb.h"
#include "sync.h"
#include "test/fuzz/fuzz.h"
#include "uint256.h"
#include "validation.h"

#include <cassert>
#include <cstdint>
#include <set>
#include <vector>

namespace {

// Minimal, always-in-bounds byte reader over the fuzz buffer.
struct Reader {
    const uint8_t* p;
    size_t n, i = 0;
    Reader(const std::vector<uint8_t>& b) : p(b.data()), n(b.size()) {}
    uint8_t u8() { return i < n ? p[i++] : 0; }
    uint64_t bits(int bytes)
    {
        uint64_t v = 0;
        for (int k = 0; k < bytes; ++k) v = (v << 8) | u8();
        return v;
    }
    bool done() const { return i >= n; }
};

CScript OpTrue()
{
    CScript s;
    s << OP_TRUE;
    return s;
}
CScript P2PKH(uint8_t tag)
{
    CScript s;
    s << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG;
    return s;
}
uint256 H(uint64_t x)
{
    uint256 h;
    unsigned char* b = h.begin();
    for (int k = 0; k < 8; ++k) b[k] = (unsigned char)(x >> (8 * k));
    b[8] = 0x5A;
    return h;
}

// Amount bounded to a sane satoshi range so we never blow past the 21M cap by
// construction alone (we WANT the fuzzer to probe the cap, but via accounting,
// not a single absurd output that trivially rejects).
CAmount Amt(Reader& r)
{
    return (CAmount)(r.bits(5) % (100000ULL * COIN + 1));
}

const size_t kMaxTx = 12;
const size_t kMaxIn = 6;
const size_t kMaxOut = 6;

} // namespace

void test_one_input(std::vector<uint8_t> buffer)
{
    if (buffer.size() < 8) return;
    Reader r(buffer);

    LOCK(cs_main);
    if (!InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true)) return;
    if (!InitHtlcDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true)) return;

    // Seed genesis with an A6-consistent set of vault/receipt pairs so UNLOCK /
    // TRANSFER inputs can match real outpoints. K pairs of amount A each:
    // M0_vaulted = M1_supply = K*A, M0_total = a large backing >= K*A.
    const int K = 4;
    const CAmount A = 100 * COIN;
    std::vector<COutPoint> seededVaults, seededReceipts;
    for (int k = 0; k < K; ++k) {
        VaultEntry v;
        v.outpoint = COutPoint(H(0x100 + k), 0);
        v.amount = A;
        v.nLockHeight = 0;
        g_settlementdb->WriteVault(v);
        seededVaults.push_back(v.outpoint);

        M1Receipt m;
        m.outpoint = COutPoint(H(0x200 + k), 1);
        m.amount = A;
        m.nCreateHeight = 0;
        g_settlementdb->WriteReceipt(m);
        seededReceipts.push_back(m.outpoint);
    }
    uint256 genHash = H(0xB47);
    SettlementState s0;
    s0.SetNull();
    s0.M0_vaulted = (CAmount)K * A;
    s0.M1_supply = (CAmount)K * A;
    s0.M0_total_supply = 1000000 * COIN;
    s0.nHeight = 0;
    s0.hashBlock = genHash;
    if (!g_settlementdb->WriteState(s0)) return;

    // Coinbase.
    CBlock blk;
    blk.nVersion = 4;
    blk.hashPrevBlock = genHash;
    blk.nTime = 1700000000;
    blk.nBits = 0x207fffff;
    blk.nNonce = 1;
    {
        CMutableTransaction cb;
        cb.nVersion = CTransaction::TxVersion::SAPLING;
        cb.nType = CTransaction::TxType::NORMAL;
        cb.vin.emplace_back(CTxIn(COutPoint()));
        cb.vout.emplace_back(CTxOut(0, OpTrue()));
        blk.vtx.push_back(MakeTransactionRef(CTransaction(cb)));
    }

    // Decode attacker txs. Collect every special-tx input outpoint so we can
    // tell whether the block is UTXO-valid (no outpoint spent twice). The real
    // ConnectBlock runs CheckInputs (double-spend / existence) BEFORE the
    // settlement layer, which therefore assumes unique, existing inputs. Feeding
    // it a double-spend legitimately breaks conservation (the settlement layer is
    // not the double-spend guard) — so the conservation oracle below only fires on
    // UTXO-valid blocks. Every input is still exercised for crash/OOM/UB safety.
    std::vector<COutPoint> allInputs;
    size_t nTx = 1 + (r.u8() % kMaxTx);
    uint8_t tag = 1;
    for (size_t t = 0; t < nTx && !r.done(); ++t) {
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        uint8_t kind = r.u8() % 4;
        switch (kind) {
        case 0: { // TX_LOCK (fresh input, vault(P)+receipt(P), maybe corrupted)
            mtx.nType = CTransaction::TxType::TX_LOCK;
            CAmount P = Amt(r);
            mtx.vin.emplace_back(CTxIn(COutPoint(H(0x1000 + t * 7 + r.u8()), 0)));
            mtx.vout.emplace_back(CTxOut(P, OpTrue()));
            // vout[1] amount possibly != P (fuzzer probes the backing invariant)
            mtx.vout.emplace_back(CTxOut((r.u8() & 1) ? P : Amt(r), P2PKH(tag++)));
            break;
        }
        case 1: { // TX_UNLOCK referencing seeded receipts+vaults + arbitrary out
            mtx.nType = CTransaction::TxType::TX_UNLOCK;
            size_t nr = 1 + (r.u8() % 3), nv = 1 + (r.u8() % 3);
            for (size_t k = 0; k < nr; ++k)
                mtx.vin.emplace_back(CTxIn(seededReceipts[r.u8() % seededReceipts.size()]));
            for (size_t k = 0; k < nv; ++k)
                mtx.vin.emplace_back(CTxIn(seededVaults[r.u8() % seededVaults.size()]));
            size_t no = 1 + (r.u8() % kMaxOut);
            for (size_t k = 0; k < no; ++k) {
                bool optrue = (r.u8() & 1);
                mtx.vout.emplace_back(CTxOut(Amt(r), optrue ? OpTrue() : P2PKH(tag++)));
            }
            break;
        }
        case 2: { // TX_TRANSFER_M1 on a seeded receipt
            mtx.nType = CTransaction::TxType::TX_TRANSFER_M1;
            mtx.vin.emplace_back(CTxIn(seededReceipts[r.u8() % seededReceipts.size()]));
            size_t no = 1 + (r.u8() % kMaxOut);
            for (size_t k = 0; k < no; ++k) {
                bool optrue = (r.u8() & 1);
                mtx.vout.emplace_back(CTxOut(Amt(r), optrue ? OpTrue() : P2PKH(tag++)));
            }
            break;
        }
        default: { // raw garbage special tx — hostile vin/vout, arbitrary special type
            static const CTransaction::TxType kinds[] = {
                CTransaction::TxType::TX_LOCK, CTransaction::TxType::TX_UNLOCK,
                CTransaction::TxType::TX_TRANSFER_M1, CTransaction::TxType::HTLC_CREATE_M1,
                CTransaction::TxType::HTLC_CLAIM, CTransaction::TxType::HTLC_REFUND};
            mtx.nType = kinds[r.u8() % (sizeof(kinds) / sizeof(kinds[0]))];
            size_t ni = r.u8() % kMaxIn, no = r.u8() % kMaxOut;
            for (size_t k = 0; k < ni; ++k) {
                // sometimes reference seeded state, sometimes fresh
                if (r.u8() & 1 && !seededReceipts.empty())
                    mtx.vin.emplace_back(CTxIn(seededReceipts[r.u8() % seededReceipts.size()]));
                else
                    mtx.vin.emplace_back(CTxIn(COutPoint(H(0x9000 + t * 11 + k + r.u8()), r.u8() % 3)));
            }
            for (size_t k = 0; k < no; ++k) {
                bool optrue = (r.u8() & 1);
                mtx.vout.emplace_back(CTxOut(Amt(r), optrue ? OpTrue() : P2PKH(tag++)));
            }
            break;
        }
        }
        for (const CTxIn& in : mtx.vin) allInputs.push_back(in.prevout);
        blk.vtx.push_back(MakeTransactionRef(CTransaction(mtx)));
    }

    // UTXO-valid iff no input outpoint is spent more than once across the block.
    bool utxoValid = true;
    {
        std::set<COutPoint> seen;
        for (const COutPoint& op : allInputs) {
            if (!seen.insert(op).second) { utxoValid = false; break; }
        }
    }

    // Build the height-1 index chain (stable local storage).
    uint256 genStore = genHash;
    CBlockIndex idxGen;
    idxGen.nHeight = 0;
    idxGen.pprev = nullptr;
    idxGen.phashBlock = &genStore;

    uint256 blkHash = blk.GetHash();
    CBlockIndex idx1;
    idx1.nHeight = 1;
    idx1.pprev = &idxGen;
    idx1.phashBlock = &blkHash;

    CValidationState state;
    CCoinsView dummy;
    CCoinsViewCache view(&dummy);

    // fSettlementOnly=true -> no MN context needed; the whole money path runs.
    bool accepted = ProcessSpecialTxsInBlock(blk, &idx1, &view, state, /*fJustCheck=*/false,
                                             /*fSettlementOnly=*/true);

    if (accepted && utxoValid) {
        // An accepted, UTXO-valid block MUST preserve every money invariant. (A
        // block with duplicate inputs would be rejected by CheckInputs before the
        // settlement layer, so its post-state is out of this oracle's scope.)
        SettlementState st;
        assert(g_settlementdb->ReadLatestState(st));
        CValidationState vs;
        assert(CheckA6P1(st, vs));                       // M0_vaulted == M1_supply
        CValidationState vs7;
        assert(CheckA7(st, Params().GetConsensus().nMaxMoneyOut, vs7)); // 0 <= M0_total <= cap
        CAmount sumVaults = 0;
        g_settlementdb->ForEachVault([&](const VaultEntry& v) { sumVaults += v.amount; return true; });
        assert(sumVaults == st.M0_vaulted);              // UTXO-level vault conservation
    }
}
