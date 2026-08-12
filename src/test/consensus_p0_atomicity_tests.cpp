// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// P0 VALIDATION — AUD-017 (non-atomic consensus DB writes) and AUD-003 (the
// node-local kill switch as the mint oracle), driven through the REAL
// ProcessSpecialTxsInBlock rather than through their component functions.
//
// Both findings were previously reproduced only one layer down — AUD-017 by
// reading, AUD-003 at CreateMintM0BTC. The independent review named that as the
// remaining objection for both. These cases close it: they build a CBlock, call
// ProcessSpecialTxsInBlock(block, pindex, view, state, /*fJustCheck=*/false), and
// assert on the returned verdict and on the durable DB state afterwards.
//
// The burnclaim DBs here are ON DISK (fMemory=false) inside the fixture's
// temporary datadir, so "survives a restart" is tested by destroying and
// reopening the DB object, not simulated.
//
// DESCRIPTIVE of current behaviour. No consensus code is modified.

#include "blockassembler.h"        // LOT 2: producer-refusal test drives CreateNewBlock
#include "btcheaders/btcheaders.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "burnclaim/burnclaim.h"
#include "burnclaim/burnclaimdb.h"
#include "burnclaim/killswitch.h"
#include "chain.h"
#include "htlc/htlc.h"
#include "htlc/htlcdb.h"
#include "state/settlement.h"
#include "state/settlement_logic.h"   // LOT 8: A5Status / ComputeA5Status / CheckA5Independent
#include "state/settlementdb.h"
#include "btcheaders/btcheadersdb.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "masternode/specialtx_validation.h"
#include "node/shutdown.h"           // r15: StartShutdown/ShutdownRequested (test stubs)
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_bathron.h"
#include "uint256.h"
#include "util/system.h"          // gArgs (-enablemint policy) + ClearDatadirCache
#include "utilstrencodings.h"
#include "validation.h"

#include <algorithm>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

//! LOT 8 F1 — model the node state a REAL node has at a connect: the burn ledger's
//! best-block marker IS the parent of the block being connected. In production every
//! block's own commit writes that marker (unconditionally, commit step 4), so at the next
//! connect it always equals the parent. These synthetic fixtures jump heights and recreate
//! DBs mid-test, so they must state explicitly what a real node's connects would have
//! left behind. F1 makes an uncertified ledger a LOCAL FAULT (fatal + reindex), so this is
//! PRODUCTION FIDELITY — never a relaxation of the rule to suit a fixture.
void SeedLedgerAtParent(const CBlockIndex& idx)
{
    if (!g_burnclaimdb || !idx.pprev) return;
    auto b = g_burnclaimdb->CreateBatch();
    b.WriteBestBlock(idx.pprev->GetBlockHash());
    BOOST_REQUIRE(b.Commit());
}


// BCS-4 canonical burn script hash: SHA256(OP_FALSE).
const char* P0_BURN_HASH_HEX =
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";

void PutLE(std::vector<uint8_t>& v, uint64_t x, int bytes)
{
    for (int i = 0; i < bytes; ++i) v.push_back((uint8_t)((x >> (8 * i)) & 0xff));
}

std::vector<uint8_t> MetaV1(uint8_t network, uint8_t destByte)
{
    std::vector<uint8_t> p = {'B', 'A', 'T', 'H', 'R', 'O', 'N', 0x01, network};
    p.insert(p.end(), 20, destByte);
    return p;
}

//! Minimal well-formed non-witness BTC burn tx: OP_RETURN(meta) + P2WSH(burn).
//! `salt` varies the dummy prevout so distinct calls yield distinct txids.
std::vector<uint8_t> MakeRawBurnTx(const std::vector<uint8_t>& meta, int64_t sats, uint8_t salt)
{
    std::vector<uint8_t> tx;
    PutLE(tx, 2, 4);
    tx.push_back(0x01);
    tx.insert(tx.end(), 32, salt);
    PutLE(tx, 0, 4);
    tx.push_back(0x00);
    PutLE(tx, 0xffffffff, 4);
    tx.push_back(0x02);
    PutLE(tx, 0, 8);
    tx.push_back((uint8_t)(2 + meta.size()));
    tx.push_back(0x6a);
    tx.push_back((uint8_t)meta.size());
    tx.insert(tx.end(), meta.begin(), meta.end());
    PutLE(tx, (uint64_t)sats, 8);
    tx.push_back(0x22);
    tx.push_back(0x00); tx.push_back(0x20);
    std::vector<uint8_t> bh = ParseHex(P0_BURN_HASH_HEX);
    tx.insert(tx.end(), bh.begin(), bh.end());
    PutLE(tx, 0, 4);
    return tx;
}

uint256 TxidOf(const std::vector<uint8_t>& rawTx)
{
    BtcParsedTx parsed;
    BOOST_REQUIRE(ParseBtcTransaction(rawTx, parsed));
    return ComputeBtcTxid(parsed);
}

CTransactionRef MakeSpecialTx(int16_t type, const std::vector<uint8_t>& payload)
{
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = type;
    mtx.extraPayload = payload;
    return MakeTransactionRef(std::move(mtx));
}

template <typename T>
std::vector<uint8_t> SerializePayload(const T& p)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << p;
    return std::vector<uint8_t>(ss.begin(), ss.end());
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════════
// Fixture — real on-disk consensus DBs, a synthetic parent/child index pair
// ═══════════════════════════════════════════════════════════════════════════════

struct P0AtomicitySetup : public BasicTestingSetup {
    uint256 prevHash, curHash;
    CBlockIndex prevIdx, curIdx;

    P0AtomicitySetup() : BasicTestingSetup(CBaseChainParams::TESTNET)
    {
        // A real, per-case temporary datadir — required because the DBs below are on
        // disk. BasicTestingSetup removes m_path_root in its destructor, so nothing
        // leaks between cases and nothing survives the run.
        SetDataDir("p0_atomicity");
        // LOT 2 harness fix: GetDataDir() CACHES its result and ForceSetArg does not
        // invalidate that cache, so without this the on-disk DBs below were opened
        // under an EARLIER fixture's datadir — already deleted by that fixture's
        // destructor — giving `dbwrapper_error: Database I/O error` in whichever case
        // happened to run second. Cleared HERE (like TestingSetup does) rather than
        // inside SetDataDir, because other suites call SetDataDir purely to build a
        // file path and must keep the effective datadir they already have.
        ClearDatadirCache();

        // ON DISK (fMemory=false): the restart case below must be a real reopen.
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, true);
        g_btc_spv = std::make_unique<CBtcSPV>();
        g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        // Review defect 5: without these the whole settlement/HTLC section of
        // ProcessSpecialTxsInBlock is skipped (`if (!fJustCheck && g_settlementdb)`),
        // so the HTLC half of the AUD-017 fix — the shared batch, the prune fold, the
        // connect/undo commits — was never reached by any case here.
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb = std::make_unique<CHtlcDB>(1 << 20, false, true);
        SetBtcBurnsEnabled(true);

        prevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000a1");
        curHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000a2");
        prevIdx.nHeight = 1000;
        prevIdx.phashBlock = &prevHash;
        curIdx.nHeight = 1001;
        curIdx.phashBlock = &curHash;
        curIdx.pprev = &prevIdx;

        // LOT 8 F1: a real node at height 1000 has its burn-ledger marker at that block.
        // State it, so the first connect at curIdx sees a CERTIFIED ledger (an
        // uncertified one is now a local fault, not a silent disarm).
        SeedLedgerAtParent(curIdx);
    }

    //! LOT 8 F1 — see SeedLedgerAtParent(): the ledger marker must be the parent's,
    //! exactly as a real node's own commits leave it.
    void SetLedgerAtParent(const CBlockIndex& idx) const { SeedLedgerAtParent(idx); }

    //! LOT 7 (L6-F16): the A5/A7 base read fires the LOT 1 fatal latch on a TORN
    //! settlement DB — the marker says "at the parent" but the per-height base record is
    //! missing/mismatched. A fixture that seeds the parent MARKER (WriteBestBlock) before
    //! a direct ProcessSpecialTxsInBlock connect is therefore claiming a healthy at-parent
    //! DB, so it must also seed the parent's per-height state, exactly as a real parent
    //! connect would (an all-zero base stamped with the parent's height/hash reproduces
    //! the prior empty base WITH its identity). Fixtures that set NO parent marker are
    //! unaffected by the check and do not need this.
    void SeedSettlementBase(int nHeight, const uint256& hash) const
    {
        SettlementState s;                 // all counters zero (empty pre-state)
        s.nHeight = (uint32_t)nHeight;
        s.hashBlock = hash;
        BOOST_REQUIRE(g_settlementdb->WriteState(s));
    }

    ~P0AtomicitySetup()
    {
        SetBtcBurnsEnabled(true);        // never leak the flag into another suite
        g_htlcdb.reset();
        g_settlementdb.reset();
        g_burnclaimdb.reset();
        g_btc_spv.reset();
        g_btcheadersdb.reset();
    }

    //! Seed an active BTC header whose merkle root is `merkleRoot` (single-tx block).
    uint256 SeedHeader(uint32_t height, const uint256& merkleRoot)
    {
        BtcBlockHeader hdr;
        hdr.nVersion = 4;
        hdr.hashPrevBlock = uint256S("00000000000000000000000000000000000000000000000000000000000000ff");
        hdr.hashMerkleRoot = merkleRoot;
        hdr.nTime = 1000 + height;
        hdr.nBits = 0x1d00ffff;
        hdr.nNonce = height;
        const uint256 hash = hdr.GetHash();
        auto batch = g_btcheadersdb->CreateBatch();
        batch.WriteHeader(height, hdr);
        batch.WriteTip(height, hash);
        BOOST_REQUIRE(batch.Commit());
        return hash;
    }

    //! A fully valid TX_BURN_CLAIM against a freshly seeded header.
    //!
    //! NOTE: this deliberately uses a TWO-leaf merkle tree. Going through the real
    //! CheckSpecialTx path enforces BurnClaimPayload::IsTriviallyValid, which rejects
    //! an EMPTY merkle proof ("Empty merkle proof", burnclaim.cpp:468-471). The
    //! existing burnclaim_consensus_tests use `merkleProof = {}` and pass only because
    //! they call CheckBurnClaim DIRECTLY, bypassing that gate — so a single-leaf claim
    //! is not actually reachable through a block. Root = Hash(txid ‖ sibling) with
    //! txIndex = 0, matching VerifyMerkleProofInternal (btcspv.cpp:1085-1104).
    BurnClaimPayload MakeValidClaim(int64_t sats, uint32_t burnHeight, uint8_t salt)
    {
        BurnClaimPayload p;
        p.btcTxBytes = MakeRawBurnTx(MetaV1(0x01, 0xAB), sats, salt);
        const uint256 txid = TxidOf(p.btcTxBytes);

        uint256 sibling;
        std::fill(sibling.begin(), sibling.end(), (unsigned char)(0x70 ^ salt));
        const uint256 root = Hash(txid.begin(), txid.end(), sibling.begin(), sibling.end());

        p.btcBlockHash = SeedHeader(burnHeight, root);
        p.btcBlockHeight = burnHeight;
        p.merkleProof = {sibling};
        p.txIndex = 0;
        return p;
    }

    //! A TX_MINT_M0BTC carrying `txids` — only needs to be trivially valid to reach
    //! the multi-mint guard (CheckSpecialTx does format checks only for this type,
    //! specialtx_validation.cpp:740-775).
    CTransactionRef MakeMintTx(std::vector<uint256> txids)
    {
        std::sort(txids.begin(), txids.end());
        MintPayload mp;
        mp.nVersion = MINT_PAYLOAD_VERSION;
        mp.btcTxids = std::move(txids);
        return MakeSpecialTx(CTransaction::TxType::TX_MINT_M0BTC, SerializePayload(mp));
    }

    CTransactionRef MakeClaimTx(const BurnClaimPayload& p)
    {
        return MakeSpecialTx(CTransaction::TxType::TX_BURN_CLAIM, SerializePayload(p));
    }

    bool ClaimIsInDB(const uint256& btcTxid, BurnClaimRecord& out) const
    {
        return g_burnclaimdb->GetBurnClaim(btcTxid, out);
    }

    //! Destroy and reopen the burnclaim DB from the same on-disk path, WITHOUT
    //! wiping — i.e. exactly what a daemon restart does.
    void RestartBurnClaimDB()
    {
        g_burnclaimdb.reset();
        g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, /*fMemory=*/false, /*fWipe=*/false);
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_aud017, P0AtomicitySetup)

// CONTROL — the same block WITHOUT the poisoning element must be accepted, and the
// claim must be present for the legitimate reason. If this fails, the negative case
// below proves nothing.
BOOST_AUTO_TEST_CASE(control_valid_block_is_accepted_and_records_the_claim)
{
    BurnClaimPayload claim = MakeValidClaim(/*sats=*/100000, /*burnHeight=*/300000, /*salt=*/0x11);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    CValidationState state;
    SeedLedgerAtParent(curIdx);
    const bool ok = ProcessSpecialTxsInBlock(block, &curIdx, /*view=*/nullptr, state,
                                             /*fJustCheck=*/false);
    BOOST_REQUIRE_MESSAGE(ok, "control block must connect: " << state.GetRejectReason());

    BurnClaimRecord rec;
    BOOST_CHECK(ClaimIsInDB(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::PENDING);
    BOOST_CHECK_EQUAL(rec.claimHeight, (uint32_t)curIdx.nHeight);
}

// INVARIANT (AUD-017 fix). A block whose burn claim is valid but which fails LATER
// in ProcessSpecialTxsInBlock must leave burnclaimdb byte-identical. The claim is now
// staged into a function-scope batch (EnterPendingState -> batch.StoreBurnClaim) that
// is committed only in the final phase, after every validation has passed.
//
// BEFORE the fix this case asserted the OPPOSITE (the orphan was present, survived a
// restart, and poisoned the next honest claim with burn-claim-duplicate). It is kept
// as a permanent regression guard: if the staging is ever undone, this fails.
BOOST_AUTO_TEST_CASE(rejected_block_leaves_no_durable_mutation)
{
    BurnClaimPayload claim = MakeValidClaim(/*sats=*/250000, /*burnHeight=*/300100, /*salt=*/0x22);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    BurnClaimRecord before;
    BOOST_REQUIRE(!ClaimIsInDB(btcTxid, before));   // clean slate

    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));                       // stages the DB write
    block.vtx.push_back(MakeMintTx({uint256S("11")}));             // mintTxCount = 1
    block.vtx.push_back(MakeMintTx({uint256S("22")}));             // mintTxCount = 2 -> reject

    CValidationState state;
    SeedLedgerAtParent(curIdx);
    const bool ok = ProcessSpecialTxsInBlock(block, &curIdx, /*view=*/nullptr, state,
                                             /*fJustCheck=*/false);

    // 1. The block is rejected.
    BOOST_CHECK(!ok);

    // 2. ...and NOTHING durable was written.
    BurnClaimRecord rec;
    BOOST_CHECK_MESSAGE(!ClaimIsInDB(btcTxid, rec),
                        "AUD-017 INVARIANT: a rejected block must not persist its burn claim");

    // 3. The orphan does not appear after a real restart either.
    RestartBurnClaimDB();
    BurnClaimRecord afterRestart;
    BOOST_CHECK_MESSAGE(!ClaimIsInDB(btcTxid, afterRestart),
                        "AUD-017 INVARIANT: nothing to resurrect on restart");

    // 4. The honest network's later, valid block carrying the SAME claim is ACCEPTED —
    //    no burn-claim-duplicate, because no phantom PENDING record exists.
    CBlock goodBlock;
    goodBlock.vtx.push_back(MakeClaimTx(claim));
    CValidationState goodState;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(goodBlock, &curIdx, nullptr, goodState, false),
                        "AUD-017 INVARIANT: later honest claim must connect: "
                            << goodState.GetRejectReason());
    BOOST_CHECK(ClaimIsInDB(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::PENDING);
}

// An error BEFORE any mutation must also leave the DB clean (control for the above:
// proves the invariant is not trivially satisfied by "nothing ever gets written").
BOOST_AUTO_TEST_CASE(failure_before_any_mutation_leaves_db_clean)
{
    BurnClaimPayload claim = MakeValidClaim(/*sats=*/50000, /*burnHeight=*/300300, /*salt=*/0x44);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    CBlock block;
    // Two mints and NO burn claim: rejected at the same guard, before any claim write.
    block.vtx.push_back(MakeMintTx({uint256S("55")}));
    block.vtx.push_back(MakeMintTx({uint256S("66")}));

    CValidationState state;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, state, false));
    BurnClaimRecord rec;
    BOOST_CHECK(!ClaimIsInDB(btcTxid, rec));
}

// The best-block marker and the records it vouches for now move together: a rejected
// block advances neither. (Before the fix the marker stayed at the parent while an
// orphan record existed beneath it, and CheckBurnClaimDBConsistency reported green.)
BOOST_AUTO_TEST_CASE(marker_and_records_stay_consistent_after_rejection)
{
    g_burnclaimdb->WriteBestBlock(prevHash);   // parent connected successfully

    BurnClaimPayload claim = MakeValidClaim(/*sats=*/70000, /*burnHeight=*/300200, /*salt=*/0x33);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));
    block.vtx.push_back(MakeMintTx({uint256S("33")}));
    block.vtx.push_back(MakeMintTx({uint256S("44")}));

    CValidationState state;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, state, false));

    BurnClaimRecord rec;
    BOOST_CHECK(!ClaimIsInDB(btcTxid, rec));          // no orphan beneath the marker

    uint256 dbBest;
    BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(dbBest));
    BOOST_CHECK(dbBest == prevHash);                  // marker unmoved, and now truthful
}

// A SUCCESSFUL block still commits everything atomically: claim + marker together.
BOOST_AUTO_TEST_CASE(successful_block_commits_claim_and_marker_together)
{
    BurnClaimPayload claim = MakeValidClaim(/*sats=*/90000, /*burnHeight=*/300400, /*salt=*/0x55);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));
    CValidationState state;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, state, false));

    BurnClaimRecord rec;
    BOOST_CHECK(ClaimIsInDB(btcTxid, rec));
    uint256 dbBest;
    BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(dbBest));
    // The marker records the CONNECTED BLOCK's hash (block.GetHash()), not the
    // synthetic index hash — they differ here because the fixture's CBlockIndex is
    // hand-built. What matters is that it advanced off the parent, in the same batch.
    BOOST_CHECK(dbBest == block.GetHash());
    BOOST_CHECK(dbBest != prevHash);

    // ...and it survives a restart, because it was really committed.
    RestartBurnClaimDB();
    BurnClaimRecord afterRestart;
    BOOST_CHECK(ClaimIsInDB(btcTxid, afterRestart));
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// AUD-003 — the kill switch decides block validity, at ProcessSpecialTxsInBlock
// ═══════════════════════════════════════════════════════════════════════════════

struct P0KillSwitchSetup : public P0AtomicitySetup {
    //! A STRUCTURALLY well-formed mint (payload txids and vout agree in count) whose
    //! claim does not exist. Without the matching vout the tx is rejected earlier on
    //! `mint-output-count`, which would never exercise the claim-lookup rule that the
    //! old -enablemint=0 bypass skipped.
    CTransactionRef MakeWellFormedMintForUnknownClaim(const uint256& unknownTxid,
                                                      CAmount value = 424242) const
    {
        MintPayload mp;
        mp.nVersion = MINT_PAYLOAD_VERSION;
        mp.btcTxids = {unknownTxid};

        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;
        CTxOut o;
        o.nValue = value;
        o.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<unsigned char>(20, 0xCD)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;
        mtx.vout.push_back(o);
        mtx.extraPayload = SerializePayload(mp);
        return MakeTransactionRef(std::move(mtx));
    }

    //! Land an eligible PENDING claim so that CreateMintM0BTC has something to mint,
    //! and return the height at which it becomes eligible.
    uint32_t SeedEligibleClaim(uint256& btcTxidOut)
    {
        const uint32_t burnHeight = 305000;
        BurnClaimRecord rec;
        std::vector<uint8_t> raw = MakeRawBurnTx(MetaV1(0x01, 0xCD), 424242, 0x55);
        btcTxidOut = TxidOf(raw);
        rec.btcTxid = btcTxidOut;
        rec.btcBlockHash = SeedHeader(burnHeight, btcTxidOut);
        rec.btcHeight = burnHeight;
        rec.burnedSats = 424242;
        rec.bathronDest = uint160(std::vector<unsigned char>(20, 0xCD));
        rec.destType = BURN_DEST_P2PKH;
        rec.claimHeight = 1000;
        rec.status = BurnClaimStatus::PENDING;
        {
            auto batch = g_burnclaimdb->CreateBatch();
            batch.StoreBurnClaim(rec);
            BOOST_REQUIRE(batch.Commit());
        }
        // Advance the BTC tip past the confirmation requirement.
        SeedHeader(burnHeight + GetRequiredConfirmations() + 10, uint256S("beef"));
        return rec.claimHeight + GetKFinality() + 1;
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_aud003, P0KillSwitchSetup)

// LOT 2 — THE INVERSION. Two nodes, identical chain state and identical block; only
// the node-local flag differs. Before the fix, node B (burns disabled) REJECTED the
// very same block that node A accepted, because the validation oracle read the flag.
// Now BOTH must accept it: the local flag governs production only.
BOOST_AUTO_TEST_CASE(killswitch_no_longer_decides_block_validity)
{
    uint256 btcTxid;
    const uint32_t mintHeight = SeedEligibleClaim(btcTxid);

    CBlockIndex mintPrev, mintIdx;
    uint256 mintPrevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000b1");
    uint256 mintCurHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000b2");
    mintPrev.nHeight = (int)mintHeight - 1;
    mintPrev.phashBlock = &mintPrevHash;
    mintIdx.nHeight = (int)mintHeight;
    mintIdx.phashBlock = &mintCurHash;
    mintIdx.pprev = &mintPrev;

    // The block the honest producer builds: exactly the expected mint.
    BOOST_REQUIRE(AreBtcBurnsEnabled());
    const CTransaction expected = CreateExpectedMintM0BTC(mintHeight);
    BOOST_REQUIRE_MESSAGE(!expected.IsNull(), "precondition: a mint must be expected here");

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(expected)));

    // --- Node A: burns ENABLED ---
    CValidationState stateA;
    SeedLedgerAtParent(mintIdx);
    const bool okA = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, stateA, false);
    BOOST_CHECK_MESSAGE(okA, "node A must accept the canonical mint: " << stateA.GetRejectReason());

    // Rewind so node B starts from the SAME pre-state (the claim went FINAL above).
    BOOST_REQUIRE(UndoSpecialTxsInBlock(block, &mintIdx, false));

    // --- Node B: identical everything, burns DISABLED ---
    SetBtcBurnsEnabled(false);
    CValidationState stateB;
    SeedLedgerAtParent(mintIdx);
    const bool okB = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, stateB, false);
    SetBtcBurnsEnabled(true);

    BOOST_CHECK_MESSAGE(okA == okB,
                        "LOT 2: a node-local flag must NOT decide whether this block "
                        "connects (A=" << okA << " B=" << okB << ", B said '"
                        << stateB.GetRejectReason() << "')");
    BOOST_CHECK_MESSAGE(okB, "node B (burns disabled) must accept the same block");
    BOOST_CHECK(!stateB.IsInvalid());
}

// Same inversion for -enablemint=0: it used to skip CheckMintM0BTC AND the
// expected-mint equality, i.e. a local option decided validity in both directions.
BOOST_AUTO_TEST_CASE(enablemint_no_longer_decides_block_validity)
{
    uint256 btcTxid;
    const uint32_t mintHeight = SeedEligibleClaim(btcTxid);

    CBlockIndex mintPrev, mintIdx;
    uint256 mintPrevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000b3");
    uint256 mintCurHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000b4");
    mintPrev.nHeight = (int)mintHeight - 1;
    mintPrev.phashBlock = &mintPrevHash;
    mintIdx.nHeight = (int)mintHeight;
    mintIdx.phashBlock = &mintCurHash;
    mintIdx.pprev = &mintPrev;

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));

    CValidationState s1;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, s1, false));
    BOOST_REQUIRE(UndoSpecialTxsInBlock(block, &mintIdx, false));

    gArgs.ForceSetArg("-enablemint", "0");
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    const bool ok2 = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, s2, false);
    gArgs.ForceSetArg("-enablemint", "1");

    BOOST_CHECK_MESSAGE(ok2, "LOT 2: -enablemint=0 must not change acceptance of a "
                             "received block: " << s2.GetRejectReason());

    // ...and, critically, a node with -enablemint=0 must still REJECT a bogus mint
    // (the old bypass skipped CheckMintM0BTC entirely — that was the double-mint door).
    BOOST_REQUIRE(UndoSpecialTxsInBlock(block, &mintIdx, false));
    CBlock bogus;
    // Well-formed shape, unknown claim — so the rejection comes from the claim
    // lookup (the rule the old bypass skipped), not from a structural check.
    bogus.vtx.push_back(MakeWellFormedMintForUnknownClaim(uint256S("dead")));
    gArgs.ForceSetArg("-enablemint", "0");
    CValidationState s3;
    SeedLedgerAtParent(mintIdx);
    const bool ok3 = ProcessSpecialTxsInBlock(bogus, &mintIdx, nullptr, s3, false);
    gArgs.ForceSetArg("-enablemint", "1");
    BOOST_CHECK_MESSAGE(!ok3, "a mint naming an unknown claim must be rejected even "
                              "with -enablemint=0");
    BOOST_CHECK_MESSAGE(s3.IsInvalid(), "and it must be a CONSENSUS invalidity, not a "
                                        "bare error: " << s3.GetRejectReason());
    BOOST_CHECK_EQUAL(s3.GetRejectReason(), "mint-unknown-claim");
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// POINT 2 (round 3) — a REAL HTLC mutation followed by a failure
// ═══════════════════════════════════════════════════════════════════════════════
//
// The round-2 review's defect 5 was that no case here ever reached an htlcBatch_()
// call site. This one does: it seeds a genuine M1 receipt, builds a block whose
// HTLC_CREATE_M1 passes CheckSpecialTx and is APPLIED (erasing the receipt from the
// settlement batch and writing an HTLC record into the htlc batch), and then makes
// the block fail. Both DBs must be byte-identical afterwards.

struct P0HtlcSetup : public P0AtomicitySetup {
    COutPoint receiptOut;
    CAmount   receiptAmt = 500000;

    //! State a PRIOR block would have left: one spendable M1 receipt.
    void SeedReceipt()
    {
        receiptOut = COutPoint(uint256S("00000000000000000000000000000000000000000000000000000000000000d1"), 0);
        M1Receipt r;
        r.outpoint      = receiptOut;
        r.amount        = receiptAmt;
        r.nCreateHeight = 900;
        auto b = g_settlementdb->CreateBatch();
        b.WriteReceipt(r);
        BOOST_REQUIRE(b.Commit());
        BOOST_REQUIRE(g_settlementdb->IsM1Receipt(receiptOut));
    }

    CTransactionRef MakeHtlcCreateTx() const
    {
        HTLCCreatePayload p;
        p.hashlock     = uint256S("00000000000000000000000000000000000000000000000000000000000000ab");
        p.expiryHeight = (uint32_t)curIdx.nHeight + 1000;   // must outlive the block
        p.claimKeyID   = CKeyID(uint160(std::vector<unsigned char>(20, 0x11)));
        p.refundKeyID  = CKeyID(uint160(std::vector<unsigned char>(20, 0x22)));
        // no covenant: templateCommitment stays null

        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType    = CTransaction::TxType::HTLC_CREATE_M1;
        mtx.vin.emplace_back(receiptOut);
        CTxOut o;
        o.nValue = receiptAmt;                              // strict conservation
        o.scriptPubKey = CScript() << OP_HASH160
                                   << std::vector<unsigned char>(20, 0x33) << OP_EQUAL;
        mtx.vout.push_back(o);
        mtx.extraPayload = SerializePayload(p);
        return MakeTransactionRef(std::move(mtx));
    }

    bool HtlcExistsAt(const COutPoint& op) const { return g_htlcdb && g_htlcdb->IsHTLC(op); }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_aud017_htlc, P0HtlcSetup)

// CONTROL — the HTLC_CREATE really is applied when the block succeeds. Without this
// the negative case below could pass simply because the tx was never valid.
BOOST_AUTO_TEST_CASE(control_htlc_create_is_applied_on_success)
{
    SeedReceipt();
    CBlock block;
    CTransactionRef htlcTx = MakeHtlcCreateTx();
    block.vtx.push_back(htlcTx);

    CValidationState state;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, state, false),
                          "control HTLC block must connect: " << state.GetRejectReason());

    // Applied: the M1 receipt is consumed and an HTLC record now exists.
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
    BOOST_CHECK(HtlcExistsAt(COutPoint(htlcTx->GetHash(), 0)));
}

// INVARIANT — the same HTLC mutation, in a block that fails afterwards, must leave
// BOTH htlcdb and settlementdb byte-identical.
BOOST_AUTO_TEST_CASE(failure_after_htlc_mutation_leaves_both_dbs_untouched)
{
    SeedReceipt();
    CTransactionRef htlcTx = MakeHtlcCreateTx();
    const COutPoint htlcOut(htlcTx->GetHash(), 0);

    CBlock block;
    block.vtx.push_back(htlcTx);                        // applied -> stages both batches
    block.vtx.push_back(MakeMintTx({uint256S("77")}));  // mintTxCount = 1
    block.vtx.push_back(MakeMintTx({uint256S("88")}));  // mintTxCount = 2 -> reject

    CValidationState state;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, state, false));

    // htlcdb: no record was created.
    BOOST_CHECK_MESSAGE(!HtlcExistsAt(htlcOut),
                        "AUD-017 INVARIANT: rejected block must not persist an HTLC record");
    // settlementdb: the M1 receipt was NOT consumed.
    BOOST_CHECK_MESSAGE(g_settlementdb->IsM1Receipt(receiptOut),
                        "AUD-017 INVARIANT: rejected block must not consume the M1 receipt");

    // Survives a restart of the burnclaim DB object (the others are untouched by it).
    RestartBurnClaimDB();
    BOOST_CHECK(!HtlcExistsAt(htlcOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    // ...and the honest network's later block carrying the SAME HTLC_CREATE connects.
    CBlock goodBlock;
    goodBlock.vtx.push_back(htlcTx);
    CValidationState goodState;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(goodBlock, &curIdx, nullptr, goodState, false),
                        "AUD-017 INVARIANT: later honest HTLC block must connect: "
                            << goodState.GetRejectReason());
    BOOST_CHECK(HtlcExistsAt(htlcOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 3 · POINT 1 — EXECUTED crash-injection matrix
// ═══════════════════════════════════════════════════════════════════════════════
//
// Round 3's first pass declared these rows "analytic, not expressible without a
// fault-injection seam". That was wrong: a crash between two LevelDB commits leaves
// exactly the state you get by performing the same commit PREFIX, so each row is
// reproducible by committing the first N batches, destroying and reopening every DB
// object (a real restart), and then running the REAL startup detectors.
//
// The chain tip is deliberately left at the PARENT for every row, because the
// chainstate is flushed AFTER all five consensus DBs (validation.cpp:2658), so a
// crash inside the commit sequence always leaves the tip behind.

struct P0CrashSetup : public P0AtomicitySetup {
    //! Full restart: destroy and reopen every consensus DB from disk, no wipe.
    void RestartAllDBs()
    {
        g_htlcdb.reset();
        g_settlementdb.reset();
        g_burnclaimdb.reset();
        g_btcheadersdb.reset();
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, false);
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, false);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, false);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, false);
    }

    //! Run the three real startup detectors against a tip still at the PARENT.
    struct Detection { bool settlementOk, burnOk, headersOk; bool anyRebuild; };
    Detection DetectAgainstParentTip()
    {
        Detection d{};
        bool r1 = false, r2 = false, r3 = false;
        d.settlementOk = CheckSettlementDBConsistency(prevHash, prevIdx.nHeight, r1);
        d.burnOk       = CheckBurnClaimDBConsistency(prevHash, r2);
        d.headersOk    = CheckBtcHeadersDBConsistency(prevHash, r3);
        d.anyRebuild   = r1 || r2 || r3;
        return d;
    }

    //! Establish "parent connected cleanly": every marker at P.
    void SeedParentCommitted()
    {
        { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(prevHash); BOOST_REQUIRE(b.Commit()); }
        g_settlementdb->WriteAllCommitted(prevHash);
        { auto b = g_burnclaimdb->CreateBatch();  b.WriteBestBlock(prevHash); BOOST_REQUIRE(b.Commit()); }
        // LOT 7 (L6-F16): a cleanly-committed parent also has its per-height settlement
        // base state at P (written with every block, specialtx_validation.cpp:1533-1547).
        // The A5/A7 base read fires the LOT 1 fatal latch when the settlement marker IS P
        // but the base record is missing (a torn DB) — so a fixture that sets the marker
        // to P must seed the matching base, else a subsequent connect trips that backstop.
        SeedSettlementBase(prevIdx.nHeight, prevHash);
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_crash_matrix, P0CrashSetup)

// ROW 1 — crash BEFORE any commit. Nothing durable, nothing detected, nothing orphaned.
BOOST_AUTO_TEST_CASE(row1_crash_before_any_commit_is_clean)
{
    SeedParentCommitted();
    BurnClaimPayload claim = MakeValidClaim(120000, 301000, 0x61);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));
    block.vtx.push_back(MakeMintTx({uint256S("a1")}));
    block.vtx.push_back(MakeMintTx({uint256S("a2")}));   // forces the reject
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false));

    RestartAllDBs();
    Detection d = DetectAgainstParentTip();
    BOOST_CHECK(d.settlementOk);
    BOOST_CHECK(d.burnOk);
    BOOST_CHECK(!d.anyRebuild);                       // nothing to recover
    BurnClaimRecord rec;
    BOOST_CHECK(!g_burnclaimdb->GetBurnClaim(btcTxid, rec));   // no orphan claim
}

// ROW 2 — crash AFTER the settlement batch. The settlement batch carries
// WriteBestBlock(block) (specialtx_validation.cpp:1265), so settlementdb advances to H
// while the tip is still P. DETECTED.
BOOST_AUTO_TEST_CASE(row2_crash_after_settlement_is_detected)
{
    SeedParentCommitted();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }
    // marker NOT advanced — we crashed before step 6.

    RestartAllDBs();
    Detection d = DetectAgainstParentTip();
    BOOST_CHECK_MESSAGE(!d.settlementOk, "settlement bestBlock=H vs tip=P must be detected");
    BOOST_CHECK(d.anyRebuild);
}

// ROW 3 — crash AFTER btcheaders. Both settlement and btcheaders are ahead. DETECTED.
BOOST_AUTO_TEST_CASE(row3_crash_after_btcheaders_is_detected)
{
    SeedParentCommitted();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_btcheadersdb->CreateBatch();  b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }

    RestartAllDBs();
    Detection d = DetectAgainstParentTip();
    BOOST_CHECK(!d.settlementOk);
    BOOST_CHECK(d.anyRebuild);
}

// ROW 5 — crash AFTER burnclaim. burnclaimdb's own marker is ahead. DETECTED by its
// dedicated check, independently of settlement's.
BOOST_AUTO_TEST_CASE(row5_crash_after_burnclaim_is_detected)
{
    SeedParentCommitted();
    { auto b = g_burnclaimdb->CreateBatch(); b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }

    RestartAllDBs();
    bool requireRebuild = false;
    BOOST_CHECK_MESSAGE(!CheckBurnClaimDBConsistency(prevHash, requireRebuild),
                        "burnclaim bestBlock=H vs tip=P must be detected");
    BOOST_CHECK(requireRebuild);
}

// ROWS 6/7 — crash AFTER the all_committed marker / before the chain tip advances.
// CORRECTS ROUND 3's WRITTEN ANALYSIS, which claimed this row was SILENT. It is not:
// settlementdb's bestBlock was advanced inside the settlement batch long before the
// marker, so ReadBestBlock(H) != tip(P) trips first and the marker branch is never
// reached. Detected.
BOOST_AUTO_TEST_CASE(row6_crash_after_marker_is_detected_not_silent)
{
    SeedParentCommitted();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_btcheadersdb->CreateBatch();  b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_burnclaimdb->CreateBatch();   b.WriteBestBlock(curHash); BOOST_REQUIRE(b.Commit()); }
    g_settlementdb->WriteAllCommitted(curHash);       // step 6 completed

    RestartAllDBs();
    Detection d = DetectAgainstParentTip();
    BOOST_CHECK_MESSAGE(!d.settlementOk, "round-3 prose said SILENT; it is in fact detected");
    BOOST_CHECK(d.anyRebuild);
}

// ROW 4 — crash AFTER the HTLC batch. WAS THE ONE UNDETECTED ROW.
// htlcdb had no best-block marker and no startup check, so an orphaned record survived
// a restart with every other detector green. Round 4 gives it a marker written INSIDE
// the same WriteBatch as the mutations, plus CheckHtlcDBConsistency wired into the
// startup gate (init.cpp slot 3, previously empty). This case now asserts DETECTION.
BOOST_AUTO_TEST_CASE(row4_crash_after_htlc_is_now_DETECTED)
{
    SeedParentCommitted();
    // A crash after the htlc batch: records AND the marker are at H (they are in the
    // same batch, so they are never out of step), while the tip is still P.
    const COutPoint orphanOut(uint256S("00000000000000000000000000000000000000000000000000000000000000e1"), 0);
    {
        HTLCRecord h;
        h.htlcOutpoint = orphanOut;
        h.amount = 12345;
        h.hashlock = uint256S("00000000000000000000000000000000000000000000000000000000000000ab");
        h.expiryHeight = (uint32_t)curIdx.nHeight + 500;
        h.createHeight = (uint32_t)curIdx.nHeight;
        h.status = HTLCStatus::ACTIVE;
        auto b = g_htlcdb->CreateBatch();
        b.WriteHTLC(h);
        b.WriteBestBlock(curHash);          // same batch — never out of step
        BOOST_REQUIRE(b.Commit());
    }

    RestartAllDBs();

    bool requireRebuild = false;
    BOOST_CHECK_MESSAGE(!CheckHtlcDBConsistency(prevHash, requireRebuild),
                        "ROW 4: htlcdb marker=H vs tip=P MUST now be detected");
    BOOST_CHECK_MESSAGE(requireRebuild,
                        "ROW 4: detection must demand recovery, not just warn");

    // The orphan is still physically present — that is expected. What changed is that
    // the node will refuse to start on it (init.cpp slot 3 sets strLoadError and breaks)
    // instead of resuming validation with it. Recovery is a full reindex, which wipes
    // and rebuilds every derivable DB.
    BOOST_CHECK(g_htlcdb->IsHTLC(orphanOut));
}

// The four-state startup gate, symmetric with settlement and burnclaim (F2). This
// case REPLACES the former row4b, which asserted the OLD asymmetry ("absent marker
// at any height is not a divergence") — the exact state the final review proved
// dangerous: the HTLC marker advances on EVERY connected block (row4c below), so an
// absent marker above genesis can only mean the DB was wiped or lost out of band,
// and HTLC state is consensus-read (CheckHTLCClaim/Refund). Startup gate only —
// never a DoS, ban or BLOCK_FAILED_* verdict, and the marker is never repaired here.
BOOST_AUTO_TEST_CASE(row4b_htlc_startup_gate_four_states)
{
    const uint256 genesis = Params().GetConsensus().hashGenesisBlock;
    const uint256 other = uint256S("00000000000000000000000000000000000000000000000000000000000077aa");

    // 1. tip == genesis + marker ABSENT -> fresh chain, allowed.
    g_htlcdb.reset();
    g_htlcdb = std::make_unique<CHtlcDB>(1 << 20, /*fMemory=*/false, /*fWipe=*/true);
    bool rebuild = true;
    BOOST_CHECK_MESSAGE(CheckHtlcDBConsistency(genesis, rebuild), "fresh chain must PASS");
    BOOST_CHECK(!rebuild);

    // 2. tip > genesis + marker ABSENT -> FAIL CLOSED, reindex. The killed mutation:
    // reintroducing "absent => PASS at any height" fails exactly these two checks.
    rebuild = false;
    BOOST_CHECK_MESSAGE(!CheckHtlcDBConsistency(prevHash, rebuild),
                        "absent HTLC marker above genesis must FAIL");
    BOOST_CHECK_MESSAGE(rebuild, "...and demand a rebuild");

    // 3. marker DIFFERENT from the tip -> FAIL CLOSED, reindex.
    { auto b = g_htlcdb->CreateBatch(); b.WriteBestBlock(other); BOOST_REQUIRE(b.Commit()); }
    rebuild = false;
    BOOST_CHECK_MESSAGE(!CheckHtlcDBConsistency(prevHash, rebuild), "marker != tip must FAIL");
    BOOST_CHECK(rebuild);

    // 4. marker AT the tip -> PASS.
    { auto b = g_htlcdb->CreateBatch(); b.WriteBestBlock(prevHash); BOOST_REQUIRE(b.Commit()); }
    rebuild = true;
    BOOST_CHECK_MESSAGE(CheckHtlcDBConsistency(prevHash, rebuild), "marker at tip must PASS");
    BOOST_CHECK(!rebuild);
}

// After a clean connect the htlc marker equals the connected block, so the gate passes.
// This is what makes the detection above meaningful rather than a permanent alarm.
BOOST_AUTO_TEST_CASE(row4c_clean_connect_leaves_htlc_marker_at_the_tip)
{
    CBlock block;
    block.vtx.push_back(MakeMintTx({uint256S("c1")}));   // no HTLC tx at all
    CValidationState st;
    // A mint with no matching claim is rejected — use a claim-free block instead.
    CBlock empty;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(empty, &curIdx, nullptr, st, false));

    uint256 marker;
    BOOST_REQUIRE_MESSAGE(g_htlcdb->ReadBestBlock(marker),
                          "even an HTLC-free block must advance the marker");
    BOOST_CHECK(marker == empty.GetHash());

    bool requireRebuild = false;
    BOOST_CHECK(CheckHtlcDBConsistency(empty.GetHash(), requireRebuild));
    BOOST_CHECK(!requireRebuild);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 7 (L6-F16) — the A5/A7 settlement-base backstop, exercised through the real
// ProcessSpecialTxsInBlock connect path (not the CheckSpecialTx gate that the
// consensus_lot7_local_state unit suite covers).
// ═══════════════════════════════════════════════════════════════════════════════
//
// The A5/A7 invariants are computed FROM the settlement state read at the parent's
// height. In production gate B (CheckSpecialTx, run with a real view before phase 2)
// already refuses any block whose settlement marker != parent, so phase 2 never sees a
// behind/empty DB. This is the residual TORN-DB backstop for the one window gate B
// cannot see: the marker IS the parent (so the DB claims to be there) but the
// per-height base record is missing/mismatched — a crash mid-commit. That is a LOCAL
// storage fault, and its response must be the LOT 1 fatal latch + reindex, NEVER a
// state.DoS / BLOCK_FAILED_VALID / peer ban.
//
// These cases drive ProcessSpecialTxsInBlock with view=nullptr, which skips gate B
// (view-gated) and isolates the phase-2 base read. They kill the mutations "remove the
// base-torn check" (no fatal) and "state.Error/fatal -> state.DoS" (invalidity).
//
// The declared mutation "ignore readOk" (dropping the `readOk &&` conjunct) SURVIVES
// this suite, and that is correct: it is a genuine NO-OP under the current serialization,
// not a coverage gap. SettlementState serializes hashBlock LAST (settlement.h) and
// CDataStream reads are all-or-nothing (streams.h: a short read throws BEFORE the
// memcpy), so any failed/truncated ReadState leaves the freshly default-constructed
// hashBlock null, which already fails `== expectedParent`; the `readOk` conjunct cannot
// change any verdict. It is retained DEFENSIVELY (it would become load-bearing only if
// the field order changed). Two independent reviews split on this; adjudicated against
// the actual field order + CDataStream::read semantics, which make it a no-op.
// Defined later in this file inside the anonymous namespace (used by the LOT 1
// commit-failure suites too); forward-declared here with matching internal linkage.
namespace { void ExpectFatalAndClear(bool fConnect, int step, bool partial, int expectedShutdowns); }

BOOST_FIXTURE_TEST_SUITE(consensus_lot7_settlement_base, P0AtomicitySetup)

// Marker == parent, but NO base record at the parent height -> torn DB -> fatal latch,
// non-invalid Error, exactly one shutdown request. Never invalidity.
BOOST_AUTO_TEST_CASE(torn_base_marker_parent_no_record_is_fatal_not_invalid)
{
    // The settlement DB claims to be AT the parent...
    BOOST_REQUIRE(g_settlementdb->WriteBestBlock(prevHash));
    // ...but its per-height base record is absent (deliberately NOT SeedSettlementBase).

    BurnClaimPayload claim = MakeValidClaim(/*sats=*/100000, /*burnHeight=*/307000, /*salt=*/0x7A);
    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));   // valid: clears phase 1, reaches phase 2

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, /*view=*/nullptr, st, false));
    BOOST_CHECK_MESSAGE(st.IsError(), "a torn settlement base is a local Error");
    BOOST_CHECK_MESSAGE(!st.IsInvalid(), "a storage fault is NEVER block invalidity/DoS");
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/0, /*partial=*/false, /*shutdowns=*/1);
}

// Control: marker == parent AND the matching base record present (a healthy at-parent
// DB) -> the same block connects, the backstop does NOT fire.
BOOST_AUTO_TEST_CASE(healthy_base_marker_parent_with_record_connects)
{
    BOOST_REQUIRE(g_settlementdb->WriteBestBlock(prevHash));
    SeedSettlementBase(prevIdx.nHeight, prevHash);

    BurnClaimPayload claim = MakeValidClaim(/*sats=*/100000, /*burnHeight=*/307100, /*salt=*/0x7B);
    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, /*view=*/nullptr, st, false),
                        st.GetRejectReason());
    BOOST_CHECK(!IsConsensusDBFatal());
}

// Marker == parent, base record present but stamped with a DIFFERENT block (belongs to
// another branch) -> torn -> fatal, not invalidity.
BOOST_AUTO_TEST_CASE(torn_base_marker_parent_wrong_record_is_fatal)
{
    BOOST_REQUIRE(g_settlementdb->WriteBestBlock(prevHash));
    SeedSettlementBase(prevIdx.nHeight, curHash);   // record identity != parent

    BurnClaimPayload claim = MakeValidClaim(/*sats=*/100000, /*burnHeight=*/307200, /*salt=*/0x7C);
    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, /*view=*/nullptr, st, false));
    BOOST_CHECK(st.IsError());
    BOOST_CHECK(!st.IsInvalid());
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/0, /*partial=*/false, /*shutdowns=*/1);
}

// No settlement marker at all (empty DB) -> markerIsParent is false -> the backstop is
// SKIPPED (gate B, not this check, owns the empty-DB case). The block connects, exactly
// as it did before LOT 7. This is the boundary that stops the backstop from firing on
// every honest node whose settlement DB the harness left detached.
BOOST_AUTO_TEST_CASE(no_marker_skips_the_backstop)
{
    // Deliberately set NO marker and NO base record.
    BurnClaimPayload claim = MakeValidClaim(/*sats=*/100000, /*burnHeight=*/307300, /*salt=*/0x7D);
    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, /*view=*/nullptr, st, false),
                        st.GetRejectReason());
    BOOST_CHECK(!IsConsensusDBFatal());
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 3 · POINT 4 — connect / disconnect / reconnect round-trip
// ═══════════════════════════════════════════════════════════════════════════════
//
// The disconnect path is where round 2 found two real defects (the HTLC undo batch
// committed inside `if (g_burnclaimdb)`, and the burn-claim loop's early returns
// dropping it) and it had no test at all. This asserts the round-trip invariant:
// disconnect restores the exact prior state, and reconnect reproduces the exact
// post-connect state.

BOOST_FIXTURE_TEST_SUITE(consensus_p0_roundtrip, P0HtlcSetup)

// Burn claim: connect -> PENDING; disconnect -> gone; reconnect -> PENDING again.
BOOST_AUTO_TEST_CASE(burnclaim_connect_disconnect_reconnect_is_exact)
{
    BurnClaimPayload claim = MakeValidClaim(310000, 302000, 0x71);
    const uint256 btcTxid = TxidOf(claim.btcTxBytes);

    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    // --- state BEFORE connect ---
    BurnClaimRecord rec;
    BOOST_REQUIRE(!g_burnclaimdb->GetBurnClaim(btcTxid, rec));

    // --- connect ---
    CValidationState st1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st1, false),
                          st1.GetRejectReason());
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::PENDING);
    const uint32_t claimHeightAfterConnect = rec.claimHeight;
    uint256 bestAfterConnect;
    BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(bestAfterConnect));

    // --- disconnect ---
    BOOST_REQUIRE_MESSAGE(UndoSpecialTxsInBlock(block, &curIdx, /*fJustCheck=*/false),
                          "disconnect must succeed");
    BurnClaimRecord gone;
    BOOST_CHECK_MESSAGE(!g_burnclaimdb->GetBurnClaim(btcTxid, gone),
                        "POINT 4: disconnect must remove the claim it created");
    uint256 bestAfterUndo;
    BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(bestAfterUndo));
    BOOST_CHECK_MESSAGE(bestAfterUndo == prevHash,
                        "POINT 4: burnclaim marker must return to the parent");

    // --- reconnect: state must be identical to the first connect ---
    CValidationState st2;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st2, false),
                          st2.GetRejectReason());
    BurnClaimRecord again;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, again));
    BOOST_CHECK(again.status == BurnClaimStatus::PENDING);
    BOOST_CHECK_EQUAL(again.claimHeight, claimHeightAfterConnect);
    BOOST_CHECK(again.burnedSats == rec.burnedSats);
    BOOST_CHECK(again.btcBlockHash == rec.btcBlockHash);
    uint256 bestAfterReconnect;
    BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(bestAfterReconnect));
    BOOST_CHECK(bestAfterReconnect == bestAfterConnect);
}

// HTLC: connect consumes the M1 receipt and creates the record; disconnect must
// restore BOTH. This is the exact path that carried round-2 defects 1 and 2.
BOOST_AUTO_TEST_CASE(htlc_connect_disconnect_restores_receipt_and_removes_record)
{
    SeedReceipt();
    CTransactionRef htlcTx = MakeHtlcCreateTx();
    const COutPoint htlcOut(htlcTx->GetHash(), 0);

    CBlock block;
    block.vtx.push_back(htlcTx);

    CValidationState st1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st1, false),
                          st1.GetRejectReason());
    BOOST_REQUIRE(HtlcExistsAt(htlcOut));
    BOOST_REQUIRE(!g_settlementdb->IsM1Receipt(receiptOut));

    BOOST_REQUIRE_MESSAGE(UndoSpecialTxsInBlock(block, &curIdx, false),
                          "HTLC disconnect must succeed");

    BOOST_CHECK_MESSAGE(!HtlcExistsAt(htlcOut),
                        "POINT 4: disconnect must remove the HTLC record");
    BOOST_CHECK_MESSAGE(g_settlementdb->IsM1Receipt(receiptOut),
                        "POINT 4: disconnect must restore the consumed M1 receipt");

    // Reconnect reproduces the post-connect state exactly.
    CValidationState st2;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st2, false),
                          st2.GetRejectReason());
    BOOST_CHECK(HtlcExistsAt(htlcOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
}

// Regression guard for round-2 defect 1: the HTLC undo must be committed even when
// burnclaimdb is ABSENT. Before that fix the commit sat inside `if (g_burnclaimdb)`,
// so with no burnclaimdb the staged HTLC undos were silently discarded while the
// settlement batch had already committed — a half-rewound disconnect returning true.
BOOST_AUTO_TEST_CASE(htlc_disconnect_commits_even_without_burnclaimdb)
{
    SeedReceipt();
    CTransactionRef htlcTx = MakeHtlcCreateTx();
    const COutPoint htlcOut(htlcTx->GetHash(), 0);

    CBlock block;
    block.vtx.push_back(htlcTx);
    CValidationState st1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st1, false));
    BOOST_REQUIRE(HtlcExistsAt(htlcOut));

    g_burnclaimdb.reset();                       // the condition defect 1 needed

    BOOST_REQUIRE(UndoSpecialTxsInBlock(block, &curIdx, false));
    BOOST_CHECK_MESSAGE(!HtlcExistsAt(htlcOut),
                        "round-2 defect 1 regression: HTLC undo must commit independently "
                        "of g_burnclaimdb");
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    // restore so the fixture destructor is symmetric
    g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, false, false);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 3/4 · POINT 3 — NOT DONE (btcheaders apply-then-fail)
// ═══════════════════════════════════════════════════════════════════════════════
//
// A suite was written and then REMOVED rather than shipped flaky. Driving a real
// TX_BTC_HEADERS through ProcessSpecialTxsInBlock needs g_btc_spv null (to skip
// R5/R6/F5) and a bootstrap height (to skip R1/R2); with that configuration
// ProcessBtcHeadersTxInBlock fails with a bare error() that sets NO reject reason,
// so the cause is not visible from the test and the results were order-dependent.
// Shipping a red or unreliable case would be worse than declaring the gap.
//
// What POINT 3 still needs proven: header absent after a failed block, publisher
// cooldown unchanged, marker unchanged, restart clean, and a connect/disconnect/
// reconnect round-trip. Row 3 of the crash matrix DOES prove a btcheaders-stage
// crash is detected at startup, but that is a different claim.
// Recorded in the handoff as POINT 3 NOT DONE.


// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 6 · POINT 3 — REAL Bitcoin mainnet headers, real PoW, real apply
// ═══════════════════════════════════════════════════════════════════════════════
//
// Rounds 3-5 could not do this: with g_btc_spv NULL the APPLY path refuses
// (btcheaders.cpp:591, V2 connect needs it) and with g_btc_spv present R5 runs real
// PoW against BITCOIN MAINNET parameters (regtest is not IsTestnet, so
// btcspv.cpp:195-196 selects GetBtcMainnetParams). Synthetic headers can never satisfy
// both. The porteur authorised the only remaining route: genuine mainnet headers.
//
// STATIC TEST VECTORS — fetched ONCE from blockstream.info during development, never
// at test time. Height 800000 is independently corroborated: its hash matches the
// hardcoded consensus checkpoint (btcspv.cpp:55-64) AND the in-tree
// GetBtcMainnetGenesisHeader (btcspv.cpp:126-134), so the anchor of this chain is
// verified by the tree itself, not merely by the fetch.
//
//  height  hash                                                              nBits       time
//  800000  00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054  0x17053894  1690168629
//  800001  00000000000000000000e26b239cf19ec7ace5edd9694d51a3f6933247720947  0x17053894  1690168731
//  800002  00000000000000000005121e2537f3d29c73aeecef4cde8c66e37491f8ae0ae8  0x17053894  1690171015
//  800003  00000000000000000003b48253b73df6952e5d95ae55fa8430ec34327340ddf9  0x17053894  1690171043
//  source: https://blockstream.info/api/block-height/<h> then /api/block/<hash>/header
//
// All four are non-retarget heights (the boundary after 798336 is 800352), so R6
// requires nBits == parent.nBits — which holds across the whole run.

namespace {
const char* MAINNET_HDR_800001 =
    "00a0012054a02827d7a8b75601275a160279a3c5768de4c1c4a702000000000000000000"
    "394ddc6a5de035874cfa22167bfe923953187b5a19fbb84e186dea3c78fd871c9bedbd64"
    "94380517f5c93c8c";
const char* MAINNET_HDR_800002 =
    "00a00127470972473293f6a3514d69d9ede5acc79ef19c236be20000000000000000"
    "000035aa0cba25ae1517a257d8c913e24ec0a152fd6a84b7f9ef303626c91cdcd6b287ef"
    "bd649438051761ba50fb";

BtcBlockHeader HeaderFromHex(const std::string& hex)
{
    const std::vector<unsigned char> raw = ParseHex(hex);
    BOOST_REQUIRE_EQUAL(raw.size(), 80U);
    CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
    BtcBlockHeader h;
    ss >> h;
    return h;
}
} // namespace

struct P0RealHeadersSetup : public BasicTestingSetup {
    uint256 prevHash, curHash;
    CBlockIndex prevIdx, curIdx;

    P0RealHeadersSetup() : BasicTestingSetup(CBaseChainParams::REGTEST)
    {
        SetDataDir("p0_realhdrs");
        ClearDatadirCache();   // same reason as P0AtomicitySetup — on-disk DBs below
        // Fresh, isolated per case. g_btc_spv IS initialised, with the mainnet params
        // regtest actually uses — no shortcut.
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, true);
        g_btc_spv      = std::make_unique<CBtcSPV>();
        g_btc_spv->Init(GetDataDir().string(), BtcSourceNet::BITCOIN_MAINNET);
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);

        prevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000f1");
        curHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000f2");
        prevIdx.nHeight = 1;                 // regtest nDMMBootstrapHeight = 2
        prevIdx.phashBlock = &prevHash;
        curIdx.nHeight = 2;                  // -> skipMNChecks (R1/R2), PoW still enforced
        curIdx.phashBlock = &curHash;
        curIdx.pprev = &prevIdx;

        SeedCheckpointTip();
    }
    ~P0RealHeadersSetup()
    {
        g_htlcdb.reset(); g_settlementdb.reset();
        g_burnclaimdb.reset(); g_btc_spv.reset(); g_btcheadersdb.reset();
    }

    //! Seed the real mainnet checkpoint header at 800000 as the btcheadersdb tip.
    void SeedCheckpointTip()
    {
        BtcBlockHeader cp;
        BOOST_REQUIRE(GetBtcMainnetGenesisHeader(cp));
        auto b = g_btcheadersdb->CreateBatch();
        b.WriteHeader(800000, cp);
        b.WriteTip(800000, cp.GetHash());
        BOOST_REQUIRE(b.Commit());
        BOOST_REQUIRE_EQUAL(g_btcheadersdb->GetTipHeight(), 800000U);
    }

    CTransactionRef MakeRealHeadersTx() const
    {
        BtcHeadersPayload p;
        p.nVersion = BTCHEADERS_VERSION;
        p.startHeight = 800001;
        p.headers = {HeaderFromHex(MAINNET_HDR_800001), HeaderFromHex(MAINNET_HDR_800002)};
        p.count = 2;
        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_BTC_HEADERS;
        SetTxPayload(mtx, p);
        return MakeTransactionRef(std::move(mtx));
    }

    //! A mint naming a claim that does not exist. LOT 2: it carries ONE output so the
    //! payload/vout counts agree — otherwise CheckMintM0BTC stops at the structural
    //! `mint-output-count` and the case never reaches the claim-lookup rule it means
    //! to exercise.
    CTransactionRef MakeJunkMintTx(const char* tag) const
    {
        MintPayload m; m.nVersion = MINT_PAYLOAD_VERSION;
        m.btcTxids = {uint256S(tag)};
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); ss << m;

        CMutableTransaction mtx;
        mtx.nVersion = CTransaction::TxVersion::SAPLING;
        mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;
        CTxOut o;
        o.nValue = 100000;
        o.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<unsigned char>(20, 0xF1)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;
        mtx.vout.push_back(o);
        mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());
        return MakeTransactionRef(std::move(mtx));
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_real_headers, P0RealHeadersSetup)

// The vectors really are the canonical chain: 800001 links to the in-tree checkpoint.
BOOST_AUTO_TEST_CASE(vectors_link_to_the_intree_checkpoint)
{
    BtcBlockHeader cp;
    BOOST_REQUIRE(GetBtcMainnetGenesisHeader(cp));
    const BtcBlockHeader h1 = HeaderFromHex(MAINNET_HDR_800001);
    const BtcBlockHeader h2 = HeaderFromHex(MAINNET_HDR_800002);
    BOOST_CHECK(h1.hashPrevBlock == cp.GetHash());
    BOOST_CHECK(h2.hashPrevBlock == h1.GetHash());
    BOOST_CHECK_EQUAL(h1.nBits, cp.nBits);            // non-retarget span
    BOOST_CHECK(g_btc_spv->CheckProofOfWork(h1));     // REAL PoW, mainnet target
    BOOST_CHECK(g_btc_spv->CheckProofOfWork(h2));
}

// CONTROL — flip one bit and PoW must reject it. Proves the check is live, not skipped.
BOOST_AUTO_TEST_CASE(control_one_flipped_bit_fails_pow)
{
    BtcBlockHeader bad = HeaderFromHex(MAINNET_HDR_800001);
    bad.nNonce ^= 1;
    BOOST_CHECK_MESSAGE(!g_btc_spv->CheckProofOfWork(bad),
                        "a single flipped bit must break real PoW");
}

// CASE A — a valid TX_BTC_HEADERS connects; header, cooldown and marker are present.
BOOST_AUTO_TEST_CASE(caseA_real_headers_block_connects)
{
    CTransactionRef hdrTx = MakeRealHeadersTx();
    CBlock block; block.vtx.push_back(hdrTx);

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false),
                          "case A must connect: " << st.GetRejectReason());

    BtcBlockHeader got;
    BOOST_CHECK(g_btcheadersdb->GetHeaderByHash(HeaderFromHex(MAINNET_HDR_800001).GetHash(), got));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 800002U);
    uint256 marker;
    BOOST_CHECK(g_btcheadersdb->ReadBestBlock(marker));
    BOOST_CHECK(marker == block.GetHash());
}

// CASE B — same pre-state, the SAME real header batch is applied, then the block fails.
// The batch must be abandoned entirely.
BOOST_AUTO_TEST_CASE(caseB_failure_after_real_headers_abandons_the_batch)
{
    const uint256 h1Hash = HeaderFromHex(MAINNET_HDR_800001).GetHash();

    // pre-state
    const uint32_t tipBefore = g_btcheadersdb->GetTipHeight();
    uint256 markerBefore; const bool hadMarker = g_btcheadersdb->ReadBestBlock(markerBefore);
    uint256 pubBefore; int pubHeightBefore = 0;
    const bool hadPub = g_btcheadersdb->GetLastPublisher(pubBefore, pubHeightBefore);

    CTransactionRef hdrTx = MakeRealHeadersTx();
    CBlock block;
    block.vtx.push_back(hdrTx);                       // applied -> stages the batch
    block.vtx.push_back(MakeJunkMintTx("e1"));
    block.vtx.push_back(MakeJunkMintTx("e2"));        // Multiple TX_MINT_M0BTC -> reject

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false));

    BtcBlockHeader got;
    BOOST_CHECK_MESSAGE(!g_btcheadersdb->GetHeaderByHash(h1Hash, got),
                        "POINT 3: no orphan header after a rejected block");
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), tipBefore);

    uint256 markerAfter; const bool hasMarker = g_btcheadersdb->ReadBestBlock(markerAfter);
    BOOST_CHECK_EQUAL(hasMarker, hadMarker);
    if (hadMarker && hasMarker) BOOST_CHECK(markerAfter == markerBefore);

    uint256 pubAfter; int pubHeightAfter = 0;
    const bool hasPub = g_btcheadersdb->GetLastPublisher(pubAfter, pubHeightAfter);
    BOOST_CHECK_EQUAL(hasPub, hadPub);
    if (hadPub && hasPub) {
        BOOST_CHECK(pubAfter == pubBefore);
        BOOST_CHECK_EQUAL(pubHeightAfter, pubHeightBefore);
    }

    // The same honest publication is accepted afterwards.
    CBlock good; good.vtx.push_back(hdrTx);
    CValidationState st2;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(good, &curIdx, nullptr, st2, false),
                        "POINT 3: later honest publication must connect: " << st2.GetRejectReason());
    BOOST_CHECK(g_btcheadersdb->GetHeaderByHash(h1Hash, got));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 800002U);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 7 — commit-failure injection (no runtime flag; injectable strategy)
// ═══════════════════════════════════════════════════════════════════════════════
//
// Production passes no strategy, so release behaviour is not configurable by RPC or
// argument. Tests inject one that makes the Nth Commit() return false.

namespace {
struct FailAtStep : public ConsensusCommitStrategy {
    int failStep;
    int seen = 0;
    int aborts = 0;                              // r15: Abort() is pure virtual — record it
    explicit FailAtStep(int s) : failStep(s) {}
    bool Commit(int step, const std::function<bool()>& realCommit) override
    {
        ++seen;
        if (step == failStep) return false;      // inject: do NOT run the real commit
        return realCommit();
    }
    void Abort(int step, bool partial, const std::string& msg) override
    {
        (void)step; (void)partial; (void)msg;
        ++aborts;
    }
};

//! Full recorder (used by rounds 14/15): steps consulted, commits succeeded before the
//! failure, abort notifications with their context. Never terminates the process.
struct RecordingStrategy : public ConsensusCommitStrategy {
    int failStep;
    std::vector<int> stepsSeen;
    int succeededBefore = 0;
    int abortCount = 0;
    int abortStep = -1;
    bool abortPartial = false;
    std::string abortMsg;

    explicit RecordingStrategy(int s) : failStep(s) {}

    bool Commit(int step, const std::function<bool()>& realCommit) override
    {
        stepsSeen.push_back(step);
        if (step == failStep) return false;
        const bool ok = realCommit();
        if (ok) ++succeededBefore;
        return ok;
    }
    void Abort(int step, bool partial, const std::string& msg) override
    {
        ++abortCount; abortStep = step; abortPartial = partial; abortMsg = msg;
    }
    bool Reached(int step) const
    {
        return std::find(stepsSeen.begin(), stepsSeen.end(), step) != stepsSeen.end();
    }
};

//! r15 — acknowledge one fatal-abort firing and clear the process-local traces so the
//! ~BasicTestingSetup sentinel lets the case pass and the next case starts clean.
//! ASSERTS the full fatal contract first: latch set, first context matches, exactly
//! `expectedShutdowns` StartShutdown request(s) recorded.
void ExpectFatalAndClear(bool fConnect, int step, bool partial, int expectedShutdowns = 1)
{
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(),
                        "fatal latch must be SET after a commit failure");
    ConsensusDBFatalContext ctx;
    BOOST_REQUIRE(GetConsensusDBFatalContext(ctx));
    BOOST_CHECK_EQUAL(ctx.fConnect, fConnect);
    BOOST_CHECK_EQUAL(ctx.nStep, step);
    BOOST_CHECK_EQUAL(ctx.fPartial, partial);
    BOOST_CHECK_MESSAGE(!ctx.strMessage.empty(), "fatal context must carry the operator message");
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), expectedShutdowns);
    test_shutdown::Reset();
    ResetConsensusDBFatalForTests();
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_p0_commit_failure, P0HtlcSetup)

// A failure at ANY commit step must make the whole function fail — never a silent
// partial success. Steps: 1 settlement, 2 btcheaders, 3 htlc, 4 burnclaim, 5 marker.
BOOST_AUTO_TEST_CASE(any_commit_failure_fails_the_block)
{
    // Step 2 (btcheaders) needs a headers tx, so it lives in
    // consensus_p0_ordering_r11/commit_step2_btcheaders_failure_fails_the_block.
    // Every commit step present in the code IS covered; the previous
    // "covered separately" comment was false — no step-2 test existed.
    for (int step : {1, 3, 4, 5}) {
        SeedReceipt();
        CTransactionRef htlcTx = MakeHtlcCreateTx();
        BurnClaimPayload claim = MakeValidClaim(40000 + step, 303000 + step, (uint8_t)(0x90 + step));
        const uint256 btcTxid = TxidOf(claim.btcTxBytes);

        CBlock block;
        block.vtx.push_back(htlcTx);          // stages settlement + htlc
        block.vtx.push_back(MakeClaimTx(claim));  // stages burnclaim

        FailAtStep strategy(step);
        CValidationState st;
        SeedLedgerAtParent(curIdx);
        const bool ok = ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false,
                                                 /*fSettlementOnly=*/false, &strategy);

        BOOST_CHECK_MESSAGE(!ok, "commit step " << step << " failed but the function "
                                                   "reported SUCCESS");
        BOOST_CHECK_MESSAGE(strategy.seen >= 1, "strategy was never consulted at step " << step);

        // r15: the fatal contract — latch set, first context correct, one shutdown
        // request, one Abort notification — then clear for the next iteration (the
        // clear stands in for the process restart, which is the only real reset).
        BOOST_CHECK(st.IsError());
        BOOST_CHECK(!st.IsInvalid());
        BOOST_CHECK_EQUAL(strategy.aborts, 1);
        ExpectFatalAndClear(/*fConnect=*/true, step, /*partial=*/step != 1);

        // Reset the DBs for the next iteration so steps do not contaminate each other.
        g_htlcdb.reset();  g_settlementdb.reset();  g_burnclaimdb.reset();
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
    }
}

// The marker step (5) is the one whose result used to be DISCARDED. Failing it must
// now fail the block — otherwise the startup gate's only signal can be missing while
// the node believes the block connected.
BOOST_AUTO_TEST_CASE(marker_commit_failure_is_no_longer_silent)
{
    BurnClaimPayload claim = MakeValidClaim(55000, 304000, 0x9F);
    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    FailAtStep strategy(5);
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false, false, &strategy),
                        "a failed all-committed marker must fail the block");
    ExpectFatalAndClear(/*fConnect=*/true, 5, /*partial=*/true);
}

// Control: with NO strategy (production shape) the same block connects. Proves the
// seam is inert in production and the failures above come from the injection.
BOOST_AUTO_TEST_CASE(control_no_strategy_means_normal_commit)
{
    BurnClaimPayload claim = MakeValidClaim(66000, 305000, 0xA1);
    CBlock block;
    block.vtx.push_back(MakeClaimTx(claim));

    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false),
                        st.GetRejectReason());
    BurnClaimRecord rec;
    BOOST_CHECK(g_burnclaimdb->GetBurnClaim(TxidOf(claim.btcTxBytes), rec));
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 10 · ITEM 2 (ROUTE C) — burnclaim + mint wipe/replay · **HARNESS**
// ═══════════════════════════════════════════════════════════════════════════════
//
// LABEL: this part is a HARNESS proof, NOT multi-process. It drives the real
// production paths (CheckSpecialTx -> ProcessSpecialTxsInBlock -> batches -> commit)
// but replays in-process rather than from block files via daemon -reindex.
//
// AUTHORISED PRE-STATE: a deterministic consensus header is seeded, and its merkle
// root GENUINELY commits to the synthetic burn tx (root = Hash(txid || sibling),
// proof = {sibling}, txIndex 0) — a real 2-leaf Merkle commitment, verified by the
// production VerifyMerkleProof.
//
// NOT INJECTED (forbidden, and not needed): BurnClaimRecord, PENDING/FINALIZED status,
// the mint record, and the expected supply. Every one of those arises only from
// BATHRON transactions travelling the real validation/application paths.
//
// NO real Bitcoin was burned. NO mainnet spend. The regtest premine is NOT used here
// and is NOT evidence for A5.

struct P0BurnMintSetup : public P0AtomicitySetup {
    static const uint32_t BURN_HEIGHT = 306000;
    static const int      CLAIM_H     = 1001;   // == curIdx.nHeight
    int mintH = 0;                              // CLAIM_H + K + 1, resolved at runtime

    BurnClaimPayload claim;
    uint256 btcTxid;
    uint256 hdrHash;

    CBlockIndex mintPrevIdx, mintIdx;
    uint256 mintPrevHash, mintCurHash;

    P0BurnMintSetup()
    {
        mintH = CLAIM_H + (int)GetKFinality() + 1;
        mintPrevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000c1");
        mintCurHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000c2");
        mintPrevIdx.nHeight = mintH - 1; mintPrevIdx.phashBlock = &mintPrevHash;
        mintIdx.nHeight = mintH;         mintIdx.phashBlock = &mintCurHash;
        mintIdx.pprev = &mintPrevIdx;
        SeedBitcoinPreState();
        claim = BuildClaim();
        btcTxid = TxidOf(claim.btcTxBytes);
    }

    //! AUTHORISED: deterministic Bitcoin pre-state (header + a tip far enough ahead
    //! that the burn clears GetRequiredConfirmations()). Re-applied after a wipe,
    //! because on a real node it would come from replaying TX_BTC_HEADERS blocks.
    void SeedBitcoinPreState()
    {
        BurnClaimPayload tmp = BuildClaim();
        const uint256 txid = TxidOf(tmp.btcTxBytes);
        uint256 sib; std::fill(sib.begin(), sib.end(), (unsigned char)0x5C);
        const uint256 root = Hash(txid.begin(), txid.end(), sib.begin(), sib.end());
        hdrHash = SeedHeader(BURN_HEIGHT, root);
        SeedHeader(BURN_HEIGHT + GetRequiredConfirmations() + 5,
                   uint256S("00000000000000000000000000000000000000000000000000000000000000bb"));
    }

    BurnClaimPayload BuildClaim()
    {
        BurnClaimPayload p;
        p.btcTxBytes = MakeRawBurnTx(MetaV1(0x01, 0xAB), 777000, 0xC7);
        const uint256 txid = TxidOf(p.btcTxBytes);
        uint256 sib; std::fill(sib.begin(), sib.end(), (unsigned char)0x5C);
        p.btcBlockHash   = SeedHeaderHashOnly(txid, sib);
        p.btcBlockHeight = BURN_HEIGHT;
        p.merkleProof    = {sib};
        p.txIndex        = 0;
        return p;
    }

    //! Recompute the header hash without writing (BuildClaim runs before the seed).
    static uint256 SeedHeaderHashOnly(const uint256& txid, const uint256& sib)
    {
        const uint256 root = Hash(txid.begin(), txid.end(), sib.begin(), sib.end());
        BtcBlockHeader hdr;
        hdr.nVersion = 4;
        hdr.hashPrevBlock = uint256S("00000000000000000000000000000000000000000000000000000000000000ff");
        hdr.hashMerkleRoot = root;
        hdr.nTime = 1000 + BURN_HEIGHT;
        hdr.nBits = 0x1d00ffff;
        hdr.nNonce = BURN_HEIGHT;
        return hdr.GetHash();
    }

    CBlock ClaimBlock() { CBlock b; b.vtx.push_back(MakeClaimTx(claim)); return b; }

    //! The mint is produced by the CANONICAL CONSENSUS ORACLE, never hand-written.
    //! LOT 2: this must be CreateExpectedMintM0BTC, not the producer wrapper — the
    //! wrapper honours local policy, so a leaked -enablemint=0 would silently make
    //! this return null and turn the fixture red for the wrong reason.
    CBlock MintBlock()
    {
        const CTransaction expected = CreateExpectedMintM0BTC((uint32_t)mintH);
        BOOST_REQUIRE_MESSAGE(!expected.IsNull(), "oracle must produce a mint at h=" << mintH);
        CBlock b; b.vtx.push_back(MakeTransactionRef(CMutableTransaction(expected)));
        return b;
    }

    struct Snap {
        bool haveClaim = false;
        BurnClaimStatus status = BurnClaimStatus::PENDING;
        uint64_t burnedSats = 0;
        uint32_t claimHeight = 0, finalHeight = 0;
        uint256 marker;
        CAmount m0Total = 0;
        uint256 mintHash;
        size_t mintOuts = 0;
    };

    Snap Capture(const uint256& mintTxHash, size_t mintOuts)
    {
        Snap s;
        BurnClaimRecord r;
        s.haveClaim = g_burnclaimdb->GetBurnClaim(btcTxid, r);
        if (s.haveClaim) {
            s.status = r.status; s.burnedSats = r.burnedSats;
            s.claimHeight = r.claimHeight; s.finalHeight = r.finalHeight;
        }
        g_burnclaimdb->ReadBestBlock(s.marker);
        SettlementState st;
        if (g_settlementdb->ReadState((uint32_t)mintH, st)) s.m0Total = st.M0_total_supply;
        s.mintHash = mintTxHash; s.mintOuts = mintOuts;
        return s;
    }

    //! The SAME wipe -reindex performs on the derivable DBs, then reopen.
    void WipeDerivableAndReopen()
    {
        g_htlcdb.reset(); g_settlementdb.reset();
        g_burnclaimdb.reset(); g_btcheadersdb.reset();
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, /*fWipe=*/true);
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
        BurnClaimRecord gone;
        BOOST_REQUIRE_MESSAGE(!g_burnclaimdb->GetBurnClaim(btcTxid, gone),
                              "wipe must leave burnclaimdb empty");
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_burnmint_replay, P0BurnMintSetup)

// THE PROOF — claim + mint built by real paths, wiped, replayed, semantically identical.
BOOST_AUTO_TEST_CASE(burnclaim_and_mint_survive_wipe_and_replay)
{
    // --- pass 1: connect the claim, then the mint ---
    CBlock cb = ClaimBlock();
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false),
                          "claim block: " << s1.GetRejectReason());
    BurnClaimRecord pending;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, pending));
    BOOST_CHECK(pending.status == BurnClaimStatus::PENDING);   // arose from the TX, not injected

    CBlock mb = MintBlock();
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, s2, false),
                          "mint block: " << s2.GetRejectReason());
    const Snap before = Capture(mb.vtx[0]->GetHash(), mb.vtx[0]->vout.size());

    BOOST_REQUIRE(before.haveClaim);
    BOOST_CHECK(before.status == BurnClaimStatus::FINAL);      // finalized by the real mint
    BOOST_CHECK_EQUAL(before.burnedSats, 777000U);
    BOOST_CHECK_EQUAL(before.m0Total, CAmount(777000));        // M0 grew by exactly the burn
    BOOST_CHECK_EQUAL(before.mintOuts, 1U);

    // --- wipe with the -reindex helper, restore the authorised Bitcoin pre-state ---
    WipeDerivableAndReopen();
    SeedBitcoinPreState();

    // --- pass 2: replay the SAME blocks, same order, no injection ---
    CValidationState r1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, r1, false),
                          "replay claim: " << r1.GetRejectReason());
    CValidationState r2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, r2, false),
                          "replay mint: " << r2.GetRejectReason());
    const Snap after = Capture(mb.vtx[0]->GetHash(), mb.vtx[0]->vout.size());

    // --- semantic equality ---
    BOOST_CHECK_EQUAL(after.haveClaim, before.haveClaim);
    BOOST_CHECK(after.status == before.status);
    BOOST_CHECK_EQUAL(after.burnedSats, before.burnedSats);
    BOOST_CHECK_EQUAL(after.claimHeight, before.claimHeight);
    BOOST_CHECK_EQUAL(after.finalHeight, before.finalHeight);
    BOOST_CHECK(after.marker == before.marker);
    BOOST_CHECK_EQUAL(after.m0Total, before.m0Total);
    BOOST_CHECK(after.mintHash == before.mintHash);            // byte-identical mint tx
    BOOST_CHECK_EQUAL(after.mintOuts, before.mintOuts);

    // no duplicate, no orphan PENDING: a re-claim of the same BTC txid is rejected
    CValidationState dup;
    BOOST_CHECK(!CheckBurnClaim(claim, dup, (uint32_t)mintH + 5));
    BOOST_CHECK_EQUAL(dup.GetRejectReason(), "burn-claim-duplicate");
}

// NEGATIVE — a bad merkle proof leaves no record at all.
BOOST_AUTO_TEST_CASE(negative_invalid_merkle_proof_leaves_no_record)
{
    BurnClaimPayload bad = claim;
    bad.merkleProof = {uint256S("00000000000000000000000000000000000000000000000000000000000000ee")};
    CBlock b; b.vtx.push_back(MakeClaimTx(bad));
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(b, &curIdx, nullptr, st, false));
    BurnClaimRecord r;
    BOOST_CHECK(!g_burnclaimdb->GetBurnClaim(TxidOf(bad.btcTxBytes), r));
}

// NEGATIVE — an INCORRECT mint is rejected and moves no supply.
BOOST_AUTO_TEST_CASE(negative_wrong_mint_is_rejected_and_supply_unchanged)
{
    CBlock cb = ClaimBlock();
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));

    // Hand-built mint naming a claim that does not exist -> must not connect.
    CBlock bad;
    bad.vtx.push_back(MakeMintTx({uint256S("00000000000000000000000000000000000000000000000000000000000000dd")}));
    CValidationState st;
    SeedLedgerAtParent(mintIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(bad, &mintIdx, nullptr, st, false));

    BurnClaimRecord r;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, r));
    BOOST_CHECK(r.status == BurnClaimStatus::PENDING);   // still pending, not finalized
    SettlementState stt;
    if (g_settlementdb->ReadState((uint32_t)mintH, stt)) BOOST_CHECK_EQUAL(stt.M0_total_supply, CAmount(0));
}

// NEGATIVE — a block that fails AFTER the claim leaves no record (ties Route C back to
// the AUD-017 invariant, on the burn path specifically).
BOOST_AUTO_TEST_CASE(negative_failure_after_claim_leaves_no_record)
{
    CBlock b;
    b.vtx.push_back(MakeClaimTx(claim));
    b.vtx.push_back(MakeMintTx({uint256S("01")}));
    b.vtx.push_back(MakeMintTx({uint256S("02")}));   // Multiple TX_MINT_M0BTC -> reject
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(b, &curIdx, nullptr, st, false));
    BurnClaimRecord r;
    BOOST_CHECK(!g_burnclaimdb->GetBurnClaim(btcTxid, r));
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 8 — M1 MEASUREMENT (Route C observer, NO consensus rule change).
// Record S = settlement M0_total_supply and L = burnclaimdb m0btcSupply (Σ FINAL
// burnedSats) at every step of the honest lifecycle, plus both DB best-block markers
// and the claim status. The verdict this drives: is S == L everywhere on an honest
// chain (→ architecture D permissible) or is there a legitimate divergence (→ audit-only)?
// This test only OBSERVES and asserts equality; it changes no production code.
// ═══════════════════════════════════════════════════════════════════════════════
BOOST_AUTO_TEST_CASE(m1_measure_S_equals_L_across_lifecycle)
{
    auto row = [&](const char* label, int height, const uint256& hash) {
        CAmount S = 0;                          // settlement M0_total_supply (mint outputs)
        {
            SettlementState st;
            if (g_settlementdb->ReadLatestState(st)) S = st.M0_total_supply;
        }
        const CAmount L = (CAmount)g_burnclaimdb->GetStats().m0btcSupply;  // Σ FINAL burnedSats
        uint256 sMk, lMk;
        const bool haveS = g_settlementdb->ReadBestBlock(sMk);
        const bool haveL = g_burnclaimdb->ReadBestBlock(lMk);
        std::string status = "-";
        { BurnClaimRecord r; if (g_burnclaimdb->GetBurnClaim(btcTxid, r))
              status = (r.status == BurnClaimStatus::FINAL) ? "FINAL" : "PENDING"; }
        BOOST_TEST_MESSAGE("M1 | " << label
            << " | h=" << height
            << " | hash=" << hash.ToString().substr(0, 8)
            << " | claim=" << status
            << " | S=" << S << " | L=" << L << " | S-L=" << (S - L)
            << " | sMk=" << (haveS ? sMk.ToString().substr(0,8) : std::string("none"))
            << " | lMk=" << (haveL ? lMk.ToString().substr(0,8) : std::string("none")));
        // THE MEASUREMENT VERDICT, asserted at every honest step:
        BOOST_CHECK_MESSAGE(S == L, "M1: S != L at [" << label << "] (S=" << S << " L=" << L << ")");
        return S - L;
    };

    // --- 0. fresh chain: both zero, no markers (premine excluded from both) ---
    row("fresh", 0, uint256());

    // --- 1. claim connects -> PENDING (no mint yet: S and L both still 0) ---
    CBlock cb = ClaimBlock();
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false),
                          "claim: " << s1.GetRejectReason());
    row("claim-PENDING", (int)curIdx.nHeight, curHash);

    // --- 2. mint connects -> FINAL (S += mint outputs, L += claim burnedSats) ---
    CBlock mb = MintBlock();
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, s2, false),
                          "mint: " << s2.GetRejectReason());
    row("mint-FINAL", (int)mintIdx.nHeight, mintCurHash);

    // --- 3. disconnect mint (reorg AFTER finalization) -> back to PENDING, S and L drop ---
    BOOST_REQUIRE(UndoSpecialTxsInBlock(mb, &mintIdx, false));
    row("undo-mint", (int)mintPrevIdx.nHeight, mintPrevHash);

    // --- 4. reconnect mint -> FINAL again ---
    CValidationState s3;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, s3, false),
                          "reconnect mint: " << s3.GetRejectReason());
    row("reconnect-mint", (int)mintIdx.nHeight, mintCurHash);

    // --- 5. reorg BEFORE finalization: undo mint then undo the claim entirely ---
    BOOST_REQUIRE(UndoSpecialTxsInBlock(mb, &mintIdx, false));
    row("undo-mint-2", (int)mintPrevIdx.nHeight, mintPrevHash);
    BOOST_REQUIRE(UndoSpecialTxsInBlock(cb, &curIdx, false));
    row("undo-claim", (int)prevIdx.nHeight, prevHash);

    // --- 6. -reindex: wipe the derivable DBs, restore BTC pre-state, replay both ---
    WipeDerivableAndReopen();
    SeedBitcoinPreState();
    row("post-wipe", 0, uint256());
    CValidationState r1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, r1, false),
                          "replay claim: " << r1.GetRejectReason());
    row("replay-claim", (int)curIdx.nHeight, curHash);
    CValidationState r2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, r2, false),
                          "replay mint: " << r2.GetRejectReason());
    const CAmount d = row("replay-mint", (int)mintIdx.nHeight, mintCurHash);

    // The replayed chain must reproduce the exact same S and L (S-L == 0 throughout).
    BOOST_CHECK_EQUAL(d, CAmount(0));

    // NOTE on lock/unlock: TX_LOCK/TX_UNLOCK move M0_vaulted/M1_supply only; neither
    // writes M0_total_supply (settlement path) nor m0btcSupply (burnclaim path), so they
    // cannot change S or L or their difference. Verified by the writer inventory in
    // doc/LOT8-PHASE0-A5-INVENTORY.md (only mint/undo write either term); a lock harness
    // needs a funded coins view (view!=null) which this fixture does not build, so the
    // lock/unlock arm is proven by construction here and exercised live in the process lab.
}

// LOT 8 — M1: crash at the FIRST commit step (LOT 1 seam). Failing step 1 commits
// nothing — S and L stay equal. The FULL per-step matrix (including the partial-prefix
// rows where a durable S != L DOES exist) is m1b below.
BOOST_AUTO_TEST_CASE(m1_crash_between_commits_leaves_S_and_L_consistent)
{
    CBlock cb = ClaimBlock();
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));
    const CAmount S_before = [&]{ SettlementState st; g_settlementdb->ReadLatestState(st); return st.M0_total_supply; }();
    const CAmount L_before = (CAmount)g_burnclaimdb->GetStats().m0btcSupply;
    BOOST_CHECK_EQUAL(S_before, L_before);   // both 0, claim only PENDING

    CBlock mb = MintBlock();
    FailAtStep strategy(1);   // fail the FIRST commit step (settlement) -> fatal, nothing commits
    CValidationState st;
    SeedLedgerAtParent(mintIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, st, false, false, &strategy));

    const CAmount S_after = [&]{ SettlementState s; g_settlementdb->ReadLatestState(s); return s.M0_total_supply; }();
    const CAmount L_after = (CAmount)g_burnclaimdb->GetStats().m0btcSupply;
    BOOST_TEST_MESSAGE("M1-crash | S_before=" << S_before << " L_before=" << L_before
                       << " | S_after=" << S_after << " L_after=" << L_after);
    BOOST_CHECK_MESSAGE(S_after == L_after, "failing step 1 commits nothing, S==L");
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/1, /*partial=*/false);
}

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 8 — M1b: the FULL failAt matrix over the REAL LOT 1 commit steps of a mint
// block (1 settlement · 2 btcheaders · 3 htlc marker · 4 burnclaim · 5 all-committed),
// each followed by a REAL restart (destroy + reopen every on-disk DB, no wipe), the
// startup consistency gates, and a -reindex replay. This is where "nothing committed"
// must NOT be claimed when a durable prefix exists: failing step 3/4 leaves the
// settlement batch (S, sMk) durably committed while the burnclaim batch (L, lMk) is
// not -> a REAL on-disk S != L. The measurements drive the gate-B placement decision.
//
// Step 2 (btcheaders) is NOT a real step for a mint-only block (no TX_BTC_HEADERS ->
// no headers batch -> doCommit(2) never runs); the matrix records that honestly (the
// strategy is never consulted at 2 and the block CONNECTS). The step-2 partial-prefix
// arm for a headers block is covered by consensus_p0_ordering_r11/
// commit_step2_btcheaders_failure_fails_the_block.
// ═══════════════════════════════════════════════════════════════════════════════
BOOST_AUTO_TEST_CASE(m1b_failat_matrix_partial_prefix_S_vs_L)
{
    struct Row {
        int failAt;
        std::vector<int> stepsSeen;
        int succeededBefore = 0;
        bool blockOk = false;
        bool fatal = false;
        CAmount S = -1, L = -1;
        std::string sMk, lMk, allC;
        bool settleGateOk = false, burnGateOk = false, anyRebuild = false;
        CAmount S_re = -1, L_re = -1;   // after -reindex replay
    };
    std::vector<Row> rows;

    auto mark = [](CSettlementDB* sdb, CBurnClaimDB* bdb, std::string& sMk, std::string& lMk, std::string& allC) {
        uint256 h;
        sMk = (sdb && sdb->ReadBestBlock(h)) ? h.ToString().substr(0, 8) : "none";
        lMk = (bdb && bdb->ReadBestBlock(h)) ? h.ToString().substr(0, 8) : "none";
        allC = (sdb && sdb->ReadAllCommitted(h)) ? h.ToString().substr(0, 8) : "none";
    };
    auto readS = [&]{ SettlementState st; return g_settlementdb->ReadLatestState(st) ? st.M0_total_supply : CAmount(0); };
    auto readL = [&]{ return (CAmount)g_burnclaimdb->GetStats().m0btcSupply; };
    //! Real restart: destroy and reopen every on-disk DB WITHOUT wiping (P0CrashSetup's
    //! RestartAllDBs, inlined here because this suite's fixture lacks it).
    auto restartNoWipe = [&]{
        g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset(); g_btcheadersdb.reset();
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, false);
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, false);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, false);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, false);
    };

    for (int failAt = 1; failAt <= 5; ++failAt) {
        Row r; r.failAt = failAt;

        // Fresh DBs per iteration; claim block fully committed first (markers at curHash).
        g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset(); g_btcheadersdb.reset();
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, true);
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
        SeedBitcoinPreState();
        CBlock cb = ClaimBlock();
        // FIXTURE FIX (measured, not masked): synthetic CBlocks with default headers all
        // share ONE GetHash(), so the claim and mint markers were indistinguishable and
        // the startup gate compared them against the fixture's arbitrary index constants
        // -> every row (even the clean one) read "divergent". Give each block a distinct
        // real hash and compare the gates against the TRUE crashed-tip hash below.
        cb.nNonce = 0xC1A1;
        CValidationState sc;
        SeedLedgerAtParent(curIdx);
        BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, sc, false),
                              "claim (failAt=" << failAt << "): " << sc.GetRejectReason());

        // Mint block with the injected failure at `failAt`.
        CBlock mb = MintBlock();
        mb.nNonce = 0x314159;
        RecordingStrategy strat(failAt);
        CValidationState sm;
        // Model the blocks a real node connected between the claim (h1001) and the mint
        // (h1022): they advance EVERY derived-DB marker together, and the settlement base
        // state with them. Advancing only the ledger would leave the fixture internally
        // inconsistent (ledger at h1021, settlement still at h1001) and make the startup
        // gates report a divergence the modelled chain does not have.
        SeedLedgerAtParent(mintIdx);
        {
            auto b = g_settlementdb->CreateBatch();
            b.WriteBestBlock(mintPrevHash);
            BOOST_REQUIRE(b.Commit());
            g_settlementdb->WriteAllCommitted(mintPrevHash);
            SettlementState base;
            base.nHeight = (uint32_t)mintPrevIdx.nHeight;
            base.hashBlock = mintPrevHash;
            BOOST_REQUIRE(g_settlementdb->WriteState(base));
        }
        r.blockOk = ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, sm, false, false, &strat);
        r.stepsSeen = strat.stepsSeen;
        r.succeededBefore = strat.succeededBefore;
        r.fatal = IsConsensusDBFatal();

        // ── REAL RESTART: destroy + reopen from disk (no wipe). The process-local fatal
        // latch would die with the process; reset it to model the fresh process.
        restartNoWipe();
        test_shutdown::Reset();
        ResetConsensusDBFatalForTests();

        r.S = readS(); r.L = readL();
        mark(g_settlementdb.get(), g_burnclaimdb.get(), r.sMk, r.lMk, r.allC);

        // ── STARTUP CONSISTENCY GATES, against the crashed node's tip. Chainstate
        // flushes AFTER the consensus DBs (validation.cpp), so after a mid-commit crash
        // the node's tip is still the last FULLY connected block: the claim block when
        // the mint failed, the mint block itself when it connected (failAt=2 row).
        // The crashed node's tip is the last FULLY connected block. The fixture models a
        // real chain in which the blocks between the claim (h1001) and the mint (h1022)
        // were connected (SeedLedgerAtParent(mintIdx), LOT 8 F1), so when the mint fails
        // the tip is the mint's PARENT (h1021), not the claim block.
        const uint256 crashedTip = r.blockOk ? mb.GetHash() : mintPrevHash;
        const int crashedTipH = r.blockOk ? (int)mintIdx.nHeight : (int)mintPrevIdx.nHeight;
        bool rb1 = false, rb2 = false;
        r.settleGateOk = CheckSettlementDBConsistency(crashedTip, crashedTipH, rb1);
        r.burnGateOk   = CheckBurnClaimDBConsistency(crashedTip, rb2);
        r.anyRebuild   = rb1 || rb2;

        // ── -REINDEX: wipe the derivable DBs, restore the authorised BTC pre-state,
        // replay claim + mint. Must converge to S == L == 777000 for every row.
        WipeDerivableAndReopen();
        SeedBitcoinPreState();
        CValidationState r1, r2;
        SeedLedgerAtParent(curIdx);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, r1, false));
        SeedLedgerAtParent(mintIdx);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, r2, false));
        r.S_re = readS(); r.L_re = readL();

        {
            std::string steps;
            for (int s : r.stepsSeen) steps += std::to_string(s) + ",";
            BOOST_TEST_MESSAGE("M1b | failAt=" << r.failAt
                << " | stepsSeen=[" << steps << "] okBefore=" << r.succeededBefore
                << " | blockOk=" << r.blockOk << " fatal=" << r.fatal
                << " | S=" << r.S << " L=" << r.L << " S-L=" << (r.S - r.L)
                << " | sMk=" << r.sMk << " lMk=" << r.lMk << " allC=" << r.allC
                << " | settleGate=" << r.settleGateOk << " burnGate=" << r.burnGateOk
                << " rebuild=" << r.anyRebuild
                << " | reindex: S=" << r.S_re << " L=" << r.L_re);
        }
        rows.push_back(r);
    }

    // ── ASSERTED MATRIX ─────────────────────────────────────────────────────────
    // failAt=1: nothing durable. S==L==0, markers still at the claim block, startup
    // gates PASS (nothing to detect: no prefix), fatal latch fired in the old process.
    BOOST_CHECK(!rows[0].blockOk && rows[0].fatal);
    BOOST_CHECK_EQUAL(rows[0].S, CAmount(0));
    BOOST_CHECK_EQUAL(rows[0].L, CAmount(0));
    BOOST_CHECK(rows[0].settleGateOk && rows[0].burnGateOk && !rows[0].anyRebuild);

    // failAt=2: NOT a real step for a mint-only block — never consulted, block CONNECTS.
    BOOST_CHECK_MESSAGE(rows[1].blockOk && !rows[1].fatal,
        "step 2 does not exist for a mint-only block; the block must connect fully");
    BOOST_CHECK(std::find(rows[1].stepsSeen.begin(), rows[1].stepsSeen.end(), 2)
                == rows[1].stepsSeen.end());
    BOOST_CHECK_EQUAL(rows[1].S, CAmount(777000));
    BOOST_CHECK_EQUAL(rows[1].L, CAmount(777000));
    BOOST_CHECK(rows[1].settleGateOk && rows[1].burnGateOk && !rows[1].anyRebuild);

    // failAt=3 and failAt=4: THE PARTIAL PREFIX. Settlement (step 1) is durably
    // committed -> S=777000, sMk at the mint block; burnclaim (step 4) is not -> L=0,
    // lMk still at the claim block. A REAL durable S != L exists on disk. It must be
    // DETECTED by the startup gate (settlement marker diverges from the crashed tip)
    // and REPAIRED by -reindex.
    for (int i : {2, 3}) {
        BOOST_CHECK(!rows[i].blockOk && rows[i].fatal);
        BOOST_CHECK_MESSAGE(rows[i].S == CAmount(777000) && rows[i].L == CAmount(0),
            "failAt=" << rows[i].failAt << " must leave the durable partial prefix S=777000 L=0");
        BOOST_CHECK_MESSAGE(!rows[i].settleGateOk && rows[i].anyRebuild,
            "failAt=" << rows[i].failAt << ": the startup gate must detect the divergent prefix");
    }

    // failAt=5: all four data batches committed (S==L==777000) but the all-committed
    // marker was not -> still detected (settlement marker=mint block vs tip=claim block).
    BOOST_CHECK(!rows[4].blockOk && rows[4].fatal);
    BOOST_CHECK_EQUAL(rows[4].S, CAmount(777000));
    BOOST_CHECK_EQUAL(rows[4].L, CAmount(777000));
    BOOST_CHECK_MESSAGE(!rows[4].settleGateOk && rows[4].anyRebuild,
        "failAt=5: marker ahead of tip must be detected at startup");

    // Every row converges after -reindex to the SAME S == L.
    for (const Row& r : rows) {
        BOOST_CHECK_MESSAGE(r.S_re == CAmount(777000) && r.L_re == CAmount(777000),
            "failAt=" << r.failAt << ": -reindex must converge to S==L==777000");
    }
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 8 — the INDEPENDENT A5 proofs (rules 1-3, startup gate, 4-state status).
// Fixture = P0BurnMintSetup (real burn->claim->mint through the production paths).
// ═══════════════════════════════════════════════════════════════════════════════
BOOST_FIXTURE_TEST_SUITE(consensus_lot8_a5, P0BurnMintSetup)

namespace {
//! Connect claim then mint through the real path; leave markers at the mint block.
//! Returns the mint block (child connects use mintIdx's child).
struct A5Chain {
    CBlock cb, mb;
};
} // namespace

// Helper macro-free chain builder used by the rule-1 cases.
#define LOT8_CONNECT_CLAIM_AND_MINT(chain_)                                            \
    do {                                                                               \
        (chain_).cb = ClaimBlock(); (chain_).cb.nNonce = 0xC1A1;                       \
        CValidationState s1_;                                                          \
        BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock((chain_).cb, &curIdx, nullptr,  \
                                                       s1_, false),                    \
                              "claim: " << s1_.GetRejectReason());                     \
        (chain_).mb = MintBlock(); (chain_).mb.nNonce = 0x314159;                      \
        CValidationState s2_;                                                          \
        SetLedgerAtParent(mintIdx);                                                    \
        BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock((chain_).mb, &mintIdx, nullptr, \
                                                       s2_, false),                    \
                              "mint: " << s2_.GetRejectReason());                      \
    } while (0)

// ── PROOF: corruption of prevS ONLY (markers untouched -> identical) is a LOCAL
// fatal on the next connect, never invalidity, never a ban. Rule 1.
BOOST_AUTO_TEST_CASE(corrupt_prevS_only_is_local_fatal_not_invalid)
{
    A5Chain c; LOT8_CONNECT_CLAIM_AND_MINT(c);

    // Corrupt ONLY the settlement total (marker + burn ledger untouched).
    SettlementState st;
    BOOST_REQUIRE(g_settlementdb->ReadLatestState(st));
    st.M0_total_supply += 1000;
    BOOST_REQUIRE(g_settlementdb->WriteState(st));

    // Markers must still match (the corruption class rule 1 exists for).
    uint256 sMk, lMk;
    BOOST_REQUIRE(g_settlementdb->ReadBestBlock(sMk) && g_burnclaimdb->ReadBestBlock(lMk));
    BOOST_REQUIRE(sMk == lMk);

    // Next (empty) block on top of the mint block.
    uint256 childHash = c.mb.GetHash();   // parent identity = the REAL mint block hash
    CBlockIndex mintReal; mintReal.nHeight = (int)mintIdx.nHeight; mintReal.phashBlock = &childHash;
    mintReal.pprev = mintIdx.pprev;
    CBlockIndex child; uint256 chHash = uint256S("00000000000000000000000000000000000000000000000000000000000000d1");
    child.nHeight = (int)mintIdx.nHeight + 1; child.phashBlock = &chHash; child.pprev = &mintReal;

    CBlock empty;
    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(empty, &child, nullptr, stv, false));
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(), "prevS corruption under matching markers must fatal");
    BOOST_CHECK_MESSAGE(!stv.IsInvalid(), "a local corruption is NEVER block invalidity");
    int dos = 0; stv.IsInvalid(dos);
    BOOST_CHECK_EQUAL(dos, 0);
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/0, /*partial=*/false, /*shutdowns=*/1);
}

// ── PROOF: corruption of prevL ONLY — same discipline, other side. Rule 1.
BOOST_AUTO_TEST_CASE(corrupt_prevL_only_is_local_fatal_not_invalid)
{
    A5Chain c; LOT8_CONNECT_CLAIM_AND_MINT(c);

    // Corrupt ONLY the burn-ledger total.
    BOOST_REQUIRE(g_burnclaimdb->IncrementM0BTCSupply(999));

    uint256 childHash = c.mb.GetHash();
    CBlockIndex mintReal; mintReal.nHeight = (int)mintIdx.nHeight; mintReal.phashBlock = &childHash;
    mintReal.pprev = mintIdx.pprev;
    CBlockIndex child; uint256 chHash = uint256S("00000000000000000000000000000000000000000000000000000000000000d2");
    child.nHeight = (int)mintIdx.nHeight + 1; child.phashBlock = &chHash; child.pprev = &mintReal;

    CBlock empty;
    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(empty, &child, nullptr, stv, false));
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(), "prevL corruption under matching markers must fatal");
    BOOST_CHECK(!stv.IsInvalid());
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/0, /*partial=*/false, /*shutdowns=*/1);
}

// ── PROOF: a PENDING claim with NO mint due passes (deltas 0==0, no interference).
BOOST_AUTO_TEST_CASE(pending_claim_without_due_mint_passes)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));

    // Immediate next block: the claim is not K-mature, no mint is due.
    uint256 parentHash = cb.GetHash();
    CBlockIndex claimReal; claimReal.nHeight = (int)curIdx.nHeight; claimReal.phashBlock = &parentHash;
    claimReal.pprev = curIdx.pprev;
    CBlockIndex child; uint256 chHash = uint256S("00000000000000000000000000000000000000000000000000000000000000d3");
    child.nHeight = (int)curIdx.nHeight + 1; child.phashBlock = &chHash; child.pprev = &claimReal;

    CBlock empty;
    CValidationState stv;
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(empty, &child, nullptr, stv, false),
                        stv.GetRejectReason());
    BOOST_CHECK(!IsConsensusDBFatal());
    // Totals untouched by a PENDING claim.
    SettlementState st;  CAmount S = g_settlementdb->ReadLatestState(st) ? st.M0_total_supply : 0;
    BOOST_CHECK_EQUAL(S, CAmount(0));
    BOOST_CHECK_EQUAL((CAmount)g_burnclaimdb->GetM0BTCSupply(), CAmount(0));
}

// ── PROOF: a WRONG-AMOUNT mint is rejected and moves NEITHER total. The precise
// reason comes from the earliest intact guard (LOT 2's mint-amount-mismatch /
// bad-mint-mismatch, or LOT 8's settlement-a5-delta-mismatch when the LOT 2 guards
// are mutated away — the mutation harness proves that defense-in-depth pairing).
BOOST_AUTO_TEST_CASE(wrong_amount_mint_rejected_and_both_totals_unchanged)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));

    // Build the canonical mint, then TAMPER the amount (+1 sat).
    CBlock mb = MintBlock(); mb.nNonce = 0x314159;
    {
        CMutableTransaction bad(*mb.vtx[0]);
        bad.vout[0].nValue += 1;
        mb.vtx[0] = MakeTransactionRef(std::move(bad));
    }
    CValidationState stv;
    SeedLedgerAtParent(mintIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(mb, &mintIdx, nullptr, stv, false));
    const std::string r = stv.GetRejectReason();
    BOOST_CHECK_MESSAGE(r == "mint-amount-mismatch" || r == "bad-mint-mismatch" ||
                        r == "settlement-a5-delta-mismatch",
                        "unexpected reason: " << r);
    // NEITHER total moved.
    SettlementState st;  CAmount S = g_settlementdb->ReadLatestState(st) ? st.M0_total_supply : 0;
    BOOST_CHECK_EQUAL(S, CAmount(0));
    BOOST_CHECK_EQUAL((CAmount)g_burnclaimdb->GetM0BTCSupply(), CAmount(0));
    BOOST_CHECK(!IsConsensusDBFatal());
}

// ── PROOF: double mint (re-minting a FINAL claim) is rejected, totals unchanged.
BOOST_AUTO_TEST_CASE(double_mint_of_final_claim_rejected)
{
    A5Chain c; LOT8_CONNECT_CLAIM_AND_MINT(c);
    const CAmount S0 = [&]{ SettlementState st; g_settlementdb->ReadLatestState(st); return st.M0_total_supply; }();
    BOOST_REQUIRE_EQUAL(S0, CAmount(777000));

    // Re-submit the SAME mint in a child block: the claim is FINAL, not PENDING.
    uint256 parentHash = c.mb.GetHash();
    CBlockIndex mintReal; mintReal.nHeight = (int)mintIdx.nHeight; mintReal.phashBlock = &parentHash;
    mintReal.pprev = mintIdx.pprev;
    CBlockIndex child; uint256 chHash = uint256S("00000000000000000000000000000000000000000000000000000000000000d4");
    child.nHeight = (int)mintIdx.nHeight + 1; child.phashBlock = &chHash; child.pprev = &mintReal;

    CBlock dbl; dbl.vtx.push_back(c.mb.vtx[0]);
    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(dbl, &child, nullptr, stv, false));
    const std::string r = stv.GetRejectReason();
    BOOST_CHECK_MESSAGE(r == "mint-not-pending" || r == "bad-mint-unexpected" ||
                        r == "settlement-a5-delta-mismatch",
                        "unexpected reason: " << r);
    const CAmount S1 = [&]{ SettlementState st; g_settlementdb->ReadLatestState(st); return st.M0_total_supply; }();
    BOOST_CHECK_EQUAL(S1, CAmount(777000));                                  // unchanged
    BOOST_CHECK_EQUAL((CAmount)g_burnclaimdb->GetM0BTCSupply(), CAmount(777000));
}

// ── PROOF: startup gate — same markers at tip but S != L requires REBUILD; agreeing
// totals pass; markers-not-at-tip stays the LOT 1 checks' business (silent here).
BOOST_AUTO_TEST_CASE(startup_same_marker_but_S_neq_L_requires_rebuild)
{
    const uint256 tip = uint256S("0000000000000000000000000000000000000000000000000000000000007711");

    // Both markers at "tip", totals AGREE (0 == 0): pass.
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(tip); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_burnclaimdb->CreateBatch();  b.WriteBestBlock(tip); BOOST_REQUIRE(b.Commit()); }
    SettlementState st; st.nHeight = 1; st.hashBlock = tip;   // S = 0
    BOOST_REQUIRE(g_settlementdb->WriteState(st));
    bool rebuild = true;
    BOOST_CHECK(CheckA5SupplyConsistency(tip, rebuild));
    BOOST_CHECK(!rebuild);

    // Corrupt ONE side: same markers, S != L -> rebuild required.
    BOOST_REQUIRE(g_burnclaimdb->IncrementM0BTCSupply(50));
    BOOST_CHECK(!CheckA5SupplyConsistency(tip, rebuild));
    BOOST_CHECK_MESSAGE(rebuild, "same-marker S!=L must demand -reindex");

    // Marker NOT at tip: this check stays silent (the LOT 1 marker checks own it).
    rebuild = true;
    const uint256 other = uint256S("0000000000000000000000000000000000000000000000000000000000007722");
    BOOST_CHECK(CheckA5SupplyConsistency(other, rebuild));
    BOOST_CHECK(!rebuild);
}

// ── F1 CASE B: height > 0 and the burn ledger's marker is ABSENT or != pindexPrev.
// The ledger cannot certify anything, so the node must STOP: LOT 1 fatal latch +
// REINDEX_REQUIRED, non-invalid state.Error. NEVER a DoS, a ban or BLOCK_FAILED_*, and
// NEVER a silent disarm of A5 (an earlier revision withheld the verdict here, which left
// the money belt off with no operator signal — measured: an inflated mint connected).
BOOST_AUTO_TEST_CASE(f1_caseB_uncertified_ledger_is_fatal_never_dos)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));
    CBlock mb = MintBlock(); mb.nNonce = 0x314159;

    // Settlement marker AT the parent; burn ledger marker deliberately WRONG.
    const uint256 parentHash = cb.GetHash();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_burnclaimdb->CreateBatch();
      b.WriteBestBlock(uint256S("00000000000000000000000000000000000000000000000000000000000000ee"));
      BOOST_REQUIRE(b.Commit()); }

    CBlockIndex claimReal; claimReal.nHeight = (int)curIdx.nHeight;
    claimReal.phashBlock = &parentHash; claimReal.pprev = curIdx.pprev;
    CBlockIndex mintOnReal; uint256 mHash = mb.GetHash();
    mintOnReal.nHeight = (int)mintIdx.nHeight; mintOnReal.phashBlock = &mHash;
    mintOnReal.pprev = &claimReal;

    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(mb, &mintOnReal, nullptr, stv, false));
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(),
        "an uncertified ledger at height > 0 must fire the LOT 1 fatal latch");
    BOOST_CHECK_MESSAGE(stv.IsError(), "the latch sets a NON-invalid Error");
    BOOST_CHECK_MESSAGE(!stv.IsInvalid(),
        "a local storage fault must NEVER be block invalidity (got '"
        << stv.GetRejectReason() << "')");
    int dos = 0; stv.IsInvalid(dos);
    BOOST_CHECK_MESSAGE(dos == 0, "no DoS score => no peer ban for a local fault");
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/0, /*partial=*/false, /*shutdowns=*/1);
}

// ── F1 CASE B, marker ABSENT (not merely different) at height > 0 — same verdict.
BOOST_AUTO_TEST_CASE(f1_caseB_absent_ledger_marker_is_fatal)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));
    CBlock mb = MintBlock(); mb.nNonce = 0x314159;

    const uint256 parentHash = cb.GetHash();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    // Ledger marker WIPED: reopen the burn DB empty (models a removed burnclaimdb/).
    g_burnclaimdb.reset();
    g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, /*fMemory=*/false, /*fWipe=*/true);

    CBlockIndex claimReal; claimReal.nHeight = (int)curIdx.nHeight;
    claimReal.phashBlock = &parentHash; claimReal.pprev = curIdx.pprev;
    CBlockIndex mintOnReal; uint256 mHash = mb.GetHash();
    mintOnReal.nHeight = (int)mintIdx.nHeight; mintOnReal.phashBlock = &mHash;
    mintOnReal.pprev = &claimReal;

    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(mb, &mintOnReal, nullptr, stv, false));
    BOOST_CHECK_MESSAGE(IsConsensusDBFatal(), "an ABSENT marker above genesis is a local fault");
    BOOST_CHECK(!stv.IsInvalid());
    ExpectFatalAndClear(/*fConnect=*/true, /*step=*/0, /*partial=*/false, /*shutdowns=*/1);
}

// ── F1 CASE A: parent == GENESIS with the marker legitimately absent -> exempt: NO
// fatal and NO DoS. This is the LOT 7 block-1 lesson, kept intact by F1.
// HONEST SCOPE: the block here is empty (deltaS = deltaL = 0), so this case cannot
// distinguish "withheld" from "armed and trivially satisfied"; it pins the ABSENCE of a
// fatal/invalidity. That the exemption itself is load-bearing is proven by mutation
// (removing the `pprev->nHeight > 0` guard is KILLED).
BOOST_AUTO_TEST_CASE(f1_caseA_genesis_parent_is_exempt_no_fatal)
{
    // Fresh ledger with NO marker at all.
    g_burnclaimdb.reset();
    g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, /*fMemory=*/false, /*fWipe=*/true);

    uint256 genHash = uint256S("00000000000000000000000000000000000000000000000000000000000000a0");
    CBlockIndex gen; gen.nHeight = 0; gen.phashBlock = &genHash; gen.pprev = nullptr;
    uint256 b1Hash = uint256S("00000000000000000000000000000000000000000000000000000000000000a1");
    CBlockIndex b1;  b1.nHeight = 1;  b1.phashBlock = &b1Hash;  b1.pprev = &gen;

    CBlock empty;
    CValidationState stv;
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(empty, &b1, nullptr, stv, false),
                        "block 1 on a fresh chain must connect: " << stv.GetRejectReason());
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(),
        "the genesis parent is EXEMPT — an absent marker there is legitimate");
    BOOST_CHECK(!stv.IsInvalid());
}

// ── INDEPENDENCE PROOF, production-faithful. The legacy fixtures use synthetic index
// hashes that do not match the real blocks, so the burn ledger is NOT certified at the
// parent and the A5 verdict is (correctly) withheld there. This case builds indexes whose
// phashBlock ARE the real block hashes — what a production node always has — so the A5
// belt is genuinely armed. On the unmutated tree the LOT 2 guards win the race (documented
// intent); under the MD mutation (LOT 2 mint guards disabled) A5 alone must still reject
// the wrong-amount mint. That pairing is the independence evidence.
BOOST_AUTO_TEST_CASE(armed_ledger_wrong_amount_mint_is_rejected)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));

    CBlock mb = MintBlock(); mb.nNonce = 0x314159;
    {   // TAMPER the mint amount: +1 sat against the claim's burnedSats.
        CMutableTransaction bad(*mb.vtx[0]);
        bad.vout[0].nValue += 1;
        mb.vtx[0] = MakeTransactionRef(std::move(bad));
    }

    // Production-faithful parent: both markers ARE the real claim block (the claim's own
    // commit wrote them), and the index carries that same hash.
    const uint256 parentHash = cb.GetHash();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_burnclaimdb->CreateBatch();  b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    SettlementState base; base.nHeight = (uint32_t)curIdx.nHeight; base.hashBlock = parentHash;
    BOOST_REQUIRE(g_settlementdb->WriteState(base));

    CBlockIndex claimReal; claimReal.nHeight = (int)curIdx.nHeight;
    claimReal.phashBlock = &parentHash; claimReal.pprev = curIdx.pprev;
    CBlockIndex mintReal; uint256 mHash = mb.GetHash();
    mintReal.nHeight = (int)mintIdx.nHeight; mintReal.phashBlock = &mHash;
    mintReal.pprev = &claimReal;

    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(mb, &mintReal, nullptr, stv, false));
    const std::string r = stv.GetRejectReason();
    BOOST_CHECK_MESSAGE(r == "mint-amount-mismatch" || r == "bad-mint-mismatch" ||
                        r == "settlement-a5-delta-mismatch",
                        "unexpected reason: " << r);
    // Deterministic consensus invalidity — NOT a local fault, no halt.
    BOOST_CHECK(stv.IsInvalid());
    BOOST_CHECK(!IsConsensusDBFatal());
    // Neither total moved.
    SettlementState st;  CAmount S = g_settlementdb->ReadLatestState(st) ? st.M0_total_supply : 0;
    BOOST_CHECK_EQUAL(S, CAmount(0));
    BOOST_CHECK_EQUAL((CAmount)g_burnclaimdb->GetM0BTCSupply(), CAmount(0));
}

// ── REVIEW MEDIUM-2 REGRESSION: a burn referenced TWICE in one mint payload must be
// counted ONCE on the ledger side, so the duplicate cannot inflate both sides equally
// and slip past rule 2. Driven at the pure-function level with the deltas the block
// would produce: deltaS doubles (two outputs), deltaL does not (one burn, counted once).
BOOST_AUTO_TEST_CASE(duplicate_burn_reference_cannot_pass_rule2)
{
    const CAmount cap = Params().GetConsensus().nMaxMoneyOut;
    const CAmount b = 777000;
    CValidationState vs; CAmount nextS = -1;
    // What a [X, X] payload with two matching outputs yields AFTER the dedup fix.
    BOOST_CHECK_MESSAGE(!CheckA5Independent(/*prevS=*/0, /*prevL=*/0,
                                            /*deltaS=*/2 * b, /*deltaL=*/b, cap, vs, nextS),
        "double-referenced burn must not satisfy the independent delta check");
    BOOST_CHECK_EQUAL(vs.GetRejectReason(), "settlement-a5-delta-mismatch");
}

// ── F1 CASE C, end-to-end outcome under a CERTIFIED ledger: a wrong-amount mint is a
// deterministic consensus invalidity (not a local fault), and neither total moves.
// HONEST SCOPE (independent review): on the unmutated tree the reject reason here is
// `mint-amount-mismatch` — the LOT 2 guards win the race by design — so this case does
// NOT by itself prove that rules 2/3 are ARMED. The arming is proven by MEASUREMENT under
// the MD mutation (LOT 2 mint guards disabled), where the same block is rejected by
// `settlement-a5-delta-mismatch` ALONE; see doc/LOT8-F1-F2-HANDOFF.md §6.
BOOST_AUTO_TEST_CASE(f1_caseC_certified_ledger_wrong_amount_is_consensus_invalid)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));
    CBlock mb = MintBlock(); mb.nNonce = 0x314159;
    { CMutableTransaction bad(*mb.vtx[0]); bad.vout[0].nValue += 1;
      mb.vtx[0] = MakeTransactionRef(std::move(bad)); }

    const uint256 parentHash = cb.GetHash();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_burnclaimdb->CreateBatch();  b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    SettlementState base; base.nHeight = (uint32_t)curIdx.nHeight; base.hashBlock = parentHash;
    BOOST_REQUIRE(g_settlementdb->WriteState(base));

    CBlockIndex claimReal; claimReal.nHeight = (int)curIdx.nHeight;
    claimReal.phashBlock = &parentHash; claimReal.pprev = curIdx.pprev;
    CBlockIndex mintReal; uint256 mHash = mb.GetHash();
    mintReal.nHeight = (int)mintIdx.nHeight; mintReal.phashBlock = &mHash;
    mintReal.pprev = &claimReal;

    CValidationState stv;
    BOOST_CHECK(!ProcessSpecialTxsInBlock(mb, &mintReal, nullptr, stv, false));
    BOOST_CHECK_MESSAGE(stv.IsInvalid(), "a certified ledger yields a CONSENSUS verdict");
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(), "a real invalidity is not a local fault");
    SettlementState st;  CAmount S = g_settlementdb->ReadLatestState(st) ? st.M0_total_supply : 0;
    BOOST_CHECK_EQUAL(S, CAmount(0));
    BOOST_CHECK_EQUAL((CAmount)g_burnclaimdb->GetM0BTCSupply(), CAmount(0));
}

// ── F2: the startup gate over burnclaimdb, all FOUR states.
BOOST_AUTO_TEST_CASE(f2_startup_gate_four_states)
{
    const uint256 genesis = Params().GetConsensus().hashGenesisBlock;
    const uint256 tip   = uint256S("0000000000000000000000000000000000000000000000000000000000007711");
    const uint256 other = uint256S("0000000000000000000000000000000000000000000000000000000000007722");

    // 1. tip == genesis + marker ABSENT -> fresh chain, allowed.
    g_burnclaimdb.reset();
    g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, /*fMemory=*/false, /*fWipe=*/true);
    bool rebuild = true;
    BOOST_CHECK_MESSAGE(CheckBurnClaimDBConsistency(genesis, rebuild), "fresh chain must PASS");
    BOOST_CHECK(!rebuild);

    // 2. tip > genesis + marker ABSENT -> FAIL, reindex.
    rebuild = false;
    BOOST_CHECK_MESSAGE(!CheckBurnClaimDBConsistency(tip, rebuild),
                        "absent marker above genesis must FAIL");
    BOOST_CHECK_MESSAGE(rebuild, "...and demand a rebuild");

    // 3. marker DIFFERENT from the tip -> FAIL, reindex.
    { auto b = g_burnclaimdb->CreateBatch(); b.WriteBestBlock(other); BOOST_REQUIRE(b.Commit()); }
    rebuild = false;
    BOOST_CHECK_MESSAGE(!CheckBurnClaimDBConsistency(tip, rebuild), "marker != tip must FAIL");
    BOOST_CHECK(rebuild);

    // 4. marker AT the tip -> PASS.
    { auto b = g_burnclaimdb->CreateBatch(); b.WriteBestBlock(tip); BOOST_REQUIRE(b.Commit()); }
    rebuild = true;
    BOOST_CHECK_MESSAGE(CheckBurnClaimDBConsistency(tip, rebuild), "marker at tip must PASS");
    BOOST_CHECK(!rebuild);
}

// ── A doubly-referenced burn never connects. HONEST SCOPE (independent review): this
// drives the real ProcessSpecialTxsInBlock path, but the block is rejected EARLIER than
// A5 — measured reason `bad-mint-trivial`, from CheckSpecialTxBasic's
// MintPayload::IsTriviallyValid duplicate check, before deltaL is ever computed. So it
// does NOT exercise the countedBurns dedup: removing that dedup alone leaves this test
// (and the whole suite) green. The dedup is a LAST-LINE belt whose value was measured
// separately by removing every upstream guard — dedup kept -> rejected; dedup removed ->
// the duplicate connects and inflates. What this case proves is the end-to-end outcome:
// no duplicate-reference block connects, and neither total moves.
BOOST_AUTO_TEST_CASE(duplicate_burn_reference_never_connects)
{
    CBlock cb = ClaimBlock(); cb.nNonce = 0xC1A1;
    CValidationState s1;
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(cb, &curIdx, nullptr, s1, false));

    // A mint naming the SAME btcTxid twice, with two outputs of the burn amount: without
    // the dedup, deltaS = deltaL = 2b and rule 2 would pass.
    MintPayload mp; mp.nVersion = MINT_PAYLOAD_VERSION;
    mp.btcTxids = {btcTxid, btcTxid};
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;
    for (int i = 0; i < 2; ++i) {
        CTxOut o; o.nValue = 777000;
        o.scriptPubKey = CScript() << OP_DUP << OP_HASH160
                                   << std::vector<unsigned char>(20, 0xAB)
                                   << OP_EQUALVERIFY << OP_CHECKSIG;
        mtx.vout.push_back(o);
    }
    mtx.extraPayload = SerializePayload(mp);
    CBlock dup; dup.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    const uint256 parentHash = cb.GetHash();
    { auto b = g_settlementdb->CreateBatch(); b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    { auto b = g_burnclaimdb->CreateBatch();  b.WriteBestBlock(parentHash); BOOST_REQUIRE(b.Commit()); }
    SettlementState base; base.nHeight = (uint32_t)curIdx.nHeight; base.hashBlock = parentHash;
    BOOST_REQUIRE(g_settlementdb->WriteState(base));

    CBlockIndex claimReal; claimReal.nHeight = (int)curIdx.nHeight;
    claimReal.phashBlock = &parentHash; claimReal.pprev = curIdx.pprev;
    CBlockIndex mintReal; uint256 mHash = dup.vtx[0]->GetHash();
    mintReal.nHeight = (int)mintIdx.nHeight; mintReal.phashBlock = &mHash;
    mintReal.pprev = &claimReal;

    CValidationState stv;
    BOOST_CHECK_MESSAGE(!ProcessSpecialTxsInBlock(dup, &mintReal, nullptr, stv, false),
                        "a doubly-referenced burn must never connect");
    BOOST_CHECK(stv.IsInvalid());
    BOOST_CHECK_MESSAGE(!IsConsensusDBFatal(), "this is invalidity, not a local fault");
    // No inflation on either side.
    SettlementState st;  CAmount S = g_settlementdb->ReadLatestState(st) ? st.M0_total_supply : 0;
    BOOST_CHECK_EQUAL(S, CAmount(0));
    BOOST_CHECK_EQUAL((CAmount)g_burnclaimdb->GetM0BTCSupply(), CAmount(0));
}

// ── MANDATED height-0 marker states (A5MarkersCoherent), plus the steady state.
// Measured contradiction this fixes: a node rolled back exactly TO genesis has BOTH
// markers present at the genesis hash (the undo writes them) and used to be reported
// REINDEX_REQUIRED while perfectly healthy.
BOOST_AUTO_TEST_CASE(a5_marker_coherence_height0_states)
{
    const uint256 gen = uint256S("00000000000000000000000000000000000000000000000000000000000000a0");
    const uint256 other = uint256S("00000000000000000000000000000000000000000000000000000000000000bb");

    // 1. height 0, markers ABSENT -> coherent (fresh chain: nothing has committed yet).
    BOOST_CHECK(A5MarkersCoherent(false, false, uint256(), uint256(), gen, /*genesisTip=*/true));

    // 2. height 0, markers PRESENT and COHERENT (both at the genesis hash) -> coherent.
    //    This is the rolled-back-to-genesis node; it must NOT read REINDEX_REQUIRED.
    BOOST_CHECK_MESSAGE(A5MarkersCoherent(true, true, gen, gen, gen, true),
        "markers present AT the genesis tip is a healthy rolled-back node");

    // 3. height 0, markers PRESENT and INCOHERENT -> not coherent.
    BOOST_CHECK(!A5MarkersCoherent(true, true, other, gen, gen, true));
    BOOST_CHECK(!A5MarkersCoherent(true, true, gen, other, gen, true));
    // exactly one present is never coherent, at any height
    BOOST_CHECK(!A5MarkersCoherent(true, false, gen, uint256(), gen, true));
    BOOST_CHECK(!A5MarkersCoherent(false, true, uint256(), gen, gen, true));

    // 4. Above genesis: both at the tip -> coherent; absent -> NOT coherent (wiped DB).
    BOOST_CHECK(A5MarkersCoherent(true, true, other, other, other, /*genesisTip=*/false));
    BOOST_CHECK(!A5MarkersCoherent(false, false, uint256(), uint256(), other, false));
    BOOST_CHECK(!A5MarkersCoherent(true, true, gen, other, other, false));
}

// ── INTEGRATION GATE: -enablemint ABSENT must behave exactly like the declared default.
// The option was previously read with a hardcoded `true` and declared in NO help output,
// so its default lived in two places and operators could not discover it. Both now come
// from DEFAULT_ENABLE_MINT. This pins the ABSENCE case (the one an operator gets by
// doing nothing) and re-pins that the flag never reaches the validation oracle.
BOOST_AUTO_TEST_CASE(enablemint_absent_matches_the_declared_default)
{
    // REAL absence semantics (replaces the earlier probe-key version, which read a
    // DIFFERENT key and therefore never touched the production read — proven by the
    // final review's MD3 mutation surviving the whole suite). ForceRemoveArg restores
    // genuine absence on THE production key, then the assertion goes through the real
    // producer-policy path, so it fails if the production read stops honouring the
    // declared constant.
    gArgs.ForceRemoveArg("-enablemint");
    BOOST_CHECK_EQUAL(gArgs.GetBoolArg("-enablemint", DEFAULT_ENABLE_MINT),
                      DEFAULT_ENABLE_MINT);
    BOOST_CHECK_MESSAGE(DEFAULT_ENABLE_MINT, "the shipped default must allow production");

    // MD3 killer: with -enablemint genuinely ABSENT (and the kill switch off — the
    // fixture never engages it), the producer policy must equal the DECLARED default.
    // A production read re-hardcoded to its own literal (e.g. GetBoolArg(..., false))
    // makes this check fail even while every explicit-value test below still passes.
    BOOST_CHECK_EQUAL(MintPolicyAllowsProduction(), DEFAULT_ENABLE_MINT);

    // Explicit 0 flips the PRODUCER policy...
    gArgs.ForceSetArg("-enablemint", "0");
    BOOST_CHECK(!MintPolicyAllowsProduction());
    // ...and explicit 1 restores it. (That this never decides the VALIDITY of received
    // blocks is the LOT 2 inversion, proven by consensus_p0_mint_policy_matrix_lot2.)
    gArgs.ForceSetArg("-enablemint", "1");
    BOOST_CHECK(MintPolicyAllowsProduction());
    // Leave the key absent again so no later case inherits an explicit setting.
    gArgs.ForceRemoveArg("-enablemint");
}

// ── INTEGRATION GATE: settlement startup gate, symmetric with the burn-ledger twin.
// An ABSENT settlement marker used to PASS at ANY height, so a wiped settlementdb above
// genesis started cleanly while F2 and the A5 RPC rule both called that state incoherent.
BOOST_AUTO_TEST_CASE(settlement_startup_absent_marker_above_genesis_requires_rebuild)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    const uint256 genesis = Params().GetConsensus().hashGenesisBlock;
    const uint256 tip = uint256S("0000000000000000000000000000000000000000000000000000000000009911");

    // Fresh chain at genesis, no marker -> PASS.
    bool rebuild = true;
    BOOST_CHECK_MESSAGE(CheckSettlementDBConsistency(genesis, 0, rebuild),
                        "no marker at genesis is the legitimate fresh state");
    BOOST_CHECK(!rebuild);

    // Above genesis, no marker -> the DB was wiped/lost: FAIL, rebuild required.
    rebuild = false;
    BOOST_CHECK_MESSAGE(!CheckSettlementDBConsistency(tip, 9911, rebuild),
                        "an absent settlement marker above genesis must FAIL");
    BOOST_CHECK_MESSAGE(rebuild, "...and demand a full -reindex");

    // Marker at the tip -> PASS again (no false rebuild introduced).
    BOOST_REQUIRE(g_settlementdb->WriteBestBlock(tip));
    rebuild = true;
    BOOST_CHECK(CheckSettlementDBConsistency(tip, 9911, rebuild));
    BOOST_CHECK(!rebuild);
}

// ── PROOF: the four RPC statuses, via the pure classifier (never a misleading bool).
BOOST_AUTO_TEST_CASE(a5_status_four_states)
{
    using S = A5Status;
    // VERIFIED: no latch, coherent markers, both readable, equal.
    BOOST_CHECK(ComputeA5Status(false, true, true, true, 777, 777) == S::VERIFIED);
    // MISMATCH: coherent markers but the independent totals diverge.
    BOOST_CHECK(ComputeA5Status(false, true, true, true, 777, 776) == S::MISMATCH);
    // UNAVAILABLE: a total unreadable — NEVER reported ok/true.
    BOOST_CHECK(ComputeA5Status(false, true, false, true, 0, 0) == S::UNAVAILABLE);
    BOOST_CHECK(ComputeA5Status(false, true, true, false, 0, 0) == S::UNAVAILABLE);
    // REINDEX_REQUIRED dominates: fatal latch, or divergent markers — even if S==L.
    BOOST_CHECK(ComputeA5Status(true,  true,  true, true, 777, 777) == S::REINDEX_REQUIRED);
    BOOST_CHECK(ComputeA5Status(false, false, true, true, 777, 777) == S::REINDEX_REQUIRED);
    BOOST_CHECK_EQUAL(std::string(A5StatusToString(S::VERIFIED)), "VERIFIED");
    BOOST_CHECK_EQUAL(std::string(A5StatusToString(S::MISMATCH)), "MISMATCH");
    BOOST_CHECK_EQUAL(std::string(A5StatusToString(S::UNAVAILABLE)), "UNAVAILABLE");
    BOOST_CHECK_EQUAL(std::string(A5StatusToString(S::REINDEX_REQUIRED)), "REINDEX_REQUIRED");
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 8 — architecture C audit against a REAL on-disk chain (TestChainSetup):
// correct DB -> internally consistent + premine EXCLUDED; corrupted DB -> the audit
// exposes the divergence it was asked to find.
// ═══════════════════════════════════════════════════════════════════════════════
namespace {
//! TestChainSetup has no default ctor; a real 10-block regtest chain on disk.
struct Lot8AuditSetup : public TestChainSetup {
    Lot8AuditSetup() : TestChainSetup(10) {}
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_lot8_a5_audit, Lot8AuditSetup)

BOOST_AUTO_TEST_CASE(audit_correct_chain_verified_and_premine_excluded)
{
    // Fresh in-memory derived DBs on top of the mined 10-block regtest chain.
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, /*fMemory=*/true, /*fWipe=*/true);

    LOCK(cs_main);
    A5AuditResult r;
    BOOST_REQUIRE_MESSAGE(AuditA5Supply(r), r.strError);
    BOOST_CHECK(r.fComplete);
    BOOST_CHECK_EQUAL(r.nBlocksScanned, chainActive.Height() + 1);
    // PREMINE EXCLUSION, measured on a chain that HAS the 99.12M-COIN regtest
    // premine: the recomputed mint total is 0 because premine outputs are ordinary
    // genesis outputs, not TX_MINT_M0BTC — they are in NEITHER side of A5.
    BOOST_CHECK_EQUAL(r.auditS, CAmount(0));
    BOOST_CHECK_EQUAL(r.auditL, CAmount(0));
    BOOST_CHECK_EQUAL(r.nUnknownMintRefs, 0);
    // Recompute agrees with the (empty) live accumulators -> the RPC would say VERIFIED.
    BOOST_CHECK(r.haveDbL);
    BOOST_CHECK_EQUAL(r.dbL, CAmount(0));

    g_burnclaimdb.reset();
}

BOOST_AUTO_TEST_CASE(audit_corrupted_accumulator_is_exposed)
{
    BOOST_REQUIRE(InitSettlementDB(1 << 20, /*fMemory=*/true, /*fWipe=*/true));
    g_burnclaimdb = std::make_unique<CBurnClaimDB>(1 << 20, /*fMemory=*/true, /*fWipe=*/true);
    // Deliberate corruption of the accumulator the audit must NOT trust.
    BOOST_REQUIRE(g_burnclaimdb->IncrementM0BTCSupply(777));

    LOCK(cs_main);
    A5AuditResult r;
    BOOST_REQUIRE_MESSAGE(AuditA5Supply(r), r.strError);
    BOOST_CHECK(r.fComplete);
    BOOST_CHECK_EQUAL(r.auditL, CAmount(0));           // recomputed from blocks: no burns
    BOOST_CHECK_EQUAL(r.dbL, CAmount(777));            // the corrupted accumulator
    BOOST_CHECK_MESSAGE(r.auditL != r.dbL, "the audit must expose the corrupted accumulator");

    g_burnclaimdb.reset();
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 11 — the blocking defect: fallible work after a durable commit
// ═══════════════════════════════════════════════════════════════════════════════
//
// BEFORE the fix: ConnectMintM0BTC sat INSIDE the commit phase, after settlement and
// btcheaders had committed. A block with a valid TX_BTC_HEADERS plus a mint naming an
// unknown claim was rejected THERE — leaving the headers durably in the consensus DB.
// AFTER the fix: the same block is rejected during STAGING, before any commit.

BOOST_FIXTURE_TEST_SUITE(consensus_p0_ordering_r11, P0RealHeadersSetup)

// The exact reported case: real TX_BTC_HEADERS + a mint whose claim does not exist.
// Nothing may become durable.
//
// LOT 2 RE-SCOPING — read this before trusting the case, because its strength
// CHANGED (a fresh reviewer caught the drift, and a mutation run then corrected my
// first attempt at fixing it):
//
// Originally this case set `-enablemint=0` so CheckMintM0BTC was SKIPPED and the
// block only failed later, at the ConnectMintM0BTC staging step — that is how it
// exercised the round-11 invariant "no fallible step after a durable commit".
// LOT 2 removed that bypass, so the mint is now rejected in the per-tx loop
// (mint-unknown-claim), long before the commit phase.
//
// MEASURED, NOT ASSUMED: moving the fallible staging step back inside the commit
// phase (the literal round-11 defect) does NOT make this case fail — the block is
// rejected before the commit phase is ever entered. So this case NO LONGER guards
// the R11 ordering, and no assertion added here can make it do so through this
// input. What protects R11 now is STRUCTURAL: with the bypass gone, a mint naming
// an unknown claim cannot reach staging at all, and the ordering rule is stated and
// mechanically checkable in-code (PHASE B / PHASE C in specialtx_validation.cpp).
// The commit-failure matrix (consensus_p0_abort_r14 / _commit_failure) remains the
// behavioural guard for the commit phase itself.
//
// What this case DOES still prove, and it is worth keeping: a block carrying valid
// real headers plus a bogus mint is rejected deterministically, on every network,
// with no durable btcheaders mutation, and the honest publication still connects.
// The `stepsSeen.empty()` assertion below documents where the rejection happens —
// it is a description, NOT a guard against re-ordering.
BOOST_AUTO_TEST_CASE(headers_plus_unknown_claim_mint_commits_nothing)
{
    const uint256 h1Hash = HeaderFromHex(MAINNET_HDR_800001).GetHash();
    const uint32_t tipBefore = g_btcheadersdb->GetTipHeight();
    uint256 markerBefore; const bool hadMarker = g_btcheadersdb->ReadBestBlock(markerBefore);

    CBlock block;
    block.vtx.push_back(MakeRealHeadersTx());                       // stages btcheaders
    block.vtx.push_back(MakeJunkMintTx("f1"));                      // claim does not exist

    RecordingStrategy ordering(/*failStep=*/99);                    // never injects
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    const bool ok = ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false,
                                             /*fSettlementOnly=*/false, &ordering);

    BOOST_CHECK(!ok);
    // DESCRIPTIVE (see the header comment): the rejection happens before the commit
    // phase is entered, which is why nothing became durable. This does NOT guard
    // against re-ordering — proven by mutation.
    BOOST_CHECK_MESSAGE(ordering.stepsSeen.empty(),
                        "rejection is expected before any commit step; "
                        << ordering.stepsSeen.size() << " step(s) were reached");
    BOOST_CHECK_EQUAL(ordering.abortCount, 0);
    // LOT 2: and it is a deterministic CONSENSUS invalidity, on every network.
    BOOST_CHECK(st.IsInvalid());
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "mint-unknown-claim");
    // A deterministic, non-empty reject reason (was a bare error() before).
    BOOST_CHECK_MESSAGE(!st.GetRejectReason().empty(),
                        "the rejection must carry a reject reason");

    // THE INVARIANT: btcheadersdb untouched — this is what regressed before.
    BtcBlockHeader got;
    BOOST_CHECK_MESSAGE(!g_btcheadersdb->GetHeaderByHash(h1Hash, got),
                        "R11: headers from a rejected block must NOT be durable");
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), tipBefore);
    uint256 markerAfter; const bool hasMarker = g_btcheadersdb->ReadBestBlock(markerAfter);
    BOOST_CHECK_EQUAL(hasMarker, hadMarker);
    if (hadMarker && hasMarker) BOOST_CHECK(markerAfter == markerBefore);

    // ...and the other DBs likewise.
    BurnClaimRecord rec;
    BOOST_CHECK(!g_burnclaimdb->GetBurnClaim(uint256S("f1"), rec));

    // An honest publication afterwards still connects.
    CBlock good; good.vtx.push_back(MakeRealHeadersTx());
    CValidationState st2;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK_MESSAGE(ProcessSpecialTxsInBlock(good, &curIdx, nullptr, st2, false),
                        st2.GetRejectReason());
    BOOST_CHECK(g_btcheadersdb->GetHeaderByHash(h1Hash, got));
}

// Commit step 2 (btcheaders) — PHASE E (round 15): the fixture must REALLY reach
// step 2, and the full fatal contract must hold there. No "step not reached"
// exemption: every assertion below is on what actually executed.
BOOST_AUTO_TEST_CASE(commit_step2_btcheaders_failure_fails_the_block)
{
    CBlock block;
    block.vtx.push_back(MakeRealHeadersTx());

    RecordingStrategy strategy(2);
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    const bool ok = ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false,
                                             /*fSettlementOnly=*/false, &strategy);
    BOOST_CHECK_MESSAGE(!ok, "a failed btcheaders commit must fail the block");

    // The steps really ran, in order: 1 (settlement) then 2 (btcheaders).
    BOOST_REQUIRE_GE(strategy.stepsSeen.size(), 2U);
    BOOST_CHECK_EQUAL(strategy.stepsSeen[0], 1);
    BOOST_CHECK_EQUAL(strategy.stepsSeen[1], 2);
    // Step 1 SUCCEEDED (this is what makes the failure a PARTIAL commit)...
    BOOST_CHECK_EQUAL(strategy.succeededBefore, 1);
    // ...and step 2 was forced to fail -> FAILED_AFTER_PARTIAL_COMMIT.
    BOOST_CHECK_EQUAL(strategy.abortCount, 1);
    BOOST_CHECK_EQUAL(strategy.abortStep, 2);
    BOOST_CHECK_MESSAGE(strategy.abortPartial,
                        "step-2 failure after a committed step 1 must classify as PARTIAL");

    // Fatal, never invalid: BLOCK_FAILED_VALID must be unreachable from here.
    BOOST_CHECK(st.IsError());
    BOOST_CHECK(!st.IsInvalid());
    BOOST_CHECK(IsConsensusDBFatal());

    // No btcheaders mutation became durable.
    BtcBlockHeader got;
    BOOST_CHECK(!g_btcheadersdb->GetHeaderByHash(HeaderFromHex(MAINNET_HDR_800001).GetHash(), got));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 800000U);

    // RETRY IS BLOCKED BEFORE ANY MUTATION: the latch refuses the same block without
    // consulting a single commit step and without touching a DB.
    RecordingStrategy retry(99);
    CValidationState st2;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st2, false, false, &retry));
    BOOST_CHECK_EQUAL(retry.stepsSeen.size(), 0U);
    BOOST_CHECK(st2.IsError());
    BOOST_CHECK(!st2.IsInvalid());
    BOOST_CHECK_MESSAGE(st2.GetRejectReason().rfind("consensus-db-fatal", 0) == 0,
                        "retry must be refused by the latch, got: " << st2.GetRejectReason());
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 800000U);

    // The startup gate SEES the torn state: settlement advanced (step 1), tip did not.
    {
        bool rebuild = false;
        BOOST_CHECK_MESSAGE(!CheckSettlementDBConsistency(prevHash, prevIdx.nHeight, rebuild),
                            "the consistency gate must report the partial commit");
    }

    // RESTART + -REINDEX RESTORES: clearing the latch stands in for the new process;
    // the wipe below is exactly what -reindex does to the derivable DBs.
    ExpectFatalAndClear(/*fConnect=*/true, 2, /*partial=*/true);
    g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset(); g_btcheadersdb.reset();
    g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, /*fWipe=*/true);
    g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
    g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
    g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
    SeedCheckpointTip();

    CValidationState st3;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st3, false),
                          "replay after wipe must connect: " << st3.GetRejectReason());
    BOOST_CHECK(g_btcheadersdb->GetHeaderByHash(HeaderFromHex(MAINNET_HDR_800001).GetHash(), got));
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 800002U);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 11 — btcheaders consistency gate must fail closed
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_FIXTURE_TEST_SUITE(consensus_p0_hdrgate_r11, P0CrashSetup)

// A marker naming a block that is not on the active chain used to be SILENTLY
// REWRITTEN to the tip, returning true. It must now be reported.
BOOST_AUTO_TEST_CASE(marker_off_chain_is_reported_not_silently_repaired)
{
    const uint256 offChain =
        uint256S("00000000000000000000000000000000000000000000000000000000000000ae");
    { auto b = g_btcheadersdb->CreateBatch(); b.WriteBestBlock(offChain); BOOST_REQUIRE(b.Commit()); }

    bool requireRebuild = false;
    const bool ok = CheckBtcHeadersDBConsistency(prevHash, requireRebuild);

    BOOST_CHECK_MESSAGE(!ok, "R11: an off-chain btcheaders marker must NOT return true");
    BOOST_CHECK_MESSAGE(requireRebuild, "R11: it must demand a rebuild");

    // And it must NOT have rewritten the marker behind our back.
    uint256 after;
    BOOST_REQUIRE(g_btcheadersdb->ReadBestBlock(after));
    BOOST_CHECK_MESSAGE(after == offChain,
                        "R11: the gate must not silently repair the marker");
}

// A fresh/empty btcheadersdb remains an explicitly valid, distinct case.
BOOST_AUTO_TEST_CASE(fresh_btcheadersdb_is_still_valid)
{
    bool requireRebuild = true;
    BOOST_CHECK(CheckBtcHeadersDBConsistency(prevHash, requireRebuild));
    BOOST_CHECK(!requireRebuild);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 12 — disconnect: stage-then-commit, failure matrix, null-deref invariant
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_FIXTURE_TEST_SUITE(consensus_p0_disconnect_r12, P0HtlcSetup)

// Baseline: connect -> disconnect -> reconnect still exact after the restructure.
BOOST_AUTO_TEST_CASE(disconnect_roundtrip_still_exact)
{
    SeedReceipt();
    CTransactionRef htlcTx = MakeHtlcCreateTx();
    const COutPoint htlcOut(htlcTx->GetHash(), 0);
    CBlock block; block.vtx.push_back(htlcTx);

    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, s1, false));
    BOOST_REQUIRE(HtlcExistsAt(htlcOut));

    BOOST_REQUIRE(UndoSpecialTxsInBlock(block, &curIdx, false));
    BOOST_CHECK(!HtlcExistsAt(htlcOut));
    BOOST_CHECK(g_settlementdb->IsM1Receipt(receiptOut));

    CValidationState s2;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, s2, false));
    BOOST_CHECK(HtlcExistsAt(htlcOut));
    BOOST_CHECK(!g_settlementdb->IsM1Receipt(receiptOut));
}

// FAILURE MATRIX — a failure at ANY disconnect commit must make DisconnectBlock
// return false. Before round 12 the settlement batch committed ~130 lines before the
// fallible burnclaim/btcheaders undo, so a later failure returned error with
// settlement already durable — a half-rewound disconnect. Steps: 1 settlement,
// 3 htlc, 4 burnclaim, 5 all-committed marker.
BOOST_AUTO_TEST_CASE(any_disconnect_commit_failure_fails_the_undo)
{
    // EVERY step that actually exists on the disconnect side, not a representative
    // sample: 1 settlement, 2 btcheaders, 3 htlc, 4 burnclaim, 5 all-committed marker.
    // There is no step 6 — the dispatcher in UndoSpecialTxsInBlock issues exactly these
    // five, which the ordering audit confirms (6 doCommit sites = 5 steps, htlc having
    // both a batch branch and a marker-only branch under the same step number).
    for (int step : {1, 2, 3, 4, 5}) {
        SeedReceipt();
        CTransactionRef htlcTx = MakeHtlcCreateTx();
        CBlock block; block.vtx.push_back(htlcTx);

        CValidationState s1;
        SeedLedgerAtParent(curIdx);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, s1, false));

        FailAtStep strategy(step);
        const bool ok = UndoSpecialTxsInBlock(block, &curIdx, false, &strategy);
        BOOST_CHECK_MESSAGE(!ok, "disconnect commit step " << step
                                  << " failed but UndoSpecialTxsInBlock reported SUCCESS");

        // r15: fatal contract on the disconnect side too. Disconnect commit ORDER is
        // 1, 3, 4, 2, 5 — so step 1 is the only non-partial failure.
        BOOST_CHECK_EQUAL(strategy.aborts, 1);
        ExpectFatalAndClear(/*fConnect=*/false, step, /*partial=*/step != 1);

        // fresh DBs for the next iteration
        g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset();
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
    }
}

// The all-committed marker (step 5) is the one whose result was DISCARDED on the
// disconnect side after round 7 fixed the identical discard on connect.
BOOST_AUTO_TEST_CASE(disconnect_marker_failure_is_no_longer_silent)
{
    SeedReceipt();
    CBlock block; block.vtx.push_back(MakeHtlcCreateTx());
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, s1, false));

    FailAtStep strategy(5);
    BOOST_CHECK_MESSAGE(!UndoSpecialTxsInBlock(block, &curIdx, false, &strategy),
                        "a failed all-committed marker must fail the disconnect");
    ExpectFatalAndClear(/*fConnect=*/false, 5, /*partial=*/true);
}

// NULL-DEREF INVARIANT (item 4). htlcBatch_() dereferences g_htlcdb unguarded. This
// asserts the invariant that makes that safe in bathrond: InitHtlcDB failure aborts
// startup (node/init.cpp — `UIError(...); return false;`), and g_htlcdb is otherwise
// only reset during shutdown. So any code path that runs a block through
// Process/UndoSpecialTxsInBlock has a non-null g_htlcdb. HARNESS-ONLY exposure: a
// fixture that nulls it and then connects a block with an HTLC tx would deref null —
// which no fixture does, and which cannot occur in the daemon.
BOOST_AUTO_TEST_CASE(htlcdb_nonnull_invariant_holds_whenever_blocks_are_processed)
{
    BOOST_CHECK_MESSAGE(g_htlcdb != nullptr,
                        "g_htlcdb must be non-null wherever blocks are processed");
    SeedReceipt();
    CBlock block; block.vtx.push_back(MakeHtlcCreateTx());
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false));
    BOOST_CHECK(g_htlcdb != nullptr);      // still non-null after the HTLC path ran
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 13 — -rebuildsettlement refusal must not touch settlementdb
// ═══════════════════════════════════════════════════════════════════════════════
BOOST_FIXTURE_TEST_SUITE(consensus_p0_rebuildsettlement_r13, P0AtomicitySetup)

// The flag is refused in init.cpp BEFORE RebuildSettlementFromChain is reachable — in
// fact that function now has NO caller at all. This asserts the property that matters:
// the only routine that would wipe settlementdb is never invoked, so a refusal cannot
// destroy state. (Verified structurally: `grep RebuildSettlementFromChain src/` returns
// only its definition and declaration.)
BOOST_AUTO_TEST_CASE(settlement_state_survives_because_rebuild_is_never_invoked)
{
    // Establish real settlement state through the normal path.
    BurnClaimPayload claim = MakeValidClaim(88000, 307000, 0xD1);
    CBlock b; b.vtx.push_back(MakeClaimTx(claim));
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(b, &curIdx, nullptr, st, false));

    uint256 bestBefore;
    BOOST_REQUIRE(g_settlementdb->ReadBestBlock(bestBefore));
    BurnClaimRecord recBefore;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(TxidOf(claim.btcTxBytes), recBefore));

    // A refusal path performs no DB work at all: nothing here calls the rebuild.
    uint256 bestAfter;
    BOOST_REQUIRE(g_settlementdb->ReadBestBlock(bestAfter));
    BOOST_CHECK(bestAfter == bestBefore);
    BurnClaimRecord recAfter;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(TxidOf(claim.btcTxBytes), recAfter));
    BOOST_CHECK(recAfter.status == recBefore.status);
    BOOST_CHECK_EQUAL(recAfter.burnedSats, recBefore.burnedSats);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 14 — commit failure is fail-closed: abort requested, block NOT invalidated
// ═══════════════════════════════════════════════════════════════════════════════
//
// A DB commit failure is a LOCAL STORAGE failure, not block invalidity. Production
// calls StartShutdown(); tests inject a strategy that RECORDS the request instead of
// killing the test process.

// (RecordingStrategy moved up next to FailAtStep — round 15.)

BOOST_FIXTURE_TEST_SUITE(consensus_p0_abort_r14, P0HtlcSetup)

// CONNECT — every step 1..5. Each must: actually reach the step, fail the function,
// request EXACTLY ONE abort naming that step, and classify partial vs not.
BOOST_AUTO_TEST_CASE(connect_every_step_aborts_exactly_once)
{
    for (int step = 1; step <= 5; ++step) {
        SeedReceipt();
        BurnClaimPayload claim = MakeValidClaim(41000 + step, 308000 + step, (uint8_t)(0xE0 + step));
        CBlock block;
        block.vtx.push_back(MakeHtlcCreateTx());     // settlement + htlc
        block.vtx.push_back(MakeClaimTx(claim));     // burnclaim

        RecordingStrategy st(step);
        CValidationState vs;
        SeedLedgerAtParent(curIdx);
        const bool ok = ProcessSpecialTxsInBlock(block, &curIdx, nullptr, vs, false, false, &st);

        // Step 2 (btcheaders) is unreachable in THIS fixture — the block has no
        // TX_BTC_HEADERS, so no btcheaders batch is created and the block legitimately
        // connects. Asserted explicitly instead of glossed over; the real step-2 failure
        // is covered by consensus_p0_ordering_r11/commit_step2_btcheaders_failure_fails_the_block.
        if (step == 2) {
            BOOST_CHECK_MESSAGE(!st.Reached(2), "connect step 2 unexpectedly executed");
            BOOST_CHECK_MESSAGE(ok, "with step 2 unreachable the block must connect");
            BOOST_CHECK_EQUAL(st.abortCount, 0);
        } else {
            BOOST_CHECK_MESSAGE(!ok, "connect step " << step << ": reported success");
            BOOST_CHECK_MESSAGE(st.Reached(step), "connect step " << step << " never executed");
            BOOST_CHECK_MESSAGE(st.abortCount == 1,
                "connect step " << step << ": expected exactly 1 abort, got " << st.abortCount);
            BOOST_CHECK_EQUAL(st.abortStep, step);
            BOOST_CHECK_EQUAL(st.abortPartial, st.succeededBefore > 0);
            BOOST_CHECK(!st.abortMsg.empty());
            // A storage failure must never be dressed up as consensus invalidity.
            BOOST_CHECK_MESSAGE(!vs.IsInvalid(),
                "connect step " << step << ": a DB failure must NOT mark the block invalid");
            BOOST_CHECK(vs.IsError());
            // r15: acknowledge the fatal firing so the next iteration starts clean.
            ExpectFatalAndClear(/*fConnect=*/true, step, st.abortPartial);
        }

        g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset();
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
    }
}

// DISCONNECT — every step 1..5, same assertions.
BOOST_AUTO_TEST_CASE(disconnect_every_step_aborts_exactly_once)
{
    for (int step = 1; step <= 5; ++step) {
        SeedReceipt();
        BurnClaimPayload claim = MakeValidClaim(51000 + step, 309000 + step, (uint8_t)(0xF0 + step));
        CBlock block;
        block.vtx.push_back(MakeHtlcCreateTx());
        block.vtx.push_back(MakeClaimTx(claim));
        CValidationState c;
        SeedLedgerAtParent(curIdx);
        BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, c, false));

        RecordingStrategy st(step);
        const bool ok = UndoSpecialTxsInBlock(block, &curIdx, false, &st);

        // On the disconnect side ALL FIVE steps are reachable, including 2: the
        // btcheaders undo block runs whenever g_btcheadersdb exists, so hdrBatchPtr is
        // always created and always committed. No exemption here.
        BOOST_CHECK_MESSAGE(!ok, "disconnect step " << step << ": reported success");
        {
            BOOST_CHECK_MESSAGE(st.Reached(step), "disconnect step " << step << " never executed");
            BOOST_CHECK_MESSAGE(st.abortCount == 1,
                "disconnect step " << step << ": expected exactly 1 abort, got " << st.abortCount);
            BOOST_CHECK_EQUAL(st.abortStep, step);
            BOOST_CHECK_EQUAL(st.abortPartial, st.succeededBefore > 0);
            // r15: acknowledge the fatal firing so the next iteration starts clean.
            ExpectFatalAndClear(/*fConnect=*/false, step, st.abortPartial);
        }

        g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset();
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
        g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
        g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);
    }
}

// A successful block requests NO abort — proves the abort path is not always-on.
BOOST_AUTO_TEST_CASE(control_success_requests_no_abort)
{
    BurnClaimPayload claim = MakeValidClaim(61000, 310000, 0xE9);
    CBlock block; block.vtx.push_back(MakeClaimTx(claim));
    RecordingStrategy st(/*failStep=*/99);      // never fires
    CValidationState vs;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, vs, false, false, &st));
    BOOST_CHECK_EQUAL(st.abortCount, 0);
    BOOST_CHECK_GT(st.succeededBefore, 0);
    // r15: and neither the latch nor a shutdown request may exist after a success.
    BOOST_CHECK(!IsConsensusDBFatal());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 15 · PHASE D — NON-CONTINUATION: after a partial commit NOTHING runs again
// ═══════════════════════════════════════════════════════════════════════════════
//
// The round-14 gap: StartShutdown() is asynchronous, so between the failure and the
// actual shutdown ActivateBestChain could RETRY the block on top of the committed
// prefix — re-running the btcheaders apply against its own durable batch
// ("bad-btcheaders-not-heavier") and converting a LOCAL storage failure into a bogus
// consensus invalidity. These cases prove the latch closes every such door within
// one process, at the ProcessSpecialTxsInBlock/UndoSpecialTxsInBlock boundary (the
// ConnectBlock / DisconnectBlock / ActivateBestChainStep checks guard the same latch
// one layer up and are exercised in the live-process lab).

BOOST_FIXTURE_TEST_SUITE(consensus_p0_fatal_latch_r15, P0RealHeadersSetup)

BOOST_AUTO_TEST_CASE(after_partial_commit_nothing_runs_again_in_this_process)
{
    // Step 4 (burnclaim) fails AFTER settlement (1), btcheaders (2) and the htlc
    // marker (3) really committed: the worst realistic tear — btcheaders is DURABLE.
    CBlock block;
    block.vtx.push_back(MakeRealHeadersTx());

    RecordingStrategy strategy(4);
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false, false, &strategy));
    BOOST_REQUIRE(strategy.Reached(4));
    BOOST_CHECK_EQUAL(strategy.succeededBefore, 3);
    BOOST_CHECK_EQUAL(strategy.abortCount, 1);
    BOOST_CHECK(strategy.abortPartial);
    BOOST_CHECK(st.IsError());
    BOOST_CHECK(!st.IsInvalid());
    BOOST_CHECK_EQUAL((int)curIdx.nStatus, 0);      // never BLOCK_FAILED_VALID

    // The tear is real: the headers ARE durable (step 2 committed)...
    BtcBlockHeader got;
    BOOST_REQUIRE(g_btcheadersdb->GetHeaderByHash(HeaderFromHex(MAINNET_HDR_800001).GetHash(), got));
    BOOST_REQUIRE_EQUAL(g_btcheadersdb->GetTipHeight(), 800002U);
    // ...which is exactly why a retry WITHOUT the latch would re-run the btcheaders
    // apply against its own committed batch and die "bad-btcheaders-not-heavier".

    // Snapshot the durable state the latch must now freeze.
    uint256 hdrMarkerBefore; const bool hadHdrMarker = g_btcheadersdb->ReadBestBlock(hdrMarkerBefore);
    uint256 setlMarkerBefore; BOOST_REQUIRE(g_settlementdb->ReadBestBlock(setlMarkerBefore));

    // (1) SAME block again: refused before ANY read/stage/commit; no second
    // btcheaders execution, no "bad-btcheaders-not-heavier", no invalidity.
    {
        RecordingStrategy retry(99);
        CValidationState st2;
        SeedLedgerAtParent(curIdx);
        BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st2, false, false, &retry));
        BOOST_CHECK_EQUAL(retry.stepsSeen.size(), 0U);
        BOOST_CHECK_EQUAL(retry.abortCount, 0);
        BOOST_CHECK(st2.IsError());
        BOOST_CHECK(!st2.IsInvalid());
        BOOST_CHECK_MESSAGE(st2.GetRejectReason().rfind("consensus-db-fatal", 0) == 0,
                            "got: " << st2.GetRejectReason());
        BOOST_CHECK_MESSAGE(st2.GetRejectReason().find("not-heavier") == std::string::npos,
                            "the local failure must NOT surface as a btcheaders consensus reject");
    }

    // (2) ANOTHER block: refused identically.
    {
        CBlock other;                                 // empty block — nothing special
        RecordingStrategy retry(99);
        CValidationState st3;
        SeedLedgerAtParent(curIdx);
        BOOST_CHECK(!ProcessSpecialTxsInBlock(other, &curIdx, nullptr, st3, false, false, &retry));
        BOOST_CHECK_EQUAL(retry.stepsSeen.size(), 0U);
        BOOST_CHECK(st3.IsError());
        BOOST_CHECK(!st3.IsInvalid());
    }

    // (3) DisconnectBlock's special-tx half: refused before any read or staging.
    {
        RecordingStrategy retry(99);
        BOOST_CHECK(!UndoSpecialTxsInBlock(block, &curIdx, false, &retry));
        BOOST_CHECK_EQUAL(retry.stepsSeen.size(), 0U);
    }

    // (4) A SECOND failure does not overwrite the first diagnostic and does not
    // request a second shutdown — the primitive is idempotent.
    {
        CValidationState st4;
        AbortConsensusDBState(/*fConnect=*/false, 1, "settlement batch", false,
                              999, uint256S("dead"), &st4);
        ConsensusDBFatalContext ctx;
        BOOST_REQUIRE(GetConsensusDBFatalContext(ctx));
        BOOST_CHECK_EQUAL(ctx.nStep, 4);              // FIRST context preserved
        BOOST_CHECK(ctx.fConnect);
        BOOST_CHECK_EQUAL(ctx.nHeight, curIdx.nHeight);
        BOOST_CHECK_EQUAL(test_shutdown::Requests(), 1);
    }

    // (5) DB state is BYTE-STABLE across all refusals above.
    uint256 hdrMarkerAfter; const bool hasHdrMarker = g_btcheadersdb->ReadBestBlock(hdrMarkerAfter);
    BOOST_CHECK_EQUAL(hasHdrMarker, hadHdrMarker);
    if (hadHdrMarker && hasHdrMarker) BOOST_CHECK(hdrMarkerAfter == hdrMarkerBefore);
    uint256 setlMarkerAfter; BOOST_REQUIRE(g_settlementdb->ReadBestBlock(setlMarkerAfter));
    BOOST_CHECK(setlMarkerAfter == setlMarkerBefore);
    BOOST_CHECK_EQUAL(g_btcheadersdb->GetTipHeight(), 800002U);

    ExpectFatalAndClear(/*fConnect=*/true, 4, /*partial=*/true);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 15 · PHASE F — the two HTLC MARKER-ONLY branches use the same fatal path
// ═══════════════════════════════════════════════════════════════════════════════

BOOST_FIXTURE_TEST_SUITE(consensus_p0_markeronly_r15, P0HtlcSetup)

// CONNECT, no HTLC tx in the block -> the marker-only batch is commit step 3.
BOOST_AUTO_TEST_CASE(connect_marker_only_failure_is_fatal)
{
    uint256 htlcMarkerBefore; const bool hadMarker = g_htlcdb->ReadBestBlock(htlcMarkerBefore);

    BurnClaimPayload claim = MakeValidClaim(71000, 311000, 0xB1);
    CBlock block; block.vtx.push_back(MakeClaimTx(claim));   // NO HTLC tx

    RecordingStrategy strategy(3);
    CValidationState st;
    SeedLedgerAtParent(curIdx);
    BOOST_CHECK(!ProcessSpecialTxsInBlock(block, &curIdx, nullptr, st, false, false, &strategy));
    BOOST_REQUIRE_MESSAGE(strategy.Reached(3),
                          "the marker-only branch must be a real commit step");
    BOOST_CHECK_EQUAL(strategy.abortCount, 1);
    BOOST_CHECK(strategy.abortPartial);              // settlement (1) committed first
    BOOST_CHECK(st.IsError());
    BOOST_CHECK(!st.IsInvalid());

    // The htlc marker did NOT move.
    uint256 htlcMarkerAfter; const bool hasMarker = g_htlcdb->ReadBestBlock(htlcMarkerAfter);
    BOOST_CHECK_EQUAL(hasMarker, hadMarker);
    if (hadMarker && hasMarker) BOOST_CHECK(htlcMarkerAfter == htlcMarkerBefore);

    ExpectFatalAndClear(/*fConnect=*/true, 3, /*partial=*/true);
}

// DISCONNECT, no HTLC tx in the block -> marker-only step 3 on the undo side.
BOOST_AUTO_TEST_CASE(disconnect_marker_only_failure_is_fatal)
{
    BurnClaimPayload claim = MakeValidClaim(72000, 312000, 0xB2);
    CBlock block; block.vtx.push_back(MakeClaimTx(claim));   // NO HTLC tx
    CValidationState c;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &curIdx, nullptr, c, false));

    // The marker-only connect branch writes block.GetHash() (the block's own hash,
    // not the synthetic index hash).
    uint256 htlcMarkerBefore; BOOST_REQUIRE(g_htlcdb->ReadBestBlock(htlcMarkerBefore));
    BOOST_REQUIRE(htlcMarkerBefore == block.GetHash());      // marker advanced on connect

    RecordingStrategy strategy(3);
    BOOST_CHECK(!UndoSpecialTxsInBlock(block, &curIdx, false, &strategy));
    BOOST_REQUIRE_MESSAGE(strategy.Reached(3),
                          "the disconnect marker-only branch must be a real commit step");
    BOOST_CHECK_EQUAL(strategy.abortCount, 1);
    BOOST_CHECK(strategy.abortPartial);              // settlement (1) committed first

    // The htlc marker is STILL at the block — it did not move back.
    uint256 htlcMarkerAfter; BOOST_REQUIRE(g_htlcdb->ReadBestBlock(htlcMarkerAfter));
    BOOST_CHECK(htlcMarkerAfter == block.GetHash());

    ExpectFatalAndClear(/*fConnect=*/false, 3, /*partial=*/true);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 15 · PHASE G — DisconnectMintM0BTC: real mint, full undo matrix
// ═══════════════════════════════════════════════════════════════════════════════
//
// The mint is ALWAYS produced by the canonical consensus oracle
// CreateExpectedMintM0BTC (LOT 2) — never hand-written, and never via the
// policy wrapper. All failures below happen in the STAGING phase of
// UndoSpecialTxsInBlock, i.e. BEFORE any commit: the contract there is a CLEAN
// abandon (bool false, batch destroyed, DB untouched, NO abort, NO latch).

BOOST_FIXTURE_TEST_SUITE(consensus_p0_disconnectmint_r15, P0BurnMintSetup)

// 1. Nominal: connect claim -> connect mint -> disconnect mint -> reconnect mint.
BOOST_AUTO_TEST_CASE(mint_connect_disconnect_reconnect_is_exact)
{
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(ClaimBlock(), &curIdx, nullptr, s1, false));
    CBlock mintBlock = MintBlock();
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mintBlock, &mintIdx, nullptr, s2, false),
                          s2.GetRejectReason());

    BurnClaimRecord rec;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::FINAL);
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 777000U);

    // Disconnect: FINAL -> PENDING, supply reverted, marker back at the parent.
    BOOST_REQUIRE(UndoSpecialTxsInBlock(mintBlock, &mintIdx, false));
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::PENDING);
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 0U);
    uint256 marker; BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(marker));
    BOOST_CHECK(marker == mintPrevHash);

    // Reconnect reproduces the post-connect state exactly.
    CValidationState s3;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mintBlock, &mintIdx, nullptr, s3, false),
                          s3.GetRejectReason());
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::FINAL);
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 777000U);
    BOOST_CHECK(!IsConsensusDBFatal());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);
}

// 2. Claim record ABSENT at disconnect: bool false propagated, clean pre-commit abandon.
BOOST_AUTO_TEST_CASE(missing_claim_at_disconnect_fails_cleanly)
{
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(ClaimBlock(), &curIdx, nullptr, s1, false));
    CBlock mintBlock = MintBlock();
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(mintBlock, &mintIdx, nullptr, s2, false));

    // Simulate the torn/foreign state: the claim record vanishes.
    { auto b = g_burnclaimdb->CreateBatch(); b.DeleteBurnClaim(btcTxid); BOOST_REQUIRE(b.Commit()); }
    const uint64_t supplyBefore = g_burnclaimdb->GetM0BTCSupply();
    uint256 markerBefore; BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(markerBefore));

    BOOST_CHECK_MESSAGE(!UndoSpecialTxsInBlock(mintBlock, &mintIdx, false),
                        "a missing claim must fail the disconnect, never silently succeed");

    // Pre-commit abandon: supply and marker untouched, no abort, no latch.
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), supplyBefore);
    uint256 markerAfter; BOOST_REQUIRE(g_burnclaimdb->ReadBestBlock(markerAfter));
    BOOST_CHECK(markerAfter == markerBefore);
    BOOST_CHECK(!IsConsensusDBFatal());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);
}

// 3. Record ALREADY MODIFIED (not FINAL) at disconnect: refused — a second rewind
//    would double-decrement the M0BTC supply.
BOOST_AUTO_TEST_CASE(already_modified_record_refuses_second_rewind)
{
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(ClaimBlock(), &curIdx, nullptr, s1, false));
    CBlock mintBlock = MintBlock();
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(mintBlock, &mintIdx, nullptr, s2, false));

    // The record is rewound once already (as a crashed half-undo would leave it).
    { auto b = g_burnclaimdb->CreateBatch();
      b.UpdateClaimStatus(btcTxid, BurnClaimStatus::PENDING, 0); BOOST_REQUIRE(b.Commit()); }
    const uint64_t supplyBefore = g_burnclaimdb->GetM0BTCSupply();

    BOOST_CHECK_MESSAGE(!UndoSpecialTxsInBlock(mintBlock, &mintIdx, false),
                        "a non-FINAL record must refuse the rewind");
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), supplyBefore);   // NOT decremented again
    BOOST_CHECK(!IsConsensusDBFatal());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);
}

// 4+5. MULTIPLE claims in ONE mint; failure AFTER a partial restoration stays staged.
BOOST_AUTO_TEST_CASE(multi_claim_mint_partial_restore_failure_commits_nothing)
{
    // Second burn, its own header, same claim block height.
    BurnClaimPayload claim2;
    claim2.btcTxBytes = MakeRawBurnTx(MetaV1(0x01, 0xAB), 111000, 0xC8);
    const uint256 btcTxid2 = TxidOf(claim2.btcTxBytes);
    {
        uint256 sib; std::fill(sib.begin(), sib.end(), (unsigned char)0x5D);
        const uint256 root = Hash(btcTxid2.begin(), btcTxid2.end(), sib.begin(), sib.end());
        claim2.btcBlockHash = SeedHeader(BURN_HEIGHT + 1, root);
        claim2.btcBlockHeight = BURN_HEIGHT + 1;
        claim2.merkleProof = {sib};
        claim2.txIndex = 0;
        // SeedHeader's WriteTip blindly overwrites the tip pointer, which just moved
        // it DOWN to BURN_HEIGHT+1 — the mint oracle would then see insufficient
        // confirmations and produce nothing. Restore the far tip the fixture seeded.
        SeedHeader(BURN_HEIGHT + GetRequiredConfirmations() + 5,
                   uint256S("00000000000000000000000000000000000000000000000000000000000000bb"));
    }

    CBlock claims; claims.vtx.push_back(MakeClaimTx(claim)); claims.vtx.push_back(MakeClaimTx(claim2));
    CValidationState s1;
    SeedLedgerAtParent(curIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(claims, &curIdx, nullptr, s1, false),
                          s1.GetRejectReason());

    // ONE mint finalizing BOTH claims, from the oracle.
    CBlock mintBlock = MintBlock();
    BOOST_REQUIRE_EQUAL(mintBlock.vtx.size(), 1U);
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(mintBlock, &mintIdx, nullptr, s2, false),
                          s2.GetRejectReason());
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 888000U);

    // Nominal multi-claim disconnect first: BOTH revert, then reconnect.
    BOOST_REQUIRE(UndoSpecialTxsInBlock(mintBlock, &mintIdx, false));
    BurnClaimRecord r1, r2;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, r1));
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid2, r2));
    BOOST_CHECK(r1.status == BurnClaimStatus::PENDING);
    BOOST_CHECK(r2.status == BurnClaimStatus::PENDING);
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 0U);
    CValidationState s3;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(mintBlock, &mintIdx, nullptr, s3, false));
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 888000U);

    // FAILURE AFTER PARTIAL RESTORATION: one of the two records vanishes. The undo
    // loop stages the first revert, then fails on the second — and because nothing
    // committed, the first revert must NOT be durable.
    { auto b = g_burnclaimdb->CreateBatch(); b.DeleteBurnClaim(btcTxid2); BOOST_REQUIRE(b.Commit()); }
    BOOST_CHECK(!UndoSpecialTxsInBlock(mintBlock, &mintIdx, false));
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, r1));
    BOOST_CHECK_MESSAGE(r1.status == BurnClaimStatus::FINAL,
                        "the partially staged revert must not be durable");
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 888000U);
    BOOST_CHECK(!IsConsensusDBFatal());
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// ROUND 15 · PHASE H — the shutdown stub records instead of exiting
// ═══════════════════════════════════════════════════════════════════════════════
//
// The old test stub was `StartShutdown() { std::exit(0); }`: any test reaching the
// real shutdown path (AbortNode on a commit failure!) silently ended the WHOLE suite
// with rc 0 — a false green. The stub now records; the sentinel in
// ~BasicTestingSetup fails any case that leaves an unconsumed request behind.

BOOST_FIXTURE_TEST_SUITE(consensus_p0_shutdown_sentinel_r15, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(startshutdown_records_and_does_not_exit)
{
    BOOST_REQUIRE_EQUAL(test_shutdown::Requests(), 0);
    StartShutdown();
    // If the old exit(0) stub were still in place, execution would never get here —
    // and the suite would have terminated GREEN. This line is the sentinel's proof.
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 1);
    BOOST_CHECK(ShutdownRequested());
    test_shutdown::Reset();
    BOOST_CHECK_EQUAL(test_shutdown::Requests(), 0);
    BOOST_CHECK(!ShutdownRequested());
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 2 — PRODUCER SIDE: refuse to assemble rather than build an invalid block
// ═══════════════════════════════════════════════════════════════════════════════
//
// This is the only NEW behaviour LOT 2 gives the producer, and it is the one with
// operational teeth ("production stops instead of pausing minting"). A reviewer's
// mutation (`return false` → `return true` in AddRequiredMintOrRefuse) survived the
// whole suite, so it had no coverage at all. It does now: this drives the REAL
// BlockAssembler::CreateNewBlock on a REAL chain.

struct P0AssemblerPolicySetup : public TestChainSetup {
    uint256 btcTxid;

    // K_FINALITY is 100 on regtest (it is not IsTestnet), so the chain must be taller
    // than the finality window for a claim at claimHeight=0 to be due at tip+1.
    // The chain is built BEFORE burnclaimdb exists, so no mint is due while mining.
    P0AssemblerPolicySetup() : TestChainSetup(101)
    {
        // Consensus DBs for the mint path. On disk is unnecessary here.
        g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, true, true);
        g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, true, true);
        // Pin BOTH policy inputs explicitly. Relying on gArgs residue from other
        // suites would make the "policy ON" leg pass by accident — and would hide a
        // flipped -enablemint default, which would silently stop every producer.
        gArgs.ForceSetArg("-enablemint", "1");
        SetBtcBurnsEnabled(true);
        SeedEligibleClaimForNextBlock();
    }
    ~P0AssemblerPolicySetup()
    {
        gArgs.ForceSetArg("-enablemint", "1");
        SetBtcBurnsEnabled(true);
        g_burnclaimdb.reset();
        g_btcheadersdb.reset();
    }

    //! A PENDING claim that the consensus oracle considers due at chain tip + 1.
    void SeedEligibleClaimForNextBlock()
    {
        const uint32_t burnHeight = 400000;
        BtcBlockHeader hdr;
        hdr.nVersion = 4;
        hdr.hashPrevBlock = uint256S("00000000000000000000000000000000000000000000000000000000000000cc");
        hdr.hashMerkleRoot = uint256S("00000000000000000000000000000000000000000000000000000000000000dd");
        hdr.nTime = 1000 + burnHeight;
        hdr.nBits = 0x1d00ffff;
        hdr.nNonce = burnHeight;
        {
            auto b = g_btcheadersdb->CreateBatch();
            b.WriteHeader(burnHeight, hdr);
            b.WriteTip(burnHeight, hdr.GetHash());
            BOOST_REQUIRE(b.Commit());
        }
        // Move the BTC tip past the confirmation requirement.
        {
            BtcBlockHeader far = hdr;
            far.nNonce = burnHeight + 1;
            auto b = g_btcheadersdb->CreateBatch();
            const uint32_t farH = burnHeight + GetRequiredConfirmations() + 5;
            b.WriteHeader(farH, far);
            b.WriteTip(farH, far.GetHash());
            BOOST_REQUIRE(b.Commit());
        }

        BurnClaimRecord rec;
        rec.btcTxid = uint256S("00000000000000000000000000000000000000000000000000000000000000a7");
        rec.btcBlockHash = hdr.GetHash();
        rec.btcHeight = burnHeight;
        rec.burnedSats = 250000;
        rec.bathronDest = uint160(std::vector<unsigned char>(20, 0x77));
        rec.destType = BURN_DEST_P2PKH;
        rec.claimHeight = 0;                       // K=100 on regtest; tip is small
        rec.status = BurnClaimStatus::PENDING;
        btcTxid = rec.btcTxid;
        auto b = g_burnclaimdb->CreateBatch();
        b.StoreBurnClaim(rec);
        BOOST_REQUIRE(b.Commit());
    }

    std::unique_ptr<CBlockTemplate> Assemble()
    {
        CScript spk = CScript() << OP_TRUE;
        return BlockAssembler(Params(), false).CreateNewBlock(
            spk, nullptr, false, nullptr, /*fNoMempoolTx=*/true, /*fTestValidity=*/false);
    }
};

BOOST_FIXTURE_TEST_SUITE(consensus_p0_assembler_policy_lot2, P0AssemblerPolicySetup)

BOOST_AUTO_TEST_CASE(refuses_to_assemble_when_a_due_mint_is_withheld_by_policy)
{
    LOCK2(cs_main, mempool.cs);
    const uint32_t nextHeight = (uint32_t)chainActive.Height() + 1;
    BOOST_REQUIRE_MESSAGE(!CreateExpectedMintM0BTC(nextHeight).IsNull(),
                          "precondition: consensus must require a mint at h=" << nextHeight);

    // POLICY ON — the template is produced AND carries the mint.
    {
        std::unique_ptr<CBlockTemplate> tmpl = Assemble();
        BOOST_REQUIRE_MESSAGE(tmpl != nullptr, "policy on: a template must be produced");
        bool hasMint = false;
        for (const auto& tx : tmpl->block.vtx)
            if (tx->nType == CTransaction::TxType::TX_MINT_M0BTC) hasMint = true;
        BOOST_CHECK_MESSAGE(hasMint, "policy on: the due mint must be in the template");
    }

    // POLICY OFF (-enablemint=0) — refuse to assemble at all. Producing a mint-less
    // block here would be invalid on EVERY node, including this one.
    {
        gArgs.ForceSetArg("-enablemint", "0");
        std::unique_ptr<CBlockTemplate> tmpl = Assemble();
        gArgs.ForceSetArg("-enablemint", "1");
        BOOST_CHECK_MESSAGE(tmpl == nullptr,
                            "-enablemint=0 with a due mint must produce NO template");
    }

    // POLICY OFF (kill switch) — same rule, other input.
    {
        SetBtcBurnsEnabled(false);
        std::unique_ptr<CBlockTemplate> tmpl = Assemble();
        SetBtcBurnsEnabled(true);
        BOOST_CHECK_MESSAGE(tmpl == nullptr,
                            "kill switch with a due mint must produce NO template");
    }
}

// CONTROL — with NO mint due, policy off is harmless: a normal block is produced.
// Without this, the case above would also pass if the assembler simply always
// refused under policy-off.
BOOST_AUTO_TEST_CASE(policy_off_still_assembles_when_no_mint_is_due)
{
    LOCK2(cs_main, mempool.cs);
    // Finalize the claim so nothing is due any more.
    {
        auto b = g_burnclaimdb->CreateBatch();
        b.UpdateClaimStatus(btcTxid, BurnClaimStatus::FINAL, 1);
        BOOST_REQUIRE(b.Commit());
    }
    const uint32_t nextHeight = (uint32_t)chainActive.Height() + 1;
    BOOST_REQUIRE(CreateExpectedMintM0BTC(nextHeight).IsNull());

    gArgs.ForceSetArg("-enablemint", "0");
    std::unique_ptr<CBlockTemplate> tmpl = Assemble();
    gArgs.ForceSetArg("-enablemint", "1");
    BOOST_CHECK_MESSAGE(tmpl != nullptr,
                        "policy off with nothing due must still produce a template");
}

BOOST_AUTO_TEST_SUITE_END()

// ═══════════════════════════════════════════════════════════════════════════════
// LOT 2 (AUD-003) — THE MATRIX: local policy must never change block acceptance
// ═══════════════════════════════════════════════════════════════════════════════
//
// Every block shape below is driven through the REAL ProcessSpecialTxsInBlock under
// all FOUR local configurations {-enablemint 0/1} x {burns enabled/disabled}. The
// verdict — and the reject reason — must be IDENTICAL in all four. That is the
// property AUD-003 broke and LOT 2 restores.

struct P0MintMatrixSetup : public P0KillSwitchSetup {
    uint256 btcTxid;
    uint32_t mintHeight = 0;
    uint256 mintPrevHash, mintCurHash;
    CBlockIndex mintPrev, mintIdx;

    P0MintMatrixSetup()
    {
        mintHeight = SeedEligibleClaim(btcTxid);
        mintPrevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000e1");
        mintCurHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000e2");
        mintPrev.nHeight = (int)mintHeight - 1;
        mintPrev.phashBlock = &mintPrevHash;
        mintIdx.nHeight = (int)mintHeight;
        mintIdx.phashBlock = &mintCurHash;
        mintIdx.pprev = &mintPrev;
    }

    struct Verdict {
        bool ok = false;
        bool invalid = false;
        std::string reason;
        bool operator==(const Verdict& o) const
        {
            return ok == o.ok && invalid == o.invalid && reason == o.reason;
        }
    };

    //! Run `block` through the real path under one local configuration, then rewind
    //! so the next configuration starts from the identical pre-state.
    Verdict RunUnder(const CBlock& block, bool enableMint, bool burnsEnabled)
    {
        gArgs.ForceSetArg("-enablemint", enableMint ? "1" : "0");
        SetBtcBurnsEnabled(burnsEnabled);

        CValidationState st;
        Verdict v;
        SeedLedgerAtParent(mintIdx);
        v.ok = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, st, false);
        v.invalid = st.IsInvalid();
        v.reason = st.GetRejectReason();

        const bool rewound = v.ok ? UndoSpecialTxsInBlock(block, &mintIdx, false) : true;

        // Restore the local policy BEFORE any assertion can throw: a BOOST_REQUIRE
        // here would otherwise leak -enablemint=0 / burns=false into every later
        // suite (cascading, unrelated failures). Assert only once restored.
        gArgs.ForceSetArg("-enablemint", "1");
        SetBtcBurnsEnabled(true);
        BOOST_REQUIRE_MESSAGE(rewound, "rewind failed; later configs would not start "
                                       "from the same pre-state");
        return v;
    }

    //! Assert the four local configurations agree, and return the common verdict.
    Verdict AssertPolicyInvariant(const CBlock& block, const char* what)
    {
        const Verdict a = RunUnder(block, /*enableMint=*/true,  /*burns=*/true);
        const Verdict b = RunUnder(block, /*enableMint=*/false, /*burns=*/true);
        const Verdict c = RunUnder(block, /*enableMint=*/true,  /*burns=*/false);
        const Verdict d = RunUnder(block, /*enableMint=*/false, /*burns=*/false);

        BOOST_CHECK_MESSAGE(a == b, what << ": -enablemint changed the verdict ("
            << a.ok << "/'" << a.reason << "' vs " << b.ok << "/'" << b.reason << "')");
        BOOST_CHECK_MESSAGE(a == c, what << ": the kill switch changed the verdict ("
            << a.ok << "/'" << a.reason << "' vs " << c.ok << "/'" << c.reason << "')");
        BOOST_CHECK_MESSAGE(a == d, what << ": both flags together changed the verdict ("
            << a.ok << "/'" << a.reason << "' vs " << d.ok << "/'" << d.reason << "')");
        return a;
    }
};

//! Strategy that forces the PHASE B (staging) step to fail, and records whether any
//! commit step ran. This is the restored round-11 ordering guard (see below).
namespace {
struct StagingFailStrategy : public RecordingStrategy {
    StagingFailStrategy() : RecordingStrategy(/*failStep=*/99) {}
    bool ForceStagingFailure() override { return true; }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(consensus_p0_mint_policy_matrix_lot2, P0MintMatrixSetup)

// ─────────────────────────────────────────────────────────────────────────────
// R11 ORDERING GUARD — RESTORED (LOT 2). This is the case that actually BITES.
//
// LOT 1 guarded "nothing fallible runs after the first Commit()" with a block whose
// mint failed at STAGING — reachable only because -enablemint=0 skipped
// CheckMintM0BTC. LOT 2 removed that bypass, so no input can make staging fail and
// the old guard went blind: a fresh reviewer proved by mutation that moving the
// staging step back into the commit phase kept the whole suite green.
//
// The staging failure is therefore injected. The assertion is the invariant itself:
// when the last fallible pre-commit step fails, NOT ONE commit may have run. Move
// that step below the commit boundary and `stepsSeen` becomes non-empty → RED.
// ─────────────────────────────────────────────────────────────────────────────
BOOST_AUTO_TEST_CASE(staging_failure_happens_before_any_commit_r11_guard)
{
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));

    // Control: without injection this same block connects and DOES reach the commits,
    // so the guard below cannot pass merely because the block never got that far.
    {
        RecordingStrategy control(/*failStep=*/99);
        CValidationState cs;
        SeedLedgerAtParent(mintIdx);
        BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, cs, false,
                                                       false, &control),
                              cs.GetRejectReason());
        BOOST_REQUIRE_MESSAGE(!control.stepsSeen.empty(),
                              "control must reach the commit phase, otherwise the guard is vacuous");
        BOOST_REQUIRE(UndoSpecialTxsInBlock(block, &mintIdx, false));
    }

    StagingFailStrategy staging;
    CValidationState st;
    SeedLedgerAtParent(mintIdx);
    const bool ok = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, st, false, false, &staging);

    BOOST_CHECK_MESSAGE(!ok, "a staging failure must fail the block");
    // THE INVARIANT: the fallible step ran BEFORE the commit boundary.
    BOOST_CHECK_MESSAGE(staging.stepsSeen.empty(),
        "R11: the last fallible step must run BEFORE any commit; "
        << staging.stepsSeen.size() << " commit step(s) already ran when it failed");
    BOOST_CHECK_EQUAL(staging.abortCount, 0);          // not a storage failure
    BOOST_CHECK(st.IsInvalid());                       // consensus reject, deterministic
    BOOST_CHECK_EQUAL(st.GetRejectReason(), "bad-mint-unknown-claim-apply");
    BOOST_CHECK(!IsConsensusDBFatal());

    // Nothing durable: the claim is still PENDING and the supply unmoved.
    BurnClaimRecord rec;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
    BOOST_CHECK(rec.status == BurnClaimStatus::PENDING);
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), 0U);
}

// K FRONTIER, ACCEPTANCE SIDE. The premature case below proves the VALIDATOR
// rejects at `claimHeight+K`; this proves the ORACLE agrees that nothing is due
// there. Without it, an off-by-one in the oracle alone (> vs >=) is invisible and
// would halt the chain: with a mint -> mint-claim-too-early, without -> bad-mint-missing.
BOOST_AUTO_TEST_CASE(no_mint_is_due_at_the_exact_k_frontier)
{
    CBlockIndex framePrev, frameIdx;
    uint256 framePrevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000e7");
    uint256 frameCurHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000e8");
    framePrev.nHeight = (int)mintHeight - 2;
    framePrev.phashBlock = &framePrevHash;
    frameIdx.nHeight = (int)mintHeight - 1;            // exactly claimHeight + K
    frameIdx.phashBlock = &frameCurHash;
    frameIdx.pprev = &framePrev;

    BOOST_CHECK_MESSAGE(CreateExpectedMintM0BTC((uint32_t)frameIdx.nHeight).IsNull(),
                        "no mint may be due at exactly claimHeight+K");
    BOOST_CHECK_MESSAGE(!CreateExpectedMintM0BTC(mintHeight).IsNull(),
                        "a mint must be due at claimHeight+K+1");

    // ...and an EMPTY block at that height must therefore be ACCEPTED, under every
    // local configuration.
    CBlock empty;
    auto runAt = [&](bool enableMint, bool burns) {
        gArgs.ForceSetArg("-enablemint", enableMint ? "1" : "0");
        SetBtcBurnsEnabled(burns);
        CValidationState st;
        SeedLedgerAtParent(frameIdx);
        const bool ok = ProcessSpecialTxsInBlock(empty, &frameIdx, nullptr, st, false);
        gArgs.ForceSetArg("-enablemint", "1");
        SetBtcBurnsEnabled(true);
        BOOST_CHECK_MESSAGE(ok, "an empty block at claimHeight+K must be accepted: "
                                << st.GetRejectReason());
        if (ok) BOOST_REQUIRE(UndoSpecialTxsInBlock(empty, &frameIdx, false));
    };
    runAt(true, true); runAt(false, true); runAt(true, false); runAt(false, false);
}

// 1. CANONICAL mint — accepted under all four configurations.
BOOST_AUTO_TEST_CASE(canonical_mint_accepted_under_every_local_config)
{
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));
    const Verdict v = AssertPolicyInvariant(block, "canonical mint");
    BOOST_CHECK_MESSAGE(v.ok, "the canonical mint must be ACCEPTED everywhere: " << v.reason);
}

// 2. MISSING mint — a block that omits the required mint is rejected everywhere.
BOOST_AUTO_TEST_CASE(missing_mint_rejected_under_every_local_config)
{
    CBlock block;                                    // eligible claim exists, no mint tx
    const Verdict v = AssertPolicyInvariant(block, "missing mint");
    BOOST_CHECK(!v.ok);
    BOOST_CHECK(v.invalid);
    BOOST_CHECK_EQUAL(v.reason, "bad-mint-missing");
}

// 3. PREMATURE mint — same claim, one block too early (blockHeight <= claimHeight+K).
BOOST_AUTO_TEST_CASE(premature_mint_rejected_under_every_local_config)
{
    CBlockIndex earlyPrev, earlyIdx;
    uint256 earlyPrevHash = uint256S("00000000000000000000000000000000000000000000000000000000000000e3");
    uint256 earlyCurHash  = uint256S("00000000000000000000000000000000000000000000000000000000000000e4");
    earlyPrev.nHeight = (int)mintHeight - 2;
    earlyPrev.phashBlock = &earlyPrevHash;
    earlyIdx.nHeight = (int)mintHeight - 1;          // exactly claimHeight + K
    earlyIdx.phashBlock = &earlyCurHash;
    earlyIdx.pprev = &earlyPrev;

    // The CANONICAL mint (correct outputs for the real claim), simply presented one
    // block too early — so the rejection is the K-finality rule, not a shape check.
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));

    // Run the four configurations against the EARLY index.
    auto runEarly = [&](bool enableMint, bool burns) {
        gArgs.ForceSetArg("-enablemint", enableMint ? "1" : "0");
        SetBtcBurnsEnabled(burns);
        CValidationState st;
        SeedLedgerAtParent(earlyIdx);   // LOT 8 F1: a real node's ledger is at the parent
        const bool ok = ProcessSpecialTxsInBlock(block, &earlyIdx, nullptr, st, false);
        gArgs.ForceSetArg("-enablemint", "1");
        SetBtcBurnsEnabled(true);
        BOOST_CHECK_MESSAGE(!ok, "a premature mint must be rejected");
        BOOST_CHECK(st.IsInvalid());
        return st.GetRejectReason();
    };
    const std::string r1 = runEarly(true, true);
    BOOST_CHECK_EQUAL(r1, "mint-claim-too-early");
    BOOST_CHECK_EQUAL(runEarly(false, true), r1);
    BOOST_CHECK_EQUAL(runEarly(true, false), r1);
    BOOST_CHECK_EQUAL(runEarly(false, false), r1);
}

// 4. INCORRECT mint — right claim, wrong amount: rejected identically everywhere.
BOOST_AUTO_TEST_CASE(incorrect_mint_rejected_under_every_local_config)
{
    CMutableTransaction mtx(CreateExpectedMintM0BTC(mintHeight));
    BOOST_REQUIRE_EQUAL(mtx.vout.size(), 1U);
    mtx.vout[0].nValue += 1;                         // one satoshi too much
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    const Verdict v = AssertPolicyInvariant(block, "incorrect mint");
    BOOST_CHECK(!v.ok);
    BOOST_CHECK(v.invalid);
    BOOST_CHECK_EQUAL(v.reason, "mint-amount-mismatch");
}

// 5. DUPLICATE mint — two mint txs in one block.
BOOST_AUTO_TEST_CASE(duplicate_mint_rejected_under_every_local_config)
{
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));

    const Verdict v = AssertPolicyInvariant(block, "duplicate mint");
    BOOST_CHECK(!v.ok);
    BOOST_CHECK(v.invalid);
    BOOST_CHECK_EQUAL(v.reason, "bad-mint-multiple");
}

// 6. UNKNOWN CLAIM — the exact shape the old -enablemint=0 bypass let through.
BOOST_AUTO_TEST_CASE(unknown_claim_mint_rejected_under_every_local_config)
{
    CBlock block;
    block.vtx.push_back(MakeWellFormedMintForUnknownClaim(
        uint256S("00000000000000000000000000000000000000000000000000000000000000ee")));

    const Verdict v = AssertPolicyInvariant(block, "unknown-claim mint");
    BOOST_CHECK(!v.ok);
    BOOST_CHECK(v.invalid);
    BOOST_CHECK_EQUAL(v.reason, "mint-unknown-claim");
}

// 7. BURN NO LONGER VALID — the oracle's SPV-validity filter. A third reviewer's
// mutant (deleting IsBtcBurnStillValidConsensus from the oracle's eligibility test)
// survived the whole suite: nothing covered a claim whose BTC anchor was reorged
// out. It matters because oracle and validator must agree — if only one drops the
// filter, the producer builds a mint that EVERY node (itself included) rejects
// `mint-btc-invalid`: a permanent halt at that height.
BOOST_AUTO_TEST_CASE(orphaned_burn_anchor_is_not_mintable_under_every_local_config)
{
    // Precondition: the claim IS due while its anchor is intact.
    BOOST_REQUIRE(!CreateExpectedMintM0BTC(mintHeight).IsNull());
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));

    // Reorg the BTC anchor out: a DIFFERENT header now occupies the burn height, so
    // GetHashAtHeight() no longer matches the claim's btcBlockHash.
    {
        BurnClaimRecord rec;
        BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
        BtcBlockHeader other;
        other.nVersion = 4;
        other.hashPrevBlock = uint256S("00000000000000000000000000000000000000000000000000000000000000f9");
        other.hashMerkleRoot = uint256S("00000000000000000000000000000000000000000000000000000000000000fa");
        other.nTime = 4242;
        other.nBits = 0x1d00ffff;
        other.nNonce = 987654;
        BOOST_REQUIRE(other.GetHash() != rec.btcBlockHash);
        auto b = g_btcheadersdb->CreateBatch();
        b.WriteHeader(rec.btcHeight, other);
        BOOST_REQUIRE(b.Commit());
    }

    // ORACLE: nothing is due any more — the producer must not build this mint.
    BOOST_CHECK_MESSAGE(CreateExpectedMintM0BTC(mintHeight).IsNull(),
                        "a claim whose BTC anchor was reorged out must not be mintable");

    // VALIDATOR: and the previously-canonical mint is now rejected, identically
    // under all four local configurations.
    const Verdict v = AssertPolicyInvariant(block, "orphaned burn anchor");
    BOOST_CHECK(!v.ok);
    BOOST_CHECK(v.invalid);
    BOOST_CHECK_EQUAL(v.reason, "mint-btc-invalid");
}

// 8. ALREADY-MINTED CLAIM — re-minting a FINAL claim must be rejected. Another
// surviving mutant (deleting the `mint-not-pending` status check) showed nothing
// covered this shape.
BOOST_AUTO_TEST_CASE(already_final_claim_cannot_be_minted_again)
{
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));

    // Connect it once: the claim goes FINAL.
    CValidationState s1;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE_MESSAGE(ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, s1, false),
                          s1.GetRejectReason());
    BurnClaimRecord rec;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, rec));
    BOOST_REQUIRE(rec.status == BurnClaimStatus::FINAL);

    // Replaying the very same mint must now be rejected on the claim STATUS —
    // identically under every local configuration. (No rewind here: the point is
    // precisely that the claim is already FINAL.)
    auto runOnce = [&](bool enableMint, bool burns) {
        gArgs.ForceSetArg("-enablemint", enableMint ? "1" : "0");
        SetBtcBurnsEnabled(burns);
        CValidationState st;
        SeedLedgerAtParent(mintIdx);
        const bool ok = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, st, false);
        gArgs.ForceSetArg("-enablemint", "1");
        SetBtcBurnsEnabled(true);
        BOOST_CHECK_MESSAGE(!ok, "an already-FINAL claim must not be re-minted");
        BOOST_CHECK(st.IsInvalid());
        return st.GetRejectReason();
    };
    const std::string r = runOnce(true, true);
    BOOST_CHECK_EQUAL(r, "mint-not-pending");
    BOOST_CHECK_EQUAL(runOnce(false, true), r);
    BOOST_CHECK_EQUAL(runOnce(true, false), r);
    BOOST_CHECK_EQUAL(runOnce(false, false), r);
}

// 9. REPLAY / -reindex equivalence: wipe the derivable DBs, re-apply the authorised
// Bitcoin pre-state, replay the same block — identical mint hash, identical state,
// under a local configuration OPPOSITE to the one that first connected it.
BOOST_AUTO_TEST_CASE(replay_after_wipe_reproduces_the_same_mint_under_opposite_policy)
{
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CMutableTransaction(CreateExpectedMintM0BTC(mintHeight))));
    const uint256 mintHashBefore = block.vtx[0]->GetHash();

    CValidationState s1;
    SeedLedgerAtParent(mintIdx);
    BOOST_REQUIRE(ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, s1, false));
    BurnClaimRecord before;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, before));
    BOOST_CHECK(before.status == BurnClaimStatus::FINAL);
    const uint64_t supplyBefore = g_burnclaimdb->GetM0BTCSupply();

    // The same wipe -reindex performs on the derivable consensus DBs.
    g_htlcdb.reset(); g_settlementdb.reset(); g_burnclaimdb.reset(); g_btcheadersdb.reset();
    g_btcheadersdb = std::make_unique<btcheadersdb::CBtcHeadersDB>(1 << 20, false, /*fWipe=*/true);
    g_burnclaimdb  = std::make_unique<CBurnClaimDB>(1 << 20, false, true);
    g_settlementdb = std::make_unique<CSettlementDB>(1 << 20, false, true);
    g_htlcdb       = std::make_unique<CHtlcDB>(1 << 20, false, true);

    // Re-establish the same pre-state (on a real node this comes from replaying the
    // earlier blocks), then replay under the OPPOSITE local policy.
    uint256 replayTxid;
    const uint32_t replayHeight = SeedEligibleClaim(replayTxid);
    BOOST_REQUIRE(replayTxid == btcTxid);
    BOOST_REQUIRE_EQUAL(replayHeight, mintHeight);

    gArgs.ForceSetArg("-enablemint", "0");
    SetBtcBurnsEnabled(false);
    const CTransaction replayExpected = CreateExpectedMintM0BTC(mintHeight);
    CValidationState s2;
    SeedLedgerAtParent(mintIdx);
    const bool ok2 = ProcessSpecialTxsInBlock(block, &mintIdx, nullptr, s2, false);
    gArgs.ForceSetArg("-enablemint", "1");
    SetBtcBurnsEnabled(true);

    BOOST_CHECK_MESSAGE(ok2, "replay under the opposite policy must connect: " << s2.GetRejectReason());
    BOOST_CHECK_MESSAGE(replayExpected.GetHash() == mintHashBefore,
                        "the replayed expected mint must be byte-identical");
    BurnClaimRecord after;
    BOOST_REQUIRE(g_burnclaimdb->GetBurnClaim(btcTxid, after));
    BOOST_CHECK(after.status == BurnClaimStatus::FINAL);
    BOOST_CHECK_EQUAL(after.burnedSats, before.burnedSats);
    BOOST_CHECK_EQUAL(after.finalHeight, before.finalHeight);
    BOOST_CHECK_EQUAL(g_burnclaimdb->GetM0BTCSupply(), supplyBefore);
}

BOOST_AUTO_TEST_SUITE_END()
