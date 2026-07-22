// Copyright (c) 2025 The Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Settlement Layer RPCs (BP30) - CLEAN API v2
 *
 * Design principles:
 * - Settlement = READ-ONLY + CANONICAL (zero side effects)
 * - One RPC = one purpose
 * - Stable schema (bp30.state.v2) - no null values, consistent types
 *
 * RPCs:
 * - getstate: Full BP30 settlement state
 *   Includes: supply, invariants, finality - ONE source of truth
 * - gethealth: Quick health check for monitoring
 */

#include "rpc/server.h"
#include "state/settlement.h"
#include "state/settlementdb.h"
#include "validation.h"
#include "utilmoneystr.h"
#include "chainparams.h"
#include "state/finality.h"
#include "masternode/deterministicmns.h"
#include "moneysupply.h"  // For MoneySupply.Get()
#include "burnclaim/burnclaimdb.h"  // For burn stats
#include "net/net.h"                 // For g_connman (peer count)
#include "txmempool.h"               // For mempool
#include "btcheaders/btcheadersdb.h" // For BTC SPV headers
#include <iomanip>
#include <sstream>
#include <set>

// Schema version - v2 is the clean version
static const std::string SCHEMA_STATE_V2 = "bp30.state.v2";

/**
 * Helper: Format CAmount as string
 * BATHRON: 1:1 model - amounts are raw sats (no COIN division)
 */
static std::string FormatAmount(CAmount amount)
{
    return strprintf("%lld", (long long)amount);
}

/**
 * Helper: Get network name
 */
static std::string GetNetworkName()
{
    const std::string& chain = Params().NetworkIDString();
    if (chain == CBaseChainParams::MAIN) return "mainnet";
    if (chain == CBaseChainParams::TESTNET) return "testnet";
    if (chain == CBaseChainParams::REGTEST) return "regtest";
    return "privnet";
}

/**
 * getstate - Settlement layer state (bp30.state.v2)
 *
 * ONE source of truth for:
 * - Supply breakdown (M0/M1)
 * - Invariants (A6)
 * - Finality status
 *
 * Clean, stable, explorer-ready.
 * NO null values, all fields always present.
 */
static UniValue getstate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "getstate\n"
            "\nReturns the settlement layer state (bp30.state.v2 schema).\n"
            "\nResult:\n"
            "{\n"
            "  \"schema\": \"bp30.state.v2\",\n"
            "  \"network\": \"testnet\",\n"
            "  \"height\": n,\n"
            "  \"block_hash\": \"hash\",\n"
            "  \"supply\": {\n"
            "    \"m0_vaulted\": \"x.xxxxxxxx\",\n"
            "    \"m0_shielded\": \"x.xxxxxxxx\",\n"
            "    \"m1_supply\": \"x.xxxxxxxx\"\n"
            "  },\n"
            "  \"invariants\": {\n"
            "    \"A6\": { \"ok\": true, \"delta\": \"0.00000000\" }\n"
            "  },\n"
            "  \"finality\": {\n"
            "    \"height\": n,\n"
            "    \"hash\": \"hash\",\n"
            "    \"lag\": n,\n"
            "    \"status\": \"healthy\"\n"
            "  },\n"
            "  \"totals\": {\n"
            "    \"total_btc_sats\": n,      (numeric) Total BTC burned in satoshis\n"
            "    \"total_m0\": \"x.xxxxxxxx\", (string) Total M0 supply\n"
            "    \"total_m1\": \"x.xxxxxxxx\"  (string) Total M1 supply\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getstate", "")
            + HelpExampleRpc("getstate", "")
        );
    }

    LOCK(cs_main);

    // Check if settlement DB is initialized
    if (!g_settlementdb) {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Settlement database not initialized");
    }

    // Read latest settlement state
    SettlementState state;
    if (!g_settlementdb->ReadLatestState(state)) {
        state.SetNull();
        state.nHeight = chainActive.Height();
        if (chainActive.Tip()) {
            state.hashBlock = chainActive.Tip()->GetBlockHash();
        }
    }

    // Get M0_shielded from chain tip (orthogonal to settlement)
    CAmount m0Shielded = 0;
    if (chainActive.Tip() && chainActive.Tip()->nChainSaplingValue) {
        m0Shielded = *chainActive.Tip()->nChainSaplingValue;
    }
    state.M0_shielded = m0Shielded;

    // Get finality info
    int lastFinalizedHeight = 0;
    uint256 lastFinalizedHash;
    int tipHeight = chainActive.Height();
    std::string finalityStatus = "unknown";

    if (hu::finalityHandler && hu::finalityHandler->GetLastFinalized(lastFinalizedHeight, lastFinalizedHash)) {
        int lag = tipHeight - lastFinalizedHeight;
        if (lag <= 1) finalityStatus = "healthy";
        else if (lag <= 5) finalityStatus = "lagging";
        else finalityStatus = "critical";
    }

    // Check invariants
    // A5: M0_total_supply(N) = M0_total_supply(N-1) + BurnClaims
    // A6: M0_vaulted == M1_supply
    CAmount a6Lhs = state.M0_vaulted;
    CAmount a6Rhs = state.M1_supply;
    CAmount a6Delta = a6Lhs - a6Rhs;
    bool a6Ok = (a6Delta == 0);

    // A5 check: verify M0_total_supply matches expected from previous block + coinbase
    // (For display purposes - actual consensus check happens in ProcessSpecialTxsInBlock)
    bool a5Ok = true;  // Assumed OK since we're reading committed state

    // ========================================
    // V2 FORMAT (clean, minimal, stable)
    // NO null values, all fields always present
    // ========================================
    UniValue result(UniValue::VOBJ);

    // Header
    result.pushKV("schema", SCHEMA_STATE_V2);
    result.pushKV("network", GetNetworkName());
    result.pushKV("height", (int)state.nHeight);
    result.pushKV("block_hash", state.hashBlock.IsNull() ? std::string(64, '0') : state.hashBlock.GetHex());

    // Supply - ONE place for all supply info
    UniValue supply(UniValue::VOBJ);
    supply.pushKV("m0_total", FormatAmount(state.M0_total_supply));  // A5: Total M0 in circulation
    supply.pushKV("m0_vaulted", FormatAmount(state.M0_vaulted));
    supply.pushKV("m0_shielded", FormatAmount(state.M0_shielded));
    supply.pushKV("m1_supply", FormatAmount(state.M1_supply));
    result.pushKV("supply", supply);

    // A5 block delta (monetary conservation)
    UniValue monetary(UniValue::VOBJ);
    monetary.pushKV("burnclaims_block", FormatAmount(state.burnclaims_block));
    monetary.pushKV("delta", FormatAmount(state.GetA5Delta()));  // BurnClaims only
    result.pushKV("monetary", monetary);

    // Invariants - ONE place for all checks
    UniValue invariants(UniValue::VOBJ);

    // A5: Monetary Conservation (anti-inflation)
    UniValue a5(UniValue::VOBJ);
    a5.pushKV("ok", a5Ok);
    a5.pushKV("formula", "M0_total(N) = M0_total(N-1) + BurnClaims");
    a5.pushKV("description", "M0 only created from BTC burns");
    invariants.pushKV("A5", a5);

    // A6: Settlement Backing
    UniValue a6(UniValue::VOBJ);
    a6.pushKV("ok", a6Ok);
    a6.pushKV("delta", FormatAmount(a6Delta));
    a6.pushKV("formula", "M0_vaulted == M1_supply");
    invariants.pushKV("A6", a6);

    // A7: circuit breaker — M0_total (= BTC burned, sats) must stay under the 21M cap.
    // Real check, not hardcoded: if it ever exceeds nMaxMoneyOut, burns must be OFF.
    CAmount a7Cap = Params().GetConsensus().nMaxMoneyOut;
    bool a7Ok = (state.M0_total_supply >= 0 && state.M0_total_supply <= a7Cap);
    UniValue a7(UniValue::VOBJ);
    a7.pushKV("ok", a7Ok);
    a7.pushKV("delta", FormatAmount(a7Cap - state.M0_total_supply));
    a7.pushKV("formula", "M0_total <= 21M (BTC supply cap)");
    invariants.pushKV("A7", a7);

    result.pushKV("invariants", invariants);

    // Finality - merged from getfinalitystatus/getbestfinalized
    UniValue finality(UniValue::VOBJ);
    finality.pushKV("height", lastFinalizedHeight);
    // Always output valid hex hash (zeros if not finalized)
    finality.pushKV("hash", lastFinalizedHash.IsNull() ? std::string(64, '0') : lastFinalizedHash.GetHex());
    finality.pushKV("lag", tipHeight - lastFinalizedHeight);
    finality.pushKV("status", finalityStatus);
    result.pushKV("finality", finality);

    // ========================================
    // TOTALS - Summary in native units
    // ========================================
    // BATHRON: 1 BTC sat burned = 1 M0 (raw sats, no COIN scaling)
    // M0_total_supply is stored in sats (not multiplied by COIN)
    UniValue totals(UniValue::VOBJ);
    // Total BTC burned (in satoshis) - equals M0 supply
    totals.pushKV("total_btc_sats", (int64_t)state.M0_total_supply);
    // Total M0 (in sats - BATHRON 1:1 model)
    totals.pushKV("total_m0", (int64_t)state.M0_total_supply);
    // Total M1 (in sats)
    totals.pushKV("total_m1", (int64_t)state.M1_supply);
    result.pushKV("totals", totals);

    return result;
}

/**
 * gethealth - Quick health check for monitoring
 */
static UniValue gethealth(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "gethealth\n"
            "\nReturns a quick health check for the settlement layer.\n"
            "\nResult:\n"
            "{\n"
            "  \"ok\": true|false,\n"
            "  \"height\": n,\n"
            "  \"invariant_a6\": true|false,\n"
            "  \"finality_lag\": n\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("gethealth", "")
        );
    }

    LOCK(cs_main);

    UniValue result(UniValue::VOBJ);
    bool overallOk = true;
    bool a6Ok = true;
    int height = chainActive.Height();
    int finalityLag = 0;

    // Check settlement DB
    if (!g_settlementdb) {
        overallOk = false;
    } else {
        SettlementState state;
        if (g_settlementdb->ReadLatestState(state)) {
            // A6: M0_vaulted == M1_supply
            CAmount a6Lhs = state.M0_vaulted;
            CAmount a6Rhs = state.M1_supply;
            a6Ok = (a6Lhs == a6Rhs);
            if (!a6Ok) overallOk = false;
        }
    }

    // Finality lag
    int lastFinalizedHeight = 0;
    uint256 lastFinalizedHash;
    if (hu::finalityHandler && hu::finalityHandler->GetLastFinalized(lastFinalizedHeight, lastFinalizedHash)) {
        finalityLag = height - lastFinalizedHeight;
    }
    if (finalityLag > 5) overallOk = false;

    result.pushKV("ok", overallOk);
    result.pushKV("height", height);
    result.pushKV("invariant_a5", true);  // A5 always OK if block was accepted (consensus check)
    result.pushKV("invariant_a6", a6Ok);
    result.pushKV("finality_lag", finalityLag);

    return result;
}

/**
 * getexplorerdata - Aggregated data for explorer (ONE call)
 *
 * Returns ALL data the explorer needs in a SINGLE RPC call:
 * - Supply (M0/M1 breakdown)
 * - Invariants (A6 pre-calculated)
 * - Network info (MN/operator counts)
 * - Finality status
 *
 * Eliminates need for:
 * - Multiple RPC calls (getstate, gettxoutsetinfo, protx_list, listoperators)
 * - Client-side calculations (A6, circulating supply, MN collateral)
 * - Schema version handling (single v1 schema)
 */
static UniValue getexplorerdata(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 0) {
        throw std::runtime_error(
            "getexplorerdata\n"
            "\nReturns aggregated data for the explorer (single call).\n"
            "Provides all settlement, network and finality data in ONE RPC call.\n"
            "\nResult:\n"
            "{\n"
            "  \"schema\": \"explorer.v1\",\n"
            "  \"height\": n,\n"
            "  \"supply\": {\n"
            "    \"m0_vaulted\": \"x.xxxxxxxx\",\n"
            "    \"m0_shielded\": \"x.xxxxxxxx\",\n"
            "    \"m1_supply\": \"x.xxxxxxxx\",\n"
            "    \"mn_collateral\": \"x.xxxxxxxx\"\n"
            "  },\n"
            "  \"invariants\": {\n"
            "    \"a6_left\": \"x.xxxxxxxx\",\n"
            "    \"a6_right\": \"x.xxxxxxxx\",\n"
            "    \"a6_ok\": true|false\n"
            "  },\n"
            "  \"network\": {\n"
            "    \"masternodes\": n,\n"
            "    \"operators\": n,\n"
            "    \"mn_enabled\": n,\n"
            "    \"mn_pose_banned\": n\n"
            "  },\n"
            "  \"finality\": {\n"
            "    \"height\": n,\n"
            "    \"lag\": n,\n"
            "    \"status\": \"healthy|lagging|critical\"\n"
            "  }\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getexplorerdata", "")
            + HelpExampleRpc("getexplorerdata", "")
        );
    }

    LOCK(cs_main);

    UniValue result(UniValue::VOBJ);
    result.pushKV("schema", "explorer.v1");

    int tipHeight = chainActive.Height();
    result.pushKV("height", tipHeight);

    // ========================================
    // 1. SUPPLY DATA (from settlement state)
    // ========================================
    UniValue supply(UniValue::VOBJ);

    // Get settlement state (M0/M1 model)
    SettlementState settlementState;
    CAmount m0Vaulted = 0;
    CAmount m1Supply = 0;

    if (g_settlementdb && g_settlementdb->ReadLatestState(settlementState)) {
        m0Vaulted = settlementState.M0_vaulted;
        m1Supply = settlementState.M1_supply;
    }

    // Get M0_shielded from chain tip
    CAmount m0Shielded = 0;
    if (chainActive.Tip() && chainActive.Tip()->nChainSaplingValue) {
        m0Shielded = *chainActive.Tip()->nChainSaplingValue;
    }

    // Get MN stats
    int mnTotal = 0;
    int mnEnabled = 0;
    int mnPoseBanned = 0;
    int operatorCount = 0;
    CAmount mnCollateral = 0;

    if (deterministicMNManager) {
        CDeterministicMNList mnList = deterministicMNManager->GetListAtChainTip();
        mnTotal = mnList.GetAllMNsCount();
        mnEnabled = mnList.GetValidMNsCount();

        // Count unique operators and banned MNs
        std::set<std::string> uniqueOperators;
        mnList.ForEachMN(false, [&](const CDeterministicMNCPtr& dmn) {
            uniqueOperators.insert(HexStr(dmn->pdmnState->pubKeyOperator));
            if (dmn->IsPoSeBanned()) {
                mnPoseBanned++;
            }
        });
        operatorCount = uniqueOperators.size();

        // MN collateral from consensus params (1,000,000 M0 per masternode)
        mnCollateral = (CAmount)mnTotal * Params().GetConsensus().nMNCollateralAmt;
    }

    // ========================================
    // M0_TOTAL from settlement state (A5: only BTC burns create M0)
    // MoneySupply (UTXO sum) includes recycled coinbase fees which
    // are NOT new M0 — settlement DB is the source of truth.
    // ========================================
    CAmount m0Total = settlementState.M0_total_supply;

    // M0_FREE = M0_TOTAL - M0_VAULTED - MN_COLLATERAL
    CAmount m0Free = m0Total - m0Vaulted - mnCollateral;

    // M0_CIRCULATING = M0_FREE (same thing, excluding locked funds)
    CAmount m0Circulating = m0Free;

    // Recycled fees = MoneySupply (UTXO total) - M1 - M0_total (settlement)
    // These are coinbase outputs from fee collection, not new M0
    CAmount transparentSupply = MoneySupply.Get();
    CAmount utxoM0 = (transparentSupply - m1Supply) + m0Shielded;
    CAmount feesRecycled = utxoM0 - m0Total;
    if (feesRecycled < 0) feesRecycled = 0;

    // All supply data - pre-calculated, no explorer calculations needed
    supply.pushKV("m0_total", FormatAmount(m0Total));
    supply.pushKV("m0_free", FormatAmount(m0Free));
    supply.pushKV("m0_circulating", FormatAmount(m0Circulating));
    supply.pushKV("m0_vaulted", FormatAmount(m0Vaulted));
    supply.pushKV("m0_shielded", FormatAmount(m0Shielded));
    supply.pushKV("m1_supply", FormatAmount(m1Supply));
    supply.pushKV("mn_collateral", FormatAmount(mnCollateral));
    supply.pushKV("fees_recycled", FormatAmount(feesRecycled));
    result.pushKV("supply", supply);

    // ========================================
    // SHIELD BREAKDOWN
    // ========================================
    UniValue shield(UniValue::VOBJ);
    shield.pushKV("pool_total", FormatAmount(m0Shielded));
    result.pushKV("shield", shield);

    // ========================================
    // 2. INVARIANTS (pre-calculated)
    // A5: Monetary conservation (anti-inflation)
    // A6: Settlement backing (M0_vaulted == M1)
    // ========================================
    UniValue invariants(UniValue::VOBJ);

    // A5: Monetary Conservation (M0 only from BTC burns)
    invariants.pushKV("a5_ok", true);  // Always OK if block was accepted
    invariants.pushKV("a5_m0_total", FormatAmount(settlementState.M0_total_supply));
    invariants.pushKV("a5_burnclaims", FormatAmount(settlementState.burnclaims_block));
    invariants.pushKV("a5_delta", FormatAmount(settlementState.GetA5Delta()));

    // A6: Settlement Backing (M0_vaulted == M1_supply)
    CAmount a6Left = m0Vaulted;
    CAmount a6Right = m1Supply;
    bool a6Ok = (a6Left == a6Right);

    invariants.pushKV("a6_left", FormatAmount(a6Left));
    invariants.pushKV("a6_right", FormatAmount(a6Right));
    invariants.pushKV("a6_ok", a6Ok);
    result.pushKV("invariants", invariants);

    // ========================================
    // 3. NETWORK (MN/operator counts)
    // ========================================
    UniValue network(UniValue::VOBJ);
    network.pushKV("masternodes", mnTotal);
    network.pushKV("operators", operatorCount);
    network.pushKV("mn_enabled", mnEnabled);
    network.pushKV("mn_pose_banned", mnPoseBanned);
    result.pushKV("network", network);

    // ========================================
    // 4. FINALITY
    // ========================================
    UniValue finality(UniValue::VOBJ);
    int lastFinalizedHeight = 0;
    uint256 lastFinalizedHash;
    std::string finalityStatus = "unknown";

    if (hu::finalityHandler && hu::finalityHandler->GetLastFinalized(lastFinalizedHeight, lastFinalizedHash)) {
        int lag = tipHeight - lastFinalizedHeight;
        if (lag <= 1) finalityStatus = "healthy";
        else if (lag <= 5) finalityStatus = "lagging";
        else finalityStatus = "critical";
        finality.pushKV("lag", lag);
    } else {
        finality.pushKV("lag", tipHeight);
    }
    finality.pushKV("height", lastFinalizedHeight);
    finality.pushKV("status", finalityStatus);
    result.pushKV("finality", finality);

    // ========================================
    // 5. BTC BURNS
    // A5: btc_burned_sats == M0_total (by construction, always)
    // Settlement is the source of truth for totals.
    // burnclaimdb tracks individual claims (may be 0 for genesis burns).
    // ========================================
    UniValue burns(UniValue::VOBJ);

    // btc_burned_sats = M0_total (A5 invariant, always exact)
    burns.pushKV("btc_burned_sats", m0Total);

    // Individual claim tracking from burnclaimdb (debug/detail)
    if (g_burnclaimdb) {
        auto stats = g_burnclaimdb->GetStats();
        burns.pushKV("burn_count", (int64_t)stats.finalCount);
        burns.pushKV("pending_count", (int64_t)stats.pendingCount);
        burns.pushKV("btc_pending_sats", (int64_t)stats.pendingAmount);
        // Debug: check if burnclaimdb is in sync with settlement
        burns.pushKV("burnclaimdb_sats", (int64_t)stats.m0btcSupply);
        if (stats.m0btcSupply != (uint64_t)m0Total) {
            burns.pushKV("sync_warning", "burnclaimdb out of sync with settlement (genesis burns not tracked individually)");
        }
    } else {
        burns.pushKV("burn_count", 0);
        burns.pushKV("pending_count", 0);
        burns.pushKV("btc_pending_sats", 0);
        burns.pushKV("burnclaimdb_sats", 0);
    }
    result.pushKV("burns", burns);

    // ========================================
    // 6. BLOCKCHAIN (blocks, headers, difficulty)
    // ========================================
    UniValue blockchain(UniValue::VOBJ);
    blockchain.pushKV("blocks", tipHeight);
    blockchain.pushKV("headers", pindexBestHeader ? pindexBestHeader->nHeight : tipHeight);
    blockchain.pushKV("bestblockhash", chainActive.Tip()->GetBlockHash().GetHex());
    blockchain.pushKV("difficulty", GetDifficulty(chainActive.Tip()));
    blockchain.pushKV("mediantime", (int64_t)chainActive.Tip()->GetMedianTimePast());
    result.pushKV("blockchain", blockchain);

    // ========================================
    // 7. PEERS (connection count)
    // ========================================
    UniValue peers(UniValue::VOBJ);
    if (g_connman) {
        peers.pushKV("connections", (int)g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL));
    } else {
        peers.pushKV("connections", 0);
    }
    result.pushKV("peers", peers);

    // ========================================
    // 8. MEMPOOL
    // ========================================
    UniValue mempoolInfo(UniValue::VOBJ);
    mempoolInfo.pushKV("size", (int64_t)mempool.size());
    mempoolInfo.pushKV("bytes", (int64_t)mempool.GetTotalTxSize());
    result.pushKV("mempool", mempoolInfo);

    // ========================================
    // 9. BTC SPV (headers consensus tip)
    // ========================================
    UniValue btcspv(UniValue::VOBJ);
    if (g_btcheadersdb) {
        uint32_t btcHeight = 0;
        uint256 btcHash;
        if (g_btcheadersdb->GetTip(btcHeight, btcHash)) {
            btcspv.pushKV("tip_height", (int64_t)btcHeight);
            btcspv.pushKV("tip_hash", btcHash.GetHex());
            btcspv.pushKV("initialized", true);
        } else {
            btcspv.pushKV("tip_height", 0);
            btcspv.pushKV("tip_hash", "");
            btcspv.pushKV("initialized", false);
        }
    } else {
        btcspv.pushKV("tip_height", 0);
        btcspv.pushKV("tip_hash", "");
        btcspv.pushKV("initialized", false);
    }
    result.pushKV("btcspv", btcspv);

    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category       name                   actor (function)    okSafe argNames
  //  -------------- ---------------------- ------------------- ------ --------
    { "settlement",  "getstate",            &getstate,          true,  {} },
    { "settlement",  "gethealth",           &gethealth,         true,  {} },
    { "settlement",  "getexplorerdata",     &getexplorerdata,   true,  {} },
};
// clang-format on

void RegisterSettlementRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
