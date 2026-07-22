// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#include "amount.h"
#include "blockassembler.h"
#include "chainparams.h"
#include "consensus/merkle.h"
#include "core_io.h"
#include "key_io.h"
#include "random.h"
#include "rpc/server.h"
#include "script/script.h"
#include "txmempool.h"
#include "util/blockstatecatcher.h"
#include "validation.h"
#include "warnings.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <limits>
#include <univalue.h>

UniValue prioritisetransaction(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw std::runtime_error(
            "prioritisetransaction \"txid\" fee_delta\n"
            "\nBumps the priority of a transaction in the mempool.\n"
            "The fee_delta adjusts the effective fee for block inclusion selection.\n"

            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id.\n"
            "2. fee_delta      (numeric, required) The fee value (in satoshis) to add (or subtract, if negative).\n"
            "                  The fee is not actually paid, only the algorithm for selecting transactions into a block\n"
            "                  considers the transaction as it would have paid a higher (or lower) fee.\n"

            "\nResult:\n"
            "true              (boolean) Returns true\n"

            "\nExamples:\n" +
            HelpExampleCli("prioritisetransaction", "\"txid\" 10000") +
            HelpExampleRpc("prioritisetransaction", "\"txid\", 10000"));

    LOCK(cs_main);

    uint256 hash = ParseHashStr(request.params[0].get_str(), "txid");
    CAmount nAmount = request.params[1].get_int64();

    mempool.PrioritiseTransaction(hash, nAmount);
    return true;
}

// NOTE: Assumes a conclusive result; if result is inconclusive, it must be handled by caller
static UniValue BIP22ValidationResult(const CValidationState& state)
{
    if (state.IsValid())
        return NullUniValue;

    std::string strRejectReason = state.GetRejectReason();
    if (state.IsError())
        throw JSONRPCError(RPC_VERIFY_ERROR, strRejectReason);
    if (state.IsInvalid()) {
        if (strRejectReason.empty())
            return "rejected";
        return strRejectReason;
    }
    // Should be impossible
    return "valid?";
}

UniValue submitblock(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "submitblock \"hexdata\" ( \"jsonparametersobject\" )\n"
            "\nSubmits a raw block to the node for validation and relay.\n"
            "The 'jsonparametersobject' parameter is currently ignored.\n"
            "See https://en.bitcoin.it/wiki/BIP_0022 for full specification.\n"

            "\nArguments:\n"
            "1. \"hexdata\"        (string, required) The hex-encoded block data to submit\n"
            "2. \"parameters\"     (string, optional) Object of optional parameters\n"
            "    {\n"
            "      \"workid\" : \"id\"    (string, optional) If the server provided a workid, it MUST be included with submissions\n"
            "    }\n"

            "\nResult:\n"
            "null if successful, otherwise an error string.\n"

            "\nExamples:\n" +
            HelpExampleCli("submitblock", "\"mydata\"") +
            HelpExampleRpc("submitblock", "\"mydata\""));

    std::shared_ptr<CBlock> blockptr = std::make_shared<CBlock>();
    CBlock& block = *blockptr;
    if (!DecodeHexBlk(block, request.params[0].get_str()))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block decode failed");

    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase()) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Block does not start with a coinbase");
    }

    uint256 hash = block.GetHash();
    bool fBlockPresent = false;
    {
        LOCK(cs_main);
        CBlockIndex* pindex = LookupBlockIndex(hash);
        if (pindex) {
            if (pindex->IsValid(BLOCK_VALID_SCRIPTS))
                return "duplicate";
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return "duplicate-invalid";
            // Otherwise, we might only have the header - process the block before returning
            fBlockPresent = true;
        }
    }

    BlockStateCatcherWrapper sc(block.GetHash());
    sc.registerEvent();
    bool fAccepted = ProcessNewBlock(blockptr, nullptr);
    if (fBlockPresent) {
        if (fAccepted && !sc.get().found)
            return "duplicate-inconclusive";
        return "duplicate";
    }
    if (fAccepted) {
        if (!sc.get().found)
            return "inconclusive";
    }
    return BIP22ValidationResult(sc.get().state);
}

UniValue estimatefee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatefee nblocks\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction\n"
            "to begin confirmation within nblocks blocks.\n"

            "\nArguments:\n"
            "1. nblocks     (numeric, required) Target number of blocks for confirmation.\n"

            "\nResult:\n"
            "n              (numeric) Estimated fee-per-kilobyte in BATHRON.\n"
            "               Returns -1.0 if not enough transactions and blocks\n"
            "               have been observed to make an estimate.\n"

            "\nExamples:\n" +
            HelpExampleCli("estimatefee", "6") +
            HelpExampleRpc("estimatefee", "6"));

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();
    if (nBlocks < 1)
        nBlocks = 1;

    CFeeRate feeRate = mempool.estimateFee(nBlocks);
    if (feeRate == CFeeRate(0))
        return -1.0;

    return ValueFromAmount(feeRate.GetFeePerK());
}

UniValue estimatesmartfee(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1)
        throw std::runtime_error(
            "estimatesmartfee nblocks\n"
            "\nEstimates the approximate fee per kilobyte needed for a transaction to begin\n"
            "confirmation within nblocks blocks if possible, and returns the number of blocks\n"
            "for which the estimate is valid.\n"

            "\nArguments:\n"
            "1. nblocks     (numeric, required) Target number of blocks for confirmation.\n"

            "\nResult:\n"
            "{\n"
            "  \"feerate\" : x.x,     (numeric) Estimated fee-per-kilobyte in satoshis\n"
            "  \"blocks\" : n         (numeric) Block number where estimate was found\n"
            "}\n"
            "\n"
            "A negative feerate is returned if not enough transactions and blocks\n"
            "have been observed to make an estimate for any number of blocks.\n"
            "However it will not return a value below the mempool reject fee.\n"

            "\nExamples:\n" +
            HelpExampleCli("estimatesmartfee", "6") +
            HelpExampleRpc("estimatesmartfee", "6"));

    RPCTypeCheck(request.params, {UniValue::VNUM});

    int nBlocks = request.params[0].get_int();

    UniValue result(UniValue::VOBJ);
    int answerFound;
    CFeeRate feeRate = mempool.estimateSmartFee(nBlocks, &answerFound);
    result.pushKV("feerate", feeRate == CFeeRate(0) ? -1.0 : ValueFromAmount(feeRate.GetFeePerK()));
    result.pushKV("blocks", answerFound);
    return result;
}

// Helper function to generate blocks in regtest mode
static UniValue generateBlocks(int nGenerate, const CScript& coinbaseScript, bool fIncludeMempool = true)
{
    UniValue blockHashes(UniValue::VARR);

    for (int i = 0; i < nGenerate; i++) {
        bool fNoMempoolTx = !fIncludeMempool;
        auto ptemplate = BlockAssembler(Params(), false).CreateNewBlock(coinbaseScript, nullptr, fNoMempoolTx);

        if (!ptemplate) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Failed to create block template");
        }

        auto pblock = std::make_shared<CBlock>(ptemplate->block);
        pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
        pblock->nNonce = GetRand(std::numeric_limits<uint32_t>::max());

        BlockStateCatcherWrapper sc(pblock->GetHash());
        sc.registerEvent();

        if (!ProcessNewBlock(pblock, nullptr)) {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Block not accepted");
        }

        blockHashes.push_back(pblock->GetHash().GetHex());
    }

    return blockHashes;
}

UniValue generate(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "generate nblocks ( \"address\" )\n"
            "\n[REGTEST ONLY] Immediately mines blocks for testing purposes.\n"
            "This command is only available in regtest mode.\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, required) How many blocks to generate immediately.\n"
            "2. \"address\"    (string, optional) The address to send the newly generated BATHRON to.\n"
            "\nResult:\n"
            "[blockhash, ...]  (array) Array of hashes of blocks generated\n"
            "\nExamples:\n"
            "\nGenerate 11 blocks\n" +
            HelpExampleCli("generate", "11") +
            HelpExampleRpc("generate", "11"));

    // BATHRON uses DMM consensus - generate only allowed in regtest
    // On testnet/mainnet, blocks are produced by masternodes via DMM scheduler
    if (!Params().IsRegTestNet())
        throw JSONRPCError(RPC_METHOD_NOT_FOUND, "generate is only available in regtest mode. BATHRON testnet/mainnet uses DMM for block production.");

    int nGenerate = request.params[0].get_int();
    if (nGenerate <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid number of blocks");

    CScript coinbaseScript;
    if (request.params.size() > 1 && !request.params[1].isNull()) {
        std::string strAddress = request.params[1].get_str();
        CTxDestination destination = DecodeDestination(strAddress);
        if (!IsValidDestination(destination))
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        coinbaseScript = GetScriptForDestination(destination);
    } else {
        // Use pilpous address as default (OP_TRUE forbidden by consensus)
        CTxDestination dest = DecodeDestination("xyszqryssGaNw13qpjbxB4PVoRqGat7RPd");
        if (IsValidDestination(dest)) {
            coinbaseScript = GetScriptForDestination(dest);
        } else {
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid hardcoded coinbase address");
        }
    }

    return generateBlocks(nGenerate, coinbaseScript);
}

UniValue generatebootstrap(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() > 1)
        throw std::runtime_error(
            "generatebootstrap ( nblocks )\n"
            "\n[TESTNET/REGTEST ONLY] Generate bootstrap blocks for BATHRON network initialization.\n"
            "\nBurn-only model — NO premine. Coinbase value = 0 at every height. Block 1 carries\n"
            "TX_BTC_HEADERS; M0 is minted (TX_MINT_M0BTC) ONLY from SPV-verified BTC burns at\n"
            "block 2+. generatebootstrap mines catch-up blocks so burns can be discovered,\n"
            "claimed and minted during cold start; MN collaterals are funded from that minted\n"
            "M0 and then registered via ProRegTx.\n"
            "\nArguments:\n"
            "1. nblocks      (numeric, optional, default=1) Number of bootstrap blocks to generate.\n"
            "\nResult:\n"
            "[blockhash, ...]  (array) Array of hashes of blocks generated\n"
            "\nExamples:\n" +
            HelpExampleCli("generatebootstrap", "1") +
            HelpExampleRpc("generatebootstrap", "1"));

    // Check current height
    int nCurrentHeight;
    {
        LOCK(cs_main);
        nCurrentHeight = chainActive.Height();
    }

    // Network gate (B2.A): testnet/regtest are disposable → always allowed. MAINNET is
    // allowed ONLY within the one-shot bootstrap window (height < nDMMBootstrapHeight): the
    // launcher PoW-mines the first blocks to cold-start the chain, then this RPC auto-refuses
    // FOREVER (height >= bootstrap) → no post-launch manual-mining path. Bootstrap blocks
    // still carry the burn-backed mint + real ProRegTx (zero premine, zero SPV bypass — same
    // burn-only model as steady state), so this is a launch convenience, not a money cheat.
    if (!Params().IsTestnet() && !Params().IsRegTestNet() &&
        nCurrentHeight >= Params().GetConsensus().nDMMBootstrapHeight) {
        throw JSONRPCError(RPC_METHOD_NOT_FOUND,
            "generatebootstrap on mainnet is only allowed during the bootstrap window "
            "(height < nDMMBootstrapHeight); the network is past cold-start.");
    }

    // Bootstrap phases (burn-only, NO premine):
    // Block 1: TX_BTC_HEADERS (coinbase=0)
    // Block 2+: burn-backed TX_MINT_M0BTC, then confirm MN collateral txs funded from minted M0
    // Final bootstrap block: includes the ProRegTx(s)

    // Count ProRegTx in mempool
    int nProRegCount = 0;
    {
        LOCK(mempool.cs);
        for (const auto& entry : mempool.mapTx) {
            const CTransaction& tx = entry.GetTx();
            if (tx.nType == CTransaction::TxType::PROREG) {
                nProRegCount++;
            }
        }
    }

    // Require minimum 3 ProRegTx to complete bootstrap (DMM activation)
    int nRequiredMN = Params().IsTestnet() ? 3 : 1;

    // If we have 3+ ProRegTx, this will be the final bootstrap block
    if (nProRegCount >= nRequiredMN) {
        LogPrintf("BATHRON Bootstrap: Found %d ProRegTx in mempool, generating DMM activation block at height %d\n", nProRegCount, nCurrentHeight + 1);
    } else if (nCurrentHeight >= 1) {
        // Allow intermediate blocks to confirm collateral transactions
        LogPrintf("BATHRON Bootstrap: Generating intermediate block at height %d (ProRegTx: %d/%d)\n",
                  nCurrentHeight + 1, nProRegCount, nRequiredMN);
    }

    int nGenerate = 1;  // Default: generate 1 block at a time
    if (request.params.size() > 0 && !request.params[0].isNull()) {
        nGenerate = request.params[0].get_int();
        if (nGenerate <= 0 || nGenerate > 1)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Generate 1 block at a time during bootstrap.");
    }

    // Use pilpous (genesis MN operator) address for coinbase
    // OP_TRUE is forbidden by consensus (only TX_LOCK/TX_UNLOCK can use OP_TRUE)
    CTxDestination dest = DecodeDestination("xyszqryssGaNw13qpjbxB4PVoRqGat7RPd");
    CScript coinbaseScript;
    if (IsValidDestination(dest)) {
        coinbaseScript = GetScriptForDestination(dest);
    } else {
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Invalid hardcoded coinbase address");
    }

    // Always include mempool during bootstrap.
    // TX_BURN_CLAIM (0-fee, no wallet inputs) need to be mined during burn discovery.
    // The original concern about wallet deadlocks does not apply to burn claims.
    bool fIncludeMempool = true;
    LogPrintf("BATHRON Bootstrap: Generating block %d (includeMempool=%d, proReg=%d)\n",
              nCurrentHeight + 1, fIncludeMempool, nProRegCount);

    g_fBootstrapGenerating = true;
    UniValue result;
    try {
        result = generateBlocks(nGenerate, coinbaseScript, fIncludeMempool);
    } catch (...) {
        g_fBootstrapGenerating = false;
        throw;
    }
    g_fBootstrapGenerating = false;
    return result;
}

// clang-format off
static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafe argNames
  //  --------------------- ------------------------  -----------------------  ------ --------
    { "generating",         "generate",               &generate,               true,  {"nblocks","address"} },
    { "generating",         "generatebootstrap",      &generatebootstrap,      true,  {"nblocks"} },
    { "util",               "estimatefee",            &estimatefee,            true,  {"nblocks"} },
    { "util",               "estimatesmartfee",       &estimatesmartfee,       true,  {"nblocks"} },
    { "blockchain",         "prioritisetransaction",  &prioritisetransaction,  true,  {"txid","fee_delta"} },
    { "blockchain",         "submitblock",            &submitblock,            true,  {"hexdata","parameters"} },
};
// clang-format on

void RegisterMiningRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
