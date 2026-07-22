// Copyright (c) 2025 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/server.h"
#include "script/conditional.h"
#include "script/standard.h"
#include "key_io.h"
#include "random.h"
#include "hash.h"
#include "utilstrencodings.h"

#include <univalue.h>

/**
 * createconditionalsecret - Generate secret and hashlock
 *
 * Generates a random 32-byte secret and its SHA256 hash.
 */
static UniValue createconditionalsecret(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 0) {
        throw std::runtime_error(
            "createconditionalsecret\n"
            "\nGenerate a random secret and its hashlock.\n"
            "\nResult:\n"
            "{\n"
            "  \"secret\": \"hex\",    (string) 32-byte secret (keep private)\n"
            "  \"hashlock\": \"hex\"   (string) SHA256(secret) for conditional script\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createconditionalsecret", "")
            + HelpExampleRpc("createconditionalsecret", "")
        );
    }

    std::vector<unsigned char> secret(32);
    GetStrongRandBytes(secret.data(), 32);

    uint256 hashlock;
    CSHA256().Write(secret.data(), secret.size()).Finalize(hashlock.begin());

    UniValue result(UniValue::VOBJ);
    result.pushKV("secret", HexStr(secret));
    // Output hashlock in same byte order as SHA256 produces (NOT GetHex which reverses)
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));
    return result;
}

/**
 * createconditional - Create conditional script address
 *
 * Creates a P2SH address with a conditional script (BIP-199 compatible).
 */
static UniValue createconditional(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4) {
        throw std::runtime_error(
            "createconditional \"destA\" \"destB\" \"hashlock\" timelock\n"
            "\nCreate a conditional script P2SH address.\n"
            "\nArguments:\n"
            "1. destA      (string, required) Address for branch A (secret reveal)\n"
            "2. destB      (string, required) Address for branch B (timeout)\n"
            "3. hashlock   (string, required) SHA256(secret), 32-byte hex\n"
            "4. timelock   (numeric, required) Block height for timeout\n"
            "\nResult:\n"
            "{\n"
            "  \"address\": \"addr\",       (string) P2SH address\n"
            "  \"redeemScript\": \"hex\",   (string) Redeem script (save this!)\n"
            "  \"hashlock\": \"hex\",       (string) Hashlock used\n"
            "  \"timelock\": n              (numeric) Timelock block height\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createconditional", "\"D...\" \"D...\" \"abc123...\" 150000")
            + HelpExampleRpc("createconditional", "\"D...\", \"D...\", \"abc123...\", 150000")
        );
    }

    CTxDestination destA = DecodeDestination(request.params[0].get_str());
    if (!IsValidDestination(destA)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destA address");
    }

    CTxDestination destB = DecodeDestination(request.params[1].get_str());
    if (!IsValidDestination(destB)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid destB address");
    }

    uint256 hashlock = uint256S(request.params[2].get_str());
    if (hashlock.IsNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid hashlock");
    }

    uint32_t timelock = request.params[3].get_int();
    if (timelock == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Timelock must be > 0");
    }

    const CKeyID* keyIdA = boost::get<CKeyID>(&destA);
    const CKeyID* keyIdB = boost::get<CKeyID>(&destB);

    if (!keyIdA || !keyIdB) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses must be P2PKH");
    }

    CScript redeemScript = CreateConditionalScript(hashlock, timelock, *keyIdA, *keyIdB);
    CScriptID scriptID(redeemScript);

    UniValue result(UniValue::VOBJ);
    result.pushKV("address", EncodeDestination(scriptID));
    result.pushKV("redeemScript", HexStr(redeemScript));
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));
    result.pushKV("timelock", (int64_t)timelock);
    return result;
}

/**
 * decodeconditional - Decode a conditional script
 *
 * Parses a conditional script and returns its parameters.
 */
static UniValue decodeconditional(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "decodeconditional \"redeemScript\"\n"
            "\nDecode a conditional script.\n"
            "\nArguments:\n"
            "1. redeemScript   (string, required) Hex-encoded redeem script\n"
            "\nResult:\n"
            "{\n"
            "  \"hashlock\": \"hex\",   (string) Hashlock\n"
            "  \"timelock\": n,         (numeric) Timelock block height\n"
            "  \"destA\": \"addr\",     (string) Destination A (secret reveal)\n"
            "  \"destB\": \"addr\"      (string) Destination B (timeout)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodeconditional", "\"6382...\"")
            + HelpExampleRpc("decodeconditional", "\"6382...\"")
        );
    }

    std::vector<unsigned char> scriptData = ParseHex(request.params[0].get_str());
    CScript script(scriptData.begin(), scriptData.end());

    uint256 hashlock;
    uint32_t timelock;
    CKeyID destA, destB;

    if (!DecodeConditionalScript(script, hashlock, timelock, destA, destB)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not a valid conditional script");
    }

    UniValue result(UniValue::VOBJ);
    result.pushKV("hashlock", HexStr(Span<const unsigned char>(hashlock.begin(), hashlock.size())));
    result.pushKV("timelock", (int64_t)timelock);
    result.pushKV("destA", EncodeDestination(destA));
    result.pushKV("destB", EncodeDestination(destB));
    return result;
}

// Register RPC commands
static const CRPCCommand commands[] =
{
    //  category       name                        actor (function)           okSafe argNames
    //  -------------- --------------------------- -------------------------- ------ ----------
    { "conditional",   "createconditionalsecret",  &createconditionalsecret,  true,  {} },
    { "conditional",   "createconditional",        &createconditional,        true,  {"destA", "destB", "hashlock", "timelock"} },
    { "conditional",   "decodeconditional",        &decodeconditional,        true,  {"redeemScript"} },
};

void RegisterConditionalRPCCommands(CRPCTable& t)
{
    for (const auto& c : commands) {
        t.appendCommand(c.name, &c);
    }
}
