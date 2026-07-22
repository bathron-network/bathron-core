// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2022 The PIVX Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpc/client.h"

#include <set>
#include <stdint.h>


class CRPCConvertParam
{
public:
    std::string methodName; //! method whose params want conversion
    int paramIdx;           //! 0-based idx of param to convert
    std::string paramName; //!< parameter name
};

// clang-format off
/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] = {
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    // Conditional commands
    { "createconditional", 3, "timelock" },
    { "addpeeraddress", 1, "port" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "estimatefee", 0, "nblocks" },
    { "estimatesmartfee", 0, "nblocks" },
    { "fundrawtransaction", 1, "options" },
    { "generate", 0, "nblocks" },
    { "getaddednodeinfo", 0, "dummy" },
    { "getbalance", 0, "minconf" },
    { "getbalance", 1, "include_watchonly" },
    { "getbalance", 2, "include_external" },
    { "getbalance", 3, "include_shield" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblockhash", 0, "height" },
    { "getfinalityparticipation", 0, "nblocks" },
    { "getblockheader", 1, "verbose" },
    { "getblockindexstats", 0, "height" },
    { "getblockindexstats", 1, "range" },
    { "getfeeinfo", 0, "blocks" },
    { "getshieldbalance", 1, "minconf" },
    { "getshieldbalance", 2, "include_watchonly" },
    { "getnodeaddresses", 0, "count" },
    { "getrawmempool", 0, "verbose" },
    { "getrawtransaction", 1, "verbose" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbylabel", 1, "minconf" },
    { "getsaplingnotescount", 0, "minconf" },
    { "getsupplyinfo", 0, "force_update" },
    { "gettransaction", 1, "include_watchonly" },
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "importprivkey", 2, "rescan" },
    { "importpubkey", 2, "rescan" },
    { "importsaplingkey", 1, "rescan" },
    { "importsaplingkey", 2, "height" },
    { "importsaplingviewingkey", 1, "rescan" },
    { "importsaplingviewingkey", 2, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbylabel", 0, "minconf" },
    { "listreceivedbylabel", 1, "include_empty" },
    { "listreceivedbylabel", 2, "include_watchonly" },
    { "listreceivedbyshieldaddress", 1, "minconf" },
    { "listshieldunspent", 0, "minconf" },
    { "listshieldunspent", 1, "maxconf" },
    { "listshieldunspent", 2, "include_watchonly" },
    { "listshieldunspent", 3, "addresses" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "from" },
    { "listtransactions", 3, "include_watchonly" },
    { "listtransactions", 4, "include_external" },
    { "listtransactions", 5, "include_cold" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "watchonly_config" },
    { "listunspent", 4, "query_options" },
    { "listunspent", 5, "include_unsafe" },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transparent" },
    { "lockunspent", 2, "transactions" },
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "prioritisetransaction", 1, "fee_delta" },
    { "rawshieldsendmany", 1, "amounts" },
    { "rawshieldsendmany", 2, "minconf" },
    { "rawshieldsendmany", 3, "fee" },
    { "rescanblockchain", 0, "start_height"},
    { "rescanblockchain", 1, "stop_height"},
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "include_external" },
    { "sendmany", 5, "subtract_fee_from" },
    { "scantxoutset", 1, "scanobjects" },
    { "sendrawtransaction", 1, "allowhighfees" },
    { "setautocombinethreshold", 0, "enable" },
    { "setautocombinethreshold", 1, "threshold" },
    { "setautocombinethreshold", 2, "frequency"},
    { "setnetworkactive", 0, "active" },
    { "setbtcburnsenabled", 0, "enabled" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    // BATHRON: setgenerate removed (DMM-only, no PoW/PoS mining)
    { "sethdseed", 0, "newkeypool" },
    { "setmocktime", 0, "timestamp" },
    { "settxfee", 0, "amount" },
    { "shieldsendmany", 1, "amounts" },
    { "shieldsendmany", 2, "minconf" },
    { "shieldsendmany", 3, "fee" },
    { "shieldsendmany", 4, "subtract_fee_from" },
    { "signrawtransaction", 1, "prevtxs" },
    { "signrawtransaction", 2, "privkeys" },
    // BATHRON: startmasternode removed (use ProTx/DMN commands instead)
    { "stop", 0, "wait" },
    { "verifychain", 0, "nblocks" },
    { "waitforblock", 1, "timeout" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "walletpassphrase", 1, "timeout" },
    // ProTx commands (DMN)
    { "protx_register", 1, "collateralIndex" },
    { "protx_register_prepare", 1, "collateralIndex" },
    // Settlement commands (BP30)
    { "split_m1", 1, "outputs" },
    { "sweepfees", 1, "dry_run" },
    // Bootstrap commands
    { "generatebootstrap", 0, "nblocks" },
    // BTC burn claim commands (BP10)
    { "submitburnclaim", 2, "height" },
    { "submitburnclaim", 3, "merkle_proof" },
    { "submitburnclaim", 4, "tx_index" },
    { "listburnclaims", 1, "count" },
    { "listburnclaims", 2, "from" },
    // F3 Burnscan RPCs
    { "setburnscanprogress", 0, "height" },
    { "getburnscanrange", 0, "max_blocks" },
    // HTLC operations (BP02)
    { "htlc_create_m1", 3, "expiry_blocks" },
    { "htlc_create_m1_covenant", 4, "expiry_blocks" },
    { "htlc_create_m1_covenant", 5, "lp_expiry_blocks" },
    { "htlc_create_m1_covenant", 6, "covenant_fee" },
    // HTLC3S operations (BP02-3S FlowSwap)
    { "htlc3s_create", 5, "expiry_blocks" },
    { "htlc3s_compute_c3", 0, "amount" },
    // BTC SPV verification
    { "verifymerkleproof", 2, "proof" },
    { "verifymerkleproof", 3, "txindex" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
};
// clang-format on

class CRPCConvertTable
{
private:
    std::set<std::pair<std::string, int>> members;
    std::set<std::pair<std::string, std::string>> membersByName;

public:
    CRPCConvertTable();

    bool convert(const std::string& method, int idx)
    {
        return (members.count(std::make_pair(method, idx)) > 0);
    }
    bool convert(const std::string& method, const std::string& name)
    {
        return (membersByName.count(std::make_pair(method, name)) > 0);
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    const unsigned int n_elem =
        (sizeof(vRPCConvertParams) / sizeof(vRPCConvertParams[0]));

    for (unsigned int i = 0; i < n_elem; i++) {
        members.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                      vRPCConvertParams[i].paramIdx));
        membersByName.insert(std::make_pair(vRPCConvertParams[i].methodName,
                                            vRPCConvertParams[i].paramName));
    }
}

static CRPCConvertTable rpcCvtTable;

/** Non-RFC4627 JSON parser, accepts internal values (such as numbers, true, false, null)
 * as well as objects and arrays.
 */
UniValue ParseNonRFCJSONValue(const std::string& strVal)
{
    UniValue jVal;
    if (!jVal.read(std::string("[")+strVal+std::string("]")) ||
        !jVal.isArray() || jVal.size()!=1)
        throw std::runtime_error(std::string("Error parsing JSON:")+strVal);
    return jVal[0];
}

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        const std::string& strVal = strParams[idx];

        if (!rpcCvtTable.convert(strMethod, idx)) {
            // insert string value directly
            params.push_back(strVal);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.push_back(ParseNonRFCJSONValue(strVal));
        }
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);

    for (const std::string &s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            throw(std::runtime_error("No '=' in named argument '"+s+"', this needs to be present for every argument (even if it is empty)"));
        }

        std::string name = s.substr(0, pos);
        std::string value = s.substr(pos+1);

        if (!rpcCvtTable.convert(strMethod, name)) {
            // insert string value directly
            params.pushKV(name, value);
        } else {
            // parse string as JSON, insert bool/number/object/etc. value
            params.pushKV(name, ParseNonRFCJSONValue(value));
        }
    }

    return params;
}
