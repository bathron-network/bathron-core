// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2017-2021 The PIVX Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "core_io.h"

#include "key_io.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "sapling/sapling_core_write.h"
#include "serialize.h"
#include "streams.h"
#include <univalue.h>
#include "util/system.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"

std::string FormatScript(const CScript& script)
{
    std::string ret;
    CScript::const_iterator it = script.begin();
    opcodetype op;
    while (it != script.end()) {
        CScript::const_iterator it2 = it;
        std::vector<unsigned char> vch;
        if (script.GetOp2(it, op, &vch)) {
            if (op == OP_0) {
                ret += "0 ";
                continue;
            } else if ((op >= OP_1 && op <= OP_16) || op == OP_1NEGATE) {
                ret += strprintf("%i ", op - OP_1NEGATE - 1);
                continue;
            } else if (op >= OP_NOP && op <= OP_NOP10) {
                std::string str(GetOpName(op));
                if (str.substr(0, 3) == std::string("OP_")) {
                    ret += str.substr(3, std::string::npos) + " ";
                    continue;
                }
            }
            if (vch.size() > 0) {
                ret += strprintf("0x%x 0x%x ", HexStr(std::vector<uint8_t>(it2, it - vch.size())),
                                 HexStr(std::vector<uint8_t>(it - vch.size(), it)));
            } else {
                ret += strprintf("0x%x", HexStr(std::vector<uint8_t>(it2, it)));
            }
            continue;
        }
        ret += strprintf("0x%x ", HexStr(std::vector<uint8_t>(it2, script.end())));
        break;
    }
    return ret.substr(0, ret.size() - 1);
}

const std::map<unsigned char, std::string> mapSigHashTypes = {
    {static_cast<unsigned char>(SIGHASH_ALL), std::string("ALL")},
    {static_cast<unsigned char>(SIGHASH_ALL | SIGHASH_ANYONECANPAY), std::string("ALL|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_NONE), std::string("NONE")},
    {static_cast<unsigned char>(SIGHASH_NONE | SIGHASH_ANYONECANPAY), std::string("NONE|ANYONECANPAY")},
    {static_cast<unsigned char>(SIGHASH_SINGLE), std::string("SINGLE")},
    {static_cast<unsigned char>(SIGHASH_SINGLE | SIGHASH_ANYONECANPAY), std::string("SINGLE|ANYONECANPAY")}
};

/**
 * Create the assembly string representation of a CScript object.
 * @param[in] script    CScript object to convert into the asm string representation.
 * @param[in] fAttemptSighashDecode    Whether to attempt to decode sighash types on data within the script that matches the format
 *                                     of a signature. Only pass true for scripts you believe could contain signatures. For example,
 *                                     pass false, or omit the this argument (defaults to false), for scriptPubKeys.
 */
std::string ScriptToAsmStr(const CScript& script, const bool fAttemptSighashDecode)
{
    std::string str;
    opcodetype opcode;
    std::vector<unsigned char> vch;
    CScript::const_iterator pc = script.begin();
    while (pc < script.end()) {
        if (!str.empty()) {
            str += " ";
        }
        if (!script.GetOp(pc, opcode, vch)) {
            str += "[error]";
            return str;
        }
        if (0 <= opcode && opcode <= OP_PUSHDATA4) {
            if (vch.size() <= static_cast<std::vector<unsigned char>::size_type>(4)) {
                str += strprintf("%d", CScriptNum(vch, false).getint());
            } else {
                // the IsUnspendable check makes sure not to try to decode OP_RETURN data that may match the format of a signature
                if (fAttemptSighashDecode && !script.IsUnspendable()) {
                    std::string strSigHashDecode;
                    // goal: only attempt to decode a defined sighash type from data that looks like a signature within a scriptSig.
                    // this won't decode correctly formatted public keys in Pubkey or Multisig scripts due to
                    // the restrictions on the pubkey formats (see IsCompressedOrUncompressedPubKey) being incongruous with the
                    // checks in CheckSignatureEncoding.
                    if (CheckSignatureEncoding(vch, SCRIPT_VERIFY_STRICTENC, nullptr)) {
                        const unsigned char chSigHashType = vch.back();
                        if (mapSigHashTypes.count(chSigHashType)) {
                            strSigHashDecode = "[" + mapSigHashTypes.find(chSigHashType)->second + "]";
                            vch.pop_back(); // remove the sighash type byte. it will be replaced by the decode.
                        }
                    }
                    str += HexStr(vch) + strSigHashDecode;
                } else {
                    str += HexStr(vch);
                }
            }
        } else {
            str += GetOpName(opcode);
        }
    }
    return str;
}

std::string EncodeHexTx(const CTransaction& tx)
{
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    return HexStr(ssTx);
}

void ScriptPubKeyToUniv(const CScript& scriptPubKey,
    UniValue& out,
    bool fIncludeHex)
{
    txnouttype type;
    std::vector<CTxDestination> addresses;
    int nRequired;

    out.pushKV("asm", ScriptToAsmStr(scriptPubKey));
    if (fIncludeHex)
        out.pushKV("hex", HexStr(scriptPubKey));

    if (!ExtractDestinations(scriptPubKey, type, addresses, nRequired)) {
        out.pushKV("type", GetTxnOutputType(type));
        return;
    }

    out.pushKV("reqSigs", nRequired);
    out.pushKV("type", GetTxnOutputType(type));

    UniValue a(UniValue::VARR);
    for (const CTxDestination& addr : addresses)
        a.push_back(EncodeDestination(addr));
    out.pushKV("addresses", a);
}

static void SpecialTxToJSON(const CTransaction& tx, UniValue& entry)
{
    if (tx.IsSpecialTx()) {
        entry.pushKV("extraPayloadSize", (int)tx.extraPayload->size());
        entry.pushKV("extraPayload", HexStr(*(tx.extraPayload)));
    }

    // BP30 Settlement TX metadata
    switch (tx.nType) {
        case CTransaction::TxType::TX_LOCK:
            entry.pushKV("tx_type_name", "TX_LOCK");
            entry.pushKV("tx_flow", "M0 \u2192 Vault + M1");
            break;
        case CTransaction::TxType::TX_UNLOCK:
            entry.pushKV("tx_type_name", "TX_UNLOCK");
            entry.pushKV("tx_flow", "M1 + Vault \u2192 M0");
            break;
        case CTransaction::TxType::TX_TRANSFER_M1:
            entry.pushKV("tx_type_name", "TX_TRANSFER_M1");
            entry.pushKV("tx_flow", "M1 \u2192 M1");
            break;
        default:
            // Standard or MN transactions - no special flow
            break;
    }
}

void TxToUniv(const CTransaction& tx, const uint256& hashBlock, UniValue& entry)
{
    entry.pushKV("txid", tx.GetHash().GetHex());
    entry.pushKV("version", tx.nVersion);
    entry.pushKV("type", tx.nType);
    entry.pushKV("size", (int)::GetSerializeSize(tx, PROTOCOL_VERSION));
    entry.pushKV("locktime", (int64_t)tx.nLockTime);

    UniValue vin(UniValue::VARR);
    for (const CTxIn& txin : tx.vin) {
        UniValue in(UniValue::VOBJ);
        if (tx.IsCoinBase())
            in.pushKV("coinbase", HexStr(txin.scriptSig));
        else {
            in.pushKV("txid", txin.prevout.hash.GetHex());
            in.pushKV("vout", (int64_t)txin.prevout.n);
            UniValue o(UniValue::VOBJ);
            o.pushKV("asm", ScriptToAsmStr(txin.scriptSig, true));
            o.pushKV("hex", HexStr(txin.scriptSig));
            in.pushKV("scriptSig", o);
        }
        in.pushKV("sequence", (int64_t)txin.nSequence);
        vin.push_back(in);
    }
    entry.pushKV("vin", vin);

    UniValue vout(UniValue::VARR);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];

        UniValue out(UniValue::VOBJ);

        UniValue outValue(UniValue::VNUM, FormatMoney(txout.nValue));
        out.pushKV("value", outValue);
        out.pushKV("n", (int64_t)i);

        UniValue o(UniValue::VOBJ);
        ScriptPubKeyToUniv(txout.scriptPubKey, o, true);
        out.pushKV("scriptPubKey", o);

        // BP30 Asset Type Detection
        // Detect M0/M1/Vault based on TX type and output position
        std::string assetType = "M0";  // Default

        // Check for OP_TRUE (Vault) script
        bool isOpTrue = (txout.scriptPubKey.size() == 1 && txout.scriptPubKey[0] == OP_TRUE);

        if (isOpTrue) {
            assetType = "Vault";
        } else {
            switch (tx.nType) {
                case CTransaction::TxType::TX_LOCK:
                    // vout[0] = Vault (OP_TRUE), vout[1] = M1 Receipt
                    if (i == 1) assetType = "M1";
                    break;

                case CTransaction::TxType::TX_UNLOCK:
                    // vout[0] = M0, vout[1+] = M1 change or Vault change
                    if (i > 0 && !isOpTrue) assetType = "M1";
                    break;

                case CTransaction::TxType::TX_TRANSFER_M1:
                    // M1 outputs first, then M0 fee change
                    // Simple heuristic: first outputs are M1, small final outputs are M0 fee
                    if (i == 0) {
                        assetType = "M1";
                    } else if (i < tx.vout.size() - 1 || txout.nValue >= COIN) {
                        // Not last output OR value >= 1 coin => M1
                        assetType = "M1";
                    }
                    // else: small last output => M0 fee change (default)
                    break;

                default:
                    // Standard TX: all M0
                    break;
            }
        }

        out.pushKV("asset", assetType);
        vout.push_back(out);
    }
    entry.pushKV("vout", vout);

    // Sapling
    TxSaplingToJSON(tx, entry);

    // Special Txes
    SpecialTxToJSON(tx, entry);

    if (!hashBlock.IsNull())
        entry.pushKV("blockhash", hashBlock.GetHex());

    entry.pushKV("hex", EncodeHexTx(tx)); // the hex-encoded transaction. used the name "hex" to be consistent with the verbose output of "getrawtransaction".
}
