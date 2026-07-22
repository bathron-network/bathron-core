// Copyright (c) 2026 The BATHRON developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "burnclaim/burnclaim.h"
#include "burnclaim/killswitch.h"
#include "amount.h"
#include "btcheaders/btcheadersdb.h"
#include "btcspv/btcspv.h"
#include "burnclaim/burnclaimdb.h"
#include "chainparams.h"
#include "hash.h"
#include "key_io.h"                   // BATHRON: DecodeDestination
#include "logging.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/standard.h"
#include "streams.h"
#include "utilmoneystr.h"             // BATHRON: FormatMoney
#include "validation.h"

#include <cstring>
#include <set>


// P2WSH(OP_FALSE) burn script hash
// SHA256(0x00) = 6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
static const uint8_t BURN_SCRIPT_HASH_BYTES[32] = {
    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
    0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
    0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d
};

// BATHRON magic bytes
static const uint8_t BATHRON_MAGIC[] = {'B', 'A', 'T', 'H', 'R', 'O', 'N'};
static const size_t BATHRON_MAGIC_LEN = 7;
static const size_t BATHRON_METADATA_LEN_V1 = 29;  // 7 + ver + net + dest20
static const size_t BATHRON_METADATA_LEN_V2 = 30;  // 7 + ver + net + destType + dest20

uint32_t GetRequiredConfirmations()
{
    return Params().IsTestnet() ? K_CONFIRMATIONS_TESTNET : K_CONFIRMATIONS_MAINNET;
}

uint32_t GetHighestFinalizedBtcHeight()
{
    // R2 consensus helper — MUST be deterministic. Computed on demand from the
    // FINAL claim records (only consulted on a btcheaders reorg, which is rare).
    if (!g_burnclaimdb) return 0;
    uint32_t maxH = 0;
    g_burnclaimdb->ForEachFinalClaim([&maxH](const BurnClaimRecord& r) {
        if (r.btcHeight > maxH) maxH = r.btcHeight;
        return true; // continue
    });
    return maxH;
}

//
// BTC Transaction Parsing
//

// Read a variable-length integer (Bitcoin's CompactSize)
static bool ReadCompactSize(const uint8_t*& p, const uint8_t* end, uint64_t& n)
{
    if (p >= end) return false;
    uint8_t chSize = *p++;
    if (chSize < 253) {
        n = chSize;
    } else if (chSize == 253) {
        if (p + 2 > end) return false;
        n = p[0] | (uint64_t(p[1]) << 8);
        p += 2;
        if (n < 253) return false;  // Not canonical
    } else if (chSize == 254) {
        if (p + 4 > end) return false;
        n = p[0] | (uint64_t(p[1]) << 8) | (uint64_t(p[2]) << 16) | (uint64_t(p[3]) << 24);
        p += 4;
        if (n < 0x10000) return false;  // Not canonical
    } else {
        if (p + 8 > end) return false;
        n = p[0] | (uint64_t(p[1]) << 8) | (uint64_t(p[2]) << 16) | (uint64_t(p[3]) << 24) |
            (uint64_t(p[4]) << 32) | (uint64_t(p[5]) << 40) | (uint64_t(p[6]) << 48) | (uint64_t(p[7]) << 56);
        p += 8;
        if (n < 0x100000000ULL) return false;  // Not canonical
    }
    return true;
}

// Read bytes from buffer
static bool ReadBytes(const uint8_t*& p, const uint8_t* end, std::vector<uint8_t>& out, size_t n)
{
    if (p + n > end) return false;
    out.assign(p, p + n);
    p += n;
    return true;
}

// Read uint32 little-endian
static bool ReadUint32(const uint8_t*& p, const uint8_t* end, uint32_t& n)
{
    if (p + 4 > end) return false;
    n = p[0] | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
    p += 4;
    return true;
}

// Read int32 little-endian
static bool ReadInt32(const uint8_t*& p, const uint8_t* end, int32_t& n)
{
    uint32_t u;
    if (!ReadUint32(p, end, u)) return false;
    n = static_cast<int32_t>(u);
    return true;
}

// Read int64 little-endian
static bool ReadInt64(const uint8_t*& p, const uint8_t* end, int64_t& n)
{
    if (p + 8 > end) return false;
    uint64_t u = p[0] | (uint64_t(p[1]) << 8) | (uint64_t(p[2]) << 16) | (uint64_t(p[3]) << 24) |
                 (uint64_t(p[4]) << 32) | (uint64_t(p[5]) << 40) | (uint64_t(p[6]) << 48) | (uint64_t(p[7]) << 56);
    n = static_cast<int64_t>(u);
    p += 8;
    return true;
}

// Read uint256 (32 bytes)
static bool ReadUint256(const uint8_t*& p, const uint8_t* end, uint256& hash)
{
    if (p + 32 > end) return false;
    memcpy(hash.begin(), p, 32);
    p += 32;
    return true;
}

bool ParseBtcTransaction(const std::vector<uint8_t>& btcTxBytes, BtcParsedTx& tx)
{
    if (btcTxBytes.empty()) return false;

    const uint8_t* p = btcTxBytes.data();
    const uint8_t* end = p + btcTxBytes.size();

    // Read version
    if (!ReadInt32(p, end, tx.nVersion)) return false;

    // Check for SegWit marker (0x00 0x01)
    tx.hasWitness = false;
    if (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01) {
        tx.hasWitness = true;
        p += 2;  // Skip marker and flag
    }

    // Read inputs
    uint64_t vinCount;
    if (!ReadCompactSize(p, end, vinCount)) return false;
    if (vinCount == 0) return false;  // Must have inputs
    if (vinCount > 10000) return false;  // Sanity limit

    tx.vin.resize(vinCount);
    for (uint64_t i = 0; i < vinCount; i++) {
        BtcTxIn& in = tx.vin[i];

        // Prevout (txid + vout index)
        if (!ReadUint256(p, end, in.prevout.hash)) return false;
        if (!ReadUint32(p, end, in.prevout.n)) return false;

        // ScriptSig
        uint64_t scriptLen;
        if (!ReadCompactSize(p, end, scriptLen)) return false;
        if (scriptLen > 10000) return false;  // Sanity
        if (!ReadBytes(p, end, in.scriptSig, scriptLen)) return false;

        // Sequence
        if (!ReadUint32(p, end, in.nSequence)) return false;
    }

    // Read outputs
    uint64_t voutCount;
    if (!ReadCompactSize(p, end, voutCount)) return false;
    if (voutCount > MAX_BTC_TX_VOUT_COUNT) return false;

    tx.vout.resize(voutCount);
    for (uint64_t i = 0; i < voutCount; i++) {
        BtcTxOut& out = tx.vout[i];

        // Value
        if (!ReadInt64(p, end, out.nValue)) return false;
        if (out.nValue < 0) return false;  // No negative values

        // ScriptPubKey
        uint64_t scriptLen;
        if (!ReadCompactSize(p, end, scriptLen)) return false;
        if (scriptLen > 10000) return false;  // Sanity
        if (!ReadBytes(p, end, out.scriptPubKey, scriptLen)) return false;
    }

    // Read witness data if present
    if (tx.hasWitness) {
        for (uint64_t i = 0; i < vinCount; i++) {
            uint64_t witnessCount;
            if (!ReadCompactSize(p, end, witnessCount)) return false;
            if (witnessCount > 10000) return false;  // Sanity: bound before resize() — unbounded count = OOM/bad_alloc DoS (mirrors vin/vout/script caps)

            tx.vin[i].scriptWitness.resize(witnessCount);
            for (uint64_t j = 0; j < witnessCount; j++) {
                uint64_t itemLen;
                if (!ReadCompactSize(p, end, itemLen)) return false;
                if (itemLen > 10000) return false;  // Sanity
                if (!ReadBytes(p, end, tx.vin[i].scriptWitness[j], itemLen)) return false;
            }
        }
    }

    // Read locktime
    if (!ReadUint32(p, end, tx.nLockTime)) return false;

    // Must consume all bytes
    if (p != end) return false;

    // Build non-witness serialization for txid calculation
    if (tx.hasWitness) {
        // Non-witness format: version || vin || vout || locktime
        // We need to rebuild this without marker/flag/witness
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

        // Version (4 bytes LE)
        ss << tx.nVersion;

        // Input count (compactsize) + inputs
        WriteCompactSize(ss, tx.vin.size());
        for (const auto& in : tx.vin) {
            ss << in.prevout.hash;
            ss << in.prevout.n;
            WriteCompactSize(ss, in.scriptSig.size());
            if (!in.scriptSig.empty()) {
                ss.write((const char*)in.scriptSig.data(), in.scriptSig.size());
            }
            ss << in.nSequence;
        }

        // Output count (compactsize) + outputs
        WriteCompactSize(ss, tx.vout.size());
        for (const auto& out : tx.vout) {
            ss << out.nValue;
            WriteCompactSize(ss, out.scriptPubKey.size());
            if (!out.scriptPubKey.empty()) {
                ss.write((const char*)out.scriptPubKey.data(), out.scriptPubKey.size());
            }
        }

        // Locktime (4 bytes LE)
        ss << tx.nLockTime;

        tx.nonWitnessSerialization.assign(ss.begin(), ss.end());
    } else {
        // No witness - use original bytes
        tx.nonWitnessSerialization.assign(btcTxBytes.begin(), btcTxBytes.end());
    }

    return true;
}

uint256 ComputeBtcTxid(const BtcParsedTx& tx)
{
    // txid = HASH256(non-witness serialization)
    return Hash(tx.nonWitnessSerialization.begin(), tx.nonWitnessSerialization.end());
}

uint256 ComputeBtcWtxid(const std::vector<uint8_t>& btcTxBytes)
{
    // wtxid = HASH256(full serialization including witness)
    return Hash(btcTxBytes.begin(), btcTxBytes.end());
}

//
// Burn Output Parsing
//

bool IsOpReturnOutput(const BtcTxOut& out)
{
    return out.scriptPubKey.size() > 0 && out.scriptPubKey[0] == 0x6a;  // OP_RETURN
}

bool ExtractOpReturnData(const std::vector<uint8_t>& scriptPubKey, std::vector<uint8_t>& data)
{
    if (scriptPubKey.size() < 2) return false;
    if (scriptPubKey[0] != 0x6a) return false;  // OP_RETURN

    // scriptPubKey format: OP_RETURN [push opcode] [data]
    size_t pos = 1;
    uint8_t pushOp = scriptPubKey[pos++];

    size_t dataLen;
    if (pushOp <= 0x4b) {
        // Direct push (1-75 bytes)
        dataLen = pushOp;
    } else if (pushOp == 0x4c) {
        // OP_PUSHDATA1
        if (pos >= scriptPubKey.size()) return false;
        dataLen = scriptPubKey[pos++];
    } else if (pushOp == 0x4d) {
        // OP_PUSHDATA2
        if (pos + 2 > scriptPubKey.size()) return false;
        dataLen = scriptPubKey[pos] | (uint16_t(scriptPubKey[pos + 1]) << 8);
        pos += 2;
    } else if (pushOp == 0x4e) {
        // OP_PUSHDATA4
        if (pos + 4 > scriptPubKey.size()) return false;
        dataLen = scriptPubKey[pos] | (uint32_t(scriptPubKey[pos + 1]) << 8) |
                  (uint32_t(scriptPubKey[pos + 2]) << 16) | (uint32_t(scriptPubKey[pos + 3]) << 24);
        pos += 4;
    } else {
        return false;  // Unknown push opcode
    }

    if (pos + dataLen > scriptPubKey.size()) return false;
    data.assign(scriptPubKey.begin() + pos, scriptPubKey.begin() + pos + dataLen);
    return true;
}

bool IsBathronMetadataOutput(const BtcTxOut& out)
{
    if (!IsOpReturnOutput(out)) return false;
    if (out.nValue != 0) return false;  // Metadata must have 0 value

    std::vector<uint8_t> data;
    if (!ExtractOpReturnData(out.scriptPubKey, data)) return false;

    // Must start with "BATHRON" (both versions)
    if (data.size() < BATHRON_MAGIC_LEN + 1) return false;
    if (memcmp(data.data(), BATHRON_MAGIC, BATHRON_MAGIC_LEN) != 0) return false;

    // Length is version-determined: v01 = 29 bytes, v02 = 30 bytes
    const uint8_t version = data[BATHRON_MAGIC_LEN];
    if (version == 1) return data.size() == BATHRON_METADATA_LEN_V1;
    if (version == 2) return data.size() == BATHRON_METADATA_LEN_V2;
    return false;
}

bool IsP2WSHBurnOutput(const BtcTxOut& out)
{
    // P2WSH script: OP_0 (0x00) + PUSH32 (0x20) + 32-byte hash
    if (out.scriptPubKey.size() != 34) return false;
    if (out.scriptPubKey[0] != 0x00) return false;  // OP_0
    if (out.scriptPubKey[1] != 0x20) return false;  // Push 32 bytes

    // Compare raw bytes to burn script hash (endianness-safe)
    return memcmp(&out.scriptPubKey[2], BURN_SCRIPT_HASH_BYTES, 32) == 0;
}

bool ParseBurnOutputs(const BtcParsedTx& btcTx, BurnInfo& info)
{
    int metadataIdx = -1;
    int burnIdx = -1;
    int metadataCount = 0;
    int burnCount = 0;

    for (size_t i = 0; i < btcTx.vout.size(); i++) {
        const BtcTxOut& out = btcTx.vout[i];

        if (IsBathronMetadataOutput(out)) {
            metadataIdx = i;
            metadataCount++;
        } else if (IsP2WSHBurnOutput(out) && out.nValue > 0) {
            burnIdx = i;
            burnCount++;
        }
    }

    // Enforce uniqueness: exactly 1 metadata, exactly 1 burn
    if (metadataCount != 1 || burnCount != 1)
        return false;
    if (metadataIdx < 0 || burnIdx < 0)
        return false;

    // Parse metadata
    const BtcTxOut& metadata = btcTx.vout[metadataIdx];
    std::vector<uint8_t> data;
    if (!ExtractOpReturnData(metadata.scriptPubKey, data))
        return false;

    // Version + exact size already vetted in IsBathronMetadataOutput
    info.version = data[7];  // After "BATHRON"
    info.network = data[8];

    if (info.version == 1) {
        // v01: implicit P2PKH destination
        info.destType = BURN_DEST_P2PKH;
        memcpy(info.bathronDest.begin(), &data[9], 20);
    } else if (info.version == 2) {
        // v02 (BCS A2): explicit destination type byte
        info.destType = data[9];
        if (info.destType != BURN_DEST_P2PKH && info.destType != BURN_DEST_P2SH)
            return false;
        memcpy(info.bathronDest.begin(), &data[10], 20);
    } else {
        return false;
    }

    // Get burn amount
    info.burnedSats = btcTx.vout[burnIdx].nValue;

    return true;
}

CScript GetMintDestScript(const BurnClaimRecord& record)
{
    if (record.destType == BURN_DEST_P2SH)
        return GetScriptForDestination(CScriptID(record.bathronDest));
    return GetScriptForDestination(CKeyID(record.bathronDest));
}

//
// BurnClaimPayload Implementation
//

uint256 BurnClaimPayload::GetBtcTxid() const
{
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(btcTxBytes, btcTx)) {
        return uint256();
    }
    return ComputeBtcTxid(btcTx);
}

bool BurnClaimPayload::IsTriviallyValid(std::string& strError) const
{
    // 1. Version check
    if (nVersion != BURN_CLAIM_PAYLOAD_VERSION) {
        strError = "Invalid payload version";
        return false;
    }

    // 2. BTC TX bytes not empty
    if (btcTxBytes.empty()) {
        strError = "Empty BTC transaction";
        return false;
    }

    // 3. DoS: BTC TX size limit
    if (btcTxBytes.size() > MAX_BTC_TX_SIZE_SANITY) {
        strError = strprintf("BTC TX too large: %zu > %zu",
                            btcTxBytes.size(), MAX_BTC_TX_SIZE_SANITY);
        return false;
    }

    // 4. Parse BTC TX
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(btcTxBytes, btcTx)) {
        strError = "BTC transaction parsing failed (malformed)";
        return false;
    }

    // 5. BTC TX must have inputs
    if (btcTx.vin.empty()) {
        strError = "BTC transaction has no inputs";
        return false;
    }

    // 6. DoS: vout count limit
    if (btcTx.vout.size() > MAX_BTC_TX_VOUT_COUNT) {
        strError = "Too many outputs in BTC TX";
        return false;
    }

    // 7. Merkle proof checks
    if (merkleProof.empty()) {
        strError = "Empty merkle proof";
        return false;
    }
    if (merkleProof.size() > MAX_MERKLE_PROOF_LENGTH) {
        strError = strprintf("Merkle proof too long: %d > %d",
                            merkleProof.size(), MAX_MERKLE_PROOF_LENGTH);
        return false;
    }

    // 8. txIndex bounds check (64-bit to avoid UB)
    uint64_t maxTxIndex = (merkleProof.size() >= 64) ? UINT64_MAX
                        : (1ULL << merkleProof.size());
    if ((uint64_t)txIndex >= maxTxIndex) {
        strError = strprintf("txIndex out of bounds: %u >= 2^%zu",
                            txIndex, merkleProof.size());
        return false;
    }

    // No signature check needed - burn proof is self-authenticating
    return true;
}

//
// Consensus Validation
//

bool CheckBurnClaim(const BurnClaimPayload& payload,
                    CValidationState& state,
                    uint32_t nHeight)
{
    // BP12 Kill Switch is NOT checked here. It used to be a "soft consensus rule"
    // (reject in CheckBurnClaim), but AreBtcBurnsEnabled() is a node-local flag
    // (-btcburnsenabled / setbtcburnsenabled RPC) with no network coordination —
    // gating a *consensus* reject on it splits honest nodes that hold different
    // states. It is now a MEMPOOL policy: a node with burns disabled refuses to
    // accept/relay/mine NEW TX_BURN_CLAIM (AcceptToMemoryPool), but still validates
    // blocks that contain them, so the emergency brake never forks the chain.

    // 0. Parse BTC TX
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(payload.btcTxBytes, btcTx)) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-parse-failed",
                             "BTC transaction parsing failed");
    }

    // 1. Compute BTC txid
    uint256 btcTxid = ComputeBtcTxid(btcTx);

    // 2. Anti-replay check
    if (IsBtcTxidAlreadyClaimed(btcTxid)) {
        return state.Invalid(false, REJECT_DUPLICATE,
                             "burn-claim-duplicate",
                             "BTC txid already claimed or pending");
    }

    // 3. Verify BTC block exists in the CONSENSUS btcheadersdb.
    // R3/BC-07: the header MUST be in the consensus btcheadersdb. Do NOT fall
    // back to local per-node btcspv on the validation path (CheckBurnClaim runs
    // in ConnectBlock) — local SPV is non-deterministic, so a burn referencing a
    // header that only some nodes hold in local SPV (e.g. during a BTC reorg)
    // would split the chain.
    BtcBlockHeader consensusHeader;
    if (!g_btcheadersdb || !g_btcheadersdb->GetHeaderByHash(payload.btcBlockHash, consensusHeader)) {
        return state.Invalid(false, REJECT_INVALID, "burnclaim-btc-header-missing",
                             "BTC header not in consensus btcheadersdb");
    }

    // R1/BC-02: the hash exists in the append-only 'H' index but must also be
    // the active-chain header at the claimed height — a header demoted by a
    // V2 btcheaders reorg (kept for undo) MUST NOT back a mint (M0 with no
    // canonical BTC burn). This also pins payload.btcBlockHeight to the header,
    // so no separate height-consistency check is needed.
    uint256 hashAtHeight;
    if (!g_btcheadersdb->GetHashAtHeight(payload.btcBlockHeight, hashAtHeight) ||
        hashAtHeight != payload.btcBlockHash) {
        return state.Invalid(false, REJECT_INVALID, "burn-claim-block-not-best",
                             "BTC block hash not on the active chain at the claimed height");
    }
    LogPrint(BCLog::NET, "BURNCLAIM: Found header in btcheadersdb at height %d\n",
             payload.btcBlockHeight);

    // 6. Verify merkle proof against the consensus header
    const uint256& merkleRoot = consensusHeader.hashMerkleRoot;

    // The merkle proof is the ONLY thing binding the claimed BTC txid to the
    // (consensus) block header — it MUST always be verified, never skipped. The
    // verifier is an instance method on g_btc_spv (the proof check itself is a
    // pure function of its arguments). If the verifier is unavailable we cannot
    // prove the burn and must REJECT, not silently accept. Defense-in-depth:
    // g_btc_spv is unconditionally initialised in production, so this only closes
    // a latent footgun — previously, a null g_btc_spv let the check be skipped,
    // letting ANY txid be claimed against any header already in btcheadersdb.
    if (!g_btc_spv) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-no-spv",
                             "Cannot verify merkle proof: SPV verifier unavailable");
    }
    if (!g_btc_spv->VerifyMerkleProof(btcTxid, merkleRoot,
                                      payload.merkleProof, payload.txIndex)) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-merkle-invalid",
                             "Merkle proof verification failed");
    }

    // 7. Validate burn format
    BurnInfo burnInfo;
    if (!ParseBurnOutputs(btcTx, burnInfo)) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-format-invalid",
                             "BTC TX is not a valid burn");
    }

    // 7b. Burn amount must be in the consensus money range and above dust. These
    // mirror the checks CheckMintM0BTC already enforces at finalization; applying
    // them here at claim acceptance stops an out-of-range/dust burn from entering
    // PENDING, where the producer would re-select it every block and the mint tx
    // would fail CheckMintM0BTC -> mint production wedges (liveness). Both terms
    // already hold for every real burn, so this rejects nothing minted today.
    if (!Params().GetConsensus().MoneyRange(burnInfo.burnedSats)) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-amount-range",
                             "Burn amount outside money range");
    }
    if (burnInfo.burnedSats < MIN_BURN_SATS) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-amount-dust",
                             "Burn amount below minimum");
    }

    // 8. Verify network byte matches
    // Accept both numeric (0x00/0x01) and ASCII ('M'/'T') formats for flexibility
    bool networkOk = false;
    if (Params().IsTestnet()) {
        // Testnet: accept 0x01 or 'T' (0x54)
        networkOk = (burnInfo.network == 0x01 || burnInfo.network == 0x54);
    } else {
        // Mainnet: accept 0x00 or 'M' (0x4D)
        networkOk = (burnInfo.network == 0x00 || burnInfo.network == 0x4D);
    }
    if (!networkOk) {
        return state.Invalid(false, REJECT_INVALID,
                             "burn-claim-network-mismatch",
                             strprintf("Wrong network byte: got %d (0x%02x), expected %s",
                                       burnInfo.network, burnInfo.network,
                                       Params().IsTestnet() ? "0x01 or 'T'" : "0x00 or 'M'"));
    }

    // No signature check needed - burn proof is self-authenticating.
    // M0BTC always goes to the destination encoded in BATHRON metadata.
    // Anyone can submit a valid claim.

    // NOTE: K_CONFIRMATIONS check is NOT done here.
    // Claim is accepted as PENDING; finalization (BP11) checks K.

    return true;
}

bool CheckNoDuplicateBurnClaimsInBlock(const std::vector<std::shared_ptr<const CTransaction>>& vtx,
                                       CValidationState& state)
{
    // B4.6 — see burnclaim.h. Dedup key = the BTC txid computed from the
    // embedded raw BTC tx (same identity CheckBurnClaim / burnclaimdb use),
    // NOT the BATHRON txid (two distinct wrappers can carry the same burn).
    std::set<uint256> seenBtcTxids;
    size_t nClaims = 0;
    for (const auto& tx : vtx) {
        if (!tx || tx->nType != CTransaction::TxType::TX_BURN_CLAIM) continue;

        if (++nClaims > MAX_BURN_CLAIMS_PER_BLOCK) {
            return state.DoS(100, error("%s: more than %zu burn claims in one block",
                                        __func__, MAX_BURN_CLAIMS_PER_BLOCK),
                             REJECT_INVALID, "bad-burnclaim-too-many");
        }

        BurnClaimPayload payload;
        if (!GetTxPayload(*tx, payload)) continue;   // rejected by CheckSpecialTx

        BtcParsedTx btcTx;
        if (!ParseBtcTransaction(payload.btcTxBytes, btcTx)) continue;  // idem

        const uint256 btcTxid = ComputeBtcTxid(btcTx);
        if (!seenBtcTxids.insert(btcTxid).second) {
            return state.DoS(100, error("%s: duplicate burn claim for BTC txid %s in one block",
                                        __func__, btcTxid.ToString()),
                             REJECT_INVALID, "bad-burnclaim-duplicate-in-block");
        }
    }
    return true;
}

// Legacy compatibility - forwards to BP11 implementation
bool IsBtcTxidAlreadyClaimed(const uint256& btcTxid)
{
    return IsBtcTxidBlockedByClaimRecord(btcTxid);
}

//==============================================================================
// BP11 - M0BTC Minting State Machine Implementation
//==============================================================================

uint32_t GetKFinality()
{
    return Params().IsTestnet() ? K_FINALITY_TESTNET : K_FINALITY_MAINNET;
}

bool BurnClaimRecord::IsOrphaned() const
{
    if (status != BurnClaimStatus::PENDING) {
        return false;
    }
    // Use btcheadersdb (consensus) to check if block is still in best chain
    if (!g_btcheadersdb) {
        return false;  // Can't determine - assume not orphaned
    }
    // Check if hash at btcHeight matches btcBlockHash
    uint256 hashAtHeight;
    if (!g_btcheadersdb->GetHashAtHeight(btcHeight, hashAtHeight)) {
        return true;  // Height not in DB - treat as orphaned
    }
    return hashAtHeight != btcBlockHash;
}

bool MintPayload::IsTriviallyValid(std::string& strError) const
{
    if (nVersion != MINT_PAYLOAD_VERSION) {
        strError = "Invalid mint payload version";
        return false;
    }

    if (btcTxids.empty()) {
        strError = "Empty btcTxids list";
        return false;
    }

    if (btcTxids.size() > MAX_MINT_CLAIMS_PER_BLOCK) {
        strError = strprintf("Too many claims: %zu > %zu", btcTxids.size(), MAX_MINT_CLAIMS_PER_BLOCK);
        return false;
    }

    // Check canonical sort
    if (!std::is_sorted(btcTxids.begin(), btcTxids.end())) {
        strError = "btcTxids not sorted canonically";
        return false;
    }

    // Check for duplicates
    for (size_t i = 1; i < btcTxids.size(); i++) {
        if (btcTxids[i] == btcTxids[i-1]) {
            strError = "Duplicate btcTxid in payload";
            return false;
        }
    }

    return true;
}

//==============================================================================
// Anti-Replay with Deterministic Release
//==============================================================================

bool IsBtcTxidBlockedByClaimRecord(const uint256& btcTxid)
{
    if (!g_burnclaimdb) {
        return false;  // DB not initialized - allow claim
    }

    BurnClaimRecord record;
    if (!g_burnclaimdb->GetBurnClaim(btcTxid, record)) {
        return false;  // No record - allow claim
    }

    // FINAL always blocks (immutable)
    if (record.status == BurnClaimStatus::FINAL) {
        return true;
    }

    // PENDING: deterministic release rule.
    // R4/MINT-03/DR-06: use the CONSENSUS btcheadersdb (not local per-node btcspv)
    // so every node reaches the same accept/reject verdict on the connect path.
    if (record.status == BurnClaimStatus::PENDING) {
        if (!g_btcheadersdb) {
            return true;  // can't verify -> block conservatively
        }
        uint256 hashAtHeight;
        if (!g_btcheadersdb->GetHashAtHeight(record.btcHeight, hashAtHeight) ||
            hashAtHeight != record.btcBlockHash) {
            // BTC block no longer the active-chain header at its height -> release
            return false;
        }
        // Still the active-chain header at its height -> block duplicate.
        return true;
    }

    return false;
}

//==============================================================================
// Finalization Logic (Consensus)
//==============================================================================

bool IsBtcBurnStillValidConsensus(const BurnClaimRecord& record)
{
    // CONSENSUS FUNCTION - MUST BE DETERMINISTIC (no GetTime()!)
    // Uses g_btcheadersdb (consensus) NOT g_btc_spv (local sync)

    if (!g_btcheadersdb) {
        LogPrintf("IsBtcBurnStillValidConsensus: btcheadersdb not available\n");
        return false;
    }

    // 1. Check BTC block is still in best chain
    // Verify hash at btcHeight matches record.btcBlockHash
    uint256 hashAtHeight;
    if (!g_btcheadersdb->GetHashAtHeight(record.btcHeight, hashAtHeight)) {
        LogPrintf("IsBtcBurnStillValidConsensus: no header at height %u\n", record.btcHeight);
        return false;  // Height not in DB
    }
    if (hashAtHeight != record.btcBlockHash) {
        LogPrintf("IsBtcBurnStillValidConsensus: hash mismatch at height %u (expected %s, got %s)\n",
                  record.btcHeight, record.btcBlockHash.ToString().substr(0, 16),
                  hashAtHeight.ToString().substr(0, 16));
        return false;  // Block reorged out
    }

    // 2. Check has sufficient confirmations (K_CONFIRMATIONS)
    // Confirmations = tip_height - btcHeight + 1
    uint32_t tipHeight = g_btcheadersdb->GetTipHeight();
    if (tipHeight < record.btcHeight) {
        LogPrintf("IsBtcBurnStillValidConsensus: tip %u < btcHeight %u\n", tipHeight, record.btcHeight);
        return false;  // Shouldn't happen, but be safe
    }
    uint32_t conf = tipHeight - record.btcHeight + 1;
    if (conf < GetRequiredConfirmations()) {
        LogPrintf("IsBtcBurnStillValidConsensus: insufficient confirmations %u < %u\n",
                  conf, GetRequiredConfirmations());
        return false;  // Not enough confirmations yet
    }

    return true;
}

bool EnterPendingState(const BurnClaimPayload& payload, uint32_t bathronHeight)
{
    if (!g_burnclaimdb) {
        LogPrintf("ERROR: EnterPendingState - burnclaimdb not initialized\n");
        return false;
    }

    // Parse BTC TX
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(payload.btcTxBytes, btcTx)) {
        LogPrintf("ERROR: EnterPendingState - BTC TX parsing failed\n");
        return false;
    }

    uint256 btcTxid = ComputeBtcTxid(btcTx);

    // Extract burn info from OP_RETURN (source of truth for dest/amount)
    BurnInfo burnInfo;
    if (!ParseBurnOutputs(btcTx, burnInfo)) {
        LogPrintf("ERROR: EnterPendingState - ParseBurnOutputs failed\n");
        return false;
    }

    // Create pending record
    BurnClaimRecord record;
    record.btcTxid = btcTxid;
    record.btcBlockHash = payload.btcBlockHash;
    record.btcHeight = payload.btcBlockHeight;
    record.burnedSats = burnInfo.burnedSats;
    record.bathronDest = burnInfo.bathronDest;
    record.destType = burnInfo.destType;
    record.claimHeight = bathronHeight;
    record.finalHeight = 0;
    record.status = BurnClaimStatus::PENDING;

    // Store in DB (upsert - overwrites if re-claim after BTC reorg)
    if (!g_burnclaimdb->StoreBurnClaim(record)) {
        LogPrintf("ERROR: EnterPendingState - StoreBurnClaim failed\n");
        return false;
    }

    LogPrint(BCLog::STATE, "Burn claim entered PENDING: btc_txid=%s amount=%lld dest=%s\n",
             btcTxid.ToString(), record.burnedSats, record.bathronDest.ToString());

    return true;
}

bool UndoBurnClaim(const BurnClaimPayload& payload, uint32_t height)
{
    if (!g_burnclaimdb) {
        return false;
    }

    // Parse BTC TX to get txid
    BtcParsedTx btcTx;
    if (!ParseBtcTransaction(payload.btcTxBytes, btcTx)) {
        return false;
    }
    uint256 btcTxid = ComputeBtcTxid(btcTx);

    // Simply remove the claim record
    // DO NOT touch supply/claimed - that's handled by DisconnectMintM0BTC
    if (!g_burnclaimdb->DeleteBurnClaim(btcTxid)) {
        LogPrintf("ERROR: UndoBurnClaim - DeleteBurnClaim failed for %s\n", btcTxid.ToString());
        return false;
    }

    LogPrint(BCLog::STATE, "Burn claim undone: btc_txid=%s at BATHRON height=%d\n",
             btcTxid.ToString(), height);

    return true;
}

//==============================================================================
// TX_MINT_M0BTC Creation and Validation
//==============================================================================

CTransaction CreateMintM0BTC(uint32_t blockHeight)
{
    LogPrintf("CreateMintM0BTC: ENTER height=%d burns_enabled=%d db=%p\n",
              blockHeight, AreBtcBurnsEnabled() ? 1 : 0, (void*)g_burnclaimdb.get());

    // BP12 Kill Switch: Don't create mint TX if burns are disabled
    if (!AreBtcBurnsEnabled()) {
        LogPrintf("CreateMintM0BTC: EXIT - burns disabled\n");
        return CTransaction();  // Burns disabled by kill switch
    }

    if (!g_burnclaimdb) {
        LogPrintf("CreateMintM0BTC: EXIT - no burnclaimdb\n");
        return CTransaction();  // DB not available
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP11 UNIFIED FINALIZATION: Same K for ALL burns (genesis and post-genesis)
    // ═══════════════════════════════════════════════════════════════════════════
    // K_FINALITY = 20 (testnet) or 100 (mainnet) for ALL burns, no exceptions.
    // Genesis bootstrap simply generates K+1 blocks before mints appear.
    // ═══════════════════════════════════════════════════════════════════════════

    const uint32_t k = GetKFinality();
    std::vector<uint256> eligibleTxids;

    // Find all PENDING claims eligible for finalization
    g_burnclaimdb->ForEachPendingClaim([&](const BurnClaimRecord& record) {
        // Claim is eligible if blockHeight > claimHeight + K
        if (blockHeight > record.claimHeight + k &&
            IsBtcBurnStillValidConsensus(record)) {
            eligibleTxids.push_back(record.btcTxid);
        }
        return true;  // Continue iteration
    });

    LogPrintf("CreateMintM0BTC: height=%d k=%d eligible=%d\n",
              blockHeight, k, eligibleTxids.size());

    if (eligibleTxids.empty()) {
        // Debug: count total pending claims
        int totalPending = 0;
        g_burnclaimdb->ForEachPendingClaim([&](const BurnClaimRecord& record) {
            totalPending++;
            LogPrintf("  PENDING claim: btcTxid=%s claimHeight=%d\n",
                      record.btcTxid.ToString().substr(0, 16), record.claimHeight);
            return totalPending < 5;  // Only log first 5
        });
        LogPrintf("CreateMintM0BTC: No eligible claims (total pending: %d)\n", totalPending);
        return CTransaction();  // No mint TX needed
    }

    // CANONICAL SORT: ensures all nodes produce identical TX
    std::sort(eligibleTxids.begin(), eligibleTxids.end());

    // APPLY CAP: if > MAX_MINT_CLAIMS_PER_BLOCK, take first N only
    if (eligibleTxids.size() > MAX_MINT_CLAIMS_PER_BLOCK) {
        eligibleTxids.resize(MAX_MINT_CLAIMS_PER_BLOCK);
    }

    // Build transaction
    CMutableTransaction mtx;
    mtx.nVersion = CTransaction::TxVersion::SAPLING;
    mtx.nType = CTransaction::TxType::TX_MINT_M0BTC;

    // Build outputs - one P2PKH for each claim
    for (const uint256& btcTxid : eligibleTxids) {
        BurnClaimRecord record;
        if (!g_burnclaimdb->GetBurnClaim(btcTxid, record)) {
            continue;  // Should never happen
        }

        CTxOut out;
        // BP10: 1 satoshi BTC = 1 satoshi M0 (1:1 conversion)
        // burnedSats is in satoshis BTC, nValue is in satoshis M0
        // No conversion needed - direct 1:1 mapping
        out.nValue = record.burnedSats;
        out.scriptPubKey = GetMintDestScript(record);
        mtx.vout.push_back(out);
    }

    // Set payload
    MintPayload payload;
    payload.nVersion = MINT_PAYLOAD_VERSION;
    payload.btcTxids = eligibleTxids;

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << payload;
    mtx.extraPayload = std::vector<uint8_t>(ss.begin(), ss.end());

    return CTransaction(mtx);
}

bool CheckMintM0BTC(const CTransaction& tx,
                    CValidationState& state,
                    uint32_t blockHeight)
{
    // Extract payload first (needed for both genesis and normal path)
    if (!tx.IsSpecialTx() || tx.nType != CTransaction::TxType::TX_MINT_M0BTC) {
        return state.Invalid(false, REJECT_INVALID, "mint-not-special",
                             "Not a TX_MINT_M0BTC transaction");
    }

    if (!tx.extraPayload) {
        return state.Invalid(false, REJECT_INVALID, "mint-no-payload",
                             "Missing extraPayload");
    }

    MintPayload payload;
    try {
        CDataStream ss(*tx.extraPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> payload;
    } catch (...) {
        return state.Invalid(false, REJECT_INVALID, "mint-payload-decode",
                             "Failed to decode MintPayload");
    }

    std::string error;
    if (!payload.IsTriviallyValid(error)) {
        return state.Invalid(false, REJECT_INVALID, "mint-payload-invalid", error);
    }

    // TX_MINT_M0BTC must have empty vin (this is money creation)
    if (!tx.vin.empty()) {
        return state.Invalid(false, REJECT_INVALID, "mint-has-inputs",
                             "TX_MINT_M0BTC must have empty vin");
    }

    // Must have outputs matching claims
    if (tx.vout.size() != payload.btcTxids.size()) {
        return state.Invalid(false, REJECT_INVALID, "mint-output-count",
                             strprintf("Output count mismatch: %zu vs %zu",
                                       tx.vout.size(), payload.btcTxids.size()));
    }

    // NOTE: Block 1 genesis SPV validation removed.
    // In new genesis flow, Block 1 = TX_BTC_HEADERS (no TX_MINT_M0BTC).
    // Burns are claimed in Block 2+ via submitburnclaim, validated through normal path.

    // ═══════════════════════════════════════════════════════════════════════════
    // Validate against burn claim DB
    // ═══════════════════════════════════════════════════════════════════════════

    // BP12 Kill Switch is NOT checked here — same principle as CheckBurnClaim
    // (commit 9a1849c): AreBtcBurnsEnabled() is a node-local flag with no network
    // coordination, so a *consensus* reject gated on it splits honest nodes that
    // hold different states — precisely during an emergency, when partial fleet
    // activation is most likely. The brake for mints is PRODUCER-side:
    // CreateMintM0BTC refuses to build a mint while burns are disabled (mints
    // never transit the mempool — AcceptToMemoryPool rejects TX_MINT_M0BTC
    // unconditionally — so the producer gate IS the policy layer). A disabled
    // node still validates blocks containing mints, which remain fully bounded
    // by the consensus checks below + the A5/A7 supply rules.

    if (!g_burnclaimdb) {
        return state.Invalid(false, REJECT_INVALID, "mint-no-db",
                             "Burn claim DB not initialized");
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // BP11 UNIFIED FINALIZATION: Same K for ALL burns (no exceptions)
    // ═══════════════════════════════════════════════════════════════════════════
    // K_FINALITY = 20 (testnet) or 100 (mainnet) for ALL burns.
    // Genesis bootstrap generates K+1 blocks before mints can appear.
    // ═══════════════════════════════════════════════════════════════════════════

    const uint32_t k = GetKFinality();

    // Validate each claim
    for (size_t i = 0; i < payload.btcTxids.size(); i++) {
        const uint256& btcTxid = payload.btcTxids[i];

        BurnClaimRecord record;
        if (!g_burnclaimdb->GetBurnClaim(btcTxid, record)) {
            return state.Invalid(false, REJECT_INVALID, "mint-unknown-claim",
                                 strprintf("Unknown claim: %s", btcTxid.ToString()));
        }

        if (record.status != BurnClaimStatus::PENDING) {
            return state.Invalid(false, REJECT_INVALID, "mint-not-pending",
                                 strprintf("Claim not PENDING: %s", btcTxid.ToString()));
        }

        // K_FINALITY check: blockHeight > claimHeight + K
        if (blockHeight <= record.claimHeight + k) {
            return state.Invalid(false, REJECT_INVALID, "mint-claim-too-early",
                                 strprintf("Claim not old enough: %s (claim=%d, k=%d, block=%d)",
                                           btcTxid.ToString(), record.claimHeight, k, blockHeight));
        }

        if (!IsBtcBurnStillValidConsensus(record)) {
            return state.Invalid(false, REJECT_INVALID, "mint-btc-invalid",
                                 strprintf("BTC burn no longer valid: %s", btcTxid.ToString()));
        }

        // Check output matches claim
        // Money-range check
        if (!Params().GetConsensus().MoneyRange(record.burnedSats)) {
            return state.Invalid(false, REJECT_INVALID, "mint-amount-range",
                                 strprintf("Amount out of range: %s", btcTxid.ToString()));
        }

        // Dust check
        if (record.burnedSats < MIN_BURN_SATS) {
            return state.Invalid(false, REJECT_INVALID, "mint-amount-dust",
                                 strprintf("Amount below dust: %s", btcTxid.ToString()));
        }

        // Script must match the claim's destination form exactly:
        // P2PKH(dest) for v01/type-0 burns, P2SH(dest) for v02 type-1 burns
        CScript expectedScript = GetMintDestScript(record);
        if (tx.vout[i].scriptPubKey != expectedScript) {
            return state.Invalid(false, REJECT_INVALID, "mint-dest-mismatch",
                                 strprintf("Output script mismatch: %s", btcTxid.ToString()));
        }

        // BP10: 1 satoshi BTC = 1 satoshi M0 (1:1, no conversion)
        CAmount expectedValue = record.burnedSats;
        if (tx.vout[i].nValue != expectedValue) {
            return state.Invalid(false, REJECT_INVALID, "mint-amount-mismatch",
                                 strprintf("Amount mismatch: %s (expected %lld sats, got %lld sats)",
                                           btcTxid.ToString(), expectedValue, tx.vout[i].nValue));
        }
    }

    // CANONICAL SORT CHECK (determinism requirement)
    if (!std::is_sorted(payload.btcTxids.begin(), payload.btcTxids.end())) {
        return state.Invalid(false, REJECT_INVALID, "mint-not-sorted",
                             "btcTxids not sorted canonically");
    }

    return true;
}

//==============================================================================
// Connect/Disconnect for TX_MINT_M0BTC
//==============================================================================

void ConnectMintM0BTC(const CTransaction& tx, uint32_t blockHeight)
{
    if (!g_burnclaimdb) {
        LogPrintf("ERROR: ConnectMintM0BTC - burnclaimdb not initialized\n");
        return;
    }

    if (!tx.extraPayload) {
        LogPrintf("ERROR: ConnectMintM0BTC - missing extraPayload\n");
        return;
    }

    MintPayload payload;
    try {
        CDataStream ss(*tx.extraPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> payload;
    } catch (...) {
        LogPrintf("ERROR: ConnectMintM0BTC - failed to decode payload\n");
        return;
    }

    auto batch = g_burnclaimdb->CreateBatch();

    for (const uint256& btcTxid : payload.btcTxids) {
        BurnClaimRecord record;
        if (!g_burnclaimdb->GetBurnClaim(btcTxid, record)) {
            LogPrintf("ERROR: ConnectMintM0BTC - claim not found: %s\n", btcTxid.ToString());
            continue;
        }

        // Update status to FINAL
        batch.UpdateClaimStatus(btcTxid, BurnClaimStatus::FINAL, blockHeight);

        // Increment M0BTC supply
        batch.IncrementM0BTCSupply(record.burnedSats);

        LogPrint(BCLog::STATE, "Burn claim finalized: btc_txid=%s amount=%lld\n",
                 btcTxid.ToString(), record.burnedSats);
    }

    batch.Commit();

    // UTXOs are created via normal vout processing
}

void DisconnectMintM0BTC(const CTransaction& tx, uint32_t blockHeight)
{
    if (!g_burnclaimdb) {
        LogPrintf("ERROR: DisconnectMintM0BTC - burnclaimdb not initialized\n");
        return;
    }

    if (!tx.extraPayload) {
        LogPrintf("ERROR: DisconnectMintM0BTC - missing extraPayload\n");
        return;
    }

    MintPayload payload;
    try {
        CDataStream ss(*tx.extraPayload, SER_NETWORK, PROTOCOL_VERSION);
        ss >> payload;
    } catch (...) {
        LogPrintf("ERROR: DisconnectMintM0BTC - failed to decode payload\n");
        return;
    }

    auto batch = g_burnclaimdb->CreateBatch();

    for (const uint256& btcTxid : payload.btcTxids) {
        BurnClaimRecord record;
        if (!g_burnclaimdb->GetBurnClaim(btcTxid, record)) {
            LogPrintf("ERROR: DisconnectMintM0BTC - claim not found: %s\n", btcTxid.ToString());
            continue;
        }

        // Revert status to PENDING
        batch.UpdateClaimStatus(btcTxid, BurnClaimStatus::PENDING, 0);

        // Decrement M0BTC supply
        batch.DecrementM0BTCSupply(record.burnedSats);

        LogPrint(BCLog::STATE, "Burn claim finalization reverted: btc_txid=%s\n", btcTxid.ToString());
    }

    batch.Commit();

    // UTXOs are removed via normal reorg UTXO handling
}
