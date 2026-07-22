"""
Generic Bitcoin-fork HTLC with 3-secrets support for FlowSwap per-leg routing.

Works with any Bitcoin-compatible fork (DASH, PIVX, ZEC) using the same HTLC
script structure as btc_3s.py. Chain-specific differences (address encoding,
block times, bech32 HRP) are handled via chain_config.

All chains use P2SH base58 addresses (DASH, PIVX, ZEC do NOT support SegWit).
ZEC uses CLI-based signing (ZIP 143/244 sighash differs from Bitcoin legacy).
DASH/PIVX use python-bitcoinlib legacy sighash (standard Bitcoin TX format).

Uses python-bitcoinlib for ECDSA signing (secp256k1 is universal across all
Bitcoin forks — SelectParams only affects address encoding, not crypto).
"""

import hashlib
import json
import logging
import struct
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

from .btc_3s import (
    HTLC3SParams, HTLC3SSecrets,
    push_data, push_int, sha256,
    generate_secret, verify_preimage,
    OP_0, OP_IF, OP_ELSE, OP_ENDIF, OP_DROP,
    OP_SHA256, OP_EQUALVERIFY, OP_CHECKSIG,
    OP_CHECKLOCKTIMEVERIFY, OP_HASH160,
    _encode_compact_size,
)

log = logging.getLogger(__name__)


# ── Chain Configurations ───────────────────────────────────────────────────────

CHAIN_CONFIGS = {
    "DASH": {
        "name": "dash",
        "segwit": False,                # DASH does NOT support SegWit
        "bech32_hrp": "",               # Not applicable (no SegWit)
        "p2sh_version": 0x13,           # Dash testnet P2SH version byte
        "p2pkh_version": 0x8c,          # Dash testnet P2PKH version byte
        "wif_version": 0xef,            # Testnet WIF prefix
        "block_time": 150,              # ~2.5 min
        "decimals": 8,
        "coin_per_sat": 100_000_000,
        "dust_limit": 546,
        "default_fee_rate": 1,          # sat/vB
    },
    "PIVX": {
        "name": "pivx",
        "segwit": False,                # PIVX does NOT support SegWit
        "bech32_hrp": "",               # Not applicable (no SegWit)
        "p2sh_version": 0x13,           # PIVX testnet P2SH version byte
        "p2pkh_version": 0x8b,
        "wif_version": 0xef,
        "block_time": 60,               # ~1 min
        "decimals": 8,
        "coin_per_sat": 100_000_000,
        "dust_limit": 546,
        "default_fee_rate": 1,
    },
    "ZEC": {
        "name": "zcash",
        "segwit": False,                # ZEC transparent layer, no SegWit
        "bech32_hrp": "",               # Not applicable
        "p2sh_version": 0xc4,           # ZEC testnet P2SH (single byte, unused — see version_bytes)
        "p2sh_version_bytes": b'\x1c\xba',  # ZEC testnet 2-byte P2SH prefix → "t2..." addresses
        "p2pkh_version": 0x25,
        "wif_version": 0xef,
        "block_time": 75,               # ~1.25 min
        "decimals": 8,
        "coin_per_sat": 100_000_000,
        "dust_limit": 546,
        "default_fee_rate": 1,
        "use_cli_signing": True,        # ZEC TX format (ZIP 243/244) incompatible with python-bitcoinlib
    },
}


# ── ForkHTLC3S Class ───────────────────────────────────────────────────────────

class ForkHTLC3S:
    """
    Generic 3-secret HTLC for Bitcoin-compatible forks.

    Reuses the identical HTLC script from btc_3s.py:
        OP_IF
            OP_SHA256 <H_user> OP_EQUALVERIFY
            OP_SHA256 <H_lp1>  OP_EQUALVERIFY
            OP_SHA256 <H_lp2>  OP_EQUALVERIFY
            <recipient_pubkey> OP_CHECKSIG
        OP_ELSE
            <timelock> OP_CHECKLOCKTIMEVERIFY OP_DROP
            <refund_pubkey> OP_CHECKSIG
        OP_ENDIF

    Chain-specific: P2SH base58 addresses (none of DASH/PIVX/ZEC support SegWit).
    ZEC uses CLI-based signing due to incompatible TX format (ZIP 243/244).
    """

    def __init__(self, client, chain_config: dict):
        """
        Args:
            client: Chain RPC client (DASHClient, PIVXClient, ZECClient)
                    Must have _call() method for RPC.
            chain_config: Dict from CHAIN_CONFIGS above.
        """
        self.client = client
        self.config = chain_config
        self.chain_name = chain_config["name"]
        self.is_segwit = chain_config.get("segwit", False)

    # ── Script Creation (identical to btc_3s.py) ──────────────────────────────

    def create_htlc_script_3s(self, params: HTLC3SParams) -> bytes:
        """Create HTLC redeem script with 3 hashlocks. Identical to BTC."""
        H_user = bytes.fromhex(params.H_user)
        H_lp1 = bytes.fromhex(params.H_lp1)
        H_lp2 = bytes.fromhex(params.H_lp2)
        recipient = bytes.fromhex(params.recipient_pubkey)
        refund = bytes.fromhex(params.refund_pubkey)

        if len(H_user) != 32 or len(H_lp1) != 32 or len(H_lp2) != 32:
            raise ValueError("Hashlocks must be 32 bytes each")
        if len(recipient) != 33 or len(refund) != 33:
            raise ValueError("Pubkeys must be 33 bytes (compressed)")

        script = bytes([OP_IF])
        script += bytes([OP_SHA256]) + push_data(H_user) + bytes([OP_EQUALVERIFY])
        script += bytes([OP_SHA256]) + push_data(H_lp1) + bytes([OP_EQUALVERIFY])
        script += bytes([OP_SHA256]) + push_data(H_lp2) + bytes([OP_EQUALVERIFY])
        script += push_data(recipient) + bytes([OP_CHECKSIG])
        script += bytes([OP_ELSE])
        script += push_int(params.timelock)
        script += bytes([OP_CHECKLOCKTIMEVERIFY, OP_DROP])
        script += push_data(refund) + bytes([OP_CHECKSIG])
        script += bytes([OP_ENDIF])

        return script

    # ── Address Encoding ──────────────────────────────────────────────────────

    def script_to_address(self, script: bytes) -> str:
        """Convert redeem script to chain-appropriate address (P2WSH or P2SH)."""
        if self.is_segwit:
            return self._script_to_p2wsh(script)
        else:
            return self._script_to_p2sh(script)

    def _script_to_p2wsh(self, script: bytes) -> str:
        """P2WSH bech32 address (reserved for future SegWit-capable chains)."""
        witness_program = sha256(script)
        hrp = self.config["bech32_hrp"]
        return self._encode_bech32(hrp, 0, witness_program)

    def _script_to_p2sh(self, script: bytes) -> str:
        """P2SH base58check address for non-SegWit chains (ZEC)."""
        script_hash = _hash160(script)
        version_bytes = self.config.get("p2sh_version_bytes")
        if version_bytes:
            # ZEC: 2-byte version prefix
            payload = version_bytes + script_hash
        else:
            payload = bytes([self.config["p2sh_version"]]) + script_hash
        return _base58check_encode(payload)

    def _encode_bech32(self, hrp: str, version: int, program: bytes) -> str:
        """Encode bech32 address (same algorithm as Bitcoin)."""
        CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

        def bech32_polymod(values):
            GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
            chk = 1
            for v in values:
                b = chk >> 25
                chk = ((chk & 0x1ffffff) << 5) ^ v
                for i in range(5):
                    chk ^= GEN[i] if ((b >> i) & 1) else 0
            return chk

        def bech32_hrp_expand(hrp):
            return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

        def bech32_create_checksum(hrp, data):
            values = bech32_hrp_expand(hrp) + data
            polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
            return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

        def convertbits(data, frombits, tobits, pad=True):
            acc, bits, ret = 0, 0, []
            maxv = (1 << tobits) - 1
            for value in data:
                acc = (acc << frombits) | value
                bits += frombits
                while bits >= tobits:
                    bits -= tobits
                    ret.append((acc >> bits) & maxv)
            if pad and bits:
                ret.append((acc << (tobits - bits)) & maxv)
            return ret

        data = [version] + convertbits(program, 8, 5)
        checksum = bech32_create_checksum(hrp, data)
        return hrp + "1" + "".join([CHARSET[d] for d in data + checksum])

    # ── HTLC Lifecycle ────────────────────────────────────────────────────────

    def create_htlc_3s(
        self,
        amount_sats: int,
        H_user: str,
        H_lp1: str,
        H_lp2: str,
        recipient_pubkey: str,
        refund_pubkey: str,
        timeout_blocks: int = 24,
    ) -> Dict:
        """
        Create a new 3-secret HTLC on this chain.

        Returns:
            {htlc_address, redeem_script, amount, timelock, H_user, H_lp1, H_lp2,
             recipient_pubkey, refund_pubkey}
        """
        current_height = self.client.get_block_count()
        timelock = current_height + timeout_blocks

        params = HTLC3SParams(
            H_user=H_user, H_lp1=H_lp1, H_lp2=H_lp2,
            recipient_pubkey=recipient_pubkey,
            refund_pubkey=refund_pubkey,
            timelock=timelock,
        )

        script = self.create_htlc_script_3s(params)
        htlc_address = self.script_to_address(script)

        log.info(f"[{self.chain_name}] Created 3S-HTLC: {htlc_address}, "
                 f"timelock={timelock}, segwit={self.is_segwit}")

        return {
            "htlc_address": htlc_address,
            "redeem_script": script.hex(),
            "amount": amount_sats,
            "timelock": timelock,
            "H_user": H_user,
            "H_lp1": H_lp1,
            "H_lp2": H_lp2,
            "recipient_pubkey": recipient_pubkey,
            "refund_pubkey": refund_pubkey,
        }

    def fund_htlc(self, htlc_address: str, amount_sats: int) -> str:
        """Fund an HTLC address from wallet."""
        coin_per_sat = self.config.get("coin_per_sat", 100_000_000)
        amount = amount_sats / coin_per_sat
        txid = self.client._call("sendtoaddress", htlc_address, f"{amount:.8f}")
        log.info(f"[{self.chain_name}] Funded 3S-HTLC {htlc_address} "
                 f"with {amount_sats} sats, txid={txid}")
        return txid

    def check_htlc_funded(
        self,
        htlc_address: str,
        expected_amount: int,
        min_confirmations: int = 1,
    ) -> Optional[Dict]:
        """
        Check if HTLC has been funded.

        Uses listunspent (fast, wallet-aware) → scantxoutset (slow fallback).
        """
        coin_per_sat = self.config.get("coin_per_sat", 100_000_000)

        # Method 1: listunspent (if address is imported/watched)
        try:
            utxos = self.client._call(
                "listunspent", min_confirmations, 9999999,
                json.dumps([htlc_address])
            )
            if utxos:
                for u in utxos:
                    amount_sats = int(round(u.get("amount", 0) * coin_per_sat))
                    if amount_sats >= expected_amount:
                        return {
                            "txid": u["txid"],
                            "vout": u["vout"],
                            "amount": amount_sats,
                            "confirmations": u.get("confirmations", 0),
                        }
        except (RuntimeError, TypeError):
            pass

        # Method 2: scantxoutset (slow, doesn't require address import)
        try:
            scan = self.client._call(
                "scantxoutset", "start",
                json.dumps([f"addr({htlc_address})"])
            )
            if scan and scan.get("success"):
                height = scan.get("height", 0)
                for u in scan.get("unspents", []):
                    amount_sats = int(round(u["amount"] * coin_per_sat))
                    u_height = u.get("height", height)
                    confs = height - u_height + 1 if u_height > 0 else 0
                    if amount_sats >= expected_amount and confs >= min_confirmations:
                        return {
                            "txid": u["txid"],
                            "vout": u["vout"],
                            "amount": amount_sats,
                            "confirmations": confs,
                        }
        except (RuntimeError, TypeError) as e:
            log.error(f"[{self.chain_name}] scantxoutset failed: {e}")

        return None

    def claim_htlc_3s(
        self,
        utxo: Dict,
        redeem_script: str,
        secrets: HTLC3SSecrets,
        recipient_address: str,
        claim_privkey_wif: str,
        fee_rate_sat_vb: int = 1,
    ) -> str:
        """
        Claim HTLC with 3 preimages.

        For SegWit chains: P2WSH witness (same as BTC).
        For non-SegWit: P2SH scriptSig.
        """
        script_bytes = bytes.fromhex(redeem_script)
        self._verify_preimages_match_script(secrets, script_bytes)

        txid = utxo["txid"]
        vout = utxo["vout"]
        amount_sats = utxo["amount"]

        log.info(f"[{self.chain_name}] Claiming 3S-HTLC: {txid}:{vout}, "
                 f"amount={amount_sats} sats")

        # Fee estimation
        estimated_vsize = 180 + len(script_bytes) // 4
        fee_sats = estimated_vsize * fee_rate_sat_vb
        output_sats = amount_sats - fee_sats
        dust = self.config.get("dust_limit", 546)
        if output_sats <= dust:
            raise ValueError(f"Output {output_sats} below dust {dust}")

        coin_per_sat = self.config.get("coin_per_sat", 100_000_000)
        # Avoid floating-point: integer division for exact decimal
        output_amount_str = f"{output_sats // coin_per_sat}.{output_sats % coin_per_sat:08d}"

        # Create raw transaction
        inputs = [{"txid": txid, "vout": vout}]
        outputs = {recipient_address: output_amount_str}
        raw_tx = self.client._call(
            "createrawtransaction",
            json.dumps(inputs), json.dumps(outputs)
        )

        if self.config.get("use_cli_signing"):
            signed_tx = self._sign_claim_via_cli(
                raw_tx, utxo, redeem_script, secrets, claim_privkey_wif
            )
        elif self.is_segwit:
            signed_tx = self._sign_claim_segwit(
                raw_tx, utxo, redeem_script, secrets, claim_privkey_wif
            )
        else:
            signed_tx = self._sign_claim_legacy(
                raw_tx, utxo, redeem_script, secrets, claim_privkey_wif
            )

        claim_txid = self.client._call("sendrawtransaction", signed_tx)
        log.info(f"[{self.chain_name}] 3S-HTLC claimed: txid={claim_txid}")
        return claim_txid

    def refund_htlc_3s(
        self,
        utxo: Dict,
        redeem_script: str,
        refund_address: str,
        refund_privkey_wif: str,
        timelock: int,
        fee_rate_sat_vb: int = 1,
    ) -> str:
        """Refund expired 3S-HTLC."""
        current_height = self.client.get_block_count()
        if current_height < timelock:
            raise ValueError(
                f"Cannot refund yet. Current {current_height}, "
                f"timelock {timelock}. Wait {timelock - current_height} blocks."
            )

        txid = utxo["txid"]
        vout = utxo["vout"]
        amount_sats = utxo["amount"]

        log.info(f"[{self.chain_name}] Refunding 3S-HTLC: {txid}:{vout}")

        script_bytes = bytes.fromhex(redeem_script)
        estimated_vsize = 120 + len(script_bytes) // 4
        fee_sats = estimated_vsize * fee_rate_sat_vb
        output_sats = amount_sats - fee_sats
        dust = self.config.get("dust_limit", 546)
        if output_sats <= dust:
            raise ValueError(f"Output {output_sats} below dust {dust}")

        coin_per_sat = self.config.get("coin_per_sat", 100_000_000)
        # Avoid floating-point: integer division for exact decimal
        output_amount_str = f"{output_sats // coin_per_sat}.{output_sats % coin_per_sat:08d}"

        # Create with nLockTime
        inputs = [{"txid": txid, "vout": vout, "sequence": 0xFFFFFFFE}]
        outputs = {refund_address: output_amount_str}
        raw_tx = self.client._call(
            "createrawtransaction",
            json.dumps(inputs), json.dumps(outputs),
            timelock
        )

        if self.config.get("use_cli_signing"):
            signed_tx = self._sign_refund_via_cli(
                raw_tx, utxo, redeem_script, refund_privkey_wif
            )
        elif self.is_segwit:
            signed_tx = self._sign_refund_segwit(
                raw_tx, utxo, redeem_script, refund_privkey_wif
            )
        else:
            signed_tx = self._sign_refund_legacy(
                raw_tx, utxo, redeem_script, refund_privkey_wif
            )

        refund_txid = self.client._call("sendrawtransaction", signed_tx)
        log.info(f"[{self.chain_name}] 3S-HTLC refunded: txid={refund_txid}")
        return refund_txid

    # ── Secret Extraction ─────────────────────────────────────────────────────

    def extract_secrets_from_txid(
        self, txid: str, vin_index: int = 0
    ) -> Optional[HTLC3SSecrets]:
        """Extract 3 secrets from a claim TX (witness or scriptSig)."""
        try:
            raw_tx = self.client._call("getrawtransaction", txid, True)
            if not raw_tx:
                return None

            vin = raw_tx.get("vin", [])
            if vin_index >= len(vin):
                return None

            if self.is_segwit:
                # SegWit: secrets in witness
                witness = vin[vin_index].get("txinwitness", [])
                if not witness or len(witness) < 6:
                    return None
                witness_bytes = [bytes.fromhex(w) for w in witness]
                return self._extract_secrets_from_witness(witness_bytes)
            else:
                # P2SH: secrets in scriptSig
                scriptsig_hex = vin[vin_index].get("scriptSig", {}).get("hex", "")
                if not scriptsig_hex:
                    return None
                return self._extract_secrets_from_scriptsig(bytes.fromhex(scriptsig_hex))

        except Exception as e:
            log.error(f"[{self.chain_name}] Failed to extract secrets from {txid}: {e}")
            return None

    def _extract_secrets_from_witness(self, witness: list) -> Optional[HTLC3SSecrets]:
        """Extract secrets from SegWit witness stack (same as BTC)."""
        if len(witness) < 6:
            return None
        branch = witness[4]
        if branch != bytes([0x01]) and branch != b'\x01':
            return None
        S_lp2 = witness[1]
        S_lp1 = witness[2]
        S_user = witness[3]
        if len(S_user) != 32 or len(S_lp1) != 32 or len(S_lp2) != 32:
            return None
        return HTLC3SSecrets(S_user=S_user.hex(), S_lp1=S_lp1.hex(), S_lp2=S_lp2.hex())

    def _extract_secrets_from_scriptsig(self, scriptsig: bytes) -> Optional[HTLC3SSecrets]:
        """Extract secrets from P2SH scriptSig.

        Expected: <sig> <S_lp2> <S_lp1> <S_user> <0x01> <redeemScript>
        """
        try:
            elements = _parse_script_elements(scriptsig)
            if len(elements) < 6:
                return None
            branch = elements[4]
            if branch != b'\x01':
                return None
            S_lp2, S_lp1, S_user = elements[1], elements[2], elements[3]
            if len(S_user) != 32 or len(S_lp1) != 32 or len(S_lp2) != 32:
                return None
            return HTLC3SSecrets(
                S_user=S_user.hex(), S_lp1=S_lp1.hex(), S_lp2=S_lp2.hex()
            )
        except Exception:
            return None

    # ── SegWit Signing (reserved for future SegWit-capable forks) ─────────────

    def _sign_claim_segwit(
        self, raw_tx: str, utxo: Dict, redeem_script: str,
        secrets: HTLC3SSecrets, privkey_wif: str
    ) -> str:
        """Sign claim TX for SegWit P2WSH (same crypto as BTC)."""
        from bitcoin import SelectParams
        from bitcoin.core import CMutableTransaction, CScript, b2x
        from bitcoin.core.script import (
            SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
        )
        from bitcoin.wallet import CBitcoinSecret
        from bitcoin.core import CTxInWitness, CTxWitness, CScriptWitness

        # SelectParams for crypto only — sighash is chain-agnostic
        SelectParams('signet')

        tx = CMutableTransaction.deserialize(bytes.fromhex(raw_tx))
        privkey = CBitcoinSecret(privkey_wif)
        script_bytes = bytes.fromhex(redeem_script)
        witness_script = CScript(script_bytes)

        sighash = SignatureHash(
            script=witness_script, txTo=tx, inIdx=0,
            hashtype=SIGHASH_ALL, amount=utxo["amount"],
            sigversion=SIGVERSION_WITNESS_V0
        )
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])

        # Build witness: [sig, S_lp2, S_lp1, S_user, 0x01, witnessScript]
        S_user = bytes.fromhex(secrets.S_user)
        S_lp1 = bytes.fromhex(secrets.S_lp1)
        S_lp2 = bytes.fromhex(secrets.S_lp2)
        witness_stack = [sig, S_lp2, S_lp1, S_user, bytes([0x01]), script_bytes]

        tx.wit = CTxWitness([CTxInWitness(CScriptWitness(witness_stack))])
        return b2x(tx.serialize())

    def _sign_refund_segwit(
        self, raw_tx: str, utxo: Dict, redeem_script: str, privkey_wif: str
    ) -> str:
        """Sign refund TX for SegWit P2WSH."""
        from bitcoin import SelectParams
        from bitcoin.core import CMutableTransaction, CScript
        from bitcoin.core.script import (
            SignatureHash, SIGHASH_ALL, SIGVERSION_WITNESS_V0
        )
        from bitcoin.wallet import CBitcoinSecret

        SelectParams('signet')

        tx = CMutableTransaction.deserialize(bytes.fromhex(raw_tx))
        privkey = CBitcoinSecret(privkey_wif)
        script_bytes = bytes.fromhex(redeem_script)

        sighash = SignatureHash(
            script=CScript(script_bytes), txTo=tx, inIdx=0,
            hashtype=SIGHASH_ALL, amount=utxo["amount"],
            sigversion=SIGVERSION_WITNESS_V0
        )
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])

        # Refund witness: [sig, 0x00 (ELSE), witnessScript]
        witness_stack = [sig, b'', script_bytes]
        witness_data = _encode_compact_size(len(witness_stack))
        for item in witness_stack:
            witness_data += _encode_compact_size(len(item)) + item

        unsigned_bytes = bytes.fromhex(raw_tx)
        version = unsigned_bytes[:4]
        locktime = unsigned_bytes[-4:]
        middle = unsigned_bytes[4:-4]

        return (version + b'\x00\x01' + middle + witness_data + locktime).hex()

    # ── P2SH Signing (ZEC) ───────────────────────────────────────────────────

    def _sign_claim_legacy(
        self, raw_tx: str, utxo: Dict, redeem_script: str,
        secrets: HTLC3SSecrets, privkey_wif: str
    ) -> str:
        """Sign claim TX for P2SH (legacy sighash)."""
        from bitcoin import SelectParams
        from bitcoin.core import CMutableTransaction, CScript
        from bitcoin.core.script import SignatureHash, SIGHASH_ALL
        from bitcoin.wallet import CBitcoinSecret

        SelectParams('signet')

        script_bytes = bytes.fromhex(redeem_script)
        tx = CMutableTransaction.deserialize(bytes.fromhex(raw_tx))

        # Legacy sighash: substitute redeemScript in scriptSig for signing
        tx.vin[0].scriptSig = CScript(script_bytes)
        privkey = CBitcoinSecret(privkey_wif)
        sighash = SignatureHash(CScript(script_bytes), tx, 0, SIGHASH_ALL)
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])

        # Build scriptSig: <sig> <S_lp2> <S_lp1> <S_user> <0x01> <redeemScript>
        S_user = bytes.fromhex(secrets.S_user)
        S_lp1 = bytes.fromhex(secrets.S_lp1)
        S_lp2 = bytes.fromhex(secrets.S_lp2)

        scriptsig = (
            push_data(sig) + push_data(S_lp2) + push_data(S_lp1) +
            push_data(S_user) + bytes([0x51]) +  # OP_1 (OP_TRUE) for IF branch
            push_data(script_bytes)
        )
        tx.vin[0].scriptSig = CScript(scriptsig)
        from bitcoin.core import b2x
        return b2x(tx.serialize())

    def _sign_refund_legacy(
        self, raw_tx: str, utxo: Dict, redeem_script: str, privkey_wif: str
    ) -> str:
        """Sign refund TX for P2SH (legacy sighash)."""
        from bitcoin import SelectParams
        from bitcoin.core import CMutableTransaction, CScript, b2x
        from bitcoin.core.script import SignatureHash, SIGHASH_ALL
        from bitcoin.wallet import CBitcoinSecret

        SelectParams('signet')

        script_bytes = bytes.fromhex(redeem_script)
        tx = CMutableTransaction.deserialize(bytes.fromhex(raw_tx))
        tx.vin[0].scriptSig = CScript(script_bytes)
        privkey = CBitcoinSecret(privkey_wif)
        sighash = SignatureHash(CScript(script_bytes), tx, 0, SIGHASH_ALL)
        sig = privkey.sign(sighash) + bytes([SIGHASH_ALL])

        # Refund scriptSig: <sig> <0x00 (ELSE)> <redeemScript>
        scriptsig = push_data(sig) + bytes([OP_0]) + push_data(script_bytes)
        tx.vin[0].scriptSig = CScript(scriptsig)
        return b2x(tx.serialize())

    # ── CLI-Based Signing (ZEC — TX format incompatible with python-bitcoinlib) ─

    def _sign_claim_via_cli(
        self, raw_tx: str, utxo: Dict, redeem_script: str,
        secrets: HTLC3SSecrets, privkey_wif: str
    ) -> str:
        """Sign claim TX using chain CLI (for ZEC with ZIP 243/244 sighash).

        Strategy: use signrawtransaction to get a valid ECDSA signature,
        then build custom scriptSig with secrets and inject into unsigned TX.
        """
        script_bytes = bytes.fromhex(redeem_script)
        coin = self.config.get("coin_per_sat", 100_000_000)

        # Build P2SH scriptPubKey for prevtxs hint
        script_hash = _hash160(script_bytes)
        p2sh_spk = bytes([0xa9, 0x14]) + script_hash + bytes([0x87])

        prevtxs = [{
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": p2sh_spk.hex(),
            "redeemScript": redeem_script,
            "amount": f"{utxo['amount'] // coin}.{utxo['amount'] % coin:08d}",
        }]

        # signrawtransaction params: hex, prevtxs, privkeys (ZEC param order)
        result = self.client._call(
            "signrawtransaction", raw_tx,
            json.dumps(prevtxs),
            json.dumps([privkey_wif])
        )
        if isinstance(result, str):
            raise RuntimeError(f"CLI signing returned string: {result}")
        if not result.get("complete"):
            errors = result.get("errors", [])
            raise RuntimeError(f"CLI signing failed: {errors}")

        signed_hex = result["hex"]

        # Extract ECDSA signature from the CLI-signed TX
        sig = self._extract_sig_from_signed_tx(signed_hex, utxo["txid"], utxo["vout"])

        # Build custom scriptSig with all 3 secrets
        S_user = bytes.fromhex(secrets.S_user)
        S_lp1 = bytes.fromhex(secrets.S_lp1)
        S_lp2 = bytes.fromhex(secrets.S_lp2)

        custom_scriptsig = (
            push_data(sig) + push_data(S_lp2) + push_data(S_lp1) +
            push_data(S_user) + bytes([0x51]) +  # OP_1 (OP_TRUE) for IF branch
            push_data(script_bytes)
        )

        # Inject into unsigned TX (avoids parsing ZEC TX format)
        return _inject_scriptsig(raw_tx, utxo["txid"], utxo["vout"], custom_scriptsig)

    def _sign_refund_via_cli(
        self, raw_tx: str, utxo: Dict, redeem_script: str, privkey_wif: str
    ) -> str:
        """Sign refund TX using chain CLI (for ZEC with ZIP 243/244 sighash)."""
        script_bytes = bytes.fromhex(redeem_script)
        coin = self.config.get("coin_per_sat", 100_000_000)

        script_hash = _hash160(script_bytes)
        p2sh_spk = bytes([0xa9, 0x14]) + script_hash + bytes([0x87])

        prevtxs = [{
            "txid": utxo["txid"],
            "vout": utxo["vout"],
            "scriptPubKey": p2sh_spk.hex(),
            "redeemScript": redeem_script,
            "amount": f"{utxo['amount'] // coin}.{utxo['amount'] % coin:08d}",
        }]

        result = self.client._call(
            "signrawtransaction", raw_tx,
            json.dumps(prevtxs),
            json.dumps([privkey_wif])
        )
        if isinstance(result, str):
            raise RuntimeError(f"CLI signing returned string: {result}")
        if not result.get("complete"):
            errors = result.get("errors", [])
            raise RuntimeError(f"CLI signing failed: {errors}")

        signed_hex = result["hex"]
        sig = self._extract_sig_from_signed_tx(signed_hex, utxo["txid"], utxo["vout"])

        # Refund: ELSE branch (no secrets, OP_0)
        custom_scriptsig = (
            push_data(sig) + bytes([OP_0]) +  # ELSE branch
            push_data(script_bytes)
        )

        return _inject_scriptsig(raw_tx, utxo["txid"], utxo["vout"], custom_scriptsig)

    def _extract_sig_from_signed_tx(self, signed_hex: str, txid: str, vout: int) -> bytes:
        """Extract ECDSA signature from a CLI-signed TX via decoderawtransaction."""
        decoded = self.client._call("decoderawtransaction", signed_hex)
        for vin in decoded.get("vin", []):
            if vin.get("txid") == txid and vin.get("vout") == vout:
                scriptsig_hex = vin.get("scriptSig", {}).get("hex", "")
                if scriptsig_hex:
                    elements = _parse_script_elements(bytes.fromhex(scriptsig_hex))
                    if elements and len(elements[0]) >= 64:
                        return elements[0]
        raise RuntimeError(f"Could not extract signature from signed TX for {txid}:{vout}")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _verify_preimages_match_script(self, secrets: HTLC3SSecrets, script: bytes):
        """Verify preimages match hashlocks in script."""
        if len(script) < 105:
            raise ValueError("Script too short for 3S-HTLC")

        H_user_script = script[3:35]
        H_lp1_script = script[38:70]
        H_lp2_script = script[73:105]

        S_user = bytes.fromhex(secrets.S_user)
        S_lp1 = bytes.fromhex(secrets.S_lp1)
        S_lp2 = bytes.fromhex(secrets.S_lp2)

        if sha256(S_user) != H_user_script:
            raise ValueError("S_user does not match H_user in script")
        if sha256(S_lp1) != H_lp1_script:
            raise ValueError("S_lp1 does not match H_lp1 in script")
        if sha256(S_lp2) != H_lp2_script:
            raise ValueError("S_lp2 does not match H_lp2 in script")

        log.info(f"[{self.chain_name}] All 3 preimages verified against script")


# ── Utility Functions ─────────────────────────────────────────────────────────

def _hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))."""
    sha = hashlib.sha256(data).digest()
    ripemd = hashlib.new('ripemd160', sha).digest()
    return ripemd


def _base58check_encode(payload: bytes) -> str:
    """Base58Check encode (used for P2SH addresses)."""
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    # Convert to base58
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, remainder = divmod(n, 58)
        result.append(ALPHABET[remainder])
    # Add leading zeros
    for byte in data:
        if byte == 0:
            result.append(ALPHABET[0])
        else:
            break
    return ''.join(reversed(result))


def _parse_script_elements(script: bytes) -> list:
    """Parse script into push-data elements (for P2SH scriptSig extraction)."""
    elements = []
    i = 0
    while i < len(script):
        op = script[i]
        i += 1
        if op == 0:
            elements.append(b'')
        elif 1 <= op <= 75:
            elements.append(script[i:i + op])
            i += op
        elif op == 0x4c:  # OP_PUSHDATA1
            length = script[i]
            i += 1
            elements.append(script[i:i + length])
            i += length
        elif op == 0x4d:  # OP_PUSHDATA2
            length = struct.unpack('<H', script[i:i + 2])[0]
            i += 2
            elements.append(script[i:i + length])
            i += length
        elif 0x51 <= op <= 0x60:  # OP_1 through OP_16
            elements.append(bytes([op - 0x50]))
        else:
            elements.append(bytes([op]))
    return elements


def _read_compact_size(data: bytes, offset: int) -> tuple:
    """Read Bitcoin compact size varint from data at offset.

    Returns (value, num_bytes_consumed).
    """
    first = data[offset]
    if first < 0xfd:
        return first, 1
    elif first == 0xfd:
        return struct.unpack_from('<H', data, offset + 1)[0], 3
    elif first == 0xfe:
        return struct.unpack_from('<I', data, offset + 1)[0], 5
    else:
        return struct.unpack_from('<Q', data, offset + 1)[0], 9


def _inject_scriptsig(unsigned_hex: str, txid: str, vout: int, new_scriptsig: bytes) -> str:
    """Inject custom scriptSig into an unsigned raw TX.

    Works with any TX format (BTC, ZEC, DASH, PIVX) by locating the prevout
    (txid + vout) in the serialized TX and replacing the empty scriptSig.
    """
    tx = bytes.fromhex(unsigned_hex)

    # Build prevout bytes (txid is reversed for internal byte order)
    prevout_hash = bytes.fromhex(txid)[::-1]
    prevout_idx = struct.pack('<I', vout)
    prevout = prevout_hash + prevout_idx

    # Find prevout in TX
    pos = tx.find(prevout)
    if pos < 0:
        raise ValueError(f"Prevout {txid}:{vout} not found in TX")

    # After prevout (36 bytes), next is scriptSig compact size
    ss_offset = pos + 36
    existing_len, varint_size = _read_compact_size(tx, ss_offset)
    if existing_len != 0:
        raise ValueError(f"Expected empty scriptSig (len=0), got len={existing_len}")

    # Replace: prefix + new_compact_size + new_scriptsig + suffix
    prefix = tx[:ss_offset]
    suffix = tx[ss_offset + varint_size:]  # Skip the 0x00 varint byte

    new_len_bytes = _encode_compact_size(len(new_scriptsig))
    new_tx = prefix + new_len_bytes + new_scriptsig + suffix
    return new_tx.hex()
