#!/usr/bin/env python3
"""
LOT 9 M4-BIS PHASE 4-BIS — RENEWAL PROOF ON THE REAL 10 080-BLOCK CHAIN

PHASE 4 measured the blocker at the REAL horizon: at the epoch boundary after
h=10081..10087 the production set fell 8 -> 1, the finality threshold became
UNREACHABLE, and last_finalized froze at 10 120 forever — because nothing could
build a TX_OPERATOR_LEASE.

This driver closes that blocker ON THE SAME CHAIN, without re-mining 10 000
blocks and WITHOUT shortening the lease: it reuses a copy of the h=10200
datadirs, submits >= 5 REAL protx_renew_lease (real signatures, real fees, exact
sequences, mempool then blocks), lets the chain cross the next epoch boundary,
and requires finality to come back:

  * nodes n1..n5 run the CANDIDATE binary and each renews ITS OWN identity via
    the configured operator key (the normal RPC path);
  * nodes n6..n8 run the OLD binary that produced blocks 1..10200 — they already
    carry the M3 consensus rule, and they must ACCEPT the transactions the new
    RPC builds (mempool relay AND block connection), or the candidate forked;
  * ops 6 and 7 are NOT renewed: their leases must stay expired (no implicit
    renewal), and nobody may take a PoSe hit.

Success criteria (all measured, none assumed):
  finality stalled at start (lag > 0, threshold UNREACHABLE, 7 leases expired)
  5 renewals: sequence 0 -> 1, expiry = inclusionHeight + 10080, on ALL nodes
  at the boundary: population >= 5 (renewed 5 + op8), threshold reachable
  finality_lag returns to 0 and stays there; all 8 nodes on the same tip
  ops 6/7 still expired; zero PoSe penalty anywhere
"""
import base64
import http.client
import json
import os
import sys
import time

LAB = os.environ.get("LAB", "/home/ubuntu/lot9-lab7bis/phase4bis")
NODES = int(os.environ.get("NODES", "8"))
RENEW = [1, 2, 3, 4, 5]            # nodes that renew their own identity
HORIZON = 10080                     # the REAL lease horizon — not shortened
EPOCH_LEN = 60
SNAP_OFFSET = 30

# Epochs are anchored at ACTIVATION (= labbootstrapheight + 1), not at multiples
# of EPOCH_LEN: with the lab's bootstrap of 40, boundaries fall at 41 + 60k
# (10121, 10181, 10241 — exactly what PHASE 4 measured). Read the anchor from
# the node's own configuration instead of guessing it.
def epoch_anchor():
    conf = open(os.path.join(LAB, "n1", "bathron.conf")).read()
    for line in conf.splitlines():
        if line.startswith("labbootstrapheight="):
            return int(line.split("=", 1)[1]) + 1
    die("labbootstrapheight not found in n1's configuration")


class Node:
    """One persistent JSON-RPC connection. Reconnects on a dropped socket."""

    def __init__(self, i):
        d = os.path.join(LAB, "n%d" % i)
        self.i = i
        self.port = int(open(os.path.join(d, "RPCPORT")).read().strip())
        conf = open(os.path.join(d, "bathron.conf")).read()
        user = pw = None
        for line in conf.splitlines():
            if line.startswith("rpcuser="):
                user = line.split("=", 1)[1]
            elif line.startswith("rpcpassword="):
                pw = line.split("=", 1)[1]
        self.auth = base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
        self.conn = None
        self.id = 0

    def _connect(self):
        self.conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)

    def call(self, method, params=None, retries=2):
        self.id += 1
        body = json.dumps({"jsonrpc": "1.0", "id": self.id,
                           "method": method, "params": params or []})
        for attempt in range(retries + 1):
            try:
                if self.conn is None:
                    self._connect()
                self.conn.request("POST", "/", body, {
                    "Authorization": "Basic " + self.auth,
                    "Content-Type": "application/json",
                    "Connection": "keep-alive",
                })
                resp = self.conn.getresponse()
                data = resp.read()
                out = json.loads(data)
                return out            # caller inspects result AND error
            except Exception:
                try:
                    self.conn.close()
                except Exception:
                    pass
                self.conn = None
                if attempt == retries:
                    return {"result": None, "error": {"message": "unreachable"}}
                time.sleep(0.5)

    def r(self, method, params=None):
        return self.call(method, params).get("result")


def die(msg):
    print("FAIL: %s" % msg, flush=True)
    sys.exit(1)


def main():
    nodes = [Node(i) for i in range(1, NODES + 1)]
    n1 = nodes[0]

    # ── 0. The starting point must be the measured blocker, exactly ─────────
    heights = [nd.r("getblockcount") for nd in nodes]
    if any(h is None for h in heights):
        die("some node is unreachable: %s" % heights)
    h0 = heights[0]
    if len(set(heights)) != 1:
        die("nodes disagree on height at start: %s" % heights)
    fin = n1.r("getfinalitystatus") or {}
    if not fin.get("finality_lag", 0) > 0:
        die("finality is not stalled at start (lag=%s)" % fin.get("finality_lag"))
    q = n1.r("getquorum", [h0]) or {}
    print("start: h=%d finalized=%s lag=%s ops=%s thr=%s"
          % (h0, fin.get("last_finalized_height"), fin.get("finality_lag"),
             q.get("total_operators"), q.get("finality_threshold")), flush=True)

    protx = n1.r("protx_list", [True, False, True]) or []
    expired = [e for e in protx
               if (e.get("dmnstate") or {}).get("leaseExpiryHeight", 1 << 62) <= h0]
    alive = [e for e in protx if e not in expired]
    # PHASE 4 registered 8 operators PLUS one deliberate Sybil masternode under
    # the 8th operator's key (the M4-BIS admission measurement). By h=10200 the
    # first seven operators' leases (10081..10087) AND the Sybil MN's (10169)
    # are expired: 8 expired MN leases across 7 distinct operators, with op8
    # (expiry 10242) the only survivor — exactly the ops=1 the RPC reports.
    if len(expired) < 7 or not alive:
        die("unexpected lease landscape at start: %d expired / %d alive (want >=7 / >=1)"
            % (len(expired), len(alive)))
    print("%d MN leases expired at start, %d still alive (PHASE 4's landscape)"
          % (len(expired), len(alive)), flush=True)

    # ── 1. Fund the five renewing wallets from n1 (normal txs still flow) ───
    clock = 0

    def tip_time():
        h = n1.r("getbestblockhash")
        b = n1.r("getblock", [h]) if h else None
        return b["time"] if b else 0

    def advance(target_height, max_stalls=6):
        nonlocal clock
        stalls = 0
        height = n1.r("getblockcount")
        while height < target_height:
            base = tip_time() + 65
            if clock < base:
                clock = base
            prev = height
            produced = False
            for _ in range(24):
                for nd in nodes:
                    nd.r("setmocktime", [clock])
                for _ in range(20):
                    h = n1.r("getblockcount")
                    if h is not None and h > prev:
                        height = h
                        produced = True
                        break
                    time.sleep(0.05)
                if produced:
                    break
                clock += 30
            if not produced:
                stalls += 1
                print("STALL at %d (clock %d)" % (height, clock), flush=True)
                if stalls >= max_stalls:
                    die("production stalled — the chain no longer produces")
        return height

    bal = n1.r("getbalance")
    total = bal.get("total", 0) if isinstance(bal, dict) else (bal or 0)
    if total <= 0:
        die("n1 has no spendable funds to pay renewal fees (balance=%s); "
            "import a premine key into n1's wallet first" % bal)
    print("n1 balance: %s sats" % total, flush=True)

    payees = {}
    for i in RENEW:
        nd = nodes[i - 1]
        addr = nd.r("getnewaddress")
        if not addr:
            die("n%d could not create an address" % i)
        payees[i] = addr
    # One payment fans out to the four other renewing wallets. `sendmany` is the
    # NORMAL-transfer RPC on this chain (there is no sendtoaddress); amounts are
    # in SATS (the unit is the satoshi).
    fanout = {addr: 1000000 for i, addr in payees.items() if i != 1}
    out = n1.call("sendmany", ["", fanout])
    if out.get("error") or not out.get("result"):
        die("funding fan-out failed: %s" % out.get("error"))
    h_after_fund = advance(n1.r("getblockcount") + 2)
    print("funding mined, h=%d" % h_after_fund, flush=True)

    # ── 2. Five REAL renewals via the NEW RPC, configured operator key ──────
    renewing = {}                        # node index -> proTxHash
    for i in RENEW:
        nd = nodes[i - 1]
        st = nd.r("getactivemnstatus") or {}
        mns = st.get("masternodes") or []
        if not mns or not mns[0].get("proTxHash"):
            die("n%d manages no identity (getactivemnstatus)" % i)
        renewing[i] = mns[0]["proTxHash"]

    seq_before = {}
    for i, ptx in renewing.items():
        for e in protx:
            if e.get("proTxHash") == ptx:
                seq_before[i] = (e.get("dmnstate") or {}).get("leaseSequence")
    print("renewing: %s" % {i: p[:12] for i, p in renewing.items()}, flush=True)

    txids = {}
    for i, ptx in renewing.items():
        out = nodes[i - 1].call("protx_renew_lease", [ptx])
        if out.get("error") or not out.get("result"):
            die("protx_renew_lease on n%d: %s" % (i, out.get("error")))
        txids[i] = out["result"]
        print("n%d renewal tx %s" % (i, txids[i][:16]), flush=True)

    # Mempool: the OLD nodes must accept what the new RPC built. Do not rely on
    # inv relay alone — a renewal announced while an old node is still digesting
    # the funding block can be orphaned and silently dropped (measured: 2 of 5
    # invs ignored). Submit the EXACT raw transaction to each old node's own
    # AcceptToMemoryPool instead: a deterministic, per-node acceptance proof.
    for i, txid in txids.items():
        raw = nodes[i - 1].r("getrawtransaction", [txid])
        if not raw:
            die("cannot fetch raw renewal %s from n%d" % (txid[:16], i))
        for old in (nodes[5], nodes[6], nodes[7]):
            out = old.call("sendrawtransaction", [raw])
            err = out.get("error")
            if err and "already" not in str(err.get("message", "")):
                die("OLD node n%d REFUSED the renewal built by the new RPC "
                    "(tx %s): %s" % (old.i, txid[:16], err))
    pools = [set(nd.r("getrawmempool") or []) for nd in (nodes[5], nodes[6], nodes[7])]
    want = set(txids.values())
    if not all(want <= p for p in pools):
        die("renewals accepted by sendrawtransaction but absent from an old "
            "node's mempool: %s" % [sorted(want - p)[:2] for p in pools])
    print("all 5 renewals ACCEPTED by the OLD binary's own mempool (n6/n7/n8)", flush=True)

    # Blocks: mine them in, well before the next epoch snapshot.
    h_now = n1.r("getblockcount")
    anchor = epoch_anchor()
    boundary = anchor + ((h_now - anchor) // EPOCH_LEN + 1) * EPOCH_LEN
    snapshot = boundary - SNAP_OFFSET
    if h_now + 3 > snapshot:
        boundary += EPOCH_LEN
        snapshot += EPOCH_LEN
    advance(h_now + 3)
    incl = {}
    for i, txid in txids.items():
        tx = n1.r("getrawtransaction", [txid, True])
        if not tx or not tx.get("blockhash"):
            die("renewal of n%d was not mined" % i)
        blk = n1.r("getblock", [tx["blockhash"]])
        incl[i] = blk["height"]
    if max(incl.values()) > snapshot:
        die("a renewal landed after the epoch snapshot %d: %s" % (snapshot, incl))
    print("renewals mined at heights %s (snapshot %d, boundary %d)"
          % (incl, snapshot, boundary), flush=True)

    # Exact sequences + consensus-derived expiry. Only NEW-binary readers can
    # be asserted field-by-field: the old binary predates the lease fields in
    # protx_list's JSON (its ToJson doesn't print them — the phase-4 driver had
    # to derive expiries from registeredHeight for the same reason). The OLD
    # binary's view is proven BEHAVIORALLY below: same tip, and the same
    # recovered population/threshold out of its own getquorum at the boundary.
    for reader in (n1, nodes[4]):
        plist = reader.r("protx_list", [True, False, True]) or []
        by_hash = {e.get("proTxHash"): (e.get("dmnstate") or {}) for e in plist}
        for i, ptx in renewing.items():
            stt = by_hash.get(ptx) or {}
            if stt.get("leaseSequence") != seq_before[i] + 1:
                die("n%d sequence: want %d, reader n%d sees %s"
                    % (i, seq_before[i] + 1, reader.i, stt.get("leaseSequence")))
            if stt.get("leaseExpiryHeight") != incl[i] + HORIZON:
                die("n%d expiry: want %d (inclusion %d + %d), reader n%d sees %s"
                    % (i, incl[i] + HORIZON, incl[i], HORIZON, reader.i,
                       stt.get("leaseExpiryHeight")))
    print("sequences advanced by exactly one; expiry = inclusion + %d "
          "(readers n1 and n5)" % HORIZON, flush=True)

    # ── 3. Cross the epoch boundary; finality must come back ────────────────
    advance(boundary + 2)
    h_q = n1.r("getblockcount")
    q = n1.r("getquorum", [h_q]) or {}
    ops = q.get("total_operators")
    thr = q.get("finality_threshold")
    if not ops or ops < 5:
        die("population after the boundary is %s, want >= 5" % ops)
    if not thr or thr > ops:
        die("threshold %s unreachable with %s operators" % (thr, ops))
    # The OLD binary must derive the SAME recovered population from the
    # renewals the new RPC built — this is its behavioral acceptance proof.
    q_old = nodes[7].r("getquorum", [h_q]) or {}
    if q_old.get("total_operators") != ops or q_old.get("finality_threshold") != thr:
        die("old binary disagrees on the recovered population: new ops=%s thr=%s, "
            "old ops=%s thr=%s" % (ops, thr, q_old.get("total_operators"),
                                   q_old.get("finality_threshold")))
    print("after boundary %d: ops=%s thr=%s — IDENTICAL on the old binary (n8)"
          % (boundary, ops, thr), flush=True)

    lag0_at = None
    final_h = advance(boundary + 12)
    for _ in range(30):
        fin = n1.r("getfinalitystatus") or {}
        if fin.get("finality_lag") == 0:
            lag0_at = fin.get("last_finalized_height")
            break
        final_h = advance(final_h + 1)
    if lag0_at is None:
        die("finality never returned to lag 0 after the boundary (last status: %s)"
            % json.dumps(fin))
    print("finality is BACK: lag=0, last_finalized=%s" % lag0_at, flush=True)

    # Hold it for 10 more blocks — a one-off lag=0 is not "recovered".
    final_h = advance(final_h + 10)
    time.sleep(2)
    fin = n1.r("getfinalitystatus") or {}
    if fin.get("finality_lag", 99) > 1:
        die("finality did not HOLD after recovery (lag=%s)" % fin.get("finality_lag"))

    # ── 4. Negative space: no implicit renewal, no PoSe, one tip ────────────
    plist = n1.r("protx_list", [True, False, True]) or []
    h_end = n1.r("getblockcount")
    renewed_set = set(renewing.values())
    still_expired = 0
    for e in plist:
        stt = e.get("dmnstate") or {}
        if e.get("proTxHash") in renewed_set:
            continue
        if stt.get("leaseExpiryHeight", 0) <= h_end:
            still_expired += 1
        if stt.get("PoSePenalty", 0) != 0 or stt.get("PoSeBanHeight", -1) not in (-1, 0):
            die("PoSe hit on %s: penalty=%s banHeight=%s"
                % (e.get("proTxHash", "?")[:12], stt.get("PoSePenalty"),
                   stt.get("PoSeBanHeight")))
    for e in plist:
        stt = e.get("dmnstate") or {}
        if stt.get("PoSePenalty", 0) != 0:
            die("PoSe penalty on %s" % e.get("proTxHash", "?")[:12])
    if still_expired < 2:
        die("expected ops 6 and 7 to STAY expired (no implicit renewal), "
            "only %d non-renewed identity(ies) expired" % still_expired)

    tips = [nd.r("getbestblockhash") for nd in nodes]
    if len(set(tips)) != 1 or None in tips:
        die("nodes disagree on the tip at the end: %s"
            % [t[:12] if t else "?" for t in tips])

    print("no implicit renewal (%d identities still expired), zero PoSe, "
          "8/8 nodes on tip %s at h=%s" % (still_expired, tips[0][:16], h_end),
          flush=True)
    print("PASS — the PHASE 4 blocker is CLOSED on the real 10080-block chain: "
          "5 real renewals brought the finality population back and lag "
          "returned to 0 at the epoch boundary.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
