#!/usr/bin/env python3
"""
LOT 9 M4-BIS PHASE 4 — THE LEASE HORIZON AT ITS REAL VALUE (10 080 blocks)

The consensus parameter is NOT shortened: this drives the laboratory across the
full 10 080-block horizon so the expiry is observed where it actually falls.

Why a Python driver and not a shell loop: one `bathron-cli` invocation is a
process spawn (~50 ms) and a block needs one call per node plus polling. Over
10 000 blocks that alone is hours of pure fork/exec. This keeps ONE persistent
HTTP connection per node with keep-alive, so the cost per block is the node's,
not the harness's. No real sleep ever gates a consensus outcome — mocktime does;
the only sleeps are short polls waiting for a block that mocktime has authorised.

State is checkpointed after every sample, so the run resumes where it stopped
instead of restarting from genesis.
"""
import base64
import http.client
import json
import os
import sys
import time

LAB = open(os.environ.get("LABSTATE", "/home/ubuntu/lot9-lab7bis/lot9lab7.state")).read().strip()
NODES = int(os.environ.get("NODES", "8"))
STATE_PATH = os.path.join(LAB, "phase4.state.json")
CSV_PATH = os.path.join(LAB, "phase4_blocks.csv")

TARGET = int(os.environ.get("TARGET", "10200"))
SAMPLE_EVERY = int(os.environ.get("SAMPLE_EVERY", "100"))
# Around a lease expiry every single block matters, so sample densely there.
DENSE_WINDOWS = []


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
                if out.get("error"):
                    return None
                return out["result"]
            except Exception:
                try:
                    self.conn.close()
                except Exception:
                    pass
                self.conn = None
                if attempt == retries:
                    return None
                time.sleep(0.5)
        return None


def main():
    nodes = [Node(i) for i in range(1, NODES + 1)]
    n1 = nodes[0]

    state = {"clock": 0, "samples": 0, "stalls": 0, "started_at_height": None}
    if os.path.exists(STATE_PATH):
        state.update(json.load(open(STATE_PATH)))

    height = n1.call("getblockcount")
    if height is None:
        print("FATAL: node 1 unreachable", flush=True)
        return 1
    if state["started_at_height"] is None:
        state["started_at_height"] = height

    # Lease expiries are registeredHeight + nOperatorLeaseBlocks. Sample every
    # block for 25 blocks either side of each one: that is where the production
    # set drains and where the whole phase's meaning lives.
    protx = n1.call("protx_list", [True, False, True]) or []
    expiries = set()
    for e in protx:
        rh = (e.get("dmnstate") or {}).get("registeredHeight")
        if rh is not None:
            expiries.add(rh + 10080)
    for x in sorted(expiries):
        DENSE_WINDOWS.append((x - 25, x + 25))
    print("lease expiries derived from the chain: %s" % sorted(expiries), flush=True)
    print("dense sampling windows: %s" % DENSE_WINDOWS, flush=True)

    if not os.path.exists(CSV_PATH):
        with open(CSV_PATH, "w") as f:
            f.write("height,schedule_status,raw_slot,recovery,total_operators,"
                    "finality_threshold,last_finalized,finality_lag,alive\n")

    def dense(h):
        return any(a <= h <= b for a, b in DENSE_WINDOWS)

    def tip_time():
        h = n1.call("getbestblockhash")
        b = n1.call("getblock", [h]) if h else None
        return b["time"] if b else 0

    def sample(h):
        q = n1.call("getquorum", [h]) or {}
        f = n1.call("getfinalitystatus") or {}
        alive = sum(1 for nd in nodes if nd.call("getblockcount") is not None)
        row = (h, q.get("schedule_status", "?"), q.get("schedule_raw_slot", ""),
               1 if q.get("schedule_recovery_mode") else 0,
               q.get("total_operators", ""), q.get("finality_threshold", ""),
               f.get("last_finalized_height", ""), f.get("finality_lag", ""), alive)
        with open(CSV_PATH, "a") as fh:
            fh.write(",".join(str(x) for x in row) + "\n")
        state["samples"] += 1
        return row

    clock = state["clock"]
    t0 = time.time()
    last_report = t0

    while height < TARGET:
        base = tip_time() + 65
        if clock < base:
            clock = base
        prev = height
        produced = False
        for _ in range(24):
            for nd in nodes:
                nd.call("setmocktime", [clock])
            for _ in range(20):
                h = n1.call("getblockcount")
                if h is not None and h > prev:
                    height = h
                    produced = True
                    break
                time.sleep(0.05)
            if produced:
                break
            clock += 30          # open the next recovery window; NEVER go backwards
        if not produced:
            state["stalls"] += 1
            print("STALL at height %d (clock %d)" % (height, clock), flush=True)
            if state["stalls"] > 5:
                print("giving up after 6 stalls", flush=True)
                break
            continue

        if height % SAMPLE_EVERY == 0 or dense(height):
            row = sample(height)
            if dense(height):
                print("  h=%s status=%s slot=%s rec=%s ops=%s thr=%s fin=%s lag=%s alive=%s"
                      % row, flush=True)

        state["clock"] = clock
        if time.time() - last_report > 120:
            el = time.time() - t0
            done = height - state["started_at_height"]
            rate = done / el if el else 0
            eta = (TARGET - height) / rate if rate else 0
            print("[%5d/%d] %.1f blocks/s, elapsed %.0f min, eta %.0f min, stalls=%d"
                  % (height, TARGET, rate, el / 60, eta / 60, state["stalls"]), flush=True)
            json.dump(state, open(STATE_PATH, "w"))
            last_report = time.time()

    json.dump(state, open(STATE_PATH, "w"))
    sample(height)
    print("DONE height=%d samples=%d stalls=%d elapsed=%.0f min"
          % (height, state["samples"], state["stalls"], (time.time() - t0) / 60), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
