#!/usr/bin/env python3
"""
pqc_handshake_core_fleet.py -- multi-vessel concurrent version of
pqc_handshake_core.py. Accepts N simultaneous UE connections (one per vessel
VM), runs each one's nonce/signature exchange in its own thread so all N are
genuinely concurrent (not round-robined), and logs:
  - per-vessel round_trip_ms / verify_ms / sig_bytes / verify_ok, same as before
  - a "contention" marker: how many OTHER verify() calls were in-flight at the
    same moment, so we can see whether concurrent load measurably slows verify.

Protocol per connection is IDENTICAL to the single-vessel version (PKREQ/PKRSP/
NONCE/SIG__), so pqc_handshake_ue.py on each vessel VM needs NO changes -- just
point all 5 at the same core IP:port and they'll each get their own connection
and thread.

Usage (on VM-02):
  python3 pqc_handshake_core_fleet.py --listen 192.168.0.17 --port 6000 \
      --alg Falcon-512 --reps 30 --n-vessels 5 --out-prefix fleet_falcon512
Produces: fleet_falcon512_vessel0.csv ... fleet_falcon512_vessel4.csv
          fleet_falcon512_summary.csv  (one row per vessel: means/stdev)
"""
import argparse, socket, struct, time, csv, sys, os, threading

import oqs

MAGIC_PUBKEY_REQ = b"PKREQ"
MAGIC_PUBKEY_RESP = b"PKRSP"
MAGIC_NONCE = b"NONCE"
MAGIC_SIG = b"SIG__"

# shared, thread-safe counter of in-flight verify() calls, for the contention marker
_inflight_lock = threading.Lock()
_inflight_count = 0

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed mid-message")
        buf += chunk
    return buf

def handle_vessel(conn, addr, vessel_idx, alg, reps, results, barrier):
    global _inflight_count
    verifier = oqs.Signature(alg)

    conn.sendall(MAGIC_PUBKEY_REQ)
    tag = recv_exact(conn, 5)
    assert tag == MAGIC_PUBKEY_RESP, f"vessel {vessel_idx}: unexpected tag {tag!r}"
    (pk_len,) = struct.unpack("!I", recv_exact(conn, 4))
    public_key = recv_exact(conn, pk_len)
    print(f"[core] vessel {vessel_idx} ({addr}) pubkey {pk_len} bytes", file=sys.stderr)

    # all vessels wait here until every connection has exchanged its pubkey,
    # so the timed reps below start genuinely together, not staggered by
    # however long each TCP connect+keygen happened to take.
    barrier.wait()

    rows = []
    for i in range(reps):
        nonce = os.urandom(32)
        t0 = time.monotonic()
        conn.sendall(MAGIC_NONCE + struct.pack("!I", len(nonce)) + nonce)

        tag = recv_exact(conn, 5)
        assert tag == MAGIC_SIG, f"vessel {vessel_idx}: unexpected tag {tag!r} on rep {i}"
        (sig_len,) = struct.unpack("!I", recv_exact(conn, 4))
        signature = recv_exact(conn, sig_len)
        t_recv = time.monotonic()

        with _inflight_lock:
            _inflight_count += 1
            concurrent_at_start = _inflight_count
        t_v0 = time.monotonic()
        ok = verifier.verify(nonce, signature, public_key)
        t_v1 = time.monotonic()
        with _inflight_lock:
            _inflight_count -= 1

        round_ms = (t_recv - t0) * 1000.0
        verify_ms = (t_v1 - t_v0) * 1000.0
        rows.append({
            "vessel": vessel_idx, "rep": i, "alg": alg, "sig_bytes": sig_len,
            "round_trip_ms": round_ms, "verify_ms": verify_ms, "verify_ok": ok,
            "concurrent_verifies": concurrent_at_start,
        })
        if not ok:
            print(f"[core] vessel {vessel_idx} *** VERIFY FAILED on rep {i} ***", file=sys.stderr)

    results[vessel_idx] = rows
    conn.close()
    print(f"[core] vessel {vessel_idx}: done, {len(rows)} reps", file=sys.stderr)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True)
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--alg", required=True, choices=["Falcon-512", "ML-DSA-44", "SLH_DSA_PURE_SHA2_128S"])
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--n-vessels", type=int, default=5)
    ap.add_argument("--out-prefix", required=True)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.listen, a.port))
    srv.listen(a.n_vessels)
    print(f"[core] alg={a.alg} listening on {a.listen}:{a.port} for {a.n_vessels} vessels ...", file=sys.stderr)

    results = {}
    barrier = threading.Barrier(a.n_vessels)
    threads = []
    for idx in range(a.n_vessels):
        conn, addr = srv.accept()
        t = threading.Thread(target=handle_vessel,
                              args=(conn, addr, idx, a.alg, a.reps, results, barrier))
        t.start()
        threads.append(t)
        print(f"[core] accepted vessel {idx} from {addr} ({idx+1}/{a.n_vessels})", file=sys.stderr)

    for t in threads:
        t.join()

    # per-vessel CSVs
    for idx in range(a.n_vessels):
        rows = results.get(idx, [])
        if not rows:
            continue
        path = f"{a.out_prefix}_vessel{idx}.csv"
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"[core] wrote {len(rows)} rows to {path}", file=sys.stderr)

    # summary CSV: one row per vessel
    summary_path = f"{a.out_prefix}_summary.csv"
    with open(summary_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["vessel", "alg", "n_reps", "mean_round_trip_ms", "mean_verify_ms",
                    "max_concurrent_verifies", "all_verify_ok"])
        for idx in range(a.n_vessels):
            rows = results.get(idx, [])
            if not rows:
                w.writerow([idx, a.alg, 0, "", "", "", ""])
                continue
            mean_rt = sum(r["round_trip_ms"] for r in rows) / len(rows)
            mean_v = sum(r["verify_ms"] for r in rows) / len(rows)
            max_c = max(r["concurrent_verifies"] for r in rows)
            all_ok = all(r["verify_ok"] for r in rows)
            w.writerow([idx, a.alg, len(rows), f"{mean_rt:.2f}", f"{mean_v:.3f}", max_c, all_ok])
    print(f"[core] wrote summary to {summary_path}", file=sys.stderr)
    srv.close()

if __name__ == "__main__":
    main()