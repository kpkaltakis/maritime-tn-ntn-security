#!/usr/bin/env python3
"""
downgrade_core.py -- honest core for the Pillar B downgrade-attack demo.
Supports N concurrent vessel sessions (threaded, like pqc_handshake_core_fleet.py).

For each connection it receives an OFFER (a list of primitive names) and
selects the FIRST one in that list that it also supports -- i.e. it honestly
respects the offerer's stated preference order. It has NO way to know whether
the list it received is the real UE's full honest list, or a relay's edited
version of it.

This is the crux of the attack's realism: the core does nothing wrong. It
correctly implements "pick the strongest mutually-supported option from
what I was shown." A downgrade succeeds purely by lying about what was
shown, not by exploiting any flaw in the core's selection logic.

Usage (single vessel, unchanged from before):
  python3 downgrade_core.py --listen 192.168.0.17 --port 6100 --reps 20 \
      --n-vessels 1 --out-prefix core_baseline
Usage (N concurrent vessels):
  python3 downgrade_core.py --listen 192.168.0.17 --port 6100 --reps 20 \
      --n-vessels 5 --out-prefix core_fleet_attack
Produces: {out-prefix}_session0.csv ... {out-prefix}_session{N-1}.csv
"""
import argparse, socket, struct, time, csv, sys, json, os, threading
from pqc_signers import verify_with, ALL_PRIMITIVES

MAGIC_OFFER = b"OFFER"
MAGIC_SELECT = b"SELCT"
MAGIC_PUBKEY = b"PKRSP"
MAGIC_NONCE = b"NONCE"
MAGIC_SIG = b"SIG__"

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("socket closed mid-message")
        buf += chunk
    return buf

def send_msg(sock, magic, payload=b""):
    sock.sendall(magic + struct.pack("!I", len(payload)) + payload)

def recv_msg(sock, expect_magic):
    tag = recv_exact(sock, 5)
    assert tag == expect_magic, f"expected {expect_magic!r}, got {tag!r}"
    (n,) = struct.unpack("!I", recv_exact(sock, 4))
    return recv_exact(sock, n) if n else b""

def handle_session(conn, addr, idx, reps, results, barrier):
    offer_raw = recv_msg(conn, MAGIC_OFFER)
    offered = json.loads(offer_raw.decode())
    print(f"[core] session {idx} ({addr}) received offer: {offered}", file=sys.stderr)

    selected = next((alg for alg in offered if alg in ALL_PRIMITIVES), None)
    if selected is None:
        print(f"[core] session {idx}: *** no mutually supported primitive, aborting ***",
              file=sys.stderr)
        conn.close()
        return
    print(f"[core] session {idx}: selecting {selected!r}", file=sys.stderr)
    send_msg(conn, MAGIC_SELECT, selected.encode())

    public_key = recv_msg(conn, MAGIC_PUBKEY)
    print(f"[core] session {idx}: UE public key, {len(public_key)} bytes", file=sys.stderr)

    barrier.wait()  # start timed reps together across all sessions

    rows = []
    for i in range(reps):
        nonce = os.urandom(32)
        send_msg(conn, MAGIC_NONCE, nonce)
        signature = recv_msg(conn, MAGIC_SIG)

        t0 = time.monotonic()
        ok = verify_with(selected, nonce, signature, public_key)
        t1 = time.monotonic()
        rows.append({
            "session": idx, "rep": i, "selected_alg": selected, "sig_bytes": len(signature),
            "verify_ms": (t1 - t0) * 1000.0, "verify_ok": ok,
        })
        if not ok:
            print(f"[core] session {idx}: *** VERIFY FAILED on rep {i} ***", file=sys.stderr)

    results[idx] = rows
    conn.close()
    print(f"[core] session {idx}: done, {len(rows)} reps, alg={selected}", file=sys.stderr)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True)
    ap.add_argument("--port", type=int, default=6100)
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--n-vessels", type=int, default=1)
    ap.add_argument("--out-prefix", required=True)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.listen, a.port))
    srv.listen(a.n_vessels)
    print(f"[core] listening on {a.listen}:{a.port} for {a.n_vessels} session(s) ...",
          file=sys.stderr)

    results = {}
    barrier = threading.Barrier(a.n_vessels)
    threads = []
    for idx in range(a.n_vessels):
        conn, addr = srv.accept()
        print(f"[core] accepted session {idx} from {addr} ({idx+1}/{a.n_vessels})",
              file=sys.stderr)
        t = threading.Thread(target=handle_session, args=(conn, addr, idx, a.reps, results, barrier))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    for idx in range(a.n_vessels):
        rows = results.get(idx, [])
        if not rows:
            continue
        path = f"{a.out_prefix}_session{idx}.csv"
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"[core] wrote {len(rows)} rows to {path}", file=sys.stderr)
    srv.close()

if __name__ == "__main__":
    main()