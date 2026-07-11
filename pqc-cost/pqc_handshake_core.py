#!/usr/bin/env python3
"""
pqc_handshake_core.py -- run on VM-02 (ntn-5gc), the CORE side of the wrapper
handshake described in the Phase 1 Step 6 methodology: this does NOT modify
Open5GS's real NAS/NGAP encoding. It is a separate, additional exchange that
runs immediately around a real UE attach, over the same real NTN network path
(192.168.0.17 <-> 192.168.0.20), to measure the added cost of a PQC signature
challenge/response at the moment of re-attach.

Protocol (one round per primitive, repeated --reps times):
  1. core generates a fresh random nonce (32 bytes) -- t0
  2. core sends nonce to UE over UDP                  -- t0_sent
  3. UE signs nonce, sends signature back              (see pqc_handshake_ue.py)
  4. core receives signature                           -- t3_recv
  5. core verifies signature against UE's public key   -- t3_verified
  6. core logs: network_rtt_estimate, verify_ms, total_round_ms, sig_bytes

The UE's public key must be exchanged once before timing starts (real protocol
would do this at credential-issuance time via PKI-CA -- here we just fetch it
over the same socket with a one-time PUBKEY message, not counted in the timed
rounds).

Usage:
  python3 pqc_handshake_core.py --listen 192.168.0.17 --port 6000 \
      --alg Falcon-512 --reps 30 --out core_falcon512.csv
  Run once per primitive (Falcon-512, ML-DSA-44, SLH_DSA_PURE_SHA2_128S).
"""
import argparse, socket, struct, time, csv, sys, os
import oqs

MAGIC_PUBKEY_REQ = b"PKREQ"
MAGIC_PUBKEY_RESP = b"PKRSP"
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="this VM's NTN-side IP, e.g. 192.168.0.17")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--alg", required=True, choices=["Falcon-512", "ML-DSA-44", "SLH_DSA_PURE_SHA2_128S"])
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    # TCP, not UDP: we need reliable delivery to get a clean round-trip timing
    # without re-implementing retransmission. The 866ms RTT dominates either way.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.listen, a.port))
    srv.listen(1)
    print(f"[core] alg={a.alg} listening on {a.listen}:{a.port} ...", file=sys.stderr)
    conn, addr = srv.accept()
    print(f"[core] UE connected from {addr}", file=sys.stderr)

    # one-time pubkey exchange (not timed)
    conn.sendall(MAGIC_PUBKEY_REQ)
    tag = recv_exact(conn, 5)
    assert tag == MAGIC_PUBKEY_RESP, f"unexpected tag {tag!r}"
    (pk_len,) = struct.unpack("!I", recv_exact(conn, 4))
    public_key = recv_exact(conn, pk_len)
    print(f"[core] received UE public key, {pk_len} bytes", file=sys.stderr)

    verifier = oqs.Signature(a.alg)

    rows = []
    for i in range(a.reps):
        nonce = os.urandom(32)
        t0 = time.monotonic()
        conn.sendall(MAGIC_NONCE + struct.pack("!I", len(nonce)) + nonce)

        tag = recv_exact(conn, 5)
        assert tag == MAGIC_SIG, f"unexpected tag {tag!r} on rep {i}"
        (sig_len,) = struct.unpack("!I", recv_exact(conn, 4))
        signature = recv_exact(conn, sig_len)
        t_recv = time.monotonic()

        t_v0 = time.monotonic()
        ok = verifier.verify(nonce, signature, public_key)
        t_v1 = time.monotonic()

        round_ms = (t_recv - t0) * 1000.0          # includes UE sign time + 2x network
        verify_ms = (t_v1 - t_v0) * 1000.0
        rows.append({
            "rep": i, "alg": a.alg, "sig_bytes": sig_len,
            "round_trip_ms": round_ms, "verify_ms": verify_ms,
            "verify_ok": ok,
        })
        print(f"[core] rep {i:2d}: round_trip={round_ms:8.2f}ms  "
              f"verify={verify_ms:6.3f}ms  sig_bytes={sig_len}  ok={ok}", file=sys.stderr)
        if not ok:
            print(f"[core] *** VERIFY FAILED on rep {i} ***", file=sys.stderr)

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[core] wrote {len(rows)} rows to {a.out}", file=sys.stderr)
    conn.close()
    srv.close()

if __name__ == "__main__":
    main()