#!/usr/bin/env python3
"""
downgrade_ue.py -- honest UE for the Pillar B downgrade-attack demonstration.
Connects to --core (which may be the REAL core VM-02, or VM-10's relay --
the UE has no way to tell the difference, which is the whole point).

Protocol:
  1. UE sends OFFER + its full primitive preference list (strongest first).
  2. Peer (real core, or a relay impersonating one) replies SELECT + chosen alg.
  3. Normal nonce/signature handshake loop runs using the selected primitive.

This file is NOT attack-aware. It always offers the full honest list from
pqc_signers.ALL_PRIMITIVES. Any narrowing of that list happens only if a
relay tampers with the OFFER message in transit -- never here.

Usage:
  python3 downgrade_ue.py --core 192.168.0.17 --port 6100 --reps 20 --out ue_downgrade.csv
  (point --core at VM-10's relay IP instead, to run the SAME command under attack)
"""
import argparse, socket, struct, time, csv, sys, json
from pqc_signers import make_signer, ALL_PRIMITIVES

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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core", required=True, help="IP to connect to -- real core OR an attacker relay")
    ap.add_argument("--port", type=int, default=6100)
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((a.core, a.port))
    print(f"[ue] connected to {a.core}:{a.port}", file=sys.stderr)

    offer = json.dumps(list(ALL_PRIMITIVES)).encode()
    send_msg(sock, MAGIC_OFFER, offer)
    print(f"[ue] offered (honest, full list): {list(ALL_PRIMITIVES)}", file=sys.stderr)

    selected = recv_msg(sock, MAGIC_SELECT).decode()
    print(f"[ue] peer selected: {selected!r}", file=sys.stderr)
    downgraded = selected != ALL_PRIMITIVES[0]
    if downgraded:
        print(f"[ue] *** NOTE: selected primitive is NOT my top preference "
              f"({ALL_PRIMITIVES[0]!r}) -- this run will use a weaker primitive "
              f"than I offered, whether by legitimate peer policy or tampering ***",
              file=sys.stderr)

    signer = make_signer(selected)
    t_kg0 = time.monotonic()
    public_key = signer.generate_keypair()
    t_kg1 = time.monotonic()
    print(f"[ue] keygen for {selected}: {(t_kg1-t_kg0)*1000:.3f}ms, "
          f"pubkey {len(public_key)} bytes", file=sys.stderr)
    send_msg(sock, MAGIC_PUBKEY, public_key)

    rows = []
    for i in range(a.reps):
        nonce = recv_msg(sock, MAGIC_NONCE)
        t0 = time.monotonic()
        signature = signer.sign(nonce)
        t1 = time.monotonic()
        send_msg(sock, MAGIC_SIG, signature)
        rows.append({
            "rep": i, "offered_top_choice": ALL_PRIMITIVES[0],
            "selected_alg": selected, "downgraded": downgraded,
            "sign_ms": (t1 - t0) * 1000.0, "sig_bytes": len(signature),
        })
        print(f"[ue] rep {i:2d}: alg={selected} sign={(t1-t0)*1000:7.3f}ms "
              f"sig_bytes={len(signature)}", file=sys.stderr)

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"[ue] wrote {len(rows)} rows to {a.out}", file=sys.stderr)
    sock.close()

if __name__ == "__main__":
    main()