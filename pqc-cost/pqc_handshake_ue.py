#!/usr/bin/env python3
"""
pqc_handshake_ue.py -- run on VM-03 (vessel1/Athena), the UE side. Pairs with
pqc_handshake_core.py running on VM-02. Generates a real liboqs keypair for
the chosen primitive, sends the public key once, then for each nonce the core
sends, signs it (real compute cost, timed) and sends the signature back.

Usage (run AFTER pqc_handshake_core.py is already listening):
  python3 pqc_handshake_ue.py --core 192.168.0.17 --port 6000 \
      --alg Falcon-512 --reps 30 --out ue_falcon512.csv
"""
import argparse, socket, struct, time, csv, sys
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
    ap.add_argument("--core", required=True, help="core VM's NTN-side IP, e.g. 192.168.0.17")
    ap.add_argument("--port", type=int, default=6000)
    ap.add_argument("--alg", required=True, choices=["Falcon-512", "ML-DSA-44", "SLH_DSA_PURE_SHA2_128S"])
    ap.add_argument("--reps", type=int, default=30)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    signer = oqs.Signature(a.alg)
    t_kg0 = time.monotonic()
    public_key = signer.generate_keypair()
    t_kg1 = time.monotonic()
    keygen_ms = (t_kg1 - t_kg0) * 1000.0
    print(f"[ue] keygen for {a.alg}: {keygen_ms:.3f}ms, pubkey {len(public_key)} bytes", file=sys.stderr)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((a.core, a.port))
    print(f"[ue] connected to core {a.core}:{a.port}", file=sys.stderr)

    tag = recv_exact(sock, 5)
    assert tag == MAGIC_PUBKEY_REQ, f"unexpected tag {tag!r}"
    sock.sendall(MAGIC_PUBKEY_RESP + struct.pack("!I", len(public_key)) + public_key)

    rows = []
    for i in range(a.reps):
        tag = recv_exact(sock, 5)
        assert tag == MAGIC_NONCE, f"unexpected tag {tag!r} on rep {i}"
        (n_len,) = struct.unpack("!I", recv_exact(sock, 4))
        nonce = recv_exact(sock, n_len)

        t0 = time.monotonic()
        signature = signer.sign(nonce)
        t1 = time.monotonic()
        sign_ms = (t1 - t0) * 1000.0

        sock.sendall(MAGIC_SIG + struct.pack("!I", len(signature)) + signature)
        rows.append({"rep": i, "alg": a.alg, "sign_ms": sign_ms, "sig_bytes": len(signature)})
        print(f"[ue] rep {i:2d}: sign={sign_ms:7.3f}ms  sig_bytes={len(signature)}", file=sys.stderr)

    with open(a.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["rep", "alg", "sign_ms", "sig_bytes"])
        w.writeheader()
        w.writerows(rows)
    print(f"[ue] wrote {len(rows)} rows to {a.out}", file=sys.stderr)
    print(f"[ue] keygen_ms={keygen_ms:.3f} pubkey_bytes={len(public_key)} (logged separately, not in csv)", file=sys.stderr)
    sock.close()

if __name__ == "__main__":
    main()