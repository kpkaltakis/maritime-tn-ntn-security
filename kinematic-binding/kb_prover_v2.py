# kb_prover_v2.py -- REAL vessel-side prover for the composed authenticated protocol.
# Run on the vessel VM. For each connection: receive one challenge, sign the FULL
# transcript with the active credential's liboqs key, send the response, close.
# One connection = one independent trial (clean for statistics).
import socket, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_wire import send_msg, recv_msg
from kb_protocol import transcript_digest
from kb_keystore import KBKeystore
from m6_rotation import CredentialPool

PORT = 9452

def main():
    pool = CredentialPool()
    ks = KBKeystore()
    cid = pool.active_id()
    if cid is None:
        print("[prover] NO ACTIVE CREDENTIAL in pool -- rotate one first (m6_rotation).", file=sys.stderr)
        sys.exit(1)
    print("[prover] active credential:", cid, flush=True)
    _, pubkey = ks.keypair_for(cid)   # ensure keypair exists; also fetch pubkey to send

    # read the REAL issued leaf certificate to transmit for chain verification
    leaf_path = os.path.join(pool.pool_dir, cid, "leaf_cert.pem")
    if not os.path.exists(leaf_path):
        print(f"[prover] WARNING: no leaf_cert.pem at {leaf_path} -- CredentialValid will fail "
              "at the verifier. Provision via m6_provisioner.py first.", file=sys.stderr)
    leaf_pem = open(leaf_path, "rb").read() if os.path.exists(leaf_path) else b""

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT)); srv.listen(16)
    print(f"[prover] listening on {PORT}", flush=True)
    n_served = 0
    while True:
        conn, addr = srv.accept()
        try:
            ch = recv_msg(conn)   # {n_hex, sid, V, bearer, context}
            n_bytes = bytes.fromhex(ch["n_hex"])
            C = "athena"
            digest = transcript_digest(n_bytes, ch["sid"], ch["V"], C, cid, ch["bearer"], ch["context"])
            sig = ks.sign(cid, digest)
            send_msg(conn, {"C": C, "credential_id": cid, "signature_hex": sig.hex(),
                             "pubkey_hex": pubkey.hex(), "leaf_cert_pem": leaf_pem.decode(),
                             "bearer": ch["bearer"], "context": ch["context"]})
            n_served += 1
            if n_served % 50 == 0:
                print(f"[prover] served {n_served} trials", flush=True)
        except Exception as e:
            print("[prover] trial error:", str(e)[:100], file=sys.stderr)
        finally:
            conn.close()

if __name__ == "__main__":
    main()