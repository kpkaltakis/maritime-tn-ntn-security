# kb_verifier_v2.py -- REAL verifier for the composed authenticated protocol.
# Connects to a prover (direct) or a relay's listening port, runs ONE trial: send
# challenge, time round trip, receive response, evaluate the FULL Accept predicate
# against the real credential pool + real liboqs signature verification.
import socket, sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_wire import send_msg, recv_msg
from kb_protocol import new_challenge, evaluate_acceptance, FreshnessCache
from kb_keystore import verify_with_pubkey

DEFAULT_CA_PATH = os.path.expanduser("~/ca.crt")  # verifier's LOCAL copy of the trusted root

def run_trial(host, port, ca_pem_bytes, freshness_cache, tau_ms=450.0, V="verifier-01",
              bearer="NTN", context=None, timeout_s=5.0):
    context = context or {"policy": "seam"}
    ch = new_challenge(V, bearer, context)
    conn_t0 = time.perf_counter()
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(timeout_s)
        sk.connect((host, port))
        # timer starts AFTER connection setup -- W measures the challenge/response
        # round trip, not TCP handshake time. This is what tau=450ms is calibrated
        # against; connection setup is a session-layer cost, not the kinematic witness.
        t0 = time.perf_counter()
        send_msg(sk, {"n_hex": ch["n"].hex(), "sid": ch["sid"], "V": ch["V"],
                       "bearer": ch["bearer"], "context": ch["context"]})
        resp = recv_msg(sk)
        rtt_ms = (time.perf_counter() - t0) * 1000
        sk.close()
    except Exception as e:
        rtt_ms = (time.perf_counter() - conn_t0) * 1000   # connection itself failed/timed out
        from kb_protocol import AcceptResult
        r = AcceptResult(); r.credential_valid=False; r.signature_valid=False
        r.fresh=True; r.context_bound=False; r.witness_ok=False; r.rtt_ms=rtt_ms
        r.reason = "connection/timeout error: %s" % str(e)[:60]
        return r

    response = {"C": resp["C"], "credential_id": resp["credential_id"],
                "signature": bytes.fromhex(resp["signature_hex"]),
                "pubkey": bytes.fromhex(resp["pubkey_hex"]),
                "leaf_cert_pem": resp["leaf_cert_pem"].encode(),
                "bearer": resp["bearer"], "context": resp["context"]}

    def sig_verify_fn(digest, signature, pubkey):
        return verify_with_pubkey(digest, signature, pubkey)

    return evaluate_acceptance(ch, response, ca_pem_bytes, freshness_cache, tau_ms, rtt_ms, sig_verify_fn)

if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser()
    ap.add_argument("host"); ap.add_argument("port", type=int)
    ap.add_argument("--tau", type=float, default=450.0)
    ap.add_argument("--ca", default=DEFAULT_CA_PATH, help="path to the local trusted CA root copy")
    a = ap.parse_args()
    if not os.path.exists(a.ca):
        print(f"ERROR: no CA root at {a.ca}. Copy the trusted root here first "
              f"(it is PUBLIC, safe to distribute): e.g. scp pki@<VM-11 IP>:/home/pki/pki-ca/pki/ca.crt {a.ca}",
              file=sys.stderr)
        sys.exit(1)
    ca_pem_bytes = open(a.ca, "rb").read()
    fc = FreshnessCache()
    r = run_trial(a.host, a.port, ca_pem_bytes, fc, tau_ms=a.tau)
    print(json.dumps(r.to_dict(), indent=2))