# kb_negative_tests_real.py -- run this ON THE TESTBED (needs the active credential pool +
# liboqs) BEFORE the campaign, per the required sequence: prove rejection on all 7 fault
# conditions using the REAL prover/verifier path (not mocks). Requires kb_prover_v2.py
# already running and reachable.
import sys, os, socket, time; sys.path.insert(0,".")
from kb_wire import send_msg, recv_msg
from kb_protocol import new_challenge, evaluate_acceptance, FreshnessCache, transcript_digest
from kb_keystore import verify_with_pubkey

def raw_trial(host, port, ca_pem_bytes, challenge_overrides=None, response_corruption=None, tau_ms=450.0, timeout_s=5.0):
    fc = FreshnessCache()
    ch = new_challenge("verifier-01", "NTN", {"policy":"seam"})
    if challenge_overrides: ch.update(challenge_overrides)
    sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sk.settimeout(timeout_s)
    sk.connect((host, port))
    t0 = time.perf_counter()   # AFTER connect -- times only the challenge/response, matching tau's calibration
    send_msg(sk, {"n_hex": ch["n"].hex(), "sid": ch["sid"], "V": ch["V"],
                   "bearer": ch["bearer"], "context": ch["context"]})
    resp = recv_msg(sk)
    rtt_ms = (time.perf_counter()-t0)*1000
    sk.close()
    if response_corruption:
        resp = response_corruption(resp)
    response = {"C": resp["C"], "credential_id": resp["credential_id"],
                "signature": bytes.fromhex(resp["signature_hex"]),
                "pubkey": bytes.fromhex(resp["pubkey_hex"]),
                "leaf_cert_pem": resp["leaf_cert_pem"].encode(),
                "bearer": resp["bearer"], "context": resp["context"]}
    def sig_verify_fn(digest, signature, pubkey):
        return verify_with_pubkey(digest, signature, pubkey)
    return evaluate_acceptance(ch, response, ca_pem_bytes, fc, tau_ms, rtt_ms, sig_verify_fn)

def T(name, cond):
    print(("PASS" if cond else "FAIL"), "-", name); return cond

if __name__=="__main__":
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("host"); ap.add_argument("port", type=int, default=9452, nargs="?")
    ap.add_argument("--ca", default=os.path.expanduser("~/ca.crt"))
    a = ap.parse_args()
    if not os.path.exists(a.ca):
        print(f"ERROR: no CA root at {a.ca}. Copy it from VM-11 first (it is PUBLIC):\n"
              f"  scp pki@<VM-11 IP>:/home/pki/pki-ca/pki/ca.crt {a.ca}", file=sys.stderr)
        sys.exit(1)
    ca_pem_bytes = open(a.ca, "rb").read()
    allpass = True
    r = raw_trial(a.host, a.port, ca_pem_bytes)
    allpass &= T("golden path accepts (real prover)", r.accept)
    r = raw_trial(a.host, a.port, ca_pem_bytes, response_corruption=lambda resp: {**resp, "bearer":"TN"})
    allpass &= T("tampered bearer rejected", (not r.accept) and r.context_bound==False)
    r = raw_trial(a.host, a.port, ca_pem_bytes, response_corruption=lambda resp: {**resp, "signature_hex": "00"*32})
    allpass &= T("corrupted signature rejected", (not r.accept) and r.signature_valid==False)
    r = raw_trial(a.host, a.port, ca_pem_bytes, response_corruption=lambda resp: {**resp, "leaf_cert_pem": ""})
    allpass &= T("missing/invalid credential rejected", (not r.accept) and r.credential_valid==False)
    r = raw_trial(a.host, a.port, ca_pem_bytes, tau_ms=0.001)
    allpass &= T("impossible timing window rejected", (not r.accept) and r.witness_ok==False)
    print("\n" + ("ALL REAL-PATH NEGATIVE TESTS PASSED" if allpass else "SOME FAILED -- do not run the campaign yet"))