# s3_measure.py -- run ON the verifier VM (VM-02). Measures Step 2.2's cost delta:
#   BASELINE  : verifier trusts a bare vessel PQC pubkey (Pillar-A style). 1 verify.
#   CREDENTIAL: verifier trusts only the CA cert; vessel presents its CA-issued PQC
#               leaf; verifier does CHAIN verify (CA-over-leaf) + vessel-over-nonce.
# Uses the REAL issued cert from s2_issue.sh. liboqs for the per-nonce sig; openssl
# (via cryptography or subprocess) for the cert-chain verify timing.
# Real measured numbers only. No fabricated values.
import oqs, os, time, json, sys, statistics, subprocess, base64

# map openssl alg name -> liboqs mechanism name (confirm on target with oqs_discover)
OQS_NAME = {"mldsa44":"ML-DSA-44","falcon512":"Falcon-512","falconpadded512":"Falcon-512"}

def load_cert_pubkey_der(cert_path):
    # extract the leaf's SubjectPublicKeyInfo so we can verify the vessel sig with liboqs
    out = subprocess.run(["openssl","x509","-provider","oqsprovider","-provider","default",
                          "-in",cert_path,"-pubkey","-noout"],
                         capture_output=True, text=True)
    return out.stdout  # PEM SPKI

def chain_verify_ms(cert_path, ca_path, reps=50):
    # time: does the RSA CA certify this PQC leaf? (the authority step the baseline skips)
    ts=[]
    for _ in range(reps):
        t0=time.perf_counter()
        r=subprocess.run(["openssl","verify","-provider","oqsprovider","-provider","default",
                          "-CAfile",ca_path,cert_path],capture_output=True)
        t1=time.perf_counter()
        ts.append((t1-t0)*1000)
    ok = (r.returncode==0)
    return ok, statistics.median(ts)

def run(vessel_key, vessel_cert, ca_cert, alg="mldsa44", n=200):
    mech = OQS_NAME.get(alg,"ML-DSA-44")
    # vessel signer from the issued private key is awkward via liboqs (key is in PEM);
    # for the per-nonce auth cost we measure the liboqs sign/verify of the SAME mechanism
    # (the cost is the primitive's, identical whether key came from cert or ad-hoc).
    signer = oqs.Signature(mech); pub = signer.generate_keypair()
    verifier = oqs.Signature(mech)

    # BASELINE: bare-key handshake (sign nonce, verify nonce). No authority.
    base=[]
    for _ in range(n):
        nonce=os.urandom(32)
        sig=signer.sign(nonce)
        t0=time.perf_counter(); ok=verifier.verify(nonce,sig,pub); t1=time.perf_counter()
        assert ok; base.append((t1-t0)*1000)

    # CREDENTIAL: same nonce verify PLUS the cert-chain verify (the authority step)
    chain_ok, chain_ms = chain_verify_ms(vessel_cert, ca_cert, reps=50)
    cred=[]
    for _ in range(n):
        nonce=os.urandom(32)
        sig=signer.sign(nonce)
        t0=time.perf_counter()
        ok=verifier.verify(nonce,sig,pub)     # vessel-over-nonce
        t1=time.perf_counter()
        assert ok; cred.append((t1-t0)*1000 + chain_ms)  # + amortized chain verify

    cert_bytes = os.path.getsize(vessel_cert)
    ca_bytes   = os.path.getsize(ca_cert)
    med=lambda L: round(statistics.median(L),4)
    print(json.dumps({
      "alg_openssl":alg, "alg_liboqs":mech, "n":n,
      "chain_verify_ok": chain_ok,
      "baseline_verify_ms_median": med(base),
      "chain_verify_ms_median": round(chain_ms,4),
      "credential_total_verify_ms_median": med(cred),
      "authority_overhead_ms": round(med(cred)-med(base),4),
      "leaf_cert_bytes": cert_bytes,
      "ca_cert_bytes": ca_bytes,
      "wire_overhead_bytes_credential_vs_barekey": cert_bytes,
      "interpretation":"authority_overhead = cost of CA-chain-verifying an issued PQC credential vs trusting a bare key",
      "note":"per-nonce sign/verify cost is the primitive's own; the DELTA is the authority chain step + cert bytes on the wire"
    }, indent=2))

if __name__=="__main__":
    if len(sys.argv)<4:
        print("usage: s3_measure.py <vessel.key> <vessel.crt> <ca.crt> [alg] [n]")
        print("example: s3_measure.py /tmp/triton_cred/athena/athena.key /tmp/triton_cred/athena/athena.crt /home/pki/pki-ca/pki/ca.crt mldsa44 200")
        sys.exit(1)
    run(sys.argv[1], sys.argv[2], sys.argv[3],
        sys.argv[4] if len(sys.argv)>4 else "mldsa44",
        int(sys.argv[5]) if len(sys.argv)>5 else 200)