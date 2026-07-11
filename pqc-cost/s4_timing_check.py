# s4_timing_check.py -- run ON VM-11. Clean in-process chain-verify timing.
import time, sys, statistics

try:
    import cryptography
    print("cryptography", cryptography.__version__)
except Exception as e:
    print("no cryptography:", e); sys.exit(1)

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

CA="/home/pki/pki-ca/pki/ca.crt"
LEAF="/tmp/triton_cred/athena/athena.crt"

# 1. load CA cert + its RSA public key
try:
    ca = x509.load_pem_x509_certificate(open(CA,"rb").read())
    ca_pub = ca.public_key()
    print("[1] CA cert loaded; CA pubkey type:", type(ca_pub).__name__)
except Exception as e:
    print("[1] CA load FAILED:", e); sys.exit(1)

# 2. load the leaf cert (its pubkey is PQC; may not parse, that's fine)
try:
    leaf = x509.load_pem_x509_certificate(open(LEAF,"rb").read())
    print("[2] leaf cert loaded OK")
    try:
        lp = leaf.public_key(); print("    leaf pubkey parsed type:", type(lp).__name__)
    except Exception as e:
        print("    leaf pubkey is PQC, not parseable here (EXPECTED, fine):", str(e)[:80])
except Exception as e:
    print("[2] leaf load FAILED:", str(e)[:120]); leaf=None

# 3. THE MEASUREMENT: time the CA RSA signature verify over the leaf TBS bytes
if leaf is not None:
    try:
        n=2000; ts=[]
        tbs = leaf.tbs_certificate_bytes
        sig = leaf.signature
        algo = leaf.signature_hash_algorithm
        for _ in range(n):
            t0=time.perf_counter()
            ca_pub.verify(sig, tbs, padding.PKCS1v15(), algo)
            t1=time.perf_counter()
            ts.append((t1-t0)*1000)
        ts.sort()
        print("[3] IN-PROCESS chain-verify (CA RSA sig over leaf TBS):")
        print("    median %.4f ms | mean %.4f ms | min %.4f ms | n=%d" % (
              statistics.median(ts), statistics.mean(ts), ts[0], n))
        print("    ^ clean crypto chain-verify time, no process-spawn noise")
    except Exception as e:
        print("[3] in-process verify FAILED:", str(e)[:120])