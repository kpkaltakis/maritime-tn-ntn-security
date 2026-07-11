# kb_cred_chain.py -- REAL credential validation for a REMOTE verifier.
# A verifier should never need another machine's private credential pool -- it needs
# only the CA's public trusted root (ca.crt, meant to be widely distributed) plus
# whatever the claimant presents over the wire. This reuses the exact in-process
# chain-verify method already proven clean in Step 2.2 (~0.036ms, cryptography lib,
# no subprocess).
import time
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

def verify_chain(leaf_pem_bytes, ca_pem_bytes):
    # returns (ok: bool, reason: str, not_after: float|None)
    try:
        ca = x509.load_pem_x509_certificate(ca_pem_bytes)
        ca_pub = ca.public_key()
    except Exception as e:
        return False, "CA cert unreadable: %s" % str(e)[:60], None
    try:
        leaf = x509.load_pem_x509_certificate(leaf_pem_bytes)
    except Exception as e:
        return False, "leaf cert unreadable: %s" % str(e)[:60], None
    try:
        ca_pub.verify(leaf.signature, leaf.tbs_certificate_bytes,
                       padding.PKCS1v15(), leaf.signature_hash_algorithm)
    except Exception as e:
        return False, "chain verify failed: %s" % str(e)[:60], None
    not_after_ts = leaf.not_valid_after_utc.timestamp() if hasattr(leaf, "not_valid_after_utc") \
                   else leaf.not_valid_after.timestamp()
    if time.time() > not_after_ts:
        return False, "certificate expired", not_after_ts
    return True, "chain verified against CA root", not_after_ts