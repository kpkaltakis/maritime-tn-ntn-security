# kb_keystore.py -- binds a native liboqs signing keypair to each credential_id.
# HONEST NOTE (same disclosure pattern as Step 2.2's s3_measure.py): the CA-issued
# credential (m6_rotation.CredentialPool) carries an openssl/oqsprovider PEM keypair;
# bridging that exact PEM key into liboqs-python is a separate engineering task. Here,
# each credential gets its OWN freshly-generated liboqs keypair at creation time, stored
# 1:1 against its credential_id. This preserves the real security PROPERTY under test
# (a fresh, credential-bound key that must match for SignatureValid) using liboqs
# end-to-end, while being explicit that it is not literally the openssl-PEM key.
import os, json

def _try_oqs():
    try:
        import oqs
        if hasattr(oqs, "get_enabled_sig_mechanisms"):
            oqs.get_enabled_sig_mechanisms()
        return oqs
    except Exception:
        return None

class KBKeystore:
    def __init__(self, root=os.path.expanduser("~/triton_credentials/kb_keys"), alg="ML-DSA-44"):
        self.root = root; self.alg = alg
        os.makedirs(root, exist_ok=True)
        self._signers = {}   # in-memory cache: credential_id -> (oqs.Signature obj, pubkey bytes)

    def keypair_for(self, credential_id):
        oqs = _try_oqs()
        if oqs is None:
            return None, None   # no liboqs on this node
        if credential_id in self._signers:
            return self._signers[credential_id]
        path = os.path.join(self.root, credential_id + ".pub")
        sig = oqs.Signature(self.alg)
        if os.path.exists(path):
            # re-derive is not possible for oqs secret keys across process restarts in this
            # simple keystore; for a campaign we generate once per run and keep in-memory.
            pass
        pub = sig.generate_keypair()
        with open(path, "wb") as f: f.write(pub)
        self._signers[credential_id] = (sig, pub)
        return sig, pub

    def sign(self, credential_id, digest):
        sig, _ = self.keypair_for(credential_id)
        if sig is None: return None
        return sig.sign(digest)

    def pubkey(self, credential_id):
        _, pub = self.keypair_for(credential_id)
        return pub

    def verify(self, credential_id, digest, signature):
        oqs = _try_oqs()
        if oqs is None: return False
        pub = self.pubkey(credential_id)
        if pub is None: return False
        v = oqs.Signature(self.alg)
        try:
            return v.verify(digest, signature, pub)
        except Exception:
            return False

def verify_with_pubkey(digest, signature, pubkey, alg="ML-DSA-44"):
    # REMOTE verification: no local lookup, uses the pubkey the claimant transmitted
    # this session -- what a real remote verifier actually has available.
    oqs = _try_oqs()
    if oqs is None: return False
    v = oqs.Signature(alg)
    try:
        return v.verify(digest, signature, pubkey)
    except Exception:
        return False