# kb_protocol.py -- Kinematic Binding as a COMPOSED AUTHENTICATED PROTOCOL, not a
# latency test. Implements exactly:
#   Accept = CredentialValid AND SignatureValid AND Fresh AND ContextBound AND (W in R)
# Signed transcript: n || sid || V || C || credential_id || bearer || context
# This module is shared by the prover (vessel) and verifier scripts. Pure stdlib + oqs.
import hashlib, json, os, time, uuid

# ---------- transcript ----------
def build_transcript(n, sid, V, C, credential_id, bearer, context):
    # canonical, deterministic byte-serialization -- both sides must reproduce identically
    parts = {
        "n": n.hex(), "sid": sid, "V": V, "C": C,
        "credential_id": credential_id, "bearer": bearer, "context": context,
    }
    return json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()

def transcript_digest(n, sid, V, C, credential_id, bearer, context):
    return hashlib.sha256(build_transcript(n, sid, V, C, credential_id, bearer, context)).digest()

# ---------- replay / freshness cache (verifier-side state) ----------
class FreshnessCache:
    # tracks (n, sid) pairs already accepted; a repeat is a replay -> Fresh=False
    def __init__(self, ttl_s=300):
        self.seen = {}   # (n_hex, sid) -> expiry_ts
        self.ttl_s = ttl_s

    def check_and_record(self, n, sid, now=None):
        now = now or time.time()
        # purge expired
        self.seen = {k: v for k, v in self.seen.items() if v > now}
        key = (n.hex(), sid)
        if key in self.seen:
            return False   # REPLAY
        self.seen[key] = now + self.ttl_s
        return True

# ---------- the composed acceptance predicate (verifier side) ----------
class AcceptResult:
    def __init__(self):
        self.credential_valid=None; self.signature_valid=None; self.fresh=None
        self.context_bound=None; self.witness_ok=None; self.rtt_ms=None
        self.reason=None
    @property
    def accept(self):
        return bool(self.credential_valid and self.signature_valid and self.fresh
                    and self.context_bound and self.witness_ok)
    def to_dict(self):
        return {"accept":self.accept,"credential_valid":self.credential_valid,
                "signature_valid":self.signature_valid,"fresh":self.fresh,
                "context_bound":self.context_bound,"witness_ok":self.witness_ok,
                "rtt_ms":self.rtt_ms,"reason":self.reason}

def evaluate_acceptance(challenge, response, ca_pem_bytes, freshness_cache, tau_ms, rtt_ms, sig_verify_fn):
    # challenge: dict {n(bytes), sid, V, bearer, context}
    # response:  dict {C, credential_id, leaf_cert_pem(bytes), pubkey(bytes),
    #                   signature(bytes), bearer, context}
    # ca_pem_bytes: the verifier's LOCAL copy of the CA's trusted root (public, shared).
    # sig_verify_fn(digest, signature, pubkey) -> bool  -- verifies against the
    #   TRANSMITTED pubkey, not a local file (a remote verifier has no other copy).
    from kb_cred_chain import verify_chain
    r = AcceptResult()
    r.rtt_ms = rtt_ms

    # 1. CredentialValid -- real chain verify against the CA root the verifier holds
    ok, why, _ = verify_chain(response["leaf_cert_pem"], ca_pem_bytes)
    r.credential_valid = ok
    if not ok: r.reason = "credential invalid: %s" % why

    # 2. ContextBound -- bearer/context in the response must match what was challenged
    r.context_bound = (response.get("bearer") == challenge["bearer"]
                        and response.get("context") == challenge["context"])
    if not r.context_bound and r.reason is None:
        r.reason = "context/bearer mismatch"

    # 3. SignatureValid -- verify over the FULL reconstructed transcript, using the
    #    pubkey the claimant transmitted this session (not a locally-cached one)
    if r.credential_valid and r.context_bound:
        digest = transcript_digest(challenge["n"], challenge["sid"], challenge["V"],
                                    response["C"], response["credential_id"],
                                    response["bearer"], response["context"])
        try:
            r.signature_valid = sig_verify_fn(digest, response["signature"], response["pubkey"])
        except Exception:
            r.signature_valid = False
        if not r.signature_valid and r.reason is None:
            r.reason = "signature invalid"
    else:
        r.signature_valid = False

    # 4. Fresh -- nonce/session not replayed
    r.fresh = freshness_cache.check_and_record(challenge["n"], challenge["sid"])
    if not r.fresh and r.reason is None:
        r.reason = "replay detected (n,sid already seen)"

    # 5. Witness -- timing acceptance region
    r.witness_ok = (rtt_ms is not None and rtt_ms <= tau_ms)
    if not r.witness_ok and r.reason is None:
        r.reason = "rtt %.1fms exceeds tau %.1fms" % (rtt_ms if rtt_ms else -1, tau_ms)

    if r.accept:
        r.reason = "all predicates satisfied"
    return r

def new_challenge(V, bearer, context):
    return {"n": os.urandom(32), "sid": uuid.uuid4().hex, "V": V,
            "bearer": bearer, "context": context}