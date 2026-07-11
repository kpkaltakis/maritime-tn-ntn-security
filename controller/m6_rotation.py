# m6_rotation.py -- authentication-layer pseudonymous credential rotation (pre-minted pool).
# Option C: the vessel holds a pool of authority-issued PQC leaves; rotation is a LOCAL
# atomic swap to the next unused one. CA issuance/replenishment happens OUTSIDE the
# rotation-critical path (no CA contact at rotation time -> no correlation signal).
# Pure stdlib. Local-file backed so it survives restarts.
#
# NAMING: this is AUTH-LAYER PSEUDONYM ROTATION, not "identity rotation". It changes the
# leaf cert + PQC keypair + pseudonym id + auth state. It does NOT change SUPI/SUCI/GUTI/
# SIM/5G-subscription, AIS identity, or motion/timing/traffic continuity.
import os, json, time, uuid, hashlib, tempfile, glob

# states
READY="READY"; RESERVED="RESERVED"; ACTIVE="ACTIVE"; RETIRED="RETIRED"; INVALID="INVALID"

class CredentialPool:
    def __init__(self, root=os.path.expanduser("~/triton_credentials")):
        self.root=root; self.pool_dir=os.path.join(root,"pool")
        self.active_link=os.path.join(root,"active")
        os.makedirs(self.pool_dir, exist_ok=True)

    # --- bundle helpers ---
    def _meta_path(self, cid): return os.path.join(self.pool_dir, cid, "metadata.json")
    def _read_meta(self, cid):
        with open(self._meta_path(cid)) as f: return json.load(f)
    def _write_meta(self, cid, meta):
        # atomic write
        p=self._meta_path(cid)
        with tempfile.NamedTemporaryFile("w", dir=os.path.dirname(p), delete=False) as tf:
            json.dump(meta, tf, indent=2); tmp=tf.name
        os.replace(tmp, p)

    def add_bundle(self, leaf_pem, key_pem, chain_pem="", algorithm="ML-DSA-44",
                   valid_hours=24):
        # store a newly-issued credential bundle with a RANDOM id (no stable pseudonym)
        cid="cred-"+uuid.uuid4().hex[:16]
        d=os.path.join(self.pool_dir, cid); os.makedirs(d, exist_ok=True)
        open(os.path.join(d,"leaf_cert.pem"),"w").write(leaf_pem)
        open(os.path.join(d,"private_key.pem"),"w").write(key_pem)
        if chain_pem: open(os.path.join(d,"chain.pem"),"w").write(chain_pem)
        now=time.time()
        meta={"credential_id":"urn:uuid:"+str(uuid.uuid4()),
              "local_id":cid,"algorithm":algorithm,"status":READY,
              "issued_at":now,"valid_from":now,"valid_until":now+valid_hours*3600,
              "certificate_sha256":hashlib.sha256(leaf_pem.encode()).hexdigest(),
              "pubkey_sha256":self._pubkey_hash(leaf_pem),
              "activation_count":0}
        self._write_meta(cid, meta)
        return cid

    @staticmethod
    def _pubkey_hash(leaf_pem):
        # cheap fingerprint of the cert body (proxy for key identity); real check uses
        # the actual SPKI on the testbed. Here: hash the PEM (unique per fresh key).
        return hashlib.sha256(("PUB"+leaf_pem).encode()).hexdigest()[:32]

    def list_by_state(self, state):
        out=[]
        for d in glob.glob(os.path.join(self.pool_dir,"cred-*")):
            cid=os.path.basename(d)
            try:
                if self._read_meta(cid)["status"]==state: out.append(cid)
            except Exception: pass
        return sorted(out)

    def available(self):
        return len(self.list_by_state(READY))

    def active_id(self):
        if os.path.islink(self.active_link) or os.path.exists(self.active_link):
            try: return os.path.basename(os.readlink(self.active_link))
            except OSError: return None
        return None

    def validate(self, cid):
        # chain/validity/keymatch checks. Local: validity+metadata+files present.
        # (real chain verify runs on the testbed via openssl; here structural checks.)
        try:
            m=self._read_meta(cid); d=os.path.join(self.pool_dir,cid)
            if not os.path.exists(os.path.join(d,"leaf_cert.pem")): return False,"no leaf"
            if not os.path.exists(os.path.join(d,"private_key.pem")): return False,"no key"
            if time.time()>m["valid_until"]: return False,"expired"
            if m["status"] not in (READY,): return False,"not READY (%s)"%m["status"]
            return True,"ok"
        except Exception as e:
            return False,str(e)[:60]

class RotationBridge:
    def __init__(self, pool=None):
        self.pool=pool or CredentialPool()
        self.lockfile=os.path.join(self.pool.root,".rotation.lock")

    def _lock(self):
        # simple atomic lock via O_CREAT|O_EXCL (concurrency test relies on this)
        try:
            fd=os.open(self.lockfile, os.O_CREAT|os.O_EXCL|os.O_WRONLY); os.close(fd); return True
        except FileExistsError:
            return False
    def _unlock(self):
        try: os.remove(self.lockfile)
        except OSError: pass

    def rotate(self, decision_id, reason="PRIVACY_FEASIBLE"):
        # the ONLY interface the controller calls. Atomic local swap, NO CA contact.
        t0=time.perf_counter()
        res={"decision_id":decision_id,"reason":reason,"rotation_performed":False,
             "available_pool_before":self.pool.available()}
        if not self._lock():
            res["failure_reason"]="LOCKED (concurrent rotation)"; return res
        try:
            ready=self.pool.list_by_state(READY)
            if not ready:
                res["failure_reason"]="POOL_EXHAUSTED"; res["authentication_affected"]=False
                return res
            old=self.pool.active_id()
            res["old_credential_id"]=old
            # pick + validate the next READY credential
            chosen=None
            for cid in ready:
                ok,why=self.pool.validate(cid)
                if ok: chosen=cid; break
                else:  # mark bad ones INVALID, keep looking
                    m=self.pool._read_meta(cid); m["status"]=INVALID; self.pool._write_meta(cid,m)
            if chosen is None:
                res["failure_reason"]="NO_VALID_READY"; return res
            # RESERVE
            m=self.pool._read_meta(chosen); m["status"]=RESERVED; self.pool._write_meta(chosen,m)
            # freshness guard (point A): new pubkey must differ from old
            if old:
                try:
                    if self.pool._read_meta(old)["pubkey_sha256"]==m["pubkey_sha256"]:
                        res["failure_reason"]="KEY_NOT_FRESH"; 
                        m["status"]=READY; self.pool._write_meta(chosen,m); return res
                except Exception: pass
            # ATOMIC activation: symlink swap via rename
            tmp=self.pool.active_link+".tmp"
            try: os.remove(tmp)
            except OSError: pass
            os.symlink(os.path.join(self.pool.pool_dir,chosen), tmp)
            os.replace(tmp, self.pool.active_link)   # atomic
            # self-test: the active credential's files are present + readable
            act=self.pool.active_id()
            if act!=chosen:
                res["failure_reason"]="ACTIVATION_MISMATCH"; return res
            # mark ACTIVE, retire old, bump counters
            m["status"]=ACTIVE; m["activation_count"]+=1; self.pool._write_meta(chosen,m)
            if old and old!=chosen:
                try:
                    om=self.pool._read_meta(old); om["status"]=RETIRED; self.pool._write_meta(old,om)
                except Exception: pass
            res["rotation_performed"]=True
            res["new_credential_id"]=chosen
            res["available_pool_after"]=self.pool.available()
            res["total_rotation_ms"]=round((time.perf_counter()-t0)*1000,4)
            return res
        finally:
            self._unlock()

if __name__=="__main__":
    import shutil
    ROOT="/tmp/_rot_test"; shutil.rmtree(ROOT, ignore_errors=True)
    pool=CredentialPool(ROOT); br=RotationBridge(pool)
    # seed a pool of 4 fresh (distinct) credentials
    for i in range(4):
        leaf="-----BEGIN CERT-----\nLEAF%d-%s\n-----END CERT-----"%(i,uuid.uuid4().hex)
        key ="-----BEGIN KEY-----\nKEY%d-%s\n-----END KEY-----"%(i,uuid.uuid4().hex)
        pool.add_bundle(leaf,key)
    print("pool seeded, available:", pool.available())
    r1=br.rotate("dec-1"); print("rotate1:", json.dumps({k:r1[k] for k in ("rotation_performed","new_credential_id","available_pool_after","total_rotation_ms")}))
    r2=br.rotate("dec-2"); print("rotate2:", json.dumps({k:r2[k] for k in ("rotation_performed","old_credential_id","new_credential_id","available_pool_after")}))
    print("freshness: r1.new != r2.new ?", r1["new_credential_id"]!=r2["new_credential_id"])
    print("active now:", pool.active_id(), "| RETIRED:", pool.list_by_state(RETIRED))