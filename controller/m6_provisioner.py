# m6_provisioner.py -- ASYNCHRONOUS provisioning. The ONLY component that contacts VM-11.
# Runs OUTSIDE the rotation-critical path: before a voyage, or when the pool falls below
# the low-water mark. Wraps s2_issue.sh over ssh behind a clean issuer interface, so the
# rotation bridge never knows about ssh/CA -- exactly the separation the spec requires.
import subprocess, os, json, time, sys
sys.path.insert(0,".")
from m6_rotation import CredentialPool

class CredentialIssuer:
    # interface: issue_batch(count, algorithm) -> list of (leaf_pem, key_pem, chain_pem)
    def issue_batch(self, count, algorithm="mldsa44"):
        raise NotImplementedError

class SshCredentialIssuer(CredentialIssuer):
    # calls s2_issue.sh on VM-11 over ssh, pulls back the issued bundle. Provisioning only.
    def __init__(self, ca_host="192.168.0.10", ca_user="pki", ssh_pass="1111",
                 issue_script="~/step22/s2_issue.sh", ca_dir="/home/pki/pki-ca/pki"):
        self.ca_host=ca_host; self.ca_user=ca_user; self.ssh_pass=ssh_pass
        self.issue_script=issue_script; self.ca_dir=ca_dir

    def _ssh(self, cmd):
        # uses sshpass if available; falls back to key-based ssh. Provisioning-time only.
        base=["ssh","-o","StrictHostKeyChecking=no","%s@%s"%(self.ca_user,self.ca_host),cmd]
        if self.ssh_pass:
            full=["sshpass","-p",self.ssh_pass]+base
        else:
            full=base
        return subprocess.run(full, capture_output=True, text=True, timeout=60)

    def issue_batch(self, count, algorithm="mldsa44"):
        # for each credential: run s2_issue.sh with a random pseudonym, cat back the files.
        bundles=[]
        for i in range(count):
            vessel="pseudo%s"%os.urandom(4).hex()   # random pseudonym, no stable name
            # issue on VM-11
            r=self._ssh("%s %s %s"%(self.issue_script, vessel, algorithm))
            if r.returncode!=0:
                print("  issue FAILED for %s: %s"%(vessel, r.stderr[:120]), file=sys.stderr)
                continue
            # retrieve leaf + key from /tmp/triton_cred/<vessel>/
            base="/tmp/triton_cred/%s"%vessel
            leaf=self._ssh("cat %s/%s.crt"%(base,vessel)).stdout
            key =self._ssh("cat %s/%s.key"%(base,vessel)).stdout
            chain=self._ssh("cat %s/ca.crt"%self.ca_dir).stdout
            if leaf and key:
                bundles.append((leaf,key,chain))
        return bundles

class PoolManager:
    def __init__(self, pool=None, issuer=None, target_size=10, low_watermark=3):
        self.pool=pool or CredentialPool()
        self.issuer=issuer
        self.target=target_size; self.low=low_watermark

    def ensure_stocked(self, algorithm="mldsa44"):
        # asynchronous replenishment policy (called offline / by a worker, NOT at rotate)
        avail=self.pool.available()
        if avail>self.low:
            return {"action":"none","available":avail}
        need=self.target-avail
        if self.issuer is None:
            return {"action":"needed_but_no_issuer","need":need,"available":avail}
        t0=time.time()
        bundles=self.issuer.issue_batch(need, algorithm)
        added=[]
        for leaf,key,chain in bundles:
            cid=self.pool.add_bundle(leaf,key,chain,
                 algorithm={"mldsa44":"ML-DSA-44","falcon512":"Falcon-512"}.get(algorithm,algorithm))
            added.append(cid)
        return {"action":"replenished","requested":need,"added":len(added),
                "available_after":self.pool.available(),
                "provisioning_s":round(time.time()-t0,2)}

if __name__=="__main__":
    print("provisioner interfaces defined: SshCredentialIssuer + PoolManager")
    print("NOTE: issue_batch/ensure_stocked contact VM-11 -- run OFFLINE, never at rotate.")
    print("needs 'sshpass' on the vessel VM (or key-based ssh to pki@192.168.0.10).")