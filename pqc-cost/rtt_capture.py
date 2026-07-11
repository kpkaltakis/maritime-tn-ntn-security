import os, json, argparse
from kb_verifier_v2 import run_trial
from kb_protocol import FreshnessCache

ap = argparse.ArgumentParser()
ap.add_argument("--prover-host", required=True)
ap.add_argument("--prover-port", type=int, default=9452)
ap.add_argument("--n", type=int, default=2000)
ap.add_argument("--tau", type=float, default=450.0)
ap.add_argument("--ca", default=os.path.expanduser("~/ca.crt"))
ap.add_argument("--out", default="logs/rtt_direct_pertrial.jsonl")
a = ap.parse_args()
ca = open(a.ca, "rb").read()
fc = FreshnessCache()                      # one cache for the run, as the campaign does
os.makedirs(os.path.dirname(a.out), exist_ok=True)
n_ok = 0
with open(a.out, "w") as f:
    for i in range(a.n):
        r = run_trial(a.prover_host, a.prover_port, ca, fc, tau_ms=a.tau)
        infra = bool(r.reason and ("connection" in r.reason.lower()
                                   or "timeout" in r.reason.lower()))
        f.write(json.dumps({"i": i, "rtt_ms": r.rtt_ms, "accept": bool(r.accept),
                            "reason": r.reason, "infra": infra}) + "\n")
        if not infra: n_ok += 1
print(f"wrote {a.out}: {n_ok} clean / {a.n} attempted")
