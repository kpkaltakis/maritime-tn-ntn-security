import os, sys, json, argparse
from kb_verifier_v2 import run_trial
from kb_protocol import FreshnessCache

ap = argparse.ArgumentParser()
ap.add_argument("--host", required=True)          # relay host for FAR, prover host for FRR
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--n", type=int, default=500)     # authentication attempts
ap.add_argument("--probes", type=int, default=3)  # k back-to-back probes per attempt
ap.add_argument("--rule", choices=["any","majority"], default="any")
ap.add_argument("--tau", type=float, default=450.0)
ap.add_argument("--ca", default=os.path.expanduser("~/ca.crt"))
ap.add_argument("--expect-accept", type=int, default=0)  # 0 for relay(FAR), 1 for direct(FRR)
a = ap.parse_args()
ca = open(a.ca, "rb").read()
fc = FreshnessCache()

def attempt_accepts():
    passes = 0
    for _ in range(a.probes):
        r = run_trial(a.host, a.port, ca, fc, tau_ms=a.tau)
        if r.reason and ("connection" in r.reason.lower() or "timeout" in r.reason.lower()):
            return None  # infra error -> exclude whole attempt
        passes += 1 if r.accept else 0
    need = 1 if a.rule == "any" else (a.probes // 2 + 1)
    return passes >= need

acc = tot = infra = 0
for _ in range(a.n):
    v = attempt_accepts()
    if v is None: infra += 1; continue
    tot += 1; acc += 1 if v else 0
errs = acc if a.expect_accept == 0 else (tot - acc)   # relay accepts are errors (FAR); direct rejects are errors (FRR)
metric = "FAR" if a.expect_accept == 0 else "FRR"
lo3 = 3.0/tot if errs == 0 and tot else None
print(json.dumps({"metric":metric,"rule":a.rule,"probes":a.probes,
    "n_attempts_clean":tot,"infra_excluded":infra,"errors":errs,
    "rate_pct":round(100*errs/tot,3) if tot else None,
    "rule_of_three_ub_pct":round(100*lo3,3) if lo3 else None}, indent=2))
