# kb_frr_breakdown.py -- runs the direct condition and reports, for every trial that
# did NOT accept, WHICH predicate failed. Answers precisely: are FRR failures purely
# timing (network loss/retransmit), or do they ever touch credential/signature/freshness?
import sys, os, json; sys.path.insert(0,".")
from kb_verifier_v2 import run_trial
from kb_protocol import FreshnessCache

def main(host, port, n=300, tau=450.0):
    fc = FreshnessCache()
    fail_breakdown = {"credential_valid":0,"signature_valid":0,"fresh":0,"context_bound":0,"witness_ok":0}
    fails = []
    n_accept = 0
    for i in range(n):
        r = run_trial(host, port, open(os.path.expanduser("~/ca.crt"),"rb").read(), fc, tau_ms=tau)
        if r.accept:
            n_accept += 1
        else:
            for k in fail_breakdown:
                if getattr(r, k) is False:
                    fail_breakdown[k] += 1
            fails.append({"rtt_ms": round(r.rtt_ms,1), "reason": r.reason,
                          "credential_valid": r.credential_valid, "signature_valid": r.signature_valid,
                          "fresh": r.fresh, "context_bound": r.context_bound, "witness_ok": r.witness_ok})
        if (i+1)%50==0: print(f"  {i+1}/{n}", file=sys.stderr)
    print(json.dumps({"n":n,"accepted":n_accept,"rejected":n-n_accept,
                       "which_predicate_failed_count": fail_breakdown,
                       "all_failures_detail": fails}, indent=2))
    only_timing = all(f["credential_valid"] and f["signature_valid"] and f["fresh"] and f["context_bound"]
                       and not f["witness_ok"] for f in fails)
    print("\nCONCLUSION: all failures were timing-only (crypto/identity/freshness all held) =", only_timing)

if __name__=="__main__":
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("host"); ap.add_argument("--port", type=int, default=9452)
    ap.add_argument("--n", type=int, default=300)
    a = ap.parse_args()
    main(a.host, a.port, a.n)