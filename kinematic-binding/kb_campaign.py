import sys, os, time, math, json, argparse, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_verifier_v2 import run_trial
from kb_protocol import FreshnessCache

def _betacf(a, b, x, maxit=200, eps=3e-12):
    qab=a+b; qap=a+1.0; qam=a-1.0
    c=1.0; d=1.0-qab*x/qap
    if abs(d)<1e-30: d=1e-30
    d=1.0/d; h=d
    for m in range(1,maxit+1):
        m2=2*m
        aa=m*(b-m)*x/((qam+m2)*(a+m2))
        d=1.0+aa*d;  d=1e-30 if abs(d)<1e-30 else d; c=1.0+aa/c; c=1e-30 if abs(c)<1e-30 else c
        d=1.0/d; h*=d*c
        aa=-(a+m)*(qab+m)*x/((a+m2)*(qap+m2))
        d=1.0+aa*d;  d=1e-30 if abs(d)<1e-30 else d; c=1.0+aa/c; c=1e-30 if abs(c)<1e-30 else c
        d=1.0/d; de=d*c; h*=de
        if abs(de-1.0)<eps: break
    return h

def _betai(a,b,x):
    if x<=0: return 0.0
    if x>=1: return 1.0
    lbeta = math.lgamma(a+b)-math.lgamma(a)-math.lgamma(b)
    bt = math.exp(lbeta + a*math.log(x) + b*math.log(1-x))
    return bt*_betacf(a,b,x)/a if x < (a+1)/(a+b+2) else 1.0-bt*_betacf(b,a,1-x)/b

def _beta_quantile(p, a, b, lo=0.0, hi=1.0, iters=100):
    for _ in range(iters):
        mid = (lo+hi)/2
        if _betai(a,b,mid) < p: lo = mid
        else: hi = mid
    return (lo+hi)/2

def clopper_pearson(k, n, conf=0.95):
    alpha = 1-conf
    lo = 0.0 if k==0 else _beta_quantile(alpha/2, k, n-k+1)
    hi = 1.0 if k==n else _beta_quantile(1-alpha/2, k+1, n-k)
    return lo, hi

def clopper_pearson_one_sided_upper(k, n, conf=0.95):
    alpha = 1-conf
    if k==n: return 1.0
    return _beta_quantile(1-alpha, k+1, n-k)

def rule_of_three(k, n):
    return (3.0/n) if k==0 else None

def pctile(sorted_x, p):
    if not sorted_x: return None
    idx = min(len(sorted_x)-1, int(p/100*len(sorted_x)))
    return sorted_x[idx]

def run_condition(name, host, port, n, tau, expect_accept, ca_pem_bytes):
    fc = FreshnessCache()
    rtts=[]; accepts=[]; reasons=[]; infra_errors=0
    for i in range(n):
        r = run_trial(host, port, ca_pem_bytes, fc, tau_ms=tau)
        rtts.append(r.rtt_ms); accepts.append(r.accept); reasons.append(r.reason)
        if r.reason and ("connection" in r.reason.lower() or "timeout" in r.reason.lower()):
            infra_errors += 1
        if (i+1)%50==0: print(f"  [{name}] {i+1}/{n} trials", file=sys.stderr)
    if infra_errors > 0:
        print(f"  WARNING [{name}]: {infra_errors}/{n} trials were INFRASTRUCTURE errors "
              f"(connection refused/reset/timeout -- not a completed protocol exchange). "
              f"These are EXCLUDED from the security-relevant FAR/FRR below.", file=sys.stderr)
    clean_idx = [i for i in range(n) if not (reasons[i] and
                 ("connection" in reasons[i].lower() or "timeout" in reasons[i].lower()))]
    clean_accepts = [accepts[i] for i in clean_idx]
    clean_rtts = [rtts[i] for i in clean_idx]
    errors = sum(1 for a in clean_accepts if a != expect_accept)
    k, ntot = errors, len(clean_accepts)
    lo3 = rule_of_three(k, ntot)
    cp_upper_1sided = clopper_pearson_one_sided_upper(k, ntot)
    cp_lo, cp_hi = clopper_pearson(k, ntot)
    srtt = sorted(clean_rtts) if clean_rtts else [0.0]
    return {
        "condition": name, "n_total_attempted": n, "n_clean": ntot,
        "infra_errors_excluded": infra_errors, "expect_accept": expect_accept,
        "error_count": k, "error_rate": round(k/ntot,4) if ntot else None,
        "rule_of_three_bound": (round(lo3,4) if lo3 else None),
        "clopper_pearson_95_one_sided_upper": round(cp_upper_1sided,4),
        "clopper_pearson_95_two_sided": [round(cp_lo,4), round(cp_hi,4)],
        "rtt_ms": {"mean":round(statistics.mean(clean_rtts),2), "median":round(statistics.median(clean_rtts),2),
                   "stdev": round(statistics.stdev(clean_rtts),2) if len(clean_rtts)>1 else 0.0,
                   "p95": round(pctile(srtt,95),2), "p99": round(pctile(srtt,99),2),
                   "min": round(srtt[0],2), "max": round(srtt[-1],2)} if clean_rtts else None,
        "reason_sample_all": reasons[:5],
        "reason_sample_clean_only": [reasons[i] for i in clean_idx[:5]],
    }

if __name__=="__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--prover-host", required=True)
    ap.add_argument("--prover-port", type=int, default=9452)
    ap.add_argument("--relay-host", default=None)
    ap.add_argument("--relay-port", type=int, default=9453)
    ap.add_argument("--n", type=int, default=300)
    ap.add_argument("--tau", type=float, default=450.0)
    ap.add_argument("--ca", default=os.path.expanduser("~/ca.crt"))
    a = ap.parse_args()
    if not os.path.exists(a.ca):
        print(f"ERROR: no CA root at {a.ca}.", file=sys.stderr)
        sys.exit(1)
    ca_pem_bytes = open(a.ca, "rb").read()

    print("="*70); print("KINEMATIC BINDING STATISTICAL CAMPAIGN"); print("="*70)
    print(f"tau={a.tau}ms  n_per_condition={a.n}  (rule-of-three target for n={a.n}: ~{3.0/a.n*100:.2f}%)\n")

    results = {}
    print("--- LEGITIMATE DIRECT trials (expect ACCEPT; measures FRR) ---")
    results["legitimate_direct"] = run_condition("legitimate_direct", a.prover_host, a.prover_port,
                                                   a.n, a.tau, expect_accept=True, ca_pem_bytes=ca_pem_bytes)

    if a.relay_host:
        print("\n--- RELAY (genuine forwarding proxy) trials (expect REJECT; measures FAR) ---")
        results["relay"] = run_condition("relay", a.relay_host, a.relay_port,
                                          a.n, a.tau, expect_accept=False, ca_pem_bytes=ca_pem_bytes)

    print("\n" + "="*70)
    print(json.dumps(results, indent=2))
    print("="*70)
    for cname, r in results.items():
        metric = "FRR" if r["expect_accept"] else "FAR"
        infra_note = f"  [{r['infra_errors_excluded']}/{r['n_total_attempted']} infra errors excluded]" if r['infra_errors_excluded'] else ""
        print(f"{cname}: {metric} = {r['error_rate']*100:.2f}%  (n_clean={r['n_clean']})"
              f"  95% upper bound (one-sided CP) = {r['clopper_pearson_95_one_sided_upper']*100:.3f}%"
              + (f"  [rule-of-three: <= {r['rule_of_three_bound']*100:.2f}%]" if r['rule_of_three_bound'] else "")
              + f"  | two-sided CI [{r['clopper_pearson_95_two_sided'][0]*100:.3f}%, {r['clopper_pearson_95_two_sided'][1]*100:.3f}%]"
              + infra_note)
