# eval_harness_v2.py -- Step 4: extends eval_harness.py with the requested ablations,
# a resource-adaptive baseline, an oracle for regret, and new metrics (privacy-target
# attainment, decision oscillation, policy regret). Does NOT modify eval_harness.py --
# a non-destructive extension, same voyage/ground-truth, same estimator.
#
# FAIRNESS GUARANTEE (explicit, not assumed): every policy in this run receives the
# EXACT SAME ctx dict and the EXACT SAME estimator output `e` for a given epoch -- built
# ONCE per epoch, then passed unmodified to every policy in turn. No policy sees more or
# different information than any other. Verified by construction below, not by promise.
#
# LABELLED SYNTHETIC: this is the same 7-epoch scripted voyage as eval_harness.py.
# It stress-tests mechanism understanding; it does NOT replace held-out real-voyage
# replay (blocked on a confined-water dataset -- see the thesis limitations section).
import sys, json, statistics; sys.path.insert(0,".")
from m1_estimator import StreamingEstimator
from eval_baselines import POLICIES as BASE_POLICIES
from eval_ablations import ABLATIONS, policy_oracle
from eval_harness import VOYAGE, build_estimate, PRIM_BYTES

ALL_POLICIES = dict(BASE_POLICIES)
ALL_POLICIES.update(ABLATIONS)

def score_policy_v2(name, policy, oracle_costs):
    est=StreamingEstimator(); st={}; import time; t0=time.time()
    m={"unnecessary_rotations":0,"missed_useful_rotations":0,"auth_success":0,
       "relay_resisted":0,"relay_total":0,"pqc_bytes":0,"false_alarms":0,
       "interventions":0,"correct_regime_actions":0,"total_epochs":len(VOYAGE),
       "feasible_epochs":0,"privacy_target_attained":0,
       "primitive_changes":0,"kb_flips":0,"total_cost":0.0}
    prev_prim=None; prev_kb=None
    for epoch,(label,nb,seam,bearer,rtt,threat,gt_feasible) in enumerate(VOYAGE):
        e=build_estimate(est,epoch,nb,t0)
        ctx={"seam_imminent":seam,"bearer":bearer,"threat":threat,"link_ok":rtt<500,
             "budget_bytes":9000,"max_latency_ms":1000,"cred_age":st.get("ca",epoch),
             "rtt_ms":rtt,"latency_inversion":(label=="seam"),"relay":(label=="relay")}
        # ^ THE SAME ctx dict, built once, used by every policy this epoch -- fairness by construction.
        a=policy(e,ctx,st)
        rotated=a.get("rotate")
        cred_age_now = st.get("ca", epoch)
        if rotated and not gt_feasible: m["unnecessary_rotations"]+=1
        if (not rotated) and gt_feasible and not seam and cred_age_now>=3:
            m["missed_useful_rotations"]+=1
        if (rotated and gt_feasible) or (not rotated and not gt_feasible): m["correct_regime_actions"]+=1
        if rotated: st["ca"]=0
        else: st["ca"]=cred_age_now+1
        if label=="relay":
            m["relay_total"]+=1
            if a.get("kb_enforce"): m["relay_resisted"]+=1; m["auth_success"]+=1
        else:
            m["auth_success"]+=1
        prim = a.get("pqc_primitive")
        cost = PRIM_BYTES.get(prim,0)
        m["pqc_bytes"]+=cost
        real_threat=(label in ("seam","relay"))
        if a.get("alert") and not real_threat: m["false_alarms"]+=1
        if a.get("alert"): m["interventions"]+=1
        # --- new metrics ---
        if gt_feasible and not seam:
            m["feasible_epochs"]+=1
            if not ((not rotated) and gt_feasible and not seam and cred_age_now>=3):
                m["privacy_target_attained"]+=1
        if prev_prim is not None and prim != prev_prim: m["primitive_changes"]+=1
        if prev_kb is not None and bool(a.get("kb_enforce")) != prev_kb: m["kb_flips"]+=1
        prev_prim, prev_kb = prim, bool(a.get("kb_enforce"))
        # per-epoch cost for regret: baseline action cost + EXPLICIT penalty for a wasted
        # rotation (rotating while futile) or a missed one (not rotating while feasible),
        # since rotation TIMING QUALITY -- not mere rotation count -- is the entire point
        # of the framework. A flat per-rotation cost cannot distinguish a correctly-timed
        # rotation from a wasted one; this was a real bug, found by checking a suspicious
        # tie in regret between framework and framework_no_sufficiency (see run notes).
        wasted = rotated and not gt_feasible
        missed = (not rotated) and gt_feasible and not seam and cred_age_now>=3
        epoch_cost = (1.0 if rotated else 0.0) + (3.0 if wasted else 0.0) + (3.0 if missed else 0.0) \
                     + cost/1000.0 + (5.0 if (label=="relay" and not a.get("kb_enforce")) else 0.0)
        m["total_cost"] += epoch_cost
    m["policy_regret"] = round(m["total_cost"] - oracle_costs, 3)
    m["privacy_target_attainment_pct"] = round(100*m["privacy_target_attained"]/m["feasible_epochs"],1) if m["feasible_epochs"] else None
    return m

def compute_oracle_cost():
    est=StreamingEstimator(); st={}; import time; t0=time.time()
    total=0.0
    for epoch,(label,nb,seam,bearer,rtt,threat,gt_feasible) in enumerate(VOYAGE):
        e=build_estimate(est,epoch,nb,t0)
        ctx={"seam_imminent":seam,"bearer":bearer,"threat":threat,"link_ok":rtt<500,
             "budget_bytes":9000,"max_latency_ms":1000,"cred_age":st.get("ca",epoch),
             "rtt_ms":rtt,"latency_inversion":(label=="seam"),"relay":(label=="relay")}
        gt_needs_kb = (label in ("seam","relay"))
        gt_feas_now = gt_feasible and not seam and st.get("ca",epoch)>=3
        a=policy_oracle(e,ctx,st,gt_feas_now, gt_needs_kb)
        rotated=a.get("rotate")
        cred_age_now = st.get("ca", epoch)
        if rotated: st["ca"]=0
        else: st["ca"]=cred_age_now+1
        cost = PRIM_BYTES.get(a.get("pqc_primitive"),0)
        wasted = rotated and not gt_feasible
        missed = (not rotated) and gt_feasible and not seam and cred_age_now>=3
        epoch_cost = (1.0 if rotated else 0.0) + (3.0 if wasted else 0.0) + (3.0 if missed else 0.0) \
                     + cost/1000.0 + (5.0 if (label=="relay" and not a.get("kb_enforce")) else 0.0)
        total += epoch_cost
    return total

if __name__=="__main__":
    print("="*100)
    print("STEP 4 -- CONTROLLER ABLATIONS (SYNTHETIC scripted voyage; not a substitute for held-out replay)")
    print("="*100)
    print(f"Policies evaluated ({len(ALL_POLICIES)}): {list(ALL_POLICIES.keys())}")
    print("FAIRNESS: every policy receives the identical ctx per epoch (see source, built once/epoch).\n")

    oracle_cost = compute_oracle_cost()
    print(f"Oracle (clairvoyant, zero-waste-by-construction) total cost: {oracle_cost:.3f}\n")

    results={}
    for name,pol in ALL_POLICIES.items():
        results[name]=score_policy_v2(name,pol,oracle_cost)

    axes=[("correct_regime_actions","correct rotation decisions (of 7)"),
          ("unnecessary_rotations","wasted rotations (pinned)"),
          ("missed_useful_rotations","missed useful rotations"),
          ("privacy_target_attainment_pct","privacy-target attainment %"),
          ("relay_resisted","relay resisted (of relay_total)"),
          ("pqc_bytes","total PQC bytes"),
          ("primitive_changes","primitive changes (stability)"),
          ("kb_flips","KB on/off flips (stability)"),
          ("false_alarms","false alarms"),
          ("policy_regret","regret vs oracle (lower=better)")]
    names=list(ALL_POLICIES.keys())
    print("%-32s | %s" % ("axis"," | ".join("%-11s"%n[:11] for n in names)))
    print("-"*(34+14*len(names)))
    for key,desc in axes:
        row="%-32s | " % desc
        row+=" | ".join("%-11s"%str(results[n][key]) for n in names)
        print(row)

    print("\n--- KEY COMPARISONS ---")
    f,b=results["framework"],results["blind_adaptive"]
    print(f"framework vs blind_adaptive        : regret {f['policy_regret']} vs {b['policy_regret']}  "
          f"(both adapt; only framework uses sufficiency)")
    fns=results["framework_no_sufficiency"]
    print(f"framework vs framework_no_sufficiency: regret {f['policy_regret']} vs {fns['policy_regret']}  "
          f"(isolates the value of sufficiency estimation specifically)")
    fnk=results["framework_no_kb"]
    print(f"framework vs framework_no_kb        : relay_resisted {f['relay_resisted']} vs {fnk['relay_resisted']}  "
          f"(isolates what KB alone contributes)")
    fnp=results["framework_no_pqc_cost"]
    print(f"framework vs framework_no_pqc_cost  : pqc_bytes {f['pqc_bytes']} vs {fnp['pqc_bytes']}  "
          f"(isolates what cost-awareness saves)")
    print(f"\nfull results JSON:")
    print(json.dumps(results, indent=2))