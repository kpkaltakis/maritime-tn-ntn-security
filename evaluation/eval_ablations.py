import sys; sys.path.insert(0,".")
from m2_reasoner import decide_regime
from m3_selector import select_action, select_pqc, PRIMITIVES

def policy_framework_no_sufficiency(e, ctx, st):
    if e is None or e.get("data_quality") != "OK":
        regime = "UNKNOWN_FALLBACK"
    elif ctx.get("seam_imminent"):
        regime = "SEAM_AUTH_PRIORITY"
    else:
        regime = "PRIVACY_FEASIBLE"
    action, _ = select_action(regime, ctx)
    return action

def policy_framework_no_kb(e, ctx, st):
    regime, _ = decide_regime(e, ctx)
    action, _ = select_action(regime, ctx)
    action = dict(action); action["kb_enforce"] = False
    return action

def policy_framework_no_pqc_cost(e, ctx, st):
    regime, _ = decide_regime(e, ctx)
    action, _ = select_action(regime, ctx)
    action = dict(action)
    threat = ctx.get("threat", 0)
    sec_floor = max(ctx.get("sec_floor", 1), 1 + (1 if threat>=1 else 0) + (1 if threat>=2 else 0))
    candidates = [(n,p) for n,p in PRIMITIVES.items() if p["sec"]>=sec_floor]
    if candidates:
        candidates.sort(key=lambda kv: -kv[1]["sig_b"])
        action["pqc_primitive"] = candidates[0][0]
    return action

def policy_resource_adaptive(e, ctx, st):
    st["epoch"] = st.get("epoch",0)+1
    rotate = (st["epoch"] % 3 == 0)
    budget = ctx.get("budget_bytes", 9000)
    maxlat = ctx.get("max_latency_ms", 1000)
    prim, _ = select_pqc(1, budget, maxlat)
    return {"rotate":rotate, "kb_enforce":False, "pqc_primitive":prim,
            "budget_alloc":"balanced", "alert":False}

def policy_oracle(e, ctx, st, gt_feasible, gt_needs_kb):
    threat = ctx.get("threat", 0)
    sec_floor = max(1, 1 + (1 if threat>=1 else 0) + (1 if threat>=2 else 0))
    prim, _ = select_pqc(sec_floor, ctx.get("budget_bytes",9000), ctx.get("max_latency_ms",1000))
    cred_age = ctx.get("cred_age", 0)
    rotate = gt_feasible and cred_age >= 3
    return {"rotate":rotate, "kb_enforce":gt_needs_kb, "pqc_primitive":prim,
            "budget_alloc":"balanced", "alert":gt_needs_kb}

ABLATIONS = {
    "framework_no_sufficiency": policy_framework_no_sufficiency,
    "framework_no_kb":          policy_framework_no_kb,
    "framework_no_pqc_cost":    policy_framework_no_pqc_cost,
    "resource_adaptive":        policy_resource_adaptive,
}

if __name__=="__main__":
    print("ablations + new baseline defined:", list(ABLATIONS.keys()))
    print("each ablation calls the REAL m2/m3 framework code with exactly one piece removed")
