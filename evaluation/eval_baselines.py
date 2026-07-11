import sys; sys.path.insert(0,".")
from m2_reasoner import decide_regime
from m3_selector import select_action

def policy_static(e, ctx, st):
    st["epoch"] = st.get("epoch",0)+1
    rotate = (st["epoch"] % 3 == 0)
    return {"rotate":rotate, "kb_enforce":False, "pqc_primitive":"ML-DSA-65",
            "budget_alloc":"balanced", "alert":False}

def policy_best_static(e, ctx, st):
    return {"rotate":False, "kb_enforce":True, "pqc_primitive":"ML-DSA-44",
            "budget_alloc":"authentication-weighted", "alert":False}

def policy_blind_adaptive(e, ctx, st):
    st["age"] = st.get("age",0)+1
    seam = ctx.get("seam_imminent")
    threat = ctx.get("threat",0)
    link_ok = ctx.get("link_ok",True)
    rotate = (link_ok and st["age"]>=3 and not seam)
    if rotate: st["age"]=0
    prim = "ML-DSA-65" if threat>=2 else ("ML-DSA-44" if threat>=1 else "Falcon-512")
    return {"rotate":rotate, "kb_enforce":bool(seam), "pqc_primitive":prim,
            "budget_alloc":"authentication-weighted" if seam else "balanced",
            "alert":bool(ctx.get("latency_inversion") or ctx.get("relay"))}

def policy_framework(e, ctx, st):
    regime, _ = decide_regime(e, ctx)
    action, _ = select_action(regime, ctx)
    return action

POLICIES = {
    "static":         policy_static,
    "best_static":    policy_best_static,
    "blind_adaptive": policy_blind_adaptive,
    "framework":      policy_framework,
}

if __name__=="__main__":
    print("4 comparators defined:", list(POLICIES.keys()))
    print("KEY comparison: framework vs blind_adaptive (both adapt; only framework uses sufficiency)")
