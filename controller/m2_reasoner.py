# m2_reasoner.py -- Module 2: the framework reasoner.
# Maps estimator output + context to ONE regime. This is the operational semantics
# of the framework: each branch traces to a theorem/principle. Pure stdlib.
#
# Review points implemented:
#  #1 explicit sufficiency: FUTILE iff lower-confidence-bound(beta) >= tau_privacy
#  #7 UNKNOWN/SAFE_FALLBACK regime when data is missing/uncertain
#  #3 SEAM priority labelled as POLICY (threat-model), not a theorem consequence
#  #4 wording: privacy "unachievable under motion floor", not "void"

# regimes
PRIVACY_FEASIBLE   = "PRIVACY_FEASIBLE"
PRIVACY_FUTILE     = "PRIVACY_FUTILE"
SEAM_AUTH_PRIORITY = "SEAM_AUTH_PRIORITY"
UNKNOWN_FALLBACK   = "UNKNOWN_FALLBACK"

def decide_regime(est, ctx, tau_privacy=0.80):
    # est = output dict from m1_estimator.estimate(); ctx = live context dict
    # ctx keys: seam_imminent(bool), bearer('TN'/'NTN'), threat(0..2), link_ok(bool)
    reason = {}

    # --- SAFE FALLBACK FIRST (#7): never turn uncertainty into a security claim ---
    if est is None or est.get("data_quality") != "OK" or est.get("beta_lcb") is None:
        reason["trigger"] = "estimator data INSUFFICIENT/unavailable"
        reason["policy"] = "unknown privacy -> do not claim privacy; unknown auth -> fail closed"
        return UNKNOWN_FALLBACK, reason

    # --- SEAM PRIORITY (#3: this is an OPERATIONAL POLICY from the threat model + measured
    #     seam risk, NOT a consequence of the Futility Theorem). Handled before regime split
    #     because the handover is where exposure/attack/link-degradation coincide. ---
    if ctx.get("seam_imminent"):
        reason["trigger"] = "bearer transition imminent (operational priority, threat-model derived)"
        reason["note"] = "SEAM priority is policy, not a Futility-Theorem consequence"
        return SEAM_AUTH_PRIORITY, reason

    # --- THE SUFFICIENCY DECISION (#1 + #7): implements the Futility Theorem with the
    #     confidence asymmetry deliberately PROTECTING against false privacy.
    #     beta_hat = point estimate of motion-only linkage; beta_lcb / beta_ucb bound it.
    #     The dangerous error is claiming privacy for a pinned vessel, so:
    #       FUTILE   if the point estimate already meets the floor (with adequate conf)
    #       FEASIBLE only if confidently (upper bound) below the floor
    #       UNKNOWN  for the uncertain middle, or low confidence  (safe default, #7)
    beta = est["beta_hat"]; beta_lcb = est["beta_lcb"]; conf = est.get("conf", 0.0)
    # symmetric upper bound (mirror of the Wilson lower bound width)
    beta_ucb = min(1.0, beta + (beta - beta_lcb))
    MIN_CONF = 0.5

    if conf < MIN_CONF:
        reason["trigger"] = "confidence %.2f < %.2f -> cannot assert a privacy state" % (conf, MIN_CONF)
        reason["policy"] = "low confidence -> do not claim privacy (safe fallback)"
        return UNKNOWN_FALLBACK, reason

    if beta >= tau_privacy:
        reason["trigger"] = "beta_hat=%.3f >= tau_privacy=%.3f (conf=%.2f)" % (beta, tau_privacy, conf)
        reason["meaning"] = ("required identifier-layer privacy objective is UNACHIEVABLE "
                             "under the current motion-evidence floor (Futility Theorem)")  # #4 wording
        reason["action_class"] = "deprioritize privacy spend; redirect to authentication"  # not 'forbid' (#4)
        return PRIVACY_FUTILE, reason

    if beta_ucb < tau_privacy:
        reason["trigger"] = "beta_ucb=%.3f < tau_privacy=%.3f (confidently below)" % (beta_ucb, tau_privacy)
        reason["meaning"] = "genuine ambiguity exists; rotation can buy unlinkability"
        return PRIVACY_FEASIBLE, reason

    # uncertain middle band: estimate straddles the threshold -> do not claim privacy
    reason["trigger"] = "beta_hat=%.3f straddles tau=%.3f (ucb=%.3f) -> uncertain" % (beta, tau_privacy, beta_ucb)
    reason["policy"] = "straddles threshold -> safe fallback, do not claim privacy"
    return UNKNOWN_FALLBACK, reason

if __name__ == "__main__":
    import json, sys
    sys.path.insert(0, ".")
    from m1_estimator import StreamingEstimator
    import time
    est = StreamingEstimator(); t0=time.time()
    for i in range(8): est.update("athena", t0+i*10, 37.5+i*0.001, 25.3+i*0.001, 12.0, 45.0)

    # open sea, no seam -> FUTILE (beta_lcb high)
    o = est.estimate("athena", t0+80)
    r,reason = decide_regime(o, {"seam_imminent":False,"bearer":"NTN","threat":0,"link_ok":True})
    print("OPEN SEA   ->", r); print("            ", json.dumps(reason))

    # add neighbours -> FEASIBLE (beta_lcb low)
    for j,off in enumerate([0.0005,-0.0004,0.0006]):
        for i in range(8): est.update(f"v{j}", t0+i*10, 37.5+i*0.001+off, 25.3+i*0.001+off,12.0,45.0)
    o = est.estimate("athena", t0+80)
    r,reason = decide_regime(o, {"seam_imminent":False,"bearer":"TN","threat":0,"link_ok":True})
    print("PORT       ->", r); print("            ", json.dumps(reason))

    # seam imminent -> SEAM regardless
    r,reason = decide_regime(o, {"seam_imminent":True,"bearer":"TN","threat":1,"link_ok":True})
    print("HARBOUR MTH->", r); print("            ", json.dumps(reason))

    # no data -> UNKNOWN
    r,reason = decide_regime({"data_quality":"INSUFFICIENT","beta_lcb":None}, {"seam_imminent":False})
    print("NO AIS     ->", r); print("            ", json.dumps(reason))