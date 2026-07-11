# m3_selector.py -- Module 3: action selector.
# Maps (regime, resource state, threat) -> concrete action vector.
# Review points implemented:
#  #2 regime sets the OBJECTIVE; concrete action also depends on budget/link/threat/cred_age
#  #5 PQC primitive = constrained pick: min cost s.t. security>=floor, fits latency+bandwidth.
#     HARD security floor: never weaker crypto just because the link is poor.
# Pure stdlib.

# PQC primitive cost profiles (from Pillar A + Step 2.2 measured work).
# sec_level = NIST level; sig_b = signature bytes; sign_ms = approx sign cost.
PRIMITIVES = {
    "Falcon-512":  {"sec":1, "sig_b":657,  "sign_ms":0.28},
    "ML-DSA-44":   {"sec":2, "sig_b":2420, "sign_ms":0.07},
    "ML-DSA-65":   {"sec":3, "sig_b":3309, "sign_ms":0.12},
    "SLH-DSA-128s":{"sec":1, "sig_b":7856, "sign_ms":615.0},  # hash-based; heavy
}

def select_pqc(sec_floor, budget_bytes, max_latency_ms, prefer="cost"):
    # constrained selection (#5): feasible set = primitives meeting the HARD security
    # floor AND fitting bandwidth + latency. Among feasible, pick lowest cost.
    # If NONE feasible, return None + reason (caller must handle -> fallback/alert).
    feasible = []
    for name, p in PRIMITIVES.items():
        if p["sec"] < sec_floor:        # HARD floor: never go below required security
            continue
        if p["sig_b"] > budget_bytes:   # bandwidth constraint
            continue
        if p["sign_ms"] > max_latency_ms:  # latency constraint
            continue
        feasible.append((name, p))
    if not feasible:
        return None, "no primitive meets security floor within budget/latency"
    # cost metric: bytes dominate on the bandwidth-bound NTN path (thesis finding)
    feasible.sort(key=lambda kv: (kv[1]["sig_b"], kv[1]["sign_ms"]))
    return feasible[0][0], "min-cost feasible at sec>=%d" % sec_floor

def select_action(regime, ctx):
    # ctx: budget_bytes, max_latency_ms, threat(0..2), bearer, cred_age, sec_floor
    a = {"rotate":False, "kb_enforce":False, "pqc_primitive":None,
         "budget_alloc":"balanced", "alert":False, "auth_mode":"standard"}
    rsn = {}
    budget = ctx.get("budget_bytes", 9000)
    maxlat = ctx.get("max_latency_ms", 1000.0)
    threat = ctx.get("threat", 0)
    cred_age = ctx.get("cred_age", 0)
    # security floor rises with threat; regime can raise it but NEVER lower below threat (#5)
    sec_floor = max(ctx.get("sec_floor", 1), 1 + (1 if threat>=1 else 0) + (1 if threat>=2 else 0))

    if regime == "PRIVACY_FEASIBLE":
        rsn["objective"] = "capture unlinkability while ambiguity exists"
        # rotate only if it's worth it: enough cred_age AND genuine ambiguity (caller gated)
        a["rotate"] = (cred_age >= ctx.get("min_rotate_age", 3))
        a["budget_alloc"] = "privacy-weighted"
        # even while pursuing privacy, a relay/high-threat signal forces KB (regime-independent)
        if threat >= 2 or ctx.get("relay") or ctx.get("latency_inversion"):
            a["kb_enforce"] = True
            a["auth_mode"] = "kinematic-binding"
            a["alert"] = True
        a["pqc_primitive"], rsn["pqc"] = select_pqc(sec_floor, budget, maxlat)

    elif regime == "PRIVACY_FUTILE":
        rsn["objective"] = "privacy unachievable under motion floor -> redirect to auth"
        a["rotate"] = False                      # do not waste a rotation
        a["budget_alloc"] = "authentication-weighted"
        # FUTILE redirects budget to AUTHENTICATION RESILIENCE -- so a relay/high-threat
        # signal here MUST trigger KB, even away from the seam. Relays are not seam-only.
        if threat >= 2 or ctx.get("relay") or ctx.get("latency_inversion"):
            a["kb_enforce"] = True
            a["auth_mode"] = "kinematic-binding"
            a["alert"] = True
        # spend the freed budget on stronger auth where it helps
        a["pqc_primitive"], rsn["pqc"] = select_pqc(sec_floor, budget, maxlat)

    elif regime == "SEAM_AUTH_PRIORITY":
        rsn["objective"] = "max exposure at handover -> authentication priority + KB"
        a["kb_enforce"] = True                   # verifier-enforced (see Module 4 trust split)
        a["auth_mode"] = "kinematic-binding"
        a["budget_alloc"] = "authentication-weighted"
        a["pqc_primitive"], rsn["pqc"] = select_pqc(sec_floor, budget, maxlat)
        # watch for the latency-inversion / downgrade signature
        a["alert"] = bool(ctx.get("latency_inversion", False))

    else:  # UNKNOWN_FALLBACK
        rsn["objective"] = "uncertain state -> fail safe: no privacy claim, strengthen auth"
        a["rotate"] = False                      # never rotate on uncertainty
        a["kb_enforce"] = True                   # fail closed on auth
        a["auth_mode"] = "kinematic-binding"
        a["budget_alloc"] = "authentication-weighted"
        # pick the strongest primitive that still fits (conservative), floor raised
        a["pqc_primitive"], rsn["pqc"] = select_pqc(max(sec_floor,2), budget, maxlat)
        a["alert"] = True

    # honest guard: if no PQC primitive is feasible, that's an alert condition, not a
    # silent weak-crypto fallback (#5).
    if a["pqc_primitive"] is None:
        a["alert"] = True
        rsn["pqc_warning"] = "NO feasible primitive at required security floor -> ALERT, do not downgrade"
    rsn["sec_floor_used"] = sec_floor
    return a, rsn

if __name__ == "__main__":
    import json
    tests = [
        ("PRIVACY_FEASIBLE", {"budget_bytes":9000,"max_latency_ms":1000,"threat":0,"cred_age":5}),
        ("PRIVACY_FUTILE",   {"budget_bytes":9000,"max_latency_ms":1000,"threat":0,"cred_age":5}),
        ("SEAM_AUTH_PRIORITY",{"budget_bytes":9000,"max_latency_ms":1000,"threat":2,"latency_inversion":True}),
        ("UNKNOWN_FALLBACK", {"budget_bytes":9000,"max_latency_ms":1000,"threat":1}),
        # constrained: tiny NB-IoT budget, only Falcon fits
        ("SEAM_AUTH_PRIORITY",{"budget_bytes":700,"max_latency_ms":1000,"threat":0}),
        # impossible: high threat (floor=3) but only 700B budget -> no feasible -> ALERT
        ("SEAM_AUTH_PRIORITY",{"budget_bytes":700,"max_latency_ms":1000,"threat":2}),
    ]
    for regime, ctx in tests:
        a, rsn = select_action(regime, ctx)
        print(regime, "budget=%s threat=%s" % (ctx.get("budget_bytes"), ctx.get("threat")))
        print("   action:", json.dumps(a))
        print("   reason:", json.dumps(rsn))