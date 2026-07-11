# m5_audit.py -- Module 5: audit trail. Every decision -> an explanation record.
# Makes the controller EXPLAINABLE (one of the 3 academic properties) and feeds the
# live demo's visible reasoning. Pure stdlib. Append-only JSONL + human-readable form.
import json, time

class AuditTrail:
    def __init__(self, path="controller_audit.jsonl"):
        self.path = path
        self.records = []

    def record(self, t, est, regime, regime_reason, action, action_reason):
        rec = {
            "time": t,
            "regime": regime,
            "evidence": {
                "K_hat": est.get("K_hat") if est else None,
                "beta_hat": est.get("beta_hat") if est else None,
                "beta_lcb": est.get("beta_lcb") if est else None,
                "conf": est.get("conf") if est else None,
                "data_quality": est.get("data_quality") if est else None,
            },
            "regime_reason": regime_reason,
            "action": action,
            "action_reason": action_reason,
        }
        self.records.append(rec)
        try:
            with open(self.path, "a") as f:
                f.write(json.dumps(rec) + "\n")
        except Exception:
            pass  # never let logging crash the controller
        return rec

    @staticmethod
    def human(rec):
        # the operator-facing explanation (also the demo's on-screen reason)
        e = rec["evidence"]
        lines = []
        lines.append("Time:   %s" % time.strftime("%H:%M:%S", time.localtime(rec["time"])))
        lines.append("Regime: %s" % rec["regime"])
        lines.append("Reason:")
        if e["beta_hat"] is not None:
            lines.append("  motion-only linkage (beta_hat) = %s" % e["beta_hat"])
            lines.append("  anonymity-set K = %s, confidence = %s" % (e["K_hat"], e["conf"]))
        if rec["regime_reason"].get("trigger"):
            lines.append("  trigger: %s" % rec["regime_reason"]["trigger"])
        if rec["regime_reason"].get("meaning"):
            lines.append("  meaning: %s" % rec["regime_reason"]["meaning"])
        a = rec["action"]
        lines.append("Decision:")
        decisions = []
        if a.get("rotate"): decisions.append("rotate credential")
        else: decisions.append("suppress rotation")
        if a.get("kb_enforce"): decisions.append("enforce Kinematic Binding")
        if a.get("pqc_primitive"): decisions.append("PQC = %s" % a["pqc_primitive"])
        else: decisions.append("PQC = NONE FEASIBLE (alert)")
        decisions.append("budget = %s" % a.get("budget_alloc"))
        if a.get("alert"): decisions.append("** OPERATOR ALERT **")
        for d in decisions: lines.append("  %s" % d)
        return "\n".join(lines)

if __name__ == "__main__":
    # demo the human-readable form with the supervisor's example shape
    at = AuditTrail("/tmp/_audit_test.jsonl")
    rec = at.record(time.time(),
        {"K_hat":1,"beta_hat":0.91,"beta_lcb":0.86,"conf":0.96,"data_quality":"OK"},
        "PRIVACY_FUTILE",
        {"trigger":"beta_hat=0.910 >= tau_privacy=0.800 (conf=0.96)",
         "meaning":"required identifier-layer privacy objective unachievable under motion floor"},
        {"rotate":False,"kb_enforce":False,"pqc_primitive":"ML-DSA-44","budget_alloc":"authentication-weighted","alert":False},
        {"objective":"redirect to auth"})
    print(AuditTrail.human(rec))