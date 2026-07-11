# consolidate_for_viz.py -- joins the three real per-run logs (audit, positions,
# enforcement) by exact timestamp, then condenses to what a Tier 2 visualization
# actually needs: every regime TRANSITION (not every epoch -- most of a chapter is
# one uniform regime), the seam event in full detail, and a downsampled trajectory
# for the map path. All values are real; downsampling reduces volume, not fidelity
# of what's reported.
import sys, json

def load_jsonl(path):
    return [json.loads(l) for l in open(path)]

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default="demo_audit_live2.jsonl")
    ap.add_argument("--positions", default="demo_positions.jsonl")
    ap.add_argument("--enforcement", default="demo_enforcement.jsonl")
    ap.add_argument("--path-downsample", type=int, default=15,
                     help="keep every Nth point for the map path (regime transitions are always kept regardless)")
    ap.add_argument("--out", default="demo_viz_data.json")
    a = ap.parse_args()

    audit = load_jsonl(a.audit)
    pos_by_t = {p["time"]: p for p in load_jsonl(a.positions)}
    enf_by_t = {}
    try:
        for e in load_jsonl(a.enforcement):
            enf_by_t.setdefault(e["time"], []).append(e)
    except FileNotFoundError:
        pass

    joined = []
    for r in audit:
        p = pos_by_t.get(r["time"])
        if not p:
            continue
        joined.append({
            "t": r["time"], "chapter": p["chapter"], "lat": p["lat"], "lon": p["lon"],
            "regime": r["regime"], "K": r["evidence"].get("K_hat"), "beta": r["evidence"].get("beta_hat"),
            "action": r["action"], "enforcement": enf_by_t.get(r["time"]),
        })
    joined.sort(key=lambda x: x["t"])

    # regime transitions: every point where regime differs from the previous one
    transitions = []
    prev_regime = None
    for j in joined:
        if j["regime"] != prev_regime:
            transitions.append(j)
            prev_regime = j["regime"]

    # downsampled path (every Nth point) -- for the map trajectory line
    path = joined[::a.path_downsample]
    # always include the very first and last point of each chapter for clean boundaries
    chapters_seen = set()
    for j in joined:
        if j["chapter"] not in chapters_seen:
            path.append(j); chapters_seen.add(j["chapter"])
    path.sort(key=lambda x: x["t"])
    # dedupe path by t
    seen_t = set(); path_dedup = []
    for p in path:
        if p["t"] not in seen_t:
            path_dedup.append(p); seen_t.add(p["t"])
    path = sorted(path_dedup, key=lambda x: x["t"])

    seam = [j for j in joined if j["chapter"] == "seam"]

    summary = {
        "total_epochs": len(joined),
        "chapters": {c: sum(1 for j in joined if j["chapter"] == c) for c in ["puget","aegean","seam","puget_return"]},
        "regime_transitions": transitions,
        "path": path,
        "seam_event": seam[0] if seam else None,
    }
    with open(a.out, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    print(f"joined {len(joined)} epochs -> {len(transitions)} regime transitions, "
          f"{len(path)} path points, written to {a.out}", file=sys.stderr)
    print(json.dumps(summary, indent=2, default=str))