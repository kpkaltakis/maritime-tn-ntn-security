# export_dashboard_data.py -- exports real run data at animation-appropriate
# resolution: FULL resolution for puget/puget_return (179 epochs each, small
# enough to keep entirely), moderate downsample for aegean (3780 epochs -- kept
# fine enough for smooth movement, coarse enough to keep file size reasonable).
# Every kept point carries its real regime/K/beta/action/enforcement, not just
# transitions -- the dashboard needs continuous values, not just changes.
import sys, json

def load_jsonl(path):
    return [json.loads(l) for l in open(path)]

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", default="demo_audit_live2.jsonl")
    ap.add_argument("--positions", default="demo_positions.jsonl")
    ap.add_argument("--enforcement", default="demo_enforcement.jsonl")
    ap.add_argument("--aegean-downsample", type=int, default=3,
                     help="keep every Nth aegean epoch (puget/return always kept in full)")
    ap.add_argument("--out", default="dashboard_data.json")
    a = ap.parse_args()

    audit = load_jsonl(a.audit)
    pos_by_t = {p["time"]: p for p in load_jsonl(a.positions)}
    enf_by_t = {}
    try:
        for e in load_jsonl(a.enforcement):
            enf_by_t[e["time"]] = e.get("note")
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
            "conf": r["evidence"].get("conf"),
            "rotate": r["action"].get("rotate"), "kb_enforce": r["action"].get("kb_enforce"),
            "primitive": r["action"].get("pqc_primitive"), "alert": r["action"].get("alert"),
            "enforcement": enf_by_t.get(r["time"]),
        })
    joined.sort(key=lambda x: x["t"])

    out = []
    for j in joined:
        if j["chapter"] == "aegean":
            pass
        out.append(j)
    # apply downsample only within the aegean run, keeping first/last of that chapter
    final = []
    aegean_idx = 0
    for j in out:
        if j["chapter"] != "aegean":
            final.append(j)
        else:
            if aegean_idx % a.aegean_downsample == 0:
                final.append(j)
            aegean_idx += 1
    # always keep the very last real aegean point (chapter boundary) even if downsample skipped it
    last_aegean = [j for j in out if j["chapter"] == "aegean"][-1]
    if last_aegean not in final:
        # insert it in correct time order
        final.append(last_aegean)
        final.sort(key=lambda x: x["t"])

    with open(a.out, "w") as f:
        json.dump(final, f, default=str)
    print(f"joined {len(joined)} real epochs -> {len(final)} kept for animation "
          f"(puget/return full resolution, aegean every {a.aegean_downsample}th)", file=sys.stderr)
    chapters = {}
    for j in final:
        chapters[j["chapter"]] = chapters.get(j["chapter"], 0) + 1
    print("per-chapter counts:", chapters, file=sys.stderr)