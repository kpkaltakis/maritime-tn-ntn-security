# reconstruct_positions.py -- recovers (t, chapter, lat, lon) for every epoch of a
# completed Tier 1 run, WITHOUT re-running any network/enforcement calls. Exploits
# a property already proven: replay_chapter()/load_chapter() are pure, deterministic
# functions of the same real CSV data + same selection JSON + same compress/offset
# arguments (confirmed by VM-02 reproducing VM-03's selection numbers exactly). This
# lets Tier 2 pair real position with the real regime/enforcement logs already on
# disk, by exact time-match, with no new testbed activity.
import sys, json
sys.path.insert(0, ".")
from live_demo_voyage import load_chapter, replay_chapter

def positions_for_chapter(target_track, candidates, label, compress=1.0, t_offset=0.0):
    # mirrors replay_chapter's epoch generation exactly, but yields position too --
    # a target report's OWN (lat, lon), not touching the estimator or any network path.
    all_reports = [("__target__", t, lat, lon, sog, cog) for (t, lat, lon, sog, cog) in target_track]
    for m, track in candidates.items():
        all_reports += [(m, t, lat, lon, sog, cog) for (t, lat, lon, sog, cog) in track]
    all_reports.sort(key=lambda r: r[1])
    t0 = target_track[0][0]
    def xform(t):
        return (t0 + (t - t0) / compress) + t_offset
    for m, t, lat, lon, sog, cog in all_reports:
        if m == "__target__":
            yield xform(t), label, lat, lon

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--selection", default="demo_vessel_selection.json")
    ap.add_argument("--compress", type=float, default=30.0)
    ap.add_argument("--out", default="demo_positions.jsonl")
    a = ap.parse_args()

    with open(a.selection) as f:
        sel = json.load(f)

    puget_target, puget_cands = load_chapter("puget", sel["puget"]["csv"], sel["puget"]["mmsi"],
                                              sel["puget"]["candidate_mmsis"],
                                              sel["puget"]["t_start"], sel["puget"]["t_end"])
    aegean_target, aegean_cands = load_chapter("aegean", sel["aegean"]["csv"], sel["aegean"]["mmsi"],
                                                sel["aegean"]["candidate_mmsis"],
                                                sel["aegean"]["t_start"], sel["aegean"]["t_end"])

    # EXACT same offset arithmetic as live_demo_voyage.py's run() -- must match precisely
    # or the reconstructed timestamps won't line up with the real audit/enforcement logs.
    aegean_t_offset = puget_target[-1][0] + 300 - aegean_target[0][0]
    seam_t = aegean_target[-1][0] + aegean_t_offset + 60
    return_t_offset = seam_t + 60 - puget_target[0][0]

    out = open(a.out, "w")
    n = 0
    for t, label, lat, lon in positions_for_chapter(puget_target, puget_cands, "puget", compress=a.compress):
        out.write(json.dumps({"time": t, "chapter": label, "lat": lat, "lon": lon}) + "\n"); n += 1
    for t, label, lat, lon in positions_for_chapter(aegean_target, aegean_cands, "aegean",
                                                     t_offset=aegean_t_offset, compress=a.compress):
        out.write(json.dumps({"time": t, "chapter": label, "lat": lat, "lon": lon}) + "\n"); n += 1
    # seam: the target's position at the seam is the last Puget fix (no new real position
    # exists for a single synthetic timing epoch) -- recorded honestly as such.
    out.write(json.dumps({"time": seam_t, "chapter": "seam",
                           "lat": puget_target[-1][1], "lon": puget_target[-1][2],
                           "note": "seam epoch uses the last real Puget position; no independent position exists for this synthetic timing point"}) + "\n"); n += 1
    for t, label, lat, lon in positions_for_chapter(puget_target, puget_cands, "puget_return",
                                                     t_offset=return_t_offset, compress=a.compress):
        out.write(json.dumps({"time": t, "chapter": label, "lat": lat, "lon": lon}) + "\n"); n += 1
    out.close()
    print(f"wrote {n} position records to {a.out}", file=sys.stderr)