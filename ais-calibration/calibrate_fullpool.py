# calibrate_fullpool.py -- full-population-candidate version of the held-out calibration.
# Targets = held-out vessels (as in calibrate_holdout). Candidates = ENTIRE fleet.
# Self-check: with candidates restricted to the held-out set it must reproduce
# calibrate_holdout's rate; then it widens the pool and reports the drop.
import argparse, sys, random, math
sys.path.insert(0, ".")
from calibrate_motion import load_tracks, split_track, predict, haversine_nm, boot
from calibrate_holdout import split_vessels, subset, GAP_CANDIDATES, ANCHOR

def reid_two_set(target_tracks, candidate_tracks, frac, gate_nm, gap_s, seed=0):
    # Re-link each target's continuation against the candidate pool. Identical scoring
    # to calibrate_motion.motion_reid, but targets and candidates are separate dicts.
    dt_max = gap_s + 900
    tb = {}  # target before/after
    for m in target_tracks:
        b, a = split_track(target_tracks[m], frac, gap_s)
        if len(b) >= 2 and len(a) >= 2:
            tb[m] = (b, a)
    cb = {}  # candidate 'before' histories
    for c in candidate_tracks:
        b, a = split_track(candidate_tracks[c], frac, gap_s)
        if len(b) >= 2 and len(a) >= 2:
            cb[c] = b
    hits = []
    for q, (qb, qa) in tb.items():
        a_lat, a_lon = qa[0][1], qa[0][2]
        scored = []
        for c, cbef in cb.items():
            dt = qa[0][0] - cbef[-1][0]
            if dt <= 0 or dt > dt_max:
                continue
            p_lat, p_lon = predict(cbef[-1], dt)
            scored.append((haversine_nm(a_lat, a_lon, p_lat, p_lon), c))
        if not scored:
            continue
        scored.sort()
        hits.append(1 if scored[0][1] == q else 0)
    rate = 100 * sum(hits) / len(hits) if hits else 0.0
    return rate, hits, len(hits)

def choose_gap(calib_tracks, frac, gate_nm, gate_s, seed):
    from calibrate_motion import motion_reid
    best = (None, None, None)
    for gap in GAP_CANDIDATES:
        rate, *_ , n = motion_reid(calib_tracks, frac, gate_nm, gate_s, gap, seed=seed)
        diff = abs(rate - ANCHOR)
        if best[1] is None or diff < best[1]:
            best = (gap, diff, rate)
    return best[0]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--split-frac", type=float, default=0.6)
    ap.add_argument("--gate-nm", type=float, default=2.0)
    ap.add_argument("--gate-s", type=float, default=3.0)
    ap.add_argument("--min-fixes", type=int, default=10)
    ap.add_argument("--calib-frac", type=float, default=0.5)
    ap.add_argument("--split-seed", type=int, default=0)
    a = ap.parse_args()

    tracks = load_tracks(a.csv, a.min_fixes)
    calib_ids, heldout_ids = split_vessels(tracks, seed=a.split_seed, calib_frac=a.calib_frac)
    calib_tracks   = subset(tracks, calib_ids)
    heldout_tracks = subset(tracks, heldout_ids)
    print(f"split: {len(calib_tracks)} calib | {len(heldout_tracks)} held-out "
          f"| {len(tracks)} full fleet (seed={a.split_seed})", file=sys.stderr)

    gap = choose_gap(calib_tracks, a.split_frac, a.gate_nm, a.gate_s, a.split_seed)
    print(f"frozen gap = {gap}s (chosen on calibration vessels only)")

    # SELF-CHECK: held-out targets vs held-out candidates == calibrate_holdout scoring.
    rate_sc, hits_sc, n_sc = reid_two_set(heldout_tracks, heldout_tracks,
                                          a.split_frac, a.gate_nm, gap, seed=a.split_seed+1)
    print(f"[self-check] held-out targets vs HELD-OUT pool: {rate_sc:.1f}%  (n={n_sc}) "
          f"-- should match calibrate_holdout for this seed")

    # FULL-POOL: held-out targets vs the ENTIRE fleet as candidates.
    rate_fp, hits_fp, n_fp = reid_two_set(heldout_tracks, tracks,
                                          a.split_frac, a.gate_nm, gap, seed=a.split_seed+1)
    lo, hi = boot(hits_fp, iters=2000, seed=a.split_seed)
    print(f"[full-pool]  held-out targets vs FULL FLEET ({len(tracks)} cand.): "
          f"{rate_fp:.1f}%  95% CI [{lo:.1f}, {hi:.1f}]  (n={n_fp})")
    print(f"drop vs held-out pool: {rate_sc - rate_fp:+.1f} pts")

if __name__ == "__main__":
    main()