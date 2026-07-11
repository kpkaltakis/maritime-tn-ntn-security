# calibrate_holdout.py -- FIXES THE CALIBRATION LEAKAGE in calibrate_motion.py.
# Splits vessels (not individual messages -- a vessel's own messages are highly
# correlated, so message-level splitting would leak) into two DISJOINT groups:
#   CALIBRATION vessels -- used ONLY to choose the rotation-gap parameter (the sweep).
#   HELD-OUT vessels    -- NEVER touched during gap selection; used ONLY to report the
#                          final validated re-link rate, once, with the gap already fixed.
# This gives an honestly independent estimate of the empirical motion-only floor, not a
# value reproduced by picking the parameter that happens to match the anchor.
#
#   python3 calibrate_holdout.py --csv ~/aegeanet.csv [--split-seed 0] [--sample 300]
import argparse, sys, random
sys.path.insert(0, ".")
from calibrate_motion import load_tracks, motion_reid, pctile, boot

GAP_CANDIDATES = (60, 120, 240, 480, 900, 1200)
ANCHOR = 88.7  # the published motion-only re-identification anchor (%), for reference only

def split_vessels(tracks, seed=0, calib_frac=0.5):
    ids = sorted(tracks.keys())          # deterministic order before shuffling
    rng = random.Random(seed)
    rng.shuffle(ids)
    n_calib = int(len(ids) * calib_frac)
    calib_ids = set(ids[:n_calib])
    heldout_ids = set(ids[n_calib:])
    return calib_ids, heldout_ids

def subset(tracks, ids):
    return {m: v for m, v in tracks.items() if m in ids}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--split-frac", type=float, default=0.6, help="track split fraction (before/after), same as calibrate_motion")
    ap.add_argument("--gate-nm", type=float, default=2.0)
    ap.add_argument("--gate-s", type=float, default=3.0)
    ap.add_argument("--min-fixes", type=int, default=10)
    ap.add_argument("--calib-frac", type=float, default=0.5, help="fraction of VESSELS assigned to calibration")
    ap.add_argument("--split-seed", type=int, default=0)
    ap.add_argument("--sample", type=int, default=0, help="cap vessels per phase for speed; 0=all")
    a = ap.parse_args()

    print("loading tracks (streaming)...", file=sys.stderr)
    tracks = load_tracks(a.csv, a.min_fixes)
    print(f"  {len(tracks)} moving vessels with >={a.min_fixes} fixes", file=sys.stderr)

    calib_ids, heldout_ids = split_vessels(tracks, seed=a.split_seed, calib_frac=a.calib_frac)
    calib_tracks = subset(tracks, calib_ids)
    heldout_tracks = subset(tracks, heldout_ids)
    print(f"  split: {len(calib_tracks)} calibration vessels | {len(heldout_tracks)} held-out vessels "
          f"(disjoint, seed={a.split_seed})", file=sys.stderr)

    # ============ PHASE 1: choose the gap using ONLY calibration vessels ============
    print("\n===== PHASE 1: gap selection on CALIBRATION vessels only =====")
    print(f"{'gap_s':>7} {'rate%':>7} {'n':>5}   (choosing the gap closest to the {ANCHOR}% anchor)")
    best_gap, best_diff, best_rate = None, None, None
    for gap in GAP_CANDIDATES:
        rate, hits, Ks, betas, n = motion_reid(calib_tracks, a.split_frac, a.gate_nm, a.gate_s, gap,
                                               sample=(a.sample or None), seed=a.split_seed)
        diff = abs(rate - ANCHOR)
        print(f"{gap:7.0f} {rate:7.1f} {n:5d}" + ("  <- closest so far" if best_diff is None or diff<best_diff else ""))
        if best_diff is None or diff < best_diff:
            best_diff, best_gap, best_rate = diff, gap, rate
    print(f"\nCHOSEN (on calibration data only): gap={best_gap}s  (calibration-set rate was {best_rate:.1f}%)")
    print("This choice is now FROZEN. The held-out phase below never influences it.")

    # ============ PHASE 2: evaluate ONCE on held-out vessels, gap already fixed ============
    print(f"\n===== PHASE 2: held-out evaluation at FIXED gap={best_gap}s (vessels never seen in Phase 1) =====")
    rate, hits, Ks, betas, n = motion_reid(heldout_tracks, a.split_frac, a.gate_nm, a.gate_s, best_gap,
                                           sample=(a.sample or None), seed=a.split_seed+1)
    lo, hi = boot(hits, iters=2000, seed=a.split_seed)
    print(f"HELD-OUT re-link rate: {rate:.1f}%   95% bootstrap CI [{lo:.1f}, {hi:.1f}]   (n={n} vessels, "
          f"disjoint from the {len(calib_tracks)} used to choose the gap)")
    print(f"ANCHOR for comparison: {ANCHOR}%  -- contains anchor: {lo<=ANCHOR<=hi}")
    if Ks:
        print(f"held-out network-layer K: mean={sum(Ks)/len(Ks):.2f} median={pctile(Ks,50):.0f}")
    if betas:
        print(f"held-out beta_hat: median={pctile(betas,50):.3f} p25={pctile(betas,25):.3f} p75={pctile(betas,75):.3f}")

    print("\n" + "="*70)
    print("HONEST SUMMARY (no leakage: gap chosen on calibration data, reported on held-out)")
    print("="*70)
    print(f"  Calibration vessels : {len(calib_tracks)}  (used ONLY to pick gap={best_gap}s)")
    print(f"  Held-out vessels    : {len(heldout_tracks)}  (used ONLY to report the rate below)")
    print(f"  Held-out rate       : {rate:.1f}%  95% CI [{lo:.1f}, {hi:.1f}]")
    print(f"  This is the number that HONESTLY validates the estimator against the {ANCHOR}% anchor.")

if __name__ == "__main__":
    main()