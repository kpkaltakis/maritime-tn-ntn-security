# validate_feasible_regime.py -- NOT a re-calibration. tau_privacy=0.80 and gap=900s
# are already locked from the Aegean-only work (Part I, Section 6). This checks how
# that ALREADY-FIXED threshold classifies real Puget Sound vessels -- zero leakage
# risk, since nothing is fit to this data. Reuses predict/haversine_nm/split_track
# unchanged; motion_reid's core loop is replicated (not modified) here only to keep
# per-vessel MMSI alongside (K, beta), which the shared function doesn't expose.
import sys, math, random
sys.path.insert(0, ".")
from calibrate_motion import predict, haversine_nm, split_track, pctile
from check_puget_pinning import load_puget_tracks

TAU_PRIVACY = 0.80  # already locked (Part I, Section 6) -- not tuned here

def motion_reid_per_vessel(tracks, frac, gate_nm, gate_s, gap_s):
    # identical logic to calibrate_motion.motion_reid(), but returns (mmsi, K, beta, hit)
    # tuples instead of aggregate lists, so classification can be checked per vessel.
    ids = list(tracks)
    befores = {}; afters = {}
    for m in ids:
        b, a = split_track(tracks[m], frac, gap_s)
        if len(b) >= 2 and len(a) >= 2:
            befores[m] = b; afters[m] = a
    ids = [m for m in ids if m in befores]
    dt_max = gap_s + 900
    results = []
    for q in ids:
        a_lat, a_lon = afters[q][0][1], afters[q][0][2]
        scored = []
        for c in ids:
            dt = afters[q][0][0] - befores[c][-1][0]
            if dt <= 0 or dt > dt_max:
                continue
            p_lat, p_lon = predict(befores[c][-1], dt)
            d = haversine_nm(a_lat, a_lon, p_lat, p_lon)
            scored.append((d, c))
        if not scored:
            continue
        scored.sort()
        bestd, pick = scored[0]
        K = sum(1 for d, _ in scored if d <= gate_nm)
        K = max(1, K)
        if K == 1:
            beta = 1.0
        else:
            ds = [d for d, _ in scored if d <= gate_nm]
            dmin = min(ds)
            w = [math.exp(-(d-dmin)/max(0.05, gate_nm/4)) for d in ds]
            beta = max(w)/sum(w)
        results.append((q, K, beta, pick == q))
    return results

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="/home/vessel1/puget_subset.csv")
    ap.add_argument("--min-fixes", type=int, default=10)
    ap.add_argument("--gate-nm", type=float, default=2.0)
    ap.add_argument("--gate-s", type=float, default=3.0)
    ap.add_argument("--gap-s", type=float, default=900)
    ap.add_argument("--split-frac", type=float, default=0.6)
    a = ap.parse_args()

    print("loading Puget tracks (streaming)...", file=sys.stderr)
    tracks = load_puget_tracks(a.csv, a.min_fixes)
    print(f"  {len(tracks)} moving vessels", file=sys.stderr)

    results = motion_reid_per_vessel(tracks, a.split_frac, a.gate_nm, a.gate_s, a.gap_s)
    n = len(results)
    if n == 0:
        print("ERROR: no vessels produced a usable before/after split.", file=sys.stderr)
        sys.exit(1)

    k1 = [r for r in results if r[1] == 1]
    kgt1 = [r for r in results if r[1] > 1]

    print("\n" + "="*78)
    print(f"FEASIBLE-REGIME VALIDATION -- tau_privacy={TAU_PRIVACY} (already locked, not tuned here)")
    print("="*78)
    print(f"n = {n} vessels (gap={a.gap_s}s, gate={a.gate_nm}nm/{a.gate_s}s)")
    print(f"K=1 (uniquely pinned): {len(k1)}   K>1 (genuinely confusable): {len(kgt1)}")

    print(f"\n--- K=1 side (n={len(k1)}) ---")
    print("By construction (calibrate_motion.py's beta formula), K=1 always gives beta=1.0,")
    print("so this side is a deterministic check of the pipeline, not an independent test:")
    k1_correct = sum(1 for r in k1 if r[2] >= TAU_PRIVACY)
    print(f"  classified FUTILE (beta>=tau): {k1_correct}/{len(k1)}  ({100*k1_correct/len(k1):.1f}%)"
          if k1 else "  (no K=1 vessels)")

    print(f"\n--- K>1 side (n={len(kgt1)}) -- THE REAL TEST: does tau=0.80, chosen only on ---")
    print("--- near-all-K=1 Aegean data, correctly recognize REAL confined-water         ---")
    print("--- confusability as FEASIBLE, or is it miscalibrated for this regime?        ---")
    if kgt1:
        feasible_correct = sum(1 for r in kgt1 if r[2] < TAU_PRIVACY)
        still_futile = sum(1 for r in kgt1 if r[2] >= TAU_PRIVACY)
        betas_kgt1 = sorted(r[2] for r in kgt1)
        print(f"  classified FEASIBLE (beta<tau):  {feasible_correct}/{len(kgt1)}  ({100*feasible_correct/len(kgt1):.1f}%)")
        print(f"  still classified FUTILE despite K>1: {still_futile}/{len(kgt1)}  ({100*still_futile/len(kgt1):.1f}%)")
        print(f"  beta distribution on K>1 vessels: min={betas_kgt1[0]:.3f} median={pctile(betas_kgt1,50):.3f} "
              f"p90={pctile(betas_kgt1,90):.3f} max={betas_kgt1[-1]:.3f}")
    else:
        print("  (no K>1 vessels in this split -- cannot evaluate)")

    print("\n" + "="*78)
    print("INTERPRETATION")
    print("="*78)
    print("This is a VALIDATION of the already-locked tau_privacy=0.80, not a re-calibration --")
    print("nothing here was fit to this data. If the K>1 'classified FEASIBLE' rate is high,")
    print("the threshold chosen on Aegean data generalizes correctly to real confined-water")
    print("cases. If it is low (most K>1 vessels still read as FUTILE), that is an honest,")
    print("real finding that tau=0.80 may be too strict for the FEASIBLE side and warrants")
    print("further investigation -- report exactly what is found, either way.")