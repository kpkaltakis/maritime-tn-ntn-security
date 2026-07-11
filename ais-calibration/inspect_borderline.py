# inspect_borderline.py -- for the K>1-but-still-FUTILE cases, show the actual scored
# candidate distances, so we can tell WHY beta stayed high: one dominant candidate
# despite technically-in-gate neighbors (favorable), or something less clean.
import sys, math
sys.path.insert(0, ".")
from calibrate_motion import predict, haversine_nm, split_track
from check_puget_pinning import load_puget_tracks

def inspect(tracks, frac, gate_nm, gate_s, gap_s, tau):
    ids = list(tracks)
    befores = {}; afters = {}
    for m in ids:
        b, a = split_track(tracks[m], frac, gap_s)
        if len(b) >= 2 and len(a) >= 2:
            befores[m] = b; afters[m] = a
    ids = [m for m in ids if m in befores]
    dt_max = gap_s + 900
    borderline = []
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
        K = sum(1 for d, _ in scored if d <= gate_nm); K = max(1, K)
        if K == 1:
            continue
        ds = [d for d, _ in scored if d <= gate_nm]
        dmin = min(ds)
        w = [math.exp(-(d-dmin)/max(0.05, gate_nm/4)) for d in ds]
        beta = max(w)/sum(w)
        if K > 1 and beta >= tau:
            borderline.append((q, K, beta, sorted(ds)))
    return borderline

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="/home/vessel1/puget_subset.csv")
    ap.add_argument("--min-fixes", type=int, default=10)
    ap.add_argument("--gate-nm", type=float, default=2.0)
    ap.add_argument("--gate-s", type=float, default=3.0)
    ap.add_argument("--gap-s", type=float, default=900)
    ap.add_argument("--split-frac", type=float, default=0.6)
    ap.add_argument("--tau", type=float, default=0.80)
    a = ap.parse_args()
    tracks = load_puget_tracks(a.csv, a.min_fixes)
    cases = inspect(tracks, a.split_frac, a.gate_nm, a.gate_s, a.gap_s, a.tau)
    print(f"{len(cases)} borderline cases (K>1 but beta>=tau={a.tau}):\n")
    for q, K, beta, ds in cases:
        gap_to_2nd = ds[1]-ds[0] if len(ds) > 1 else None
        print(f"  MMSI {q}: K={K} beta={beta:.3f}  in-gate distances(nm)={[round(d,3) for d in ds]}  "
              f"gap to 2nd-best={gap_to_2nd:.3f}nm" if gap_to_2nd is not None else f"  MMSI {q}: K={K} beta={beta:.3f}")