# check_puget_pinning.py -- the decisive check: does this Puget subset actually show
# more K>1 (confusable, FEASIBLE-regime) behavior than the Aegean data did? Reuses
# haversine_nm/predict/split_track/motion_reid UNCHANGED from calibrate_motion.py --
# only the data loader changes, since the column format differs (mmsi/base_date_time/
# longitude/latitude vs MMSI/TIMESTAMP/LAT/LON).
import sys, csv, time as time_mod
sys.path.insert(0, ".")
from calibrate_motion import haversine_nm, predict, split_track, motion_reid, pctile, boot

def load_puget_tracks(csv_path, min_fixes):
    tracks = {}
    with open(csv_path, newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            try:
                m = row["mmsi"].strip()
                # base_date_time like "2025-01-03 00:00:08" -> epoch seconds
                t = time_mod.mktime(time_mod.strptime(row["base_date_time"], "%Y-%m-%d %H:%M:%S"))
                lat = float(row["latitude"]); lon = float(row["longitude"])
                sog = float(row["sog"]); cog = float(row["cog"]) if row["cog"] else 0.0
            except (KeyError, ValueError):
                continue
            if sog < 0.5:   # same moving-vessel filter used throughout this project
                continue
            tracks.setdefault(m, []).append((t, lat, lon, sog, cog))
    out = {}
    for m, fixes in tracks.items():
        if len(fixes) >= min_fixes:
            fixes.sort(); out[m] = fixes
    return out

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default="/home/vessel1/puget_subset.csv")
    ap.add_argument("--min-fixes", type=int, default=10)
    ap.add_argument("--gate-nm", type=float, default=2.0)
    ap.add_argument("--gate-s", type=float, default=3.0)
    ap.add_argument("--gap-s", type=float, default=900)   # same gap used for the Aegean anchor
    ap.add_argument("--split-frac", type=float, default=0.6)
    ap.add_argument("--sample", type=int, default=0)
    a = ap.parse_args()

    print("loading Puget tracks (streaming)...", file=sys.stderr)
    tracks = load_puget_tracks(a.csv, a.min_fixes)
    print(f"  {len(tracks)} moving vessels with >={a.min_fixes} fixes in the Puget bounding box", file=sys.stderr)

    rate, hits, Ks, betas, n = motion_reid(tracks, a.split_frac, a.gate_nm, a.gate_s, a.gap_s,
                                            sample=(a.sample or None), seed=0)

    k1 = sum(1 for k in Ks if k == 1)
    kgt1 = sum(1 for k in Ks if k > 1)
    print("\n" + "="*70)
    print("PUGET SOUND SUBSET -- K/pinning check (same gate as the Aegean work)")
    print("="*70)
    if n == 0:
        print(f"n = 0 -- no vessels produced a usable before/after split at gap={a.gap_s}s "
              f"(need >=2 fixes in each half, gap_end within the track). Try a smaller --gap-s "
              f"or check --min-fixes against this dataset's actual reporting density.", file=sys.stderr)
        sys.exit(1)
    print(f"n = {n} vessels evaluated (gap={a.gap_s}s, gate={a.gate_nm}nm/{a.gate_s}s)")
    print(f"motion-only re-link rate: {rate:.1f}%")
    print(f"K=1 (uniquely pinned):     {k1}/{n}  ({100*k1/n:.1f}%)")
    print(f"K>1 (genuinely confusable): {kgt1}/{n}  ({100*kgt1/n:.1f}%)")
    if Ks:
        print(f"K distribution: mean={sum(Ks)/len(Ks):.2f}  median={pctile(sorted(Ks),50):.0f}  "
              f"p90={pctile(sorted(Ks),90):.0f}  max={max(Ks)}")
    print("\nFOR COMPARISON -- the Aegean open-water result was ~99% uniquely pinned (K=1),")
    print("which is exactly why the FEASIBLE side has been under-constrained until now.")
    print(f"\nCONCLUSION: this Puget subset shows K>1 in {100*kgt1/n:.1f}% of vessels", file=sys.stderr)