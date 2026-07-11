# select_demo_vessels.py -- picks real, evidence-backed target vessels for the two
# Tier 1 demo chapters: a Puget vessel from the CONFIRMED correctly-FEASIBLE set
# (K>1, beta<0.80, per the real validation already run), and an Aegean vessel from
# the well-established K=1/FUTILE population. Outputs a small JSON config the live
# driver reads -- no guessing of MMSIs, only real, checked selections.
import sys, json, math
sys.path.insert(0, ".")
from calibrate_motion import predict, haversine_nm, split_track, load_tracks as load_aegean_tracks
from check_puget_pinning import load_puget_tracks

TAU = 0.80

def longest_continuous_segment(fixes, max_gap_s):
    # fixes: sorted list of (t, lat, lon, sog, cog). Returns the longest run where no
    # consecutive gap exceeds max_gap_s -- i.e. one genuinely continuous voyage leg,
    # not a raw total history that may silently splice together separate real trips.
    if not fixes:
        return []
    best_start = 0; best_end = 0
    cur_start = 0
    for i in range(1, len(fixes)):
        if fixes[i][0] - fixes[i-1][0] > max_gap_s:
            if (i-1) - cur_start > best_end - best_start:
                best_start, best_end = cur_start, i-1
            cur_start = i
    if (len(fixes)-1) - cur_start > best_end - best_start:
        best_start, best_end = cur_start, len(fixes)-1
    return fixes[best_start:best_end+1]

def sustained_feasible_fraction(target_track, candidates, tau_privacy, compress):
    # Replays the FULL continuous track through the REAL estimator + reasoner --
    # exactly what live_demo_voyage.py does at demo time -- and returns the fraction
    # of epochs landing in PRIVACY_FEASIBLE. A single before/after snapshot (score_all)
    # can catch one brief, transient encounter that is not representative of the
    # vessel's overall voyage; this checks SUSTAINED feasibility instead, using the
    # same compress value the actual demo will use, so selection matches reality.
    from m1_estimator import StreamingEstimator
    from m2_reasoner import decide_regime
    from live_demo_voyage import replay_chapter
    est = StreamingEstimator()
    n_feasible = 0; n_total = 0
    for t, label in replay_chapter(est, target_track, candidates, "scan", compress=compress):
        e = est.estimate("athena", t)
        regime, _ = decide_regime(e, {"seam_imminent": False}, tau_privacy=tau_privacy)
        n_total += 1
        if regime == "PRIVACY_FEASIBLE":
            n_feasible += 1
    return (n_feasible / n_total) if n_total else 0.0, n_total

def score_all(tracks, frac, gate_nm, gate_s, gap_s):
    ids = list(tracks)
    befores = {}; afters = {}
    for m in ids:
        b, a = split_track(tracks[m], frac, gap_s)
        if len(b) >= 2 and len(a) >= 2:
            befores[m] = b; afters[m] = a
    ids = [m for m in ids if m in befores]
    dt_max = gap_s + 900
    out = {}
    for q in ids:
        a_lat, a_lon = afters[q][0][1], afters[q][0][2]
        scored = []
        for c in ids:
            dt = afters[q][0][0] - befores[c][-1][0]
            if dt <= 0 or dt > dt_max: continue
            p_lat, p_lon = predict(befores[c][-1], dt)
            d = haversine_nm(a_lat, a_lon, p_lat, p_lon)
            scored.append((d, c))
        if not scored: continue
        scored.sort()
        K = max(1, sum(1 for d, _ in scored if d <= gate_nm))
        if K == 1:
            beta = 1.0
        else:
            ds = [d for d, _ in scored if d <= gate_nm]
            dmin = min(ds)
            w = [math.exp(-(d-dmin)/max(0.05, gate_nm/4)) for d in ds]
            beta = max(w)/sum(w)
        out[q] = {"K": K, "beta": beta, "n_fixes": len(tracks[q]),
                  "t_start": tracks[q][0][0], "t_end": tracks[q][-1][0]}
    return out, ids

def trim_to_continuous(tracks, max_gap_s, min_fixes_after_trim):
    # Applies longest_continuous_segment to EVERY vessel in tracks, dropping any
    # whose continuous segment is too short. This must happen BEFORE scoring, so
    # K/beta are computed on exactly the data that will actually be replayed --
    # not on a raw history that may silently splice separate real trips together.
    out = {}
    dropped_for_length = 0
    for m, fixes in tracks.items():
        seg = longest_continuous_segment(sorted(fixes), max_gap_s)
        if len(seg) >= min_fixes_after_trim:
            out[m] = seg
        else:
            dropped_for_length += 1
    return out, dropped_for_length

if __name__ == "__main__":
    import argparse
    from live_demo_voyage import closest_candidates
    ap = argparse.ArgumentParser()
    ap.add_argument("--puget-csv", default="/home/vessel1/puget_subset.csv")
    ap.add_argument("--aegean-csv", default="/home/vessel1/aegeanet.csv")
    ap.add_argument("--gap-s", type=float, default=900)
    ap.add_argument("--gate-nm", type=float, default=2.0)
    ap.add_argument("--gate-s", type=float, default=3.0)
    ap.add_argument("--split-frac", type=float, default=0.6)
    ap.add_argument("--max-continuous-gap-s", type=float, default=600,
                     help="max gap (seconds) within one continuous voyage leg; larger gaps split it")
    ap.add_argument("--compress", type=float, default=30.0,
                     help="playback compression used for the sustained-feasibility check -- must "
                          "match what the actual demo run will use (live_demo_voyage.py's default)")
    ap.add_argument("--max-sustain-checks", type=int, default=10,
                     help="cap how many snapshot-feasible candidates get the (more expensive) "
                          "full continuous-replay check")
    ap.add_argument("--min-sustain-frac", type=float, default=0.15,
                     help="warn if even the best candidate's sustained FEASIBLE fraction is below this")
    ap.add_argument("--out", default="demo_vessel_selection.json")
    a = ap.parse_args()

    print("=== Puget: trimming every vessel to its own longest continuous segment ===", file=sys.stderr)
    puget_tracks_raw = load_puget_tracks(a.puget_csv, min_fixes=10)
    puget_tracks, pd = trim_to_continuous(puget_tracks_raw, a.max_continuous_gap_s, min_fixes_after_trim=10)
    print(f"  {len(puget_tracks)} vessels retained ({pd} dropped: continuous segment too short "
          f"after applying a {a.max_continuous_gap_s:.0f}s max-gap rule)", file=sys.stderr)

    print("=== Puget: selecting a confirmed correctly-FEASIBLE (K>1, beta<tau) vessel ===", file=sys.stderr)
    puget_scores, _ = score_all(puget_tracks, a.split_frac, a.gate_nm, a.gate_s, a.gap_s)
    feasible_candidates = [(m, s) for m, s in puget_scores.items() if s["K"] > 1 and s["beta"] < TAU]
    if not feasible_candidates:
        print("ERROR: no correctly-FEASIBLE Puget vessel found with a usable continuous segment.", file=sys.stderr)
        sys.exit(1)
    print(f"  {len(feasible_candidates)} candidates have at least one confusable (K>1) snapshot moment. "
          f"Checking SUSTAINED feasibility for each (full continuous replay, not one snapshot) --", file=sys.stderr)
    print(f"  a single snapshot can catch one brief, transient encounter unrepresentative of the "
          f"whole voyage; this is exactly the gap found and fixed after the first real demo run.", file=sys.stderr)
    scored_by_sustain = []
    for m, s in feasible_candidates[:a.max_sustain_checks]:
        cands_all = {c: puget_tracks[c] for c in puget_tracks if c != m}
        # CRITICAL: use the SAME candidate cap the actual demo replay will use, ranked by
        # real closest approach -- not an unbounded candidate set. Verifying against every
        # real vessel here, then replaying against only 15 (however chosen) at demo time,
        # is exactly the mismatch that gave contradictory 95.5% vs 1.1% results before.
        cands = closest_candidates(puget_tracks[m], cands_all, max_candidates=15)
        frac, n_epochs = sustained_feasible_fraction(puget_tracks[m], cands, TAU, a.compress)
        scored_by_sustain.append((m, s, frac, n_epochs))
        print(f"    {m}: sustained FEASIBLE fraction = {frac*100:.1f}% ({n_epochs} epochs checked, "
              f"{len(cands)} closest real candidates)", file=sys.stderr)
    scored_by_sustain.sort(key=lambda x: -x[2])
    puget_mmsi, puget_score, puget_sustain_frac, _ = scored_by_sustain[0]
    span_h = (puget_score['t_end'] - puget_score['t_start']) / 3600
    print(f"  selected {puget_mmsi}: K={puget_score['K']} beta={puget_score['beta']:.3f} "
          f"n_fixes={puget_score['n_fixes']} (continuous segment, span={span_h:.2f}h), "
          f"SUSTAINED feasible fraction={puget_sustain_frac*100:.1f}%", file=sys.stderr)
    if puget_sustain_frac < a.min_sustain_frac:
        print(f"  WARNING: best candidate's sustained FEASIBLE fraction ({puget_sustain_frac*100:.1f}%) "
              f"is below the requested minimum ({a.min_sustain_frac*100:.0f}%). Proceeding, but the demo's "
              f"FEASIBLE segment may be brief -- consider a lower --min-sustain-frac if none qualify, "
              f"or a genuinely different data source.", file=sys.stderr)

    print("=== Aegean: trimming every vessel to its own longest continuous segment ===", file=sys.stderr)
    aegean_tracks_raw = load_aegean_tracks(a.aegean_csv, min_fixes=15)
    aegean_tracks, ad = trim_to_continuous(aegean_tracks_raw, a.max_continuous_gap_s, min_fixes_after_trim=15)
    print(f"  {len(aegean_tracks)} vessels retained ({ad} dropped: continuous segment too short)", file=sys.stderr)

    print("=== Aegean: selecting a well-established K=1/FUTILE vessel ===", file=sys.stderr)
    aegean_scores, _ = score_all(aegean_tracks, a.split_frac, a.gate_nm, a.gate_s, a.gap_s)
    futile_candidates = [(m, s) for m, s in aegean_scores.items() if s["K"] == 1]
    futile_candidates.sort(key=lambda ms: -ms[1]["n_fixes"])
    if not futile_candidates:
        print("ERROR: no K=1 Aegean vessel found -- unexpected given the known ~99% pinning rate.", file=sys.stderr)
        sys.exit(1)
    aegean_mmsi, aegean_score = futile_candidates[0]
    print(f"  selected {aegean_mmsi}: K={aegean_score['K']} beta={aegean_score['beta']:.3f} "
          f"n_fixes={aegean_score['n_fixes']}", file=sys.stderr)

    selection = {
        "puget": {"mmsi": puget_mmsi, "csv": a.puget_csv, "score": puget_score,
                  "t_start": puget_score["t_start"], "t_end": puget_score["t_end"],
                  "candidate_mmsis": list(puget_tracks.keys())},
        "aegean": {"mmsi": aegean_mmsi, "csv": a.aegean_csv, "score": aegean_score,
                   "t_start": aegean_score["t_start"], "t_end": aegean_score["t_end"],
                   "candidate_mmsis": list(aegean_tracks.keys())[:200]},  # cap for file size
        "params": {"gate_nm": a.gate_nm, "gate_s": a.gate_s, "gap_s": a.gap_s,
                   "split_frac": a.split_frac, "tau_privacy": TAU,
                   "max_continuous_gap_s": a.max_continuous_gap_s},
    }
    with open(a.out, "w") as f:
        json.dump(selection, f, indent=2)
    print(f"\nwritten: {a.out}", file=sys.stderr)
    print(f"Puget target: {puget_mmsi} (K={puget_score['K']}, beta={puget_score['beta']:.3f})")
    print(f"Aegean target: {aegean_mmsi} (K=1, beta=1.0)")
