# live_demo_voyage.py -- Tier 1 live demonstration driver. Composite scenario:
# real Puget Sound confined-water segment (FEASIBLE) -> real Aegean open-water
# segment (FUTILE) -> the seam, with an injected, clearly-announced relay attack
# -> return leg (replays the Puget segment again, to show reversibility live).
#
# HONEST LABEL -- state this at the start of every run, per Demonstration-Strategy-v4:
# "This is a composite demonstration assembled from real AIS segments and real
#  testbed enforcement, designed to exercise every framework regime."
#
# Two modes:
#   --dry-run (default): real replay data, real m1/m2/m3 decisions, NO enforcement
#     calls (no network, no crypto). Safe to test the control logic anywhere,
#     including off the testbed.
#   --live: adds real enforcement. PQC sign/rotate/alert via m4_enforce_real.py.
#     KB via kb_verifier_v2.run_trial() directly -- the validated, composed,
#     statistically-measured protocol (port 9452), NOT m4_enforce_real's older
#     built-in KB method (port 9451, timing-only, superseded).
#
# Run select_demo_vessels.py first to produce demo_vessel_selection.json.
import sys, os, csv, json, time, argparse
sys.path.insert(0, ".")
from m1_estimator import StreamingEstimator
from m2_reasoner import decide_regime
from m3_selector import select_action
from m5_audit import AuditTrail
from check_puget_pinning import load_puget_tracks
from calibrate_motion import load_tracks as load_aegean_tracks, haversine_nm

PRIM_BYTES = {"Falcon-512":657,"ML-DSA-44":2420,"ML-DSA-65":3309,"SLH-DSA-128s":7856,None:0}

def closest_candidates(target_track, all_candidates, max_candidates, sample_every=5):
    # Ranks candidates by real minimum approach distance to the target's track, not
    # arbitrary file order. A file-order cap can silently exclude the specific vessel(s)
    # actually responsible for the target's confusability -- found and fixed after the
    # selector (checking all real candidates) and the demo replay (file-order-capped)
    # gave contradictory results for the same real vessel (95.5% vs 1.1% FEASIBLE).
    # sample_every subsamples the target track for speed; a proxy for closest approach,
    # not a claim of exact minimum distance.
    if len(all_candidates) <= max_candidates:
        return all_candidates
    target_sample = target_track[::sample_every] or target_track
    scored = []
    for m, track in all_candidates.items():
        cand_sample = track[::sample_every] or track
        best = min(haversine_nm(tlat, tlon, clat, clon)
                   for (_, tlat, tlon, *_ ) in target_sample
                   for (_, clat, clon, *_ ) in cand_sample)
        scored.append((best, m))
    scored.sort()
    keep = set(m for _, m in scored[:max_candidates])
    return {m: t for m, t in all_candidates.items() if m in keep}

def load_chapter(kind, csv_path, target_mmsi, candidate_mmsis, t_start, t_end, max_candidates=15):
    # CRITICAL: bounds every track (target AND candidates) to [t_start, t_end] -- the
    # continuous-segment window the selector already identified. Without this, a
    # vessel's full raw history could span many disconnected real trips over months
    # (found and fixed during selection: one Aegean candidate's raw history spanned
    # 91 days with 26 gaps over a day, some 3-6 days long -- not one continuous
    # voyage). Re-loading the full history here without the same bound would silently
    # undo that fix.
    if kind == "puget":
        tracks = load_puget_tracks(csv_path, min_fixes=5)
    else:
        tracks = load_aegean_tracks(csv_path, min_fixes=5)
    def clip(fixes):
        return sorted(f for f in fixes if t_start <= f[0] <= t_end)
    if target_mmsi not in tracks:
        raise SystemExit(f"target {target_mmsi} not found in {csv_path} at min_fixes=5")
    target_clipped = clip(tracks[target_mmsi])
    if len(target_clipped) < 5:
        raise SystemExit(f"target {target_mmsi} has only {len(target_clipped)} fixes in the "
                          f"[{t_start},{t_end}] continuous-segment window -- selection/replay window mismatch.")
    cands = {}
    for m in candidate_mmsis:
        if m == target_mmsi or m not in tracks:
            continue
        c = clip(tracks[m])
        if c:
            cands[m] = c
    if len(cands) > max_candidates:
        cands = closest_candidates(target_clipped, cands, max_candidates)
    return target_clipped, cands

def replay_chapter(est, target_track, candidates, label, compress=1.0, t_offset=0.0):
    # yields (t_now, epoch_label) for each real target fix, after feeding all real
    # position reports (target + candidates) up to that point into the estimator.
    # CRITICAL: the same offset/compress transform must apply to BOTH the update()
    # timestamps and the yielded query timestamps, or replayed chapters (e.g. the
    # return leg re-using the same source data) fall outside the estimator's
    # sliding window by query time -- found and fixed via direct debugging.
    all_reports = [("__target__", t, lat, lon, sog, cog) for (t, lat, lon, sog, cog) in target_track]
    for m, track in candidates.items():
        all_reports += [(m, t, lat, lon, sog, cog) for (t, lat, lon, sog, cog) in track]
    all_reports.sort(key=lambda r: r[1])
    t0 = target_track[0][0]
    def xform(t):
        return (t0 + (t - t0) / compress) + t_offset
    for m, t, lat, lon, sog, cog in all_reports:
        mmsi = "athena" if m == "__target__" else m
        t_xformed = xform(t)
        est.update(mmsi, t_xformed, lat, lon, sog, cog)
        if m == "__target__":
            yield t_xformed, label

def make_ctx(seam_imminent, bearer, threat, rtt_ms, relay, cred_age, budget_bytes=9000, max_latency_ms=1000):
    return {"seam_imminent": seam_imminent, "bearer": bearer, "threat": threat,
            "link_ok": rtt_ms < 500, "budget_bytes": budget_bytes, "max_latency_ms": max_latency_ms,
            "cred_age": cred_age, "rtt_ms": rtt_ms, "latency_inversion": seam_imminent, "relay": relay}

def narrate(chapter, t, e, regime, regime_reason, action, action_reason, enforcement_note=None):
    print(f"\n[{chapter}] t={time.strftime('%H:%M:%S', time.localtime(t))}")
    if e:
        print(f"  K\u0302={e.get('K_hat')}  \u03b2\u0302={e.get('beta_hat'):.3f}" if e.get('beta_hat') is not None else "  (insufficient data)")
    print(f"  regime: {regime}  ({regime_reason})")
    print(f"  action: rotate={action.get('rotate')} kb_enforce={action.get('kb_enforce')} "
          f"primitive={action.get('pqc_primitive')} alert={action.get('alert')}")
    print(f"  why:    {action_reason}")
    if enforcement_note:
        print(f"  ENFORCED: {enforcement_note}")

def run(args):
    with open(args.selection) as f:
        sel = json.load(f)
    params = sel["params"]
    print("="*78)
    print("This is a composite demonstration assembled from real AIS segments and")
    print("real testbed enforcement, designed to exercise every framework regime.")
    print(f"Mode: {'LIVE (real enforcement)' if args.live else 'DRY RUN (no enforcement, control logic only)'}")
    print("="*78)

    puget_target, puget_cands = load_chapter("puget", sel["puget"]["csv"], sel["puget"]["mmsi"],
                                              sel["puget"]["candidate_mmsis"],
                                              sel["puget"]["t_start"], sel["puget"]["t_end"])
    aegean_target, aegean_cands = load_chapter("aegean", sel["aegean"]["csv"], sel["aegean"]["mmsi"],
                                                sel["aegean"]["candidate_mmsis"],
                                                sel["aegean"]["t_start"], sel["aegean"]["t_end"])
    print(f"Puget target {sel['puget']['mmsi']}: {len(puget_target)} real fixes (continuous segment), "
          f"{len(puget_cands)} real contemporaneous candidates")
    print(f"Aegean target {sel['aegean']['mmsi']}: {len(aegean_target)} real fixes (continuous segment), "
          f"{len(aegean_cands)} real contemporaneous candidates")
    puget_span = puget_target[-1][0] - puget_target[0][0]
    aegean_span = aegean_target[-1][0] - aegean_target[0][0]
    puget_avg_s = puget_span / max(1, len(puget_target)-1)
    aegean_avg_s = aegean_span / max(1, len(aegean_target)-1)
    print(f"Real average reporting interval: Puget {puget_avg_s:.1f}s, Aegean {aegean_avg_s:.1f}s")
    print(f"Playback compression: {args.compress}x real-time "
          f"(effective interval: Puget {puget_avg_s/args.compress:.1f}s, Aegean {aegean_avg_s/args.compress:.1f}s) "
          f"-- REAL data, real relative spacing, sped up uniformly for demo pacing, disclosed here explicitly.")

    audit = AuditTrail(path=args.audit_log)
    enforcement_log = open(args.enforcement_log, "w") if args.live else None
    est = StreamingEstimator()
    st = {}
    cred_age = 0
    real_enforcer = None
    if args.live:
        from m4_enforce_real import RealEnforcement
        from kb_verifier_v2 import run_trial as kb_run_trial
        from kb_protocol import FreshnessCache
        real_enforcer = RealEnforcement(side="vessel")
        kb_freshness = FreshnessCache()
        kb_ca_bytes = open(os.path.expanduser(args.ca_path), "rb").read()

    def process_epoch(chapter, t, seam_imminent, bearer, threat, rtt_ms, relay_flag, relay_target=None):
        nonlocal cred_age
        e = est.estimate("athena", t)
        ctx = make_ctx(seam_imminent, bearer, threat, rtt_ms, relay_flag, cred_age)
        regime, regime_reason = decide_regime(e, ctx, tau_privacy=params["tau_privacy"])
        action, action_reason = select_action(regime, ctx)
        enforcement_note = None
        if action.get("rotate"): cred_age = 0
        else: cred_age += 1
        if args.live:
            notes = []
            if action.get("pqc_primitive"):
                r = real_enforcer.select_and_sign(action["pqc_primitive"])
                notes.append(f"sign={r}")
            if action.get("kb_enforce"):
                host = relay_target if relay_flag else args.prover_host
                r = kb_run_trial(host, args.relay_port if relay_flag else args.prover_port,
                                  kb_ca_bytes, kb_freshness, tau_ms=450.0)
                notes.append(f"KB accept={r.accept} rtt={r.rtt_ms:.1f}ms reason={r.reason}")
            if action.get("alert"):
                notes.append("ALERT raised")
            enforcement_note = "; ".join(notes) if notes else None
            if enforcement_log:
                enforcement_log.write(json.dumps({"time": t, "chapter": chapter, "note": enforcement_note}) + "\n")
                enforcement_log.flush()
        narrate(chapter, t, e, regime, regime_reason, action, action_reason, enforcement_note)
        audit.record(t, e, regime, regime_reason, action, action_reason)

    print("\n" + "="*78); print("STEP 2 -- Early voyage: FEASIBLE (Puget segment)"); print("="*78)
    for t, label in replay_chapter(est, puget_target, puget_cands, "puget", compress=args.compress):
        process_epoch("puget", t, seam_imminent=False, bearer="TN", threat=0, rtt_ms=300, relay_flag=False)

    print("\n" + "="*78); print("STEP 3 -- Open water: FUTILE (Aegean segment)"); print("="*78)
    aegean_t_offset = puget_target[-1][0] + 300 - aegean_target[0][0]
    for t, label in replay_chapter(est, aegean_target, aegean_cands, "aegean", t_offset=aegean_t_offset, compress=args.compress):
        process_epoch("aegean", t, seam_imminent=False, bearer="NTN", threat=0, rtt_ms=280, relay_flag=False)

    print("\n" + "="*78); print("STEP 4 -- The seam: injected relay attack (announced, controlled)"); print("="*78)
    seam_t = aegean_target[-1][0] + aegean_t_offset + 60
    process_epoch("seam", seam_t, seam_imminent=True, bearer="NTN", threat=2, rtt_ms=900,
                  relay_flag=True, relay_target=args.relay_host)

    print("\n" + "="*78); print("STEP 5 -- Return leg: reversibility (replaying the Puget segment)"); print("="*78)
    return_t_offset = seam_t + 60 - puget_target[0][0]
    for t, label in replay_chapter(est, puget_target, puget_cands, "puget_return", t_offset=return_t_offset, compress=args.compress):
        process_epoch("puget_return", t, seam_imminent=False, bearer="TN", threat=0, rtt_ms=300, relay_flag=False)

    print("\n" + "="*78)
    print("STEP 6 -- Close. Real decisions, real crypto, real timing where --live was used;")
    print("not RF/orbital physics; one relay condition of the range the statistical")
    print("campaign covers (FAR 0.10% upper bound, n=3000 -- see the progress report).")
    print("="*78)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--selection", default="demo_vessel_selection.json")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--prover-host", default="192.168.0.20")
    ap.add_argument("--prover-port", type=int, default=9452)
    ap.add_argument("--relay-host", default="192.168.0.27")
    ap.add_argument("--relay-port", type=int, default=9453)
    ap.add_argument("--ca-path", default="~/ca.crt")
    ap.add_argument("--audit-log", default="demo_audit.jsonl")
    ap.add_argument("--enforcement-log", default="demo_enforcement.jsonl",
                     help="separate JSONL log of real enforcement results (PQC sign, KB accept/"
                          "reject), keyed by time -- kept separate from AuditTrail's fixed schema "
                          "(m5_audit.py) rather than modifying that shared, already-validated module")
    ap.add_argument("--compress", type=float, default=30.0,
                     help="real-time playback speed-up factor (uniform across all chapters). "
                          "Empirically verified (not merely estimated): the binding constraint "
                          "is not the flat n/10 confidence metric but the Wilson-score upper "
                          "bound on beta, which needs more real fixes to tighten than a naive "
                          "confidence calculation suggests. compress=6 was tried first and found "
                          "insufficient (stayed at UNKNOWN_FALLBACK -- beta_ucb=0.95 still "
                          "straddled tau=0.80 despite conf=0.8); compress=30 was confirmed to "
                          "reach a genuine beta_ucb=0.798<0.80 crossing on the real sparse-vessel "
                          "pattern. Does not touch the estimator itself -- this is playback speed "
                          "only, applied uniformly and disclosed in the run's own printed output.")
    args = ap.parse_args()
    run(args)