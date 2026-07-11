# m1_estimator.py -- Module 1: streaming exposure / sufficiency estimator.
# Pure standard library (vessel VMs lack numpy/scipy). Sliding-window, online.
# Outputs the variables the reasoner needs, INCLUDING the explicit sufficiency
# variable beta_hat with a lower confidence bound (supervisor review point #1).
#
# beta_hat = estimated motion-only linkage success: given the target's recent track,
# how reliably can a motion-only adversary pick the true continuation out of the local
# candidate set? This is the operational shadow of the Futility Theorem's floor.
import math, time, json
from collections import deque

class StreamingEstimator:
    def __init__(self, window_s=120.0, gate_nm=2.0, gate_s=3.0):
        # window_s: how much recent history to keep per track
        # gate_nm/gate_s: kinematic gate (Paper 1's 2nm/3s nearest-neighbour gate)
        self.window_s = window_s
        self.gate_nm = gate_nm
        self.gate_s = gate_s
        self.tracks = {}   # mmsi -> deque[(t, lat, lon, sog, cog)]

    def update(self, mmsi, t, lat, lon, sog, cog):
        d = self.tracks.setdefault(mmsi, deque())
        d.append((t, lat, lon, sog, cog))
        cutoff = t - self.window_s
        while d and d[0][0] < cutoff:
            d.popleft()

    @staticmethod
    def _haversine_nm(a_lat, a_lon, b_lat, b_lon):
        R_nm = 3440.065
        p1, p2 = math.radians(a_lat), math.radians(b_lat)
        dp = math.radians(b_lat - a_lat); dl = math.radians(b_lon - a_lon)
        x = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
        return 2*R_nm*math.asin(min(1.0, math.sqrt(x)))

    def _predict(self, track, dt_s):
        # constant-velocity dead-reckon one step ahead from last fix
        t, lat, lon, sog, cog = track[-1]
        dist_nm = sog * (dt_s/3600.0)
        brg = math.radians(cog)
        dlat = (dist_nm/60.0)*math.cos(brg)
        dlon = (dist_nm/60.0)*math.sin(brg)/max(1e-6, math.cos(math.radians(lat)))
        return lat+dlat, lon+dlon

    def estimate(self, target_mmsi, t_now):
        # returns the full estimator output dict for the target at time t_now
        out = {"t": t_now, "target": target_mmsi}
        tgt = self.tracks.get(target_mmsi)
        if not tgt or len(tgt) < 2:
            out.update({"data_quality":"INSUFFICIENT","K_hat":None,"E_hat":None,
                        "beta_hat":None,"beta_lcb":None,"conf":0.0})
            return out
        # candidate continuations: tracks whose predicted next position falls within the
        # kinematic gate of the target's predicted next position.
        tgt_pred = self._predict(tgt, self.gate_s)
        candidates = []
        for mmsi, tr in self.tracks.items():
            if len(tr) < 2: continue
            if (t_now - tr[-1][0]) > self.window_s: continue
            pred = self._predict(tr, self.gate_s)
            d_nm = self._haversine_nm(tgt_pred[0], tgt_pred[1], pred[0], pred[1])
            if d_nm <= self.gate_nm:
                candidates.append((mmsi, d_nm))
        K = max(1, len(candidates))
        # beta_hat: motion-only linkage success ~ probability the nearest candidate is the
        # true one. With K equally-plausible candidates, a uniform adversary picks true with
        # 1/K; but proximity concentrates the posterior. We weight by inverse distance.
        if K == 1:
            beta = 1.0
        else:
            # softmin over gate distances: closer candidates dominate the posterior
            ds = [d for _, d in candidates]
            dmin = min(ds)
            weights = [math.exp(-(d - dmin)/max(0.05, self.gate_nm/4)) for d in ds]
            Z = sum(weights)
            # the target's own weight is the one at d~0 (it predicts closest to itself)
            beta = max(weights)/Z
        # confidence from sample support: more fixes + more candidates observed = tighter.
        n = len(tgt)
        # Wilson-style lower bound on beta given effective sample size n
        z = 1.96
        if n > 0:
            denom = 1 + z*z/n
            centre = (beta + z*z/(2*n))/denom
            half = (z*math.sqrt(max(0.0, (beta*(1-beta)/n) + z*z/(4*n*n))))/denom
            beta_lcb = max(0.0, centre - half)
        else:
            beta_lcb = 0.0
        conf = min(1.0, n/10.0)   # saturates at 10 fixes in window
        # E_hat: exposure = how concentrated the posterior is (1 = fully pinned)
        E = beta
        out.update({"data_quality":"OK","K_hat":K,"E_hat":round(E,4),
                    "beta_hat":round(beta,4),"beta_lcb":round(beta_lcb,4),
                    "conf":round(conf,4),"n_fixes":n,"n_candidates":K})
        return out

if __name__ == "__main__":
    # smoke test with synthetic tracks (no testbed needed) -- proves the math runs
    est = StreamingEstimator()
    t0 = time.time()
    # target on a steady course
    for i in range(8):
        est.update("athena", t0+i*10, 37.50+i*0.001, 25.30+i*0.001, 12.0, 45.0)
    # open sea: no neighbours -> K=1, beta=1 (pinned)
    print("OPEN SEA:", json.dumps(est.estimate("athena", t0+80)))
    # add 3 nearby confusable vessels -> K>1, beta<1 (privacy feasible)
    for j,off in enumerate([0.0005,-0.0004,0.0006]):
        for i in range(8):
            est.update(f"v{j}", t0+i*10, 37.50+i*0.001+off, 25.30+i*0.001+off, 12.0, 45.0)
    print("PORT (3 neighbours):", json.dumps(est.estimate("athena", t0+80)))