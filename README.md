# Maritime TN-NTN Security — Empirical Testbed Code

Supporting code for the doctoral thesis on identity privacy and post-quantum
authentication in maritime 5G TN-NTN hybrid networks, run on the TRITON
16-node testbed.

Companion repository (formal Lean 4 verification):
https://github.com/kpkaltakis/maritime-evidence-proofs

## Structure
- `pqc-cost/` — post-quantum handover cost measurement
- `downgrade-attack/` — capability-downgrade attack and detection
- `kinematic-binding/` — RTT calibration and the Kinematic Binding protocol
- `controller/` — the m1-m6 evidence-aware controller modules
- `evaluation/` — controller ablation and baseline comparison
- `ais-calibration/` — AIS-based kinematic exposure and pinning analysis
- `live-demo/` — end-to-end demonstration voyage
- `visualization/` — dashboard and figure generation

## Not included
Raw AIS records (licensing under review), PKI private material, and VM/network
configuration are excluded — see the thesis's Data and Code Availability section.
