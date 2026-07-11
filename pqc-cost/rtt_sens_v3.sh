#!/usr/bin/env bash
# rtt_sens_v3.sh — run with: bash rtt_sens_v3.sh   (as your normal user)
IFACE=ens3
REPS=300
OUTDIR=~/rtt_sensitivity
mkdir -p "$OUTDIR"

for D in 100 275 550; do
  echo "=== [$D] setting delay ${D}ms 15ms loss 0% ==="
  sudo tc qdisc replace dev "$IFACE" root netem delay "${D}ms" 15ms loss 0%
  sleep 2
  echo "=== [$D] CONFIRMED ACTIVE QDISC (must show delay ${D}ms) ==="
  tc qdisc show dev "$IFACE" | tee "$OUTDIR/qdisc_${D}ms.txt"
  if ! grep -q "delay ${D}ms" "$OUTDIR/qdisc_${D}ms.txt"; then
    echo "  !! qdisc did NOT change to ${D}ms — aborting this leg, fix sudo/tc first"
    continue
  fi
  echo ""
  echo ">>> NOW, in Terminal B on VM-03, run:"
  echo ">>>   python3 rtt_sweep_vessel.py 192.168.0.17"
  echo ">>> Only press Enter here AFTER you see '[core] listening...' below."
  timeout 300 python3 rtt_sweep_core.py "$REPS" | tee "$OUTDIR/log_${D}ms.txt" &
  CORE_PID=$!
  sleep 1
  read -p "Core is listening — go start the vessel side now, then press Enter to wait for it to finish... " _
  wait $CORE_PID
  cp rtt_sweep_results.jsonl "$OUTDIR/rtt_${D}ms.jsonl"
  echo "=== [$D] done ==="
done

echo "=== restoring baseline ==="
sudo tc qdisc replace dev "$IFACE" root netem delay 275ms 15ms loss 5%
tc qdisc show dev "$IFACE"