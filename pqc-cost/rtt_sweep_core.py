#!/usr/bin/env python3
import socket, struct, time, json, sys, statistics

HOST = "0.0.0.0"
PORT = 9450
N_ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 300
TIMEOUT_S = 3.0
OUTFILE = "rtt_sweep_results.jsonl"

def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    print(f"[core] listening on {PORT}, waiting for vessel...", flush=True)
    conn, addr = srv.accept()
    conn.settimeout(TIMEOUT_S)
    print(f"[core] vessel connected from {addr}", flush=True)

    results = []
    n_timeout = 0
    for i in range(N_ROUNDS):
        nonce = struct.pack(">Q", i) + bytes(24)
        t0 = time.monotonic()
        try:
            conn.sendall(nonce)
            resp = conn.recv(64)
            t1 = time.monotonic()
            rtt_ms = (t1 - t0) * 1000.0
            ok = (len(resp) >= 8 and struct.unpack(">Q", resp[:8])[0] == i)
            results.append({"round": i, "rtt_ms": rtt_ms, "ok": ok, "timeout": False})
        except socket.timeout:
            t1 = time.monotonic()
            rtt_ms = (t1 - t0) * 1000.0
            n_timeout += 1
            results.append({"round": i, "rtt_ms": rtt_ms, "ok": False, "timeout": True})
        if (i+1) % 50 == 0:
            print(f"[core] {i+1}/{N_ROUNDS} done, {n_timeout} timeouts so far", flush=True)
        time.sleep(0.02)

    conn.close(); srv.close()

    rtts = [r["rtt_ms"] for r in results if not r["timeout"]]
    rtts.sort()
    def pct(p):
        if not rtts: return None
        k = int(len(rtts)*p)
        return rtts[min(k, len(rtts)-1)]

    summary = {
        "n_rounds": N_ROUNDS,
        "n_ok": sum(1 for r in results if r["ok"]),
        "n_timeout": n_timeout,
        "rtt_min_ms": min(rtts) if rtts else None,
        "rtt_max_ms": max(rtts) if rtts else None,
        "rtt_mean_ms": statistics.mean(rtts) if rtts else None,
        "rtt_median_ms": statistics.median(rtts) if rtts else None,
        "rtt_stdev_ms": statistics.stdev(rtts) if len(rtts) > 1 else None,
        "rtt_p90_ms": pct(0.90), "rtt_p95_ms": pct(0.95), "rtt_p99_ms": pct(0.99),
    }
    with open(OUTFILE, "w") as f:
        for r in results: f.write(json.dumps(r) + "\n")
        f.write(json.dumps({"summary": summary}) + "\n")
    print("\n=== SUMMARY ===")
    print(json.dumps(summary, indent=2))
    print(f"\nraw results written to {OUTFILE}")

if __name__ == "__main__":
    main()
