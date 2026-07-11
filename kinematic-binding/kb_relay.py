# kb_relay.py -- a GENUINE forwarding relay for the KB protocol (not just NetEm delay).
# Listens on a port; on each connection, opens its OWN connection to the real prover
# and forwards bytes verbatim in both directions. This adds REAL processing/hop latency
# from actually relaying (extra socket hop, extra buffering), and can optionally add a
# configurable extra delay to model a relay at a different physical distance.
# Run this BETWEEN the verifier and the prover: verifier -> relay -> prover.
import socket, sys, threading, time, argparse

def pipe(src, dst, extra_delay_s=0.0):
    try:
        while True:
            data = src.recv(4096)
            if not data: break
            if extra_delay_s > 0:
                time.sleep(extra_delay_s)
            dst.sendall(data)
    except Exception:
        pass
    finally:
        try: dst.shutdown(socket.SHUT_WR)
        except Exception: pass

def handle(client, target_host, target_port, extra_delay_s):
    try:
        upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        upstream.settimeout(5.0)
        upstream.connect((target_host, target_port))
    except Exception as e:
        print("[relay] upstream connect failed:", e, file=sys.stderr)
        client.close(); return
    t1 = threading.Thread(target=pipe, args=(client, upstream, extra_delay_s))
    t2 = threading.Thread(target=pipe, args=(upstream, client, extra_delay_s))
    t1.start(); t2.start(); t1.join(); t2.join()
    client.close(); upstream.close()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen-port", type=int, default=9453)
    ap.add_argument("--target-host", required=True)
    ap.add_argument("--target-port", type=int, default=9452)
    ap.add_argument("--extra-delay-ms", type=float, default=0.0,
                     help="additional one-way delay per direction, modelling relay distance")
    a = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", a.listen_port)); srv.listen(16)
    print(f"[relay] listening on {a.listen_port}, forwarding to {a.target_host}:{a.target_port}, "
          f"extra_delay={a.extra_delay_ms}ms", flush=True)
    n = 0
    while True:
        client, addr = srv.accept()
        n += 1
        if n % 50 == 0: print(f"[relay] relayed {n} connections", flush=True)
        threading.Thread(target=handle, args=(client, a.target_host, a.target_port,
                                                a.extra_delay_ms/1000.0)).start()

if __name__ == "__main__":
    main()
