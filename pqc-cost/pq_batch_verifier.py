#!/usr/bin/env python3
import time, json, os, hashlib, requests

LEDGER = "http://192.168.0.10:8096"
LOG    = "/tmp/accumulator/vm11_verification.jsonl"
os.makedirs("/tmp/accumulator", exist_ok=True)

def sha3(d): return hashlib.sha3_256(d if isinstance(d,bytes) else d.encode()).hexdigest()

def verify_merkle(events, hashes, claimed_root):
    computed = [sha3(json.dumps(e,sort_keys=True)) for e in events]
    hash_ok  = all(c==h for c,h in zip(computed,hashes))
    layer = computed[:]
    while len(layer)>1:
        if len(layer)%2: layer.append(layer[-1])
        layer=[sha3(layer[i]+layer[i+1]) for i in range(0,len(layer),2)]
    root_ok = (layer[0] if layer else sha3(b"empty")) == claimed_root
    return hash_ok, root_ok

def verify_seq(events):
    seqs=[e.get("seq",i) for i,e in enumerate(events)]
    ts=[e.get("ts_ms",0) for e in events]
    return (all(seqs[i]+1==seqs[i+1] for i in range(len(seqs)-1)) if len(seqs)>1 else True,
            all(ts[i]<=ts[i+1] for i in range(len(ts)-1)) if len(ts)>1 else True)

print("[VER] Batch Verifier started — monitoring " + LEDGER)
seen = set()
last_leaf = 0

with open(LOG,"w") as f:
    f.write(json.dumps({"ts_ms":int(time.time()*1000),"EVENT":"VERIFIER_STARTED"})+"\n")

while True:
    try:
        r = requests.get(LEDGER+"/tail?n=200", timeout=5)
        if r.status_code != 200: time.sleep(3); continue
        entries = r.json()
        if not isinstance(entries, list): entries=[]

        for entry in entries:
            leaf = entry.get("leaf", 0)
            if leaf <= last_leaf: continue

            # Extract raw event
            raw = entry.get("raw", {})
            if isinstance(raw, str):
                try: raw = json.loads(raw)
                except: raw = {}

            if not isinstance(raw, dict): continue
            if raw.get("type") != "ACCUMULATOR_BATCH": continue

            bid = raw.get("batch_id","")
            if bid in seen: continue
            seen.add(bid)
            last_leaf = max(last_leaf, leaf)

            events = raw.get("events",[])
            hashes = raw.get("event_hashes",[])
            root   = raw.get("merkle_root","")
            gap_s  = raw.get("gap_s", raw.get("gap_duration_s",0))
            count  = raw.get("event_count",0)
            source = raw.get("data_source","unknown")
            sig    = raw.get("signature",{})

            hash_ok, root_ok = verify_merkle(events, hashes, root)
            seq_ok,  ts_ok   = verify_seq(events)
            ok = root_ok and seq_ok

            result = {
                "ts_ms":    int(time.time()*1000),
                "EVENT":    "BATCH_VERIFIED" if ok else "BATCH_TAMPERED",
                "batch_id": bid, "event_count": count,
                "gap_s":    gap_s, "source": source,
                "merkle_ok": root_ok, "hash_ok": hash_ok,
                "seq_ok":   seq_ok, "ts_ok": ts_ok,
                "integrity": ok,
                "algorithm": sig.get("alg","SHA3-256"),
                "leaf_index": leaf,
            }
            with open(LOG,"a") as f:
                f.write(json.dumps(result)+"\n")

            status = "VERIFIED" if ok else "TAMPERED"
            print("[VER] " + status + " batch=" + bid[:8] +
                  " events=" + str(count) +
                  " gap=" + str(gap_s) + "s" +
                  " merkle=" + str(root_ok) +
                  " seq=" + str(seq_ok) +
                  " alg=" + str(sig.get("alg","SHA3-256")) +
                  " source=" + str(source))

    except Exception as e:
        print("[VER] error: " + str(e))
    time.sleep(3)
