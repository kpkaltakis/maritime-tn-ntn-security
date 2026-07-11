# kb_wire.py -- tiny length-prefixed JSON framing shared by prover/verifier/relay.
import json, struct

def send_msg(sock, obj):
    data = json.dumps(obj).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: raise ConnectionError("peer closed")
        buf += chunk
    return buf

def recv_msg(sock):
    hdr = recv_exact(sock, 4)
    n = struct.unpack(">I", hdr)[0]
    return json.loads(recv_exact(sock, n).decode())