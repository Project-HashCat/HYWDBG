#!/usr/bin/env python3
import json
import socket
import sys

HOST = "127.0.0.1"
PORT = 31337

if len(sys.argv) < 2:
    print("usage: hywctl.py <method> [json_params]")
    print("example: hywctl.py core.startBackend '{\"kind\":\"titan\"}'")
    raise SystemExit(2)

method = sys.argv[1]
params = None
if len(sys.argv) >= 3:
    params = json.loads(sys.argv[2])

req = {"id": 1, "method": method, "params": params}
with socket.create_connection((HOST, PORT), timeout=5) as s:
    s.sendall((json.dumps(req) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
print(json.dumps(json.loads(data.decode()), indent=2, ensure_ascii=False))
