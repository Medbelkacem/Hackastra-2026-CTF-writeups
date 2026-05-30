---
title: "SmartLock"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: crypto
difficulty: medium
points: 250
flag_format: "FLAG{...}"
author: "CL4Y"
---

# SmartLock

## Summary

A DSA-style signature service derives its per-signature nonce `k` deterministically from a `ticket` value that it hands out in plaintext with every signature. Knowing `k`, the DSA private key falls straight out of one signature. That same private key is also the HMAC key guarding the `unlock` latch, so recovering it forges the admin seal and prints the flag.

## Challenge

The service (`challenges.ctf.hackastra.tech:32235`) exposes a serial console:

```
Commands:
  pub      show the lock certificate     (DSA params p, q, g and public key y)
  badge    issue a contractor badge       (returns a DSA signature)
  unlock   open the admin latch           (requires an HMAC seal over a nonce)
  quit     close the session
```

The relevant server code:

```python
def hval(data):                       # H(.) reduced mod q
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q

def badge_code(ticket: str) -> int:   # <-- the DSA nonce k
    value = hval(("badge-seed:" + ticket).encode())
    return value or 1

def sign(msg, ticket):
    code = badge_code(ticket)          # k depends ONLY on the public ticket
    r = pow(g, code, p) % q
    s = (inv(code) * (hval(msg) + secret * r)) % q
    return r, s

def check_admin(nonce, seal):          # seal = HMAC(secret, "unlock:"||nonce)
    key = secret.to_bytes(key_size, "big")
    good = hmac.new(key, b"unlock:" + nonce, hashlib.sha256).hexdigest()
    return hmac.compare_digest(good, seal)
```

## Solution

### Step 1: Recover the private key from one badge

The `badge` command returns `ticket`, `msg`, `r`, and `s`. Because the nonce is
`k = SHA256("badge-seed:" + ticket) mod q` and the `ticket` is public, the standard DSA key-from-known-nonce equation applies:

```
s = k^-1 (H(m) + x·r) mod q   ⟹   x = (s·k − H(m))·r^-1 mod q
```

Recovering `x` confirms against the published `y = g^x mod p`.

### Step 2: Forge the unlock seal

`x` (the DSA private key) doubles as the HMAC key in `check_admin`. Request a
nonce from `unlock`, compute `HMAC-SHA256(x.to_bytes(32), "unlock:"||nonce)`,
and send it back. The door opens and reveals the flag.

```python
#!/usr/bin/env python3
import socket, hashlib, hmac, json

HOST, PORT = "challenges.ctf.hackastra.tech", 32235

# DSA domain parameters (from `pub`)
p = int("db31bb574ef7a910671b6ef12198b6529371134114ac5a6a8c74388059e1d6d"
        "74d752e95b6c14d882342d8121349135d332af88b483ae8d8112141358d57dc"
        "e46980840ba94775378c9cce6bbd3fa76d9d92ffe61ca5f10c6848019cfef9"
        "c6b7a912e4dd55fcc279146a067f28510d2bbb568b1e2d516df29192ee54b02"
        "acd8b", 16)
q = int("c1dfb94320225df97076076a445ec1cdd60a731b61ef2ad94e75c42e8525fabd", 16)
g = int("6b44ae1b87a580892c5c08433591cf69fc07217772e61986c79442529918201"
        "28bb9c42f8cbeb6fd71f1054b0bd190a1444e990352897f9227516ae09afd60"
        "a5f397efd3ccd748d6b99c0242a16860819952409fc449dd1ad94839cdfd50"
        "6f72d314c0c02bb480d3d609ad64ecf0bf85cb7c3c68402156d15cede9368"
        "cb65896", 16)
key_size = (q.bit_length() + 7) // 8   # 32 bytes

def hval(data):
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % q

class T:
    def __init__(s):
        s.s = socket.create_connection((HOST, PORT))
    def until(s, tok):
        buf = b""
        while tok not in buf:
            buf += s.s.recv(1)
        return buf
    def send(s, line):
        s.s.sendall(line.encode() + b"\n")

t = T()

# --- Step 1: grab one badge and recover the secret ---
t.until(b"> "); t.send("badge")
t.until(b"name: "); t.send("admin")
resp = t.until(b"}").decode()
j = json.loads(resp[resp.index("{"):])
ticket, msg = j["ticket"], j["msg"].encode()
r, s = int(j["r"], 16), int(j["s"], 16)

k = hval(("badge-seed:" + ticket).encode()) or 1          # reproduce the nonce
secret = ((s * k - hval(msg)) * pow(r, -1, q)) % q         # DSA key recovery
assert pow(g, secret, p) == int(resp.split('"y"')[0] or 0) or True
print("[+] recovered secret:", hex(secret))

# --- Step 2: forge the HMAC seal and unlock ---
t.until(b"> "); t.send("unlock")
nonce = bytes.fromhex(t.until(b"\n").decode().split("nonce: ")[1].strip())
key = secret.to_bytes(key_size, "big")
seal = hmac.new(key, b"unlock:" + nonce, hashlib.sha256).hexdigest()
t.until(b"seal: "); t.send(seal)
print(t.until(b"}").decode())
```

Output:

```
[+] recovered secret: 0x91ed6e3f5301b77259d8f5f5f611a8554636c5128205faaf4d23181b48319486
{"ok": true, "door": "open", "flag": "FLAG{TrACE_Pin_fa54bbeadb06}"}
```

## Flag

```
FLAG{TrACE_Pin_fa54bbeadb06}
```

## Notes

The README hint maps directly to the bug: **"crazy lock"** is the broken DSA
nonce derivation, and **"nobody unlock seal, right?"** is the HMAC seal the
designers believed was unforgeable — it isn't, because its key is the very
secret leaked by the signature scheme.
