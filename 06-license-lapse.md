---
title: "License Lapse"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: reverse
difficulty: medium
points: 250
flag_format: "FLAG{...}"
author: "CL4Y"
---

# License Lapse

## Summary

`maintcheck` is a stripped x86-64 PIE that issues a "recovery token" only when fed
the correct override code for a specific controller device ID. The token is derived
deterministically from the device ID and the code, so once we recover the unique
code that satisfies the per-byte constraint loop, the program prints the flag
directly as the token.

## Solution

### Step 1: Map the validator

Disassembling `main` (`objdump -d -M intel`) reveals three input-processing stages:

1. **Device ID** (`device id>`): non-alphanumeric chars are stripped and the rest
   uppercased → `PLC7F2A4410`. It must be 11 chars, start with `PLC` (`memcmp` at
   `0x12f2`), and have 8 hex digits in positions 3–10 (`_ISxdigit` check).
2. **Code** (`code>`): dashes/spaces are skipped, chars uppercased, then each is
   decoded against the base32 alphabet `ABCDEFGHJKLMNPQRSTUVWXYZ23456789` at `0x20c0`.
   Exactly 16 indices are required.
3. **Constraint loop** (`0x1428`): a helper at `0x1700` (`mix`) hashes the device ID
   into a 16-byte buffer `M`. Tables `T1/T2/T3` live in `.rodata` (`0x20f0/0x2100/0x2110`).
   For each byte `i` the decoded code index `idx[i]` must satisfy:

   ```
   rol((idx[i] + T1[i] + (M[(i+1)%16] & 0xf)) & 0xff, 2) ^ (M[i] ^ T2[i]) == T3[i]
   ```

This is fully invertible: `idx[i] = ror(T3[i]^M[i]^T2[i], 2) - T1[i] - (M[(i+1)%16]&0xf)`.

### Step 2: Recover the code and token

We re-implement `mix` (the `0x1700` helper) exactly, derive `M`, invert the
constraint to get the 16 base32 indices, and reproduce the token-generation loop
(`0x153d`) — which turns out to emit the flag verbatim.

```python
M32 = 0xffffffff

def mix(idb):
    """Reimplementation of fcn @ 0x1700: device ID -> 16-byte buffer M."""
    L = len(idb); r11 = 0x13; r8 = 5; r10 = 0xffffff9d; r9 = 0x42; r12 = 0x27
    out = []
    for i in range(16):
        rem_i = i % L; oldr8 = r8; r8 = (r8 + 3) & M32
        c = idb[rem_i]; rem2 = oldr8 % L
        eax = r11 & M32; r11 = (r11 + 0x13) & M32
        eax ^= c
        ecx = (c + i) & M32
        r9 = (r9 + eax) & M32
        edx = idb[rem2]
        eax = edx; eax ^= r12; r12 = (r12 + 7) & M32; eax ^= r10
        al = ((eax & 0xff) << 1 | (eax & 0xff) >> 7) & 0xff      # rol al,1
        eax = (eax & 0xffffff00) | al; r10 = eax & M32
        eax = (ecx + edx) & M32                                  # lea eax,[rcx+rdx]
        cnt = (i & 0x1f) % 8; al = eax & 0xff                    # rol al,cl
        if cnt: al = ((al << cnt) | (al >> (8 - cnt))) & 0xff
        eax = (eax & 0xffffff00) | al
        eax = (eax ^ r9) & M32; eax = (eax ^ r10) & M32
        out.append(eax & 0xff)
    return out

ror8 = lambda v, c: (((v & 0xff) >> (c & 7)) | ((v & 0xff) << (8 - (c & 7)))) & 0xff if c & 7 else v & 0xff
rol8 = lambda v, c: (((v & 0xff) << (c & 7)) | ((v & 0xff) >> (8 - (c & 7)))) & 0xff if c & 7 else v & 0xff

ID  = b"PLC7F2A4410"                                # uppercased alnum device ID
T1  = bytes.fromhex("11071b0d0915031f0b1305190f17011d")
T2  = bytes.fromhex("6a3c5127780e44196 32d5a317408461b".replace(" ", ""))
T3  = bytes.fromhex("e4723c23f2aef0e61dcbad45601795ba")
S   = bytes.fromhex("766753ea064780e78e1a29a0b2774d9b7f263344 1052bd8e54a14670de30158d".replace(" ", ""))
AL  = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

M = mix(ID)

# Invert the constraint loop to recover the 16 code indices.
idxs = []
for i in range(16):
    acc = ror8(T3[i] ^ M[i] ^ T2[i], 2)
    idx = (acc - T1[i] - (M[(i + 1) & 0xf] & 0xf)) & 0xff
    assert 0 <= idx < 32
    idxs.append(idx)

code = "".join(AL[i] for i in idxs)
print("code      :", "-".join(code[i:i+4] for i in range(0, 16, 4)))

# Reproduce the token loop @ 0x153d (the token *is* the flag).
tok = []
for r in range(32):
    al = ((idxs[(r * 5) & 0xf] * 7) + r) & 0xff
    al ^= M[r & 0xf]
    al = rol8(al, r & 31)
    al ^= S[r]
    al ^= 0x6b
    tok.append(al)
print("flag      :", bytes(tok).decode())
```

Output:

```
code      : M7Q3-X9NC-T4VK-2H6R
flag      : FLAG{offline_plc_maint_7F2A4410}
```

### Step 3: Verify against the real binary

```bash
$ printf 'PLC-7F2A-4410\nM7Q3-X9NC-T4VK-2H6R\n' | ./maintcheck
Field Maintenance Utility v2.4
offline support mode
device id> code> [+] recovery token issued
token: FLAG{offline_plc_maint_7F2A4410}
```

## Flag

```
FLAG{offline_plc_maint_7F2A4410}
```
