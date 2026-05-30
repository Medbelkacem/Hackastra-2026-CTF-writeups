---
title: "crackme"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: reverse
difficulty: easy
points: 251
flag_format: "FLAG{...}"
author: "CL4Y"
---

# crackme

> A retired embedded systems engineer encrypted his life's work before vanishing. All that remains is a small utility he wrote. It asks for something. Can you find it?

## Summary

A Swift `arm64` Mach-O binary reads a 22-byte input and checks it byte-by-byte against a hardcoded blob in a custom `__ckdata` Mach-O section. Each byte is transformed with `XOR 0x5A → rotate-right-3 → add index`. Inverting the transform over the stored bytes recovers the flag — no input guessing needed.

## Solution

### Step 1: Triage

`file` reports a `Mach-O 64-bit arm64` PIE Swift binary. Symbols reveal a `validate` function, and the section table shows a non-standard `__DATA.__ckdata` section (22 bytes) — clearly the comparison target.

```bash
file crackme
rabin2 -S crackme          # shows __DATA.__ckdata, 22 bytes @ paddr 0x8008
xxd -s 0x8008 -l 0x16 crackme
# 83c3 65a6 28d2 0bed 95d6 aa10 3992 ae75 35b1 99f8 9af9
```

### Step 2: Reverse `validate`

Disassembling `validate` (`r2 -c 'aaa; pdf @ sym._validate'`) shows:

- Length must equal `0x16` (22): `cmp x1, #0x16`.
- A loop over indices `0..21` computing, for each input byte:
  - `w0 = input[i] ^ 0x5A`
  - `ror w0, w0, #3`
  - `+ i`, mask to a byte
  - compare against `ckdata[i]`.

So the constraint is `ckdata[i] == (ROR8(input[i] ^ 0x5A, 3) + i) & 0xFF`. Inverting per byte: undo `+i`, rotate-left-3, then XOR `0x5A`.

```python
#!/usr/bin/env python3
# crackme solver — recovers flag from the __ckdata section bytes

ck = bytes.fromhex("83c365a628d20bed95d6aa103992ae7535b199f89af9")

def rol8(v, r):                       # inverse of the in-binary ROR8 by r
    return ((v << r) | (v >> (8 - r))) & 0xFF

flag = bytes(rol8((c - i) & 0xFF, 3) ^ 0x5A for i, c in enumerate(ck))
print(flag.decode())
```

Output:

```
FLAG{4rm64_r3v_is_fun}
```

## Flag

```
FLAG{4rm64_r3v_is_fun}
```
