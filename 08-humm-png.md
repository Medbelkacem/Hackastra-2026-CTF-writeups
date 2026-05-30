---
title: "humm.png"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: forensics
difficulty: easy
points: 0
flag_format: "FLAG{...}"
author: "CL4Y"
---

# humm.png — Forensics / Steganography

## Summary

A plain PNG with no metadata, no appended data, and nothing in `strings`. The flag is hidden in the **least-significant bit** of the R/G/B channels, read in normal `xy` pixel order — classic LSB steganography, recovered in one `zsteg` sweep and verified by hand.

## Challenge

We are given a single archive `file_for_participants.zip`. Extracting it yields one file:

```
given/humm.png
```

No prompt, no hint — just an image. The flag has to be hidden inside it.

## Solution

### Step 1: Recon

First, identify the file and pull its metadata.

```bash
unzip file_for_participants.zip -d extracted
file extracted/given/humm.png
# PNG image data, 558 x 597, 8-bit/color RGB, non-interlaced

exiftool extracted/given/humm.png
# Standard PNG, no suspicious metadata fields, no comments
```

Nothing interesting in the metadata. Next, check for appended/embedded files:

```bash
binwalk humm.png
# 0    PNG image, 558 x 597, 8-bit/color RGB
# 41   Zlib compressed data, default compression   <-- this is just the IDAT stream
```

Only the normal PNG image data — no trailing archive after `IEND`, no second file. `strings` also turned up nothing readable.

That rules out the easy stuff (metadata, file overlays, appended archives), which points squarely at **pixel-level steganography**.

### Step 2: The Find

For an 8-bit RGB PNG with no other leads, the canonical move is to sweep the bit planes. `zsteg` automates this across every channel, bit position, bit order, and pixel-scan order:

```bash
zsteg -a humm.png
```

One line jumps out:

```
b1,rgb,lsb,xy   .. text: "FLAG{LSB_1s_n0t_d34d}<<<END>>>"
```

Decoded: the message lives in **bit 0 (the least-significant bit)** of each of the R, G, and B channels, read across the image in normal left-to-right, top-to-bottom (`xy`) pixel order. The author tacked on `<<<END>>>` as a terminator so the extractor knows where the payload stops.

### Step 3: Manual Verification

To confirm it's a genuine LSB embed and not a zsteg artifact, we can extract the same bits by hand with Python:

```python
from PIL import Image

img = Image.open("extracted/given/humm.png").convert("RGB")
bits = []
for px in img.getdata():          # iterate pixels in xy order
    for channel in px:            # R, G, B
        bits.append(channel & 1)  # least-significant bit

# pack 8 bits/byte, MSB-first, until we hit the END marker
out = bytearray()
for i in range(0, len(bits) // 8 * 8, 8):
    byte = 0
    for b in bits[i:i+8]:
        byte = (byte << 1) | b
    out.append(byte)
    if b"<<<END>>>" in out:
        break

print(out.split(b"<<<END>>>")[0].decode())
# FLAG{LSB_1s_n0t_d34d}
```

Same result — the flag is reproducible from first principles.

## Flag

```
FLAG{LSB_1s_n0t_d34d}
```

## Takeaways

- Work the checklist in order of effort: `file` → `exiftool` → `strings` → `binwalk` → bit-plane analysis. The metadata/overlay checks are cheap and rule out whole families of tricks.
- When an image has no metadata and nothing appended, default to LSB / bit-plane stego. `zsteg -a` sweeps all the standard permutations in one shot — don't hand-guess channel/bit/order combos first.
- The flag is self-describing on purpose: LSB steganography is old, but it's *not dead*. It's still the first thing to try on a plain PNG/BMP.
