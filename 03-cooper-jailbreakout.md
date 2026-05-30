---
title: "Cooper JailBreakout"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: crypto
difficulty: hard
points: 250
flag_format: "FLAG{...}"
author: "CL4Y"
---

# Cooper JailBreakout

## Summary

Three independent RSA-style levels, all using `e=3`, each leaking a different chapter of the flag. Every level reduces to a **Coppersmith small-roots** problem — known high bits of a factor (Level 1), short-pad related messages (Level 2), and a partially-known message via `m|x` (Level 3). The flag is the concatenation of the three recovered chapters.

The challenge name is the hint: *Cooper* = Coppersmith, *JailBreakout* = escaping the "cage" of each weak construction.

## Background

The same flag is split across `note_level{1,2,3}.txt`, one chapter per level, so all three must be solved:

- **Level 1** — Goldwasser-Micali bit encryption; leaks `hint = ⌊D·(√p+√q)⌋`.
- **Level 2** — two cubes of `note‖md5(note)` and `note‖md5("One more time!"+note)`.
- **Level 3** — `c = (m|x)³ mod N` with `x` and `m&x` given.

All three need the same univariate Coppersmith routine, so we build it once.

## Solution

### Step 0: Shared Coppersmith routine (`coppersmith.py`)

Standard Howgrave-Graham construction with `fpylll` LLL. Root extraction uses **pairwise polynomial GCD** of the shortest reduced vectors (the small root is their common linear factor) — far faster than exact `all_roots()` on the high-degree LLL output.

```python
# coppersmith.py  -- univariate Coppersmith (Howgrave-Graham) via fpylll
from fpylll import IntegerMatrix, LLL
from sympy import symbols
X = symbols('X')

def _mul(a, b):
    r = [0]*(len(a)+len(b)-1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            r[i+j] += ai*bj
    return r

def _poly_pow(c, k):
    res = [1]
    for _ in range(k):
        res = _mul(res, c)
    return res

def small_roots(f_coeffs, N, beta, bound, m=None, t=None):
    """f_coeffs monic, low->high. Find x0 with f(x0)==0 mod b, b>=N^beta, |x0|<=bound."""
    d = len(f_coeffs) - 1
    assert f_coeffs[-1] == 1
    if m is None: m = 3
    if t is None: t = max(1, int(d*m*(1.0/beta - 1)) + 1)
    polys = []
    for i in range(m):                       # N^(m-i) * x^j * f^i
        fi = _poly_pow(f_coeffs, i)
        for j in range(d):
            polys.append([N**(m-i)*c for c in _mul([0]*j+[1], fi)])
    fm = _poly_pow(f_coeffs, m)
    for i in range(t):                       # x^i * f^m
        polys.append(_mul([0]*i+[1], fm))
    dim = d*m + t
    M = [[0]*dim for _ in range(len(polys))]
    for r, g in enumerate(polys):
        for power, cf in enumerate(g):
            if power < dim:
                M[r][power] = cf*(bound**power)
    A = IntegerMatrix.from_matrix(M)
    LLL.reduction(A)
    rows = []
    for row in range(min(dim, A.nrows)):
        coeffs, ok = [], True
        for power in range(dim):
            v = A[row, power]
            if v % (bound**power): ok = False; break
            coeffs.append(v // (bound**power))
        if not ok: continue
        while len(coeffs) > 1 and coeffs[-1] == 0: coeffs.pop()
        if len(coeffs) >= 2: rows.append(coeffs)
    return roots_from_gcd(rows)

def roots_from_gcd(rows_polys, nrows=6):
    from sympy import Poly, gcd, QQ, Rational
    Xs = symbols('Xs')
    polys = [Poly(list(reversed(c)), Xs, domain=QQ) for c in rows_polys[:nrows] if len(c) >= 2]
    roots = set()
    for i in range(len(polys)):
        for j in range(i+1, len(polys)):
            g = gcd(polys[i], polys[j])
            if g.degree() >= 1:
                for r in g.all_roots():
                    if r.is_rational and Rational(r).q == 1:
                        roots.add(int(Rational(r)))
    return roots
```

### Step 1: Level 1 — Chapter 1 (known-high-bits factoring + GM decryption)

The leak `hint = ⌊D·(√p+√q)⌋` (with `D` given) pins `√p+√q` to ~84 bits of precision. Combined with the exact `n`, solving `t² − (√p+√q)t + √n = 0` gives `p` to within ~2⁵⁸⁶ — i.e. >55% of its top bits. Coppersmith (`f(x)=x+p_approx`, root `mod p`, `β=0.5`) then recovers the exact `p`. Since `2674 = 2·1337`, the per-bit ciphertext `xᵇⁱᵗ⁺¹³³⁷·r²⁶⁷⁴` is a quadratic residue iff the bit is `1` — pure Goldwasser-Micali, trivially decrypted once `n` is factored.

```python
import re, mpmath as mp
from coppersmith import small_roots
from Crypto.Util.number import long_to_bytes

mp.mp.dps = 1500
data = open('file_for_participants/output_level1.txt').read()
hint = int(re.search(r'hint = (\d+)', data).group(1))
D    = int(re.search(r'D = (\d+)', data).group(1))
n    = int(re.search(r'n = (\d+)', data).group(1))
enc  = [int(t) for t in re.search(r'c = \[(.*?)\]', data, re.S).group(1).split(',')]

s   = mp.mpf(hint)/mp.mpf(D)              # sqrt(p)+sqrt(q)
sqn = mp.sqrt(mp.mpf(n))
a   = (s + mp.sqrt(s*s - 4*sqn))/2        # sqrt(p)
p_approx = int(a*a)

p = None
for m in (6, 8, 10, 12):                  # bound 2^600 < n^0.25 ~ 2^668
    for r0 in small_roots([p_approx, 1], n, 0.5, 1 << 600, m=m, t=m):
        if (p_approx + r0) > 1 and n % (p_approx + r0) == 0:
            p = p_approx + r0; break
    if p: break
assert n % p == 0

bits = [1 if pow(c % p, (p-1)//2, p) == 1 else 0 for c in enc]   # Legendre -> bit
note = int(''.join(map(str, bits)), 2)
print(long_to_bytes(note))
# [Chapter 1] - Whisper Weakness >>> FLAG{R34DY_T0_3SC4P3_WH3N
```

### Step 2: Level 2 — Chapter 2 (Coppersmith short-pad + Franklin-Reiter)

Both messages are `note·2¹²⁸ + h`, sharing the `note` prefix and differing only in the 128-bit md5 pad. The resultant of `x³−C1` and `(x+y)³−C2` is a degree-9 polynomial in the pad difference `Δ = h₂−h₁ < 2¹²⁸` (well under the `n^{1/9} ≈ 2²²⁷` bound). Coppersmith recovers `Δ`; Franklin-Reiter (poly GCD mod n) then yields the message.

```python
import re
from sympy import symbols, resultant, Poly
from coppersmith import small_roots
from Crypto.Util.number import long_to_bytes

d = open('file_for_participants/output_level2.txt').read()
n  = int(re.search(r'n = (0x[0-9a-f]+)',  d).group(1), 16)
C1 = int(re.search(r'C1 = (0x[0-9a-f]+)', d).group(1), 16)
C2 = int(re.search(r'C2 = (0x[0-9a-f]+)', d).group(1), 16)

x, y = symbols('x y')
res = Poly(resultant(x**3 - C1, (x+y)**3 - C2, x), y)   # deg-9 poly in Delta
hi  = [int(c) % n for c in res.all_coeffs()]
linv = pow(hi[0], -1, n)
coeffs = [(c*linv) % n for c in hi[::-1]]               # monic, low->high

delta = None
for m in (3, 4, 5):
    for r0 in small_roots(coeffs, n, 1.0, 1 << 130, m=m, t=1):
        if sum(c*pow(r0, i, n) for i, c in enumerate(coeffs)) % n == 0:
            delta = r0; break
    if delta: break

# Franklin-Reiter: gcd(x^3 - C1, (x+delta)^3 - C2) over Z_n -> (x - M1)
def trim(p): 
    p = [c % n for c in p]
    while len(p) > 1 and p[-1] == 0: p.pop()
    return p
def poly_mod(a, b):
    a, b = trim(a[:]), trim(b[:]); db = len(b)-1; binv = pow(b[db], -1, n)
    while len(a)-1 >= db and not (len(a) == 1 and a[0] == 0):
        da = len(a)-1; co = (a[da]*binv) % n; sh = da-db
        for i in range(db+1): a[sh+i] = (a[sh+i] - co*b[i]) % n
        a = trim(a)
        if len(a)-1 == da: a[da] = 0; a = trim(a)
    return a
def poly_gcd(a, b):
    a, b = trim(a[:]), trim(b[:])
    while not (len(b) == 1 and b[0] == 0): a, b = b, poly_mod(a, b)
    return a

D = delta % n
g = poly_gcd([(-C1) % n, 0, 0, 1], [(D**3 - C2) % n, (3*D*D) % n, (3*D) % n, 1])
M1 = (-g[0] * pow(g[1], -1, n)) % n
print(long_to_bytes(M1 >> 128))
# [Chapter 2] - The Forged Seal >>> _TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R
```

### Step 3: Level 3 — Chapter 3 (Coppersmith on `m|x`)

Given `x` and `m&x`, note that `m|x = x + (m&~x)`, where `delta = m&~x` is small (only the flag-sized low bits). So `c = (x+delta)³ mod N`, and Coppersmith finds the small `delta`; then `m = (m&x) + delta`.

```python
import re
from coppersmith import small_roots
from Crypto.Util.number import long_to_bytes

d = open('file_for_participants/output_level3.txt').read()
N   = int(re.search(r'N = (\d+)', d).group(1))
c   = int(re.search(r'^c = (\d+)', d, re.M).group(1))
mx  = int(re.search(r'\(m & x\) = (\d+)', d).group(1))
x   = int(re.search(r'^x = (\d+)', d, re.M).group(1))

# f(D) = (x+D)^3 - c mod N, small root D = m & ~x
f = [ (x**3 - c) % N, (3*x*x) % N, (3*x) % N, 1 ]
for m in (3, 4, 6, 8):
    for delta in small_roots(f, N, 1.0, 1 << 480, m=m, t=1):
        if pow(x + delta, 3, N) == c % N:
            print(long_to_bytes(mx + delta)); raise SystemExit
# [Chapter 3] - The Oracle's Mask >>> _7H3_C4G3_xD}
```

### Step 4: Assemble the flag

Concatenate the text after `>>> ` from each chapter:

```
FLAG{R34DY_T0_3SC4P3_WH3N} + _TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R + _7H3_C4G3_xD}
```

## Flag

```
FLAG{R34DY_T0_3SC4P3_WH3N_TH3_D00R_0P3N5_WH1L3_C0PP3R5M17H_3NT3R_7H3_C4G3_xD}
```

## Notes & Gotchas

- **No SageMath needed** — `fpylll` + `sympy` are enough; the only trick is doing root extraction via pairwise GCD of the shortest LLL vectors instead of `all_roots()` on the full degree-`(dim−1)` output (which is pathologically slow on huge integer coefficients).
- **Level 1 precision**: `hint` fixes `√p+√q` only to ~84 bits, giving `p` to ~2⁵⁸⁶ error — exactly inside Coppersmith's `n^{0.25}` (2⁶⁶⁸) window. `m=6` (dim 12) already satisfies `(m−1)/(2(2m−1)) = 0.227 ≥ 0.219`.
- **GM bit rule**: `2674 = 2·1337`, so `r²⁶⁷⁴` is always a square; the parity of the `x` exponent (`1337+bit`) decides residuosity → `bit = [Legendre(c, p) == 1]`.
- **Tools**: Python 3, `pycryptodome`, `sympy`, `fpylll`, `mpmath`.
