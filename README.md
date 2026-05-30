# Hackastra 2026 CTF — Write-ups

Solutions for the challenges I solved during **Hackastra 2026 CTF**, one file per
challenge. Each write-up is self-contained: it includes the analysis, a single
complete solve script that runs from the challenge data to the final flag, and the
flag itself.

**Author:** CL4Y

## Challenges

| # | Challenge | Category | Difficulty | Points | Write-up |
|---|-----------|----------|:----------:|:------:|----------|
| 1 | Alibaba Game (Ali Baba's Enchanted Cave) | crypto    | medium | 373 | [01-alibaba-cave.md](01-alibaba-cave.md) |
| 2 | SmartLock                                | crypto    | medium | 250 | [02-smartlock.md](02-smartlock.md) |
| 3 | Cooper JailBreakout                      | crypto    | hard   | 250 | [03-cooper-jailbreakout.md](03-cooper-jailbreakout.md) |
| 4 | VOIDSTATION Mission Control (Hal-9)      | web       | medium | 253 | [04-voidstation-mission-control.md](04-voidstation-mission-control.md) |
| 5 | Corp Portal                              | web       | medium | 257 | [05-corp-portal.md](05-corp-portal.md) |
| 6 | License Lapse                            | reverse   | medium | 250 | [06-license-lapse.md](06-license-lapse.md) |
| 7 | crackme                                  | reverse   | easy   | 251 | [07-crackme.md](07-crackme.md) |
| 8 | humm.png                                 | forensics | easy   |  —  | [08-humm-png.md](08-humm-png.md) |
| 9 | MobileApp Beta Portal                    | misc      | medium | 318 | [09-mobileapp-beta-portal.md](09-mobileapp-beta-portal.md) |

## By category

- **Crypto** — [Alibaba Cave](01-alibaba-cave.md) (NFSR stream cipher → z3 → AES-CBC), [SmartLock](02-smartlock.md) (DSA nonce-from-ticket → HMAC forge), [Cooper JailBreakout](03-cooper-jailbreakout.md) (3× Coppersmith small-roots)
- **Web** — [VOIDSTATION Mission Control](04-voidstation-mission-control.md) (SVG-namespace stored XSS → cookie theft), [Corp Portal](05-corp-portal.md) (SAML signature wrapping, CVE-2025-47949)
- **Reverse** — [License Lapse](06-license-lapse.md) (invert per-byte constraint loop), [crackme](07-crackme.md) (arm64 `__ckdata` inverse transform)
- **Forensics** — [humm.png](08-humm-png.md) (LSB steganography)
- **Misc** — [MobileApp Beta Portal](09-mobileapp-beta-portal.md) (AWS Cognito `amr` trust-policy gap)

## Tooling

Solve scripts are Python 3. Depending on the challenge they use `pwntools`/sockets,
`z3-solver`, `pycryptodome`, `sympy`, `fpylll`, `mpmath`, `requests`, `boto3`, and
the standard reversing/forensics CLIs (`objdump`, `radare2`, `binwalk`, `zsteg`,
`exiftool`).

---

*All challenges solved & documented by **CL4Y**.*
