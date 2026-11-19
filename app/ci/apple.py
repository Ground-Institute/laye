#!/usr/bin/env python3
"""What Apple needs to hold for laye, made where it is missing.

Modelled on teranos/QNTX-App's .github/scripts/island-apple.py. laye is signed
by the team's distribution certificate, the one in IOS_CERTIFICATE. Apple signs
nothing without an App ID for laye and an App Store profile made against that
certificate; both are asked for with the key CI holds, and made when Apple has
none:

    apple.py OUT    the profile, as Apple wrote it, into the file OUT

The profile is no secret: it ships inside every build.

Reads APPLE_API_KEY, APPLE_API_ISSUER, APPLE_API_KEY_CONTENT, IOS_CERTIFICATE
and IOS_CERTIFICATE_PASSWORD from the environment.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile
import time

import jwt
import requests

ASC = "https://api.appstoreconnect.apple.com/v1"
# The app's bundle identifier is tauri.conf.json's, read rather than restated.
APP = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tauri.conf.json")))["identifier"]
PROFILE = "laye"


def bearer():
    key = base64.b64decode(os.environ["APPLE_API_KEY_CONTENT"]).decode()
    now = int(time.time())
    token = jwt.encode(
        {"iss": os.environ["APPLE_API_ISSUER"], "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        key, algorithm="ES256", headers={"kid": os.environ["APPLE_API_KEY"], "typ": "JWT"})
    return {"Authorization": f"Bearer {token}"}


def get(path, **params):
    r = requests.get(ASC + path, headers=bearer(), params=params, timeout=30)
    if r.status_code != 200:
        sys.exit(f"GET {path} answered {r.status_code}: {r.text}")
    return r.json()


def post(path, body):
    r = requests.post(ASC + path, headers={**bearer(), "Content-Type": "application/json"}, json=body, timeout=30)
    if r.status_code != 201:
        sys.exit(f"POST {path} answered {r.status_code}: {r.text}")
    return r.json()


def the_app_id():
    """laye's App ID, registered when Apple has none. The filter matches what
    begins with the identifier too, so the exact one is picked."""
    for held in get("/bundleIds", **{"filter[identifier]": APP, "limit": 200})["data"]:
        if held["attributes"]["identifier"] == APP:
            print("App ID:", APP, "is registered,", held["id"])
            return held["id"]
    made = post("/bundleIds", {"data": {"type": "bundleIds",
                                        "attributes": {"identifier": APP, "name": "laye", "platform": "IOS"}}})
    print("App ID:", APP, "registered now,", made["data"]["id"])
    return made["data"]["id"]


def the_certificate():
    """The distribution certificate laye is signed with: the one in
    IOS_CERTIFICATE, found at Apple by its serial number."""
    with tempfile.NamedTemporaryFile(suffix=".p12") as p12:
        p12.write(base64.b64decode(os.environ["IOS_CERTIFICATE"]))
        p12.flush()
        pem = subprocess.run(
            ["openssl", "pkcs12", "-in", p12.name, "-nokeys", "-passin", "env:IOS_CERTIFICATE_PASSWORD", "-legacy"],
            capture_output=True, check=False)
        if pem.returncode != 0:
            pem = subprocess.run(
                ["openssl", "pkcs12", "-in", p12.name, "-nokeys", "-passin", "env:IOS_CERTIFICATE_PASSWORD"],
                capture_output=True, check=True)
    serial = subprocess.run(["openssl", "x509", "-noout", "-serial"], input=pem.stdout,
                            capture_output=True, check=True).stdout.decode().strip().split("=", 1)[1]
    for held in get("/certificates", limit=200)["data"]:
        if held["attributes"]["serialNumber"].upper().lstrip("0") == serial.upper().lstrip("0"):
            print("certificate:", held["attributes"]["name"], held["id"], "expires", held["attributes"]["expirationDate"])
            return held["id"]
    sys.exit(f"Apple holds no certificate with the serial {serial} that IOS_CERTIFICATE carries")


def the_profile(app_id, certificate):
    """laye's profile as Apple wrote it, made when Apple has none that is active."""
    for held in get("/profiles", **{"filter[name]": PROFILE, "limit": 200})["data"]:
        a = held["attributes"]
        if a["name"] != PROFILE or a["profileState"] != "ACTIVE" or a["profileType"] != "IOS_APP_STORE":
            continue
        of = get(f"/profiles/{held['id']}/bundleId")["data"]["id"]
        against = [c["id"] for c in get(f"/profiles/{held['id']}/certificates", limit=200)["data"]]
        if of == app_id and certificate in against:
            print("profile:", repr(PROFILE), "is held,", held["id"], "expires", a["expirationDate"])
            return a["profileContent"]
        sys.exit(
            f"Apple holds the profile {PROFILE!r} ({held['id']}) of {of} against {against}, and laye is "
            f"{app_id} against {certificate}: it signs nothing here. Revoke it at Apple, and run this again")
    made = post("/profiles", {"data": {
        "type": "profiles",
        "attributes": {"name": PROFILE, "profileType": "IOS_APP_STORE"},
        "relationships": {
            "bundleId": {"data": {"type": "bundleIds", "id": app_id}},
            "certificates": {"data": [{"type": "certificates", "id": certificate}]},
        }}})["data"]
    print("profile:", repr(PROFILE), "made now,", made["id"], "expires", made["attributes"]["expirationDate"])
    return made["attributes"]["profileContent"]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    content = the_profile(the_app_id(), the_certificate())
    with open(sys.argv[1], "wb") as out:
        out.write(base64.b64decode(content))
    print("written:", sys.argv[1])
