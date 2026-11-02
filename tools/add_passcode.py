#!/usr/bin/env python3
"""Add (or replace) an extra passcode on data.enc.json without re-encrypting the data.

The main passcode (ATTENDANCE_PASSCODE) derives the data key as before. Each extra passcode gets
an entry in blob["keys"]: the 32 data-key bytes AES-GCM-wrapped under PBKDF2(extra passcode).
Old pages ignore "keys", so the main passcode keeps working everywhere.

    ATTENDANCE_PASSCODE=... ATTENDANCE_EXTRA_PASSCODE=... python3 tools/add_passcode.py [--data data.enc.json]
Re-run after every tools/build_snapshot.py run (a rebuild uses a new salt and drops "keys").
Nothing secret is printed.
"""
import argparse, base64, json, os, sys, tempfile
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

b64 = lambda b: base64.b64encode(b).decode()
d64 = base64.b64decode


def kdf(pw, salt, it):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=it).derive(pw.encode("utf-8"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=os.path.join(os.path.dirname(__file__), "..", "data.enc.json"))
    ap.add_argument("--iterations", type=int, default=650000)
    a = ap.parse_args()
    main_pw, extra = os.environ.get("ATTENDANCE_PASSCODE"), os.environ.get("ATTENDANCE_EXTRA_PASSCODE")
    if not main_pw or not extra:
        sys.exit("Set ATTENDANCE_PASSCODE and ATTENDANCE_EXTRA_PASSCODE")
    blob = json.load(open(a.data))
    bits = kdf(main_pw, d64(blob["salt"]), blob["iter"])
    AESGCM(bits).decrypt(d64(blob["iv"]), d64(blob["ct"]), None)  # proves the main passcode is right
    keys = []
    for k in blob.get("keys", []):  # drop any existing entry for this same extra passcode
        try:
            AESGCM(kdf(extra, d64(k["salt"]), k["iter"])).decrypt(d64(k["iv"]), d64(k["ct"]), None)
        except Exception:
            keys.append(k)
    salt, iv = os.urandom(16), os.urandom(12)
    keys.append({"salt": b64(salt), "iv": b64(iv), "iter": a.iterations,
                 "ct": b64(AESGCM(kdf(extra, salt, a.iterations)).encrypt(iv, bits, None))})
    blob["keys"] = keys
    out = os.path.abspath(a.data)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(out), suffix=".tmp")
    with os.fdopen(fd, "w") as f:
        json.dump(blob, f); f.write("\n")
    os.chmod(tmp, 0o644); os.replace(tmp, out)
    print(f"OK: {len(keys)} extra passcode(s) on {os.path.basename(out)}", file=sys.stderr)


if __name__ == "__main__":
    main()
