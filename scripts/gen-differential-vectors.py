#!/usr/bin/env python3
"""Generate differential test vectors with independent Python implementations
(pyemv 1.5 and psec) so the Rust crate is checked against a second codebase
on random inputs, not just a handful of fixed examples.

    pip install pyemv psec
    python3 scripts/gen-differential-vectors.py > crates/cardcrypto/tests/data/differential.json
"""
import json
import random

from pyemv import cvn, kd, ac
import psec

rng = random.Random(8583)


def rhex(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def rdigits(n):
    return "".join(rng.choice("0123456789") for _ in range(n))


cases = []
for i in range(60):
    imk = rhex(16)
    pan = rdigits(rng.choice([16, 16, 16, 19]))
    psn = rdigits(2)
    pin = rdigits(4)
    data = {
        "9F02": rhex(6), "9F03": rhex(6), "9F1A": rhex(2), "95": rhex(5),
        "5F2A": rhex(2), "9A": rhex(3), "9C": rhex(1), "9F37": rhex(4),
        "82": rhex(2), "9F36": rhex(2),
    }
    c = {
        "imk": imk.hex().upper(), "pan": pan, "psn": psn, "pin": pin,
        "txn": {k: v.hex().upper() for k, v in data.items()},
        "mk_a": kd.derive_icc_mk_a(imk, pan, psn).hex().upper(),
        "mk_b": kd.derive_icc_mk_b(imk, pan, psn).hex().upper(),
    }
    args = dict(tag_9f02=data["9F02"], tag_9f03=data["9F03"], tag_9f1a=data["9F1A"],
                tag_95=data["95"], tag_5f2a=data["5F2A"], tag_9a=data["9A"],
                tag_9c=data["9C"], tag_9f37=data["9F37"], tag_82=data["82"],
                tag_9f36=data["9F36"])
    cvr = rhex(4)
    c10 = cvn.VisaCVN10(imk, imk, imk, pan, psn)
    arqc10 = c10.generate_ac(**args, cvr=cvr)
    c["cvn10"] = {"iad": ("06010A" + cvr.hex() + "").upper(), "arqc": arqc10.hex().upper(),
                  "arpc_3030": c10.generate_arpc(arqc10, b"00").hex().upper()}
    iad18 = bytes.fromhex("060112") + rhex(4)
    c18 = cvn.VisaCVN18(imk, imk, imk, pan, psn)
    arqc18 = c18.generate_ac(**args, tag_9f10=iad18)
    csu = rhex(4)
    c["cvn18"] = {"iad": iad18.hex().upper(), "arqc": arqc18.hex().upper(), "csu": csu.hex().upper(),
                  "arpc": c18.generate_arpc(arqc18, data["9F36"], csu).hex().upper()}
    pvk = rhex(16)
    c["pvk"] = pvk.hex().upper()
    c["pvv_pvki1"] = psec.pin.generate_visa_pvv(pvk, "1", pin, pan)
    c["iso0"] = psec.pinblock.encode_pinblock_iso_0(pin, pan).hex().upper()
    exp = rdigits(4)
    c["expiry"] = exp
    c["cvv_101"] = psec.cvv.generate_cvv(pvk, pan, exp, "101")
    cases.append(c)

print(json.dumps(cases, indent=1))
