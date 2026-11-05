#!/usr/bin/env python3
"""Real-device PRF (hmac-secret) verification for iphone-fido-key.

Talks CTAPHID to the daemon's UHID device (/dev/hidraw10) and plays the
platform role of pinUvAuthProtocol ONE exactly like src/selftest.rs:
getInfo -> ClientPIN getKeyAgreement -> makeCredential(hmac-secret)
-> getAssertion with salts (A, A, B): outputs must be encrypted on the
wire, deterministic per salt, different across salts, and every
signature must verify.
"""
import hashlib
import hmac as hmac_mod
import os
import struct
import sys
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: F401  (unused, clarity)
from cryptography.exceptions import InvalidSignature

DEV = sys.argv[1] if len(sys.argv) > 1 else "/dev/hidraw10"

# ---------- minimal CBOR ----------
def enc(v):
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        if v >= 0:
            return _enc_head(0, v)
        return _enc_head(1, -1 - v)
    if isinstance(v, (bytes, bytearray)):
        return _enc_head(2, len(v)) + bytes(v)
    if isinstance(v, str):
        b = v.encode()
        return _enc_head(3, len(b)) + b
    if isinstance(v, (list, tuple)):
        return _enc_head(4, len(v)) + b"".join(enc(x) for x in v)
    if isinstance(v, dict):
        return _enc_head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
    raise TypeError(v)

def _enc_head(mt, n):
    mt <<= 5
    if n < 24:
        return bytes([mt | n])
    if n < 256:
        return bytes([mt | 24, n])
    if n < 65536:
        return bytes([mt | 25]) + struct.pack(">H", n)
    return bytes([mt | 26]) + struct.pack(">I", n)

class Dec:
    def __init__(self, b, i=0):
        self.b, self.i = b, i
    def read(self):
        ib = self.b[self.i]; self.i += 1
        mt, ai = ib >> 5, ib & 31
        if ai < 24:
            n = ai
        elif ai == 24:
            n = self.b[self.i]; self.i += 1
        elif ai == 25:
            n = struct.unpack(">H", self.b[self.i:self.i+2])[0]; self.i += 2
        elif ai == 26:
            n = struct.unpack(">I", self.b[self.i:self.i+4])[0]; self.i += 4
        elif ai == 27:
            n = struct.unpack(">Q", self.b[self.i:self.i+8])[0]; self.i += 8
        else:
            raise ValueError(f"ai {ai}")
        if mt == 0:
            return n
        if mt == 1:
            return -1 - n
        if mt == 2:
            v = self.b[self.i:self.i+n]; self.i += n; return bytes(v)
        if mt == 3:
            v = self.b[self.i:self.i+n]; self.i += n; return v.decode()
        if mt == 4:
            return [self.read() for _ in range(n)]
        if mt == 5:
            d = {}
            for _ in range(n):
                k = self.read(); d[k] = self.read()
            return d
        if mt == 7:
            return {20: False, 21: True, 22: None}[n]
        raise ValueError(f"mt {mt}")

def dec(b):
    return Dec(b).read()

# ---------- CTAPHID ----------
fd = os.open(DEV, os.O_RDWR | os.O_NONBLOCK)

def hid_write(cid, cmd, payload):
    pkt = struct.pack(">IBH", cid, 0x80 | cmd, len(payload)) + payload[:57]
    os.write(fd, pkt.ljust(64, b"\x00"))
    rest, seq = payload[57:], 0
    while rest:
        chunk, rest = rest[:59], rest[59:]
        os.write(fd, struct.pack(">IB", cid, seq) + chunk .ljust(59, b"\x00") if False else (struct.pack(">IB", cid, seq) + chunk).ljust(64, b"\x00"))
        seq += 1

def hid_read(cid_want, timeout=150):
    buf, total = b"", None
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data = os.read(fd, 64)
        except BlockingIOError:
            time.sleep(0.03); continue
        if not data:
            time.sleep(0.03); continue
        cid, b = struct.unpack(">IB", data[:5])
        if cid != cid_want and cid_want != 0xFFFFFFFF:
            continue
        if b & 0x80:
            cmd, total = b & 0x7F, struct.unpack(">H", data[5:7])[0]
            buf = data[7:]
            if len(buf) >= total:
                return cmd, buf[:total]
        else:
            buf += data[5:]
            if total is not None and len(buf) >= total:
                return 0x83, buf[:total]
    raise TimeoutError("CTAPHID read timeout")

def ctap(cid, payload, timeout=150):
    hid_write(cid, 0x10, payload)  # CBOR
    cmd, resp = hid_read(cid, timeout)
    if not resp:
        raise RuntimeError("empty CTAP response")
    status, body = resp[0], resp[1:]
    return status, body

nonce = os.urandom(8)
hid_write(0xFFFFFFFF, 0x06, nonce)
_, resp = hid_read(0xFFFFFFFF, 15)
cid = struct.unpack(">I", resp[8:12])[0]
print(f"channel: {cid:#010x}")

def sha256(b):
    return hashlib.sha256(b).digest()

# ---------- getInfo ----------
status, body = ctap(cid, bytes([0x04]))
assert status == 0, f"getInfo status {status:#x}"
info = dec(body)
print("getInfo versions:", info.get(1), "extensions:", info.get(2), "pinUvAuthProtocols:", info.get(6))
assert "hmac-secret" in info.get(2, []), "hmac-secret not advertised"
assert "FIDO_2_1" in info.get(1, []), "FIDO_2_1 not advertised"
assert info.get(6) == [1], "pinUvAuthProtocols != [1]"
print("getInfo OK: PRF advertised")

# ---------- ClientPIN getKeyAgreement ----------
status, body = ctap(cid, bytes([0x06]) + enc({1: 1, 2: 2}))
assert status == 0, f"getKeyAgreement status {status:#x}"
ka = dec(body)[1]
auth_pub = ec.EllipticCurvePublicNumbers(
    int.from_bytes(ka[-2], "big"), int.from_bytes(ka[-3], "big"), ec.SECP256R1()
).public_key()
plat_priv = ec.generate_private_key(ec.SECP256R1())
shared_x = plat_priv.exchange(ec.ECDH(), auth_pub)
K = sha256(shared_x)
pn = plat_priv.public_key().public_numbers()
plat_cose = {1: 2, 3: -25, -1: 1, -2: pn.x.to_bytes(32, "big"), -3: pn.y.to_bytes(32, "big")}
print("getKeyAgreement OK, protocol key derived")

def aes_cbc(key, data, encrypt=True):
    c = Cipher(algorithms.AES(key), modes.CBC(b"\x00" * 16))
    ctx = c.encryptor() if encrypt else c.decryptor()
    return ctx.update(data) + ctx.finalize()

# ---------- makeCredential with hmac-secret ----------
cdh = sha256(b"prf real-device clientData")
mc = {
    1: cdh,
    2: {"id": "example.com", "name": "Example"},
    3: {"id": b"prf-user-1", "name": "prf@example.com", "displayName": "PRF User"},
    4: [{"type": "public-key", "alg": -7}],
    6: {"hmac-secret": True},
}
print(">> approve makeCredential on the phone (Face ID) ...")
status, body = ctap(cid, bytes([0x01]) + enc(mc))
assert status == 0, f"makeCredential status {status:#x}"
mc_resp = dec(body)
ad = mc_resp[2]
flags = ad[32]
print(f"makeCredential OK: flags {flags:#04x}")
assert flags & 0x20, "ED flag not set on PRF makeCredential"
pos = 37 + 18
cred_len = struct.unpack(">H", ad[pos-2:pos])[0]
cred_id = ad[pos:pos+cred_len]
d = Dec(ad, pos + cred_len)
cose = d.read()
cred_pub = ec.EllipticCurvePublicNumbers(
    int.from_bytes(cose[-2], "big"), int.from_bytes(cose[-3], "big"), ec.SECP256R1()
).public_key()
if flags & 0x20:
    ext_out = Dec(ad, d.i).read()
    print("attested extension outputs:", ext_out)
    assert ext_out.get("hmac-secret") is True, "makeCredential ext output hmac-secret != true"
else:
    print("no extension outputs in authData; raw authData:", ad.hex())
print(f"credential created: id {cred_id.hex()[:16]}... (PRF key on phone)")

# ---------- getAssertion PRF evals ----------
def prf_eval(salt, cdh_v):
    salt_enc = aes_cbc(K, salt)
    salt_auth = hmac_mod.new(K, salt_enc, hashlib.sha256).digest()[:16]
    hs = {1: plat_cose, 2: salt_enc, 3: salt_auth}
    ga = {
        1: "example.com",
        2: cdh_v,
        3: [{"type": "public-key", "id": cred_id}],
        4: {"hmac-secret": hs},
    }
    print(">> approve getAssertion on the phone (Face ID) ...")
    status, body = ctap(cid, bytes([0x02]) + enc(ga))
    if status != 0:
        print(f"EVAL RESULT: getAssertion CTAP status {status:#x} (eval not understood or refused)")
        return None
    r = dec(body)
    ad2, sig = r[2], r[3]
    assert ad2[32] == 0x25, f"assertion flags {ad2[32]:#04x} != 0x25 (UP|UV|ED)"
    try:
        cred_pub.verify(sig, ad2 + cdh_v, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise AssertionError("assertion signature INVALID")
    ext = dec(ad2[37:])
    enc_out = ext["hmac-secret"]
    return aes_cbc(K, enc_out, encrypt=False)

salt_a, salt_b = sha256(b"real-device prf salt A"), sha256(b"real-device prf salt B")
out1 = prf_eval(salt_a, sha256(b"prf cdh 1"))
print(f"eval A1: {out1.hex()[:24]}... ({len(out1)} bytes)")
out2 = prf_eval(salt_a, sha256(b"prf cdh 2"))
print(f"eval A2: {out2.hex()[:24]}...")
out3 = prf_eval(salt_b, sha256(b"prf cdh 3"))
print(f"eval B : {out3.hex()[:24]}...")
if out1 is None:
    print("DIAGNOSIS: eval path failed -> phone app likely predates PRF (old build) or eval unsupported")
else:
    assert len(out1) == 32, "PRF output not 32 bytes"
    assert out1 == out2, "same salt must give the same output"
    assert out1 != out3, "different salt must give a different output"
    print("PRF REAL-DEVICE VERIFICATION: ALL PASS")
