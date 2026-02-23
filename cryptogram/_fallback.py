"""
cryptogram._fallback — Pure-Python backend using `cryptography` library.
Falls back automatically when the C extension is not compiled.
"""

from __future__ import annotations
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import math

_BACKEND = default_backend()


def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=_BACKEND)
    enc = c.encryptor()
    return enc.update(block) + enc.finalize()


def _aes_ecb_decrypt(key: bytes, block: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.ECB(), backend=_BACKEND)
    dec = c.decryptor()
    return dec.update(block) + dec.finalize()


# ── IGE ──────────────────────────────────────────────────────────────

def ige256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if not data:
        raise ValueError("data must not be empty")
    if len(data) % 16 != 0:
        raise ValueError("data size must be a multiple of 16 bytes")
    if len(key) != 32:
        raise ValueError("key size must be exactly 32 bytes")
    if len(iv) != 32:
        raise ValueError("IV size must be exactly 32 bytes")

    iv1, iv2 = bytearray(iv[:16]), bytearray(iv[16:])
    out = bytearray(len(data))
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        xored = bytes(a ^ b for a, b in zip(chunk, iv1))
        enc   = _aes_ecb_encrypt(key, xored)
        block = bytes(a ^ b for a, b in zip(enc, iv2))
        out[i:i+16] = block
        iv1[:] = block
        iv2[:] = chunk
    return bytes(out)


def ige256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if not data:
        raise ValueError("data must not be empty")
    if len(data) % 16 != 0:
        raise ValueError("data size must be a multiple of 16 bytes")
    if len(key) != 32:
        raise ValueError("key size must be exactly 32 bytes")
    if len(iv) != 32:
        raise ValueError("IV size must be exactly 32 bytes")

    iv2, iv1 = bytearray(iv[:16]), bytearray(iv[16:])
    out = bytearray(len(data))
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        xored = bytes(a ^ b for a, b in zip(chunk, iv1))
        dec   = _aes_ecb_decrypt(key, xored)
        block = bytes(a ^ b for a, b in zip(dec, iv2))
        out[i:i+16] = block
        iv1[:] = block   # new I_{i-1} = current plaintext
        iv2[:] = chunk   # new O_{i-1} = current ciphertext
    return bytes(out)


# cryptg aliases
encrypt_ige = ige256_encrypt
decrypt_ige = ige256_decrypt


# ── CTR ──────────────────────────────────────────────────────────────

def ctr256_encrypt(data: bytes, key: bytes, iv: bytearray, state: bytearray) -> bytes:
    if not data:
        raise ValueError("data must not be empty")
    if len(key) != 32:
        raise ValueError("key size must be exactly 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV size must be exactly 16 bytes")
    if len(state) != 1:
        raise ValueError("state size must be exactly 1 byte")
    if state[0] > 15:
        raise ValueError("state must be in range [0, 15]")

    out   = bytearray(len(data))
    ks    = bytearray(_aes_ecb_encrypt(key, bytes(iv)))
    st    = state[0]

    for i in range(len(data)):
        out[i] = data[i] ^ ks[st]
        st += 1
        if st >= 16:
            st = 0
            # Increment IV (big-endian)
            k = 15
            while k >= 0:
                iv[k] = (iv[k] + 1) & 0xFF
                if iv[k] != 0:
                    break
                k -= 1
            ks[:] = _aes_ecb_encrypt(key, bytes(iv))

    state[0] = st
    return bytes(out)


ctr256_decrypt = ctr256_encrypt


# ── CBC ──────────────────────────────────────────────────────────────

def cbc256_encrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if not data:
        raise ValueError("data must not be empty")
    if len(data) % 16 != 0:
        raise ValueError("data size must be a multiple of 16 bytes")
    if len(key) != 32:
        raise ValueError("key size must be exactly 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV size must be exactly 16 bytes")
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_BACKEND)
    enc = c.encryptor()
    return enc.update(data) + enc.finalize()


def cbc256_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    if not data:
        raise ValueError("data must not be empty")
    if len(data) % 16 != 0:
        raise ValueError("data size must be a multiple of 16 bytes")
    if len(key) != 32:
        raise ValueError("key size must be exactly 32 bytes")
    if len(iv) != 16:
        raise ValueError("IV size must be exactly 16 bytes")
    c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=_BACKEND)
    dec = c.decryptor()
    return dec.update(data) + dec.finalize()


# ── PQ Factorisation ─────────────────────────────────────────────────

def _gcd(a: int, b: int) -> int:
    while b:
        a, b = b, a % b
    return a

def _miller_rabin(n: int, a: int) -> bool:
    if n % a == 0:
        return n == a
    d, r = n - 1, 0
    while not (d & 1):
        d >>= 1; r += 1
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(r - 1):
        x = x * x % n
        if x == n - 1:
            return True
    return False

def _is_prime(n: int) -> bool:
    if n < 2: return False
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n == a: return True
        if not _miller_rabin(n, a): return False
    return True

def _brent_rho(n: int, c: int) -> int:
    y, r, q, x = 2, 1, 1, 2
    while True:
        x = y
        for _ in range(r):
            y = (y * y + c) % n
        k = 0
        while k < r:
            ys = y
            for _ in range(min(128, r - k)):
                y = (y * y + c) % n
                q = q * abs(x - y) % n
            d = _gcd(q, n)
            k += 128
            if d != 1:
                break
        r *= 2
        if d != 1:
            break
    if d == n:
        while True:
            ys = (ys * ys + c) % n
            d = _gcd(abs(x - ys), n)
            if d > 1:
                break
    return d

def _factorize_one(n: int) -> int:
    if n == 1: return 1
    if _is_prime(n): return n
    if n % 2 == 0: return 2
    c = 1
    while True:
        d = _brent_rho(n, c)
        if d != n:
            return _factorize_one(d)
        c += 1

def factorize_pq_pair(pq: int) -> tuple[int, int]:
    p = _factorize_one(pq)
    q = pq // p
    return (min(p, q), max(p, q))
