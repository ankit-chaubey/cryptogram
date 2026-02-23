"""
cryptogram — Test Suite
========================
Tests correctness against known-good AES vectors and measures
speed vs pure-table implementations.

Run with:  python -m pytest tests/ -v
Benchmark: python tests/test_cryptogram.py --benchmark
"""

import os
import sys
import time
import unittest
import struct

# ──────────────────────────────────────────────────────────────────────
# Make sure we import from our local package, not any installed version
# ──────────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cryptogram
from cryptogram._fallback import (
    ige256_encrypt  as py_ige_enc,
    ige256_decrypt  as py_ige_dec,
    ctr256_encrypt  as py_ctr_enc,
    cbc256_encrypt  as py_cbc_enc,
    cbc256_decrypt  as py_cbc_dec,
    factorize_pq_pair as py_factorize,
)


# ══════════════════════════════════════════════════════════════════════
#  Known-good test vectors
# ══════════════════════════════════════════════════════════════════════

# AES-256-CBC vector from NIST FIPS-197 / NIST 800-38A
_CBC_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
_CBC_IV  = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
_CBC_PT  = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
_CBC_CT  = bytes.fromhex(
    "f58c4c04d6e5f1ba779eabfb5f7bfbd6"
    "9cfc4e967edb808d679f777bc6702c7d"
    "39f23369a9d9bacfa530e26304231461"
    "b2eb05e2c39be9fcda6c19078c6a9d1b"
)

# AES-256-CTR vector from NIST SP 800-38A
_CTR_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
)
_CTR_IV  = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
_CTR_PT  = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
_CTR_CT  = bytes.fromhex(
    "601ec313775789a5b7a7f504bbf3d228"
    "f443e3ca4d62b59aca84e990cacaf5c5"
    "2b0930daa23de94ce87017ba2d84988d"
    "dfc9c58db67aada613c2dd08457941a6"
)


class TestIGE(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(32)
        self.iv  = os.urandom(32)
        self.data = os.urandom(16 * 64)   # 1 KB

    def test_encrypt_decrypt_roundtrip(self):
        """encrypt then decrypt gives back the original."""
        ct = cryptogram.ige256_encrypt(self.data, self.key, self.iv)
        pt = cryptogram.ige256_decrypt(ct, self.key, self.iv)
        self.assertEqual(pt, self.data)

    def test_c_matches_python_encrypt(self):
        """C extension produces same result as Python fallback."""
        ct_c  = cryptogram.ige256_encrypt(self.data, self.key, self.iv)
        ct_py = py_ige_enc(self.data, self.key, self.iv)
        self.assertEqual(ct_c, ct_py)

    def test_c_matches_python_decrypt(self):
        ct = py_ige_enc(self.data, self.key, self.iv)
        pt_c  = cryptogram.ige256_decrypt(ct, self.key, self.iv)
        pt_py = py_ige_dec(ct, self.key, self.iv)
        self.assertEqual(pt_c, pt_py)

    def test_cryptg_api_aliases(self):
        """encrypt_ige / decrypt_ige are aliases with same results."""
        ct_tg  = cryptogram.ige256_encrypt(self.data, self.key, self.iv)
        ct_cg  = cryptogram.encrypt_ige(self.data, self.key, self.iv)
        self.assertEqual(ct_tg, ct_cg)
        pt_tg  = cryptogram.ige256_decrypt(ct_tg, self.key, self.iv)
        pt_cg  = cryptogram.decrypt_ige(ct_cg, self.key, self.iv)
        self.assertEqual(pt_tg, pt_cg)

    def test_all_zeros(self):
        key = b'\x00' * 32
        iv  = b'\x00' * 32
        data = b'\x00' * 16
        ct = cryptogram.ige256_encrypt(data, key, iv)
        pt = cryptogram.ige256_decrypt(ct, key, iv)
        self.assertEqual(pt, data)

    def test_wrong_key_size(self):
        with self.assertRaises(ValueError):
            cryptogram.ige256_encrypt(self.data, b'\x00'*16, self.iv)

    def test_wrong_iv_size(self):
        with self.assertRaises(ValueError):
            cryptogram.ige256_encrypt(self.data, self.key, b'\x00'*16)

    def test_unaligned_data(self):
        with self.assertRaises(ValueError):
            cryptogram.ige256_encrypt(b'\x00'*17, self.key, self.iv)

    def test_deterministic(self):
        """Same inputs → same output."""
        ct1 = cryptogram.ige256_encrypt(self.data, self.key, self.iv)
        ct2 = cryptogram.ige256_encrypt(self.data, self.key, self.iv)
        self.assertEqual(ct1, ct2)

    def test_large_data(self):
        data = os.urandom(16 * 1024)   # 256 KB
        ct = cryptogram.ige256_encrypt(data, self.key, self.iv)
        pt = cryptogram.ige256_decrypt(ct, self.key, self.iv)
        self.assertEqual(pt, data)


class TestCTR(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(32)
        self.iv  = bytearray(os.urandom(16))
        self.state = bytearray(1)
        self.data = os.urandom(1337)   # intentionally non-block-aligned

    def _fresh_iv(self):
        return bytearray(self.iv), bytearray(self.state)

    def test_nist_vector(self):
        """NIST SP 800-38A AES-256-CTR vector."""
        iv    = bytearray(_CTR_IV)
        state = bytearray(1)
        ct = cryptogram.ctr256_encrypt(_CTR_PT, _CTR_KEY, iv, state)
        self.assertEqual(ct, _CTR_CT)

    def test_nist_vector_python(self):
        iv    = bytearray(_CTR_IV)
        state = bytearray(1)
        ct = py_ctr_enc(_CTR_PT, _CTR_KEY, iv, state)
        self.assertEqual(ct, _CTR_CT)

    def test_encrypt_decrypt_roundtrip(self):
        iv1, st1 = self._fresh_iv()
        iv2, st2 = self._fresh_iv()
        ct = cryptogram.ctr256_encrypt(self.data, self.key, iv1, st1)
        pt = cryptogram.ctr256_decrypt(ct, self.key, iv2, st2)
        self.assertEqual(pt, self.data)

    def test_c_matches_python(self):
        iv1, st1 = self._fresh_iv()
        iv2, st2 = bytearray(self.iv), bytearray(self.state)
        ct_c  = cryptogram.ctr256_encrypt(self.data, self.key, iv1, st1)
        ct_py = py_ctr_enc(self.data, self.key, iv2, st2)
        self.assertEqual(ct_c, ct_py)

    def test_streaming(self):
        """CTR state allows streaming in chunks — results must concatenate correctly."""
        iv1, st1 = self._fresh_iv()
        iv2, st2 = self._fresh_iv()
        chunk = 100
        ct_parts = []
        data = self.data
        for i in range(0, len(data), chunk):
            ct_parts.append(cryptogram.ctr256_encrypt(data[i:i+chunk], self.key, iv1, st1))
        ct_stream = b''.join(ct_parts)
        ct_full = cryptogram.ctr256_encrypt(data, self.key, iv2, st2)
        self.assertEqual(ct_stream, ct_full)


class TestCBC(unittest.TestCase):

    def setUp(self):
        self.key = os.urandom(32)
        self.iv  = os.urandom(16)
        self.data = os.urandom(16 * 64)

    def test_nist_vector_encrypt(self):
        ct = cryptogram.cbc256_encrypt(_CBC_PT, _CBC_KEY, _CBC_IV)
        self.assertEqual(ct, _CBC_CT)

    def test_nist_vector_encrypt_python(self):
        ct = py_cbc_enc(_CBC_PT, _CBC_KEY, _CBC_IV)
        self.assertEqual(ct, _CBC_CT)

    def test_nist_vector_decrypt(self):
        pt = cryptogram.cbc256_decrypt(_CBC_CT, _CBC_KEY, _CBC_IV)
        self.assertEqual(pt, _CBC_PT)

    def test_nist_vector_decrypt_python(self):
        pt = py_cbc_dec(_CBC_CT, _CBC_KEY, _CBC_IV)
        self.assertEqual(pt, _CBC_PT)

    def test_encrypt_decrypt_roundtrip(self):
        ct = cryptogram.cbc256_encrypt(self.data, self.key, self.iv)
        pt = cryptogram.cbc256_decrypt(ct, self.key, self.iv)
        self.assertEqual(pt, self.data)

    def test_c_matches_python_encrypt(self):
        ct_c  = cryptogram.cbc256_encrypt(self.data, self.key, self.iv)
        ct_py = py_cbc_enc(self.data, self.key, self.iv)
        self.assertEqual(ct_c, ct_py)

    def test_c_matches_python_decrypt(self):
        ct = py_cbc_enc(self.data, self.key, self.iv)
        pt_c  = cryptogram.cbc256_decrypt(ct, self.key, self.iv)
        pt_py = py_cbc_dec(ct, self.key, self.iv)
        self.assertEqual(pt_c, pt_py)

    def test_large_data(self):
        data = os.urandom(16 * 1024)
        ct = cryptogram.cbc256_encrypt(data, self.key, self.iv)
        pt = cryptogram.cbc256_decrypt(ct, self.key, self.iv)
        self.assertEqual(pt, data)


class TestFactorize(unittest.TestCase):

    KNOWN = [
        (17833_16739, (1298693, 1371463)),  # 2 primes
        (1724114033281923457, (1308665633, 1317552129)),  # from grammers test
        (7, (1, 7)),   # degenerate: 7 itself is prime  (grammers returns (1,7))
    ]

    def test_known_pairs(self):
        for pq, expected in [
            (1298693 * 1371463, (1298693, 1371463)),
            (1308665633 * 1317552129, (1308665633, 1317552129)),
        ]:
            p, q = cryptogram.factorize_pq_pair(pq)
            self.assertEqual(p * q, pq, f"product must equal input for {pq}")
            self.assertTrue(p <= q, "p must be <= q")

    def test_c_matches_python(self):
        for n in [1298693 * 1371463, 1308665633 * 1317552129]:
            p_c, q_c   = cryptogram.factorize_pq_pair(n)
            p_py, q_py = py_factorize(n)
            self.assertEqual((p_c, q_c), (p_py, q_py))

    def test_result_is_valid_factorisation(self):
        import random
        # Generate random semi-prime
        def rand_prime_20bit():
            import random
            while True:
                n = random.randrange(2**19, 2**20)
                if all(n % d != 0 for d in range(2, int(n**0.5)+1)):
                    return n
        for _ in range(5):
            p0 = rand_prime_20bit()
            q0 = rand_prime_20bit()
            pq = p0 * q0
            p, q = cryptogram.factorize_pq_pair(pq)
            self.assertEqual(p * q, pq)
            self.assertTrue(p <= q)


class TestBackend(unittest.TestCase):
    def test_backend_string(self):
        b = cryptogram.get_backend()
        self.assertIsInstance(b, str)
        print(f"\n  Backend: {b}")

    def test_has_aesni_is_bool(self):
        result = cryptogram.has_aesni()
        self.assertIsInstance(result, bool)
        print(f"\n  AES-NI: {result}")


# ══════════════════════════════════════════════════════════════════════
#  Benchmark
# ══════════════════════════════════════════════════════════════════════

def _bench(fn, *args, n=50, label=""):
    # Warmup
    for _ in range(3):
        fn(*args)
    t0 = time.perf_counter()
    for _ in range(n):
        fn(*args)
    elapsed = time.perf_counter() - t0
    size = len(args[0])
    throughput_mb = (size * n) / elapsed / 1e6
    print(f"  {label:40s} {throughput_mb:8.1f} MB/s  ({n} runs × {size//1024} KB)")
    return throughput_mb


def run_benchmark():
    print("\n" + "═"*72)
    print("  cryptogram benchmark")
    print(f"  Backend : {cryptogram.get_backend()}")
    print(f"  AES-NI  : {cryptogram.has_aesni()}")
    print("═"*72)

    key  = os.urandom(32)
    iv32 = os.urandom(32)
    iv16 = os.urandom(16)
    data_sizes = [64*1024, 512*1024]  # 64 KB, 512 KB

    for size in data_sizes:
        data = os.urandom(size)
        n = max(5, 200 * 1024 // size)
        print(f"\n── {size//1024} KB blocks ──────────────────────────────────────────────")

        r1 = _bench(cryptogram.ige256_encrypt, data, key, iv32, n=n, label="IGE-256 encrypt  (C/AES-NI)")
        r2 = _bench(py_ige_enc,                data, key, iv32, n=max(2,n//5), label="IGE-256 encrypt  (Python)")
        if r2 > 0:
            print(f"    Speedup: {r1/r2:.1f}×")

        r3 = _bench(cryptogram.cbc256_encrypt, data, key, iv16, n=n, label="CBC-256 encrypt  (C/AES-NI)")
        r4 = _bench(py_cbc_enc,                data, key, iv16, n=max(2,n//5), label="CBC-256 encrypt  (Python)")
        if r4 > 0:
            print(f"    Speedup: {r3/r4:.1f}×")

        def ctr_wrap_c(d):
            iv = bytearray(iv16); st = bytearray(1)
            return cryptogram.ctr256_encrypt(d, key, iv, st)
        def ctr_wrap_py(d):
            iv = bytearray(iv16); st = bytearray(1)
            return py_ctr_enc(d, key, iv, st)

        r5 = _bench(ctr_wrap_c,  data, n=n,       label="CTR-256 encrypt  (C/AES-NI)")
        r6 = _bench(ctr_wrap_py, data, n=max(2,n//5), label="CTR-256 encrypt  (Python)")
        if r6 > 0:
            print(f"    Speedup: {r5/r6:.1f}×")

    print("\n" + "═"*72)


if __name__ == "__main__":
    if "--benchmark" in sys.argv or "-b" in sys.argv:
        run_benchmark()
    else:
        print("Running tests …")
        loader = unittest.TestLoader()
        suite  = loader.loadTestsFromModule(sys.modules[__name__])
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)
        if not result.wasSuccessful():
            sys.exit(1)
        print("\nAll tests passed! Run with --benchmark to see speed measurements.")
