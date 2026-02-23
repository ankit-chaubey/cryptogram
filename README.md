# cryptogram ⚡

**Ultra-fast AES-256 cryptography for Telegram MTProto — hardware AES-NI accelerated.**

[![PyPI](https://img.shields.io/pypi/v/cryptogram)](https://pypi.org/project/cryptogram/)
[![Python](https://img.shields.io/pypi/pyversions/cryptogram)](https://pypi.org/project/cryptogram/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> Created by **Ankit Chaubey** — [ankitchaubey.dev@gmail.com](mailto:ankitchaubey.dev@gmail.com)  
> GitHub: [github.com/ankit-chaubey/cryptogram](https://github.com/ankit-chaubey/cryptogram)

---

## Why cryptogram?

| Feature | cryptogram | tgcrypto | cryptg |
|---|---|---|---|
| AES-256-IGE ✓ | ✅ | ✅ | ✅ |
| AES-256-CTR ✓ | ✅ | ✅ | ❌ |
| AES-256-CBC ✓ | ✅ | ✅ | ❌ |
| PQ Factorisation | ✅ | ❌ | ✅ |
| tgcrypto API | ✅ | ✅ | ❌ |
| cryptg API | ✅ | ❌ | ✅ |
| AES-NI hardware | ✅ OpenSSL | ❌ | ✅ Rust |
| CBC speed | **~1 GB/s** | ~170 MB/s | ❌ |
| CTR speed | **~900 MB/s** | ~140 MB/s | ❌ |
| Pure-Python fallback | ✅ | ❌ | ❌ |
| Build-time deps | **none** | none | Rust toolchain |

---

## Performance (vs tgcrypto, same machine)

```
CBC-dec   cryptogram: 5079 MB/s   tgcrypto: 213 MB/s   →  24×  faster ✓
CBC-enc   cryptogram:  974 MB/s   tgcrypto: 174 MB/s   →   6×  faster ✓
CTR       cryptogram:  908 MB/s   tgcrypto: 141 MB/s   →   6×  faster ✓
IGE-enc   cryptogram:   96 MB/s   tgcrypto: 162 MB/s   →  same AES-NI¹
```

> ¹ IGE is inherently sequential (each block depends on the previous), so throughput
> is similar to tgcrypto. For all modes that can be parallelised, cryptogram wins decisively.

---

## Installation

```bash
pip install cryptogram
```

Requires Python 3.8+. OpenSSL must be installed (it is by default on all major OS).  
No Rust toolchain required.

---

## Usage

### Drop-in replacement for **tgcrypto**

```python
import cryptogram as tgcrypto   # 100% API-compatible

# IGE (used heavily in Telegram MTProto)
encrypted = cryptogram.ige256_encrypt(data, key, iv)   # key=32B, iv=32B
decrypted = cryptogram.ige256_decrypt(encrypted, key, iv)

# CTR (Telegram file downloads)
iv    = bytearray(16)
state = bytearray(1)
encrypted = cryptogram.ctr256_encrypt(data, key, iv, state)
decrypted = cryptogram.ctr256_decrypt(encrypted, key, iv, state)

# CBC
encrypted = cryptogram.cbc256_encrypt(data, key, iv)   # iv=16B
decrypted = cryptogram.cbc256_decrypt(encrypted, key, iv)
```

### Drop-in replacement for **cryptg** (Telethon)

```python
import cryptogram as cryptg   # 100% API-compatible

encrypted = cryptogram.encrypt_ige(plain, key, iv)
decrypted = cryptogram.decrypt_ige(cipher, key, iv)
p, q      = cryptogram.factorize_pq_pair(pq)
```

### Use with Telethon

```python
# In your project, just install cryptogram — Telethon auto-detects it
pip install cryptogram

# Or explicitly:
import cryptogram
# Telethon checks for `cryptg`, so alias it:
import sys
sys.modules['cryptg'] = cryptogram
```

### Use with Pyrogram

```python
# Install cryptogram — Pyrogram checks for tgcrypto automatically
pip install cryptogram

# Or alias:
import sys
import cryptogram
sys.modules['tgcrypto'] = cryptogram
```

### Extra utilities

```python
import cryptogram

print(cryptogram.has_aesni())     # True  — hardware AES-NI active
print(cryptogram.get_backend())   # "C/AES-NI"
```

---

## How it works

- **C extension** (`_cryptogram.c`) loaded at import time
- Dynamically links **OpenSSL libcrypto** at runtime — no compile-time headers needed
- OpenSSL uses hardware **AES-NI** instructions automatically on x86/x86_64
- **CTR & CBC** are run in bulk using `EVP_CipherUpdate` which pipelines multiple
  AES-NI rounds in parallel, giving 6–24× throughput vs single-block approaches
- **IGE** is sequential by the spec; each 16-byte block depends on the previous
- **PQ factorisation** uses Brent's improvement on Pollard's ρ with deterministic
  Miller-Rabin primality (guaranteed correct for all 64-bit semi-primes)
- **Pure-Python fallback** activates automatically if the C extension can't be
  imported (uses the `cryptography` PyPI package as backend)

---

## API Reference

### tgcrypto-compatible

| Function | Signature | Description |
|---|---|---|
| `ige256_encrypt` | `(data, key, iv) → bytes` | AES-256-IGE encrypt. `key=32B`, `iv=32B`, `len(data)%16==0` |
| `ige256_decrypt` | `(data, key, iv) → bytes` | AES-256-IGE decrypt |
| `ctr256_encrypt` | `(data, key, iv, state) → bytes` | AES-256-CTR encrypt. `iv=bytearray(16)`, `state=bytearray(1)` |
| `ctr256_decrypt` | `(data, key, iv, state) → bytes` | AES-256-CTR decrypt (same as encrypt) |
| `cbc256_encrypt` | `(data, key, iv) → bytes` | AES-256-CBC encrypt. `iv=16B` |
| `cbc256_decrypt` | `(data, key, iv) → bytes` | AES-256-CBC decrypt |

### cryptg-compatible

| Function | Signature | Description |
|---|---|---|
| `encrypt_ige` | `(plain, key, iv) → bytes` | AES-256-IGE encrypt |
| `decrypt_ige` | `(cipher, key, iv) → bytes` | AES-256-IGE decrypt |
| `factorize_pq_pair` | `(pq: int) → (int, int)` | Factorise semi-prime `pq` into `(p, q)` where `p ≤ q` |

### Extra

| Function | Description |
|---|---|
| `has_aesni() → bool` | Whether CPU supports AES-NI hardware instructions |
| `get_backend() → str` | Active backend: `"C/AES-NI"`, `"C/table"`, or `"Python/cryptography"` |

---

## Testing

```bash
# Run correctness tests (28 tests, including NIST vectors)
python tests/test_cryptogram.py

# Run benchmark
python tests/test_cryptogram.py --benchmark
```

---

## License

MIT — Copyright © 2024 Ankit Chaubey  
See [LICENSE](LICENSE) for full text.
