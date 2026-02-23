"""
cryptogram — Ultra-fast AES-256 cryptography for Telegram MTProto
=================================================================
Provides AES-NI hardware-accelerated encryption with full API
compatibility with both tgcrypto and cryptg.

Author : Ankit Chaubey <ankitchaubey.dev@gmail.com>
GitHub : https://github.com/ankit-chaubey/cryptogram
PyPI   : cryptogram
License: MIT
"""

__version__ = "0.1.1"
__author__  = "Ankit Chaubey"
__email__   = "ankitchaubey.dev@gmail.com"
__all__ = [
    # tgcrypto-compatible API
    "ige256_encrypt",
    "ige256_decrypt",
    "ctr256_encrypt",
    "ctr256_decrypt",
    "cbc256_encrypt",
    "cbc256_decrypt",
    # cryptg-compatible API
    "encrypt_ige",
    "decrypt_ige",
    "factorize_pq_pair",
    # extra
    "has_aesni",
]

try:
    from ._cryptogram import (
        ige256_encrypt,
        ige256_decrypt,
        ctr256_encrypt,
        ctr256_decrypt,
        cbc256_encrypt,
        cbc256_decrypt,
        encrypt_ige,
        decrypt_ige,
        factorize_pq_pair,
        has_aesni,
    )
    _BACKEND = "C/AES-NI" if has_aesni() else "C/table"
except ImportError:
    from ._fallback import (
        ige256_encrypt,
        ige256_decrypt,
        ctr256_encrypt,
        ctr256_decrypt,
        cbc256_encrypt,
        cbc256_decrypt,
        encrypt_ige,
        decrypt_ige,
        factorize_pq_pair,
    )
    has_aesni = lambda: False
    _BACKEND = "Python/cryptography"


def get_backend() -> str:
    """Return the active backend name (useful for diagnostics)."""
    return _BACKEND
