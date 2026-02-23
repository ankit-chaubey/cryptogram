"""
cryptogram — AES-NI accelerated Telegram MTProto crypto
Automatically enables hardware AES-NI when the CPU supports it.
"""
import os
import sys
from setuptools import setup, Extension

# Detect compiler
is_msvc = sys.platform == "win32" and "MSC" in sys.version

# Compiler flags for maximum performance
if is_msvc:
    extra_compile_args = ["/O2", "/W3"]
    aesni_flags = ["/arch:SSE2"]
else:
    extra_compile_args = [
        "-O3",           # maximum optimisation
        "-funroll-loops",
        "-fomit-frame-pointer",
        "-std=c11",
        "-Wall",
        "-Wno-unused-variable",
    ]
    # -march=native is only safe for single-arch builds.
    # On macOS universal2 (arm64 + x86_64), ARCHFLAGS contains both arches;
    # using -march=native there maps to the host CPU (e.g. apple-m3) which is
    # not a valid target when clang compiles the x86_64 slice.
    archflags = os.environ.get("ARCHFLAGS", "")
    is_universal2 = "arm64" in archflags and "x86_64" in archflags
    if not is_universal2:
        extra_compile_args.insert(1, "-march=native")
    # Explicit AES-NI / SSE2 flags for function-level target attrs
    # (used by __attribute__((target("aes"))) in the source)
    aesni_flags = ["-maes", "-msse2", "-msse4.1"]

ext = Extension(
    "cryptogram._cryptogram",
    sources=["cryptogram/_cryptogram.c"],
    extra_compile_args=extra_compile_args + aesni_flags,
    # Link nothing extra — we use only Python.h and compiler intrinsics
)

setup(ext_modules=[ext])
