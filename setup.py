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
    # -march=native tells the compiler to optimise for the build host's CPU.
    # On macOS this is unsafe: Python installers ship as universal2 fat
    # binaries, so the build system passes both -arch arm64 and -arch x86_64
    # to clang.  With -march=native clang resolves the native CPU (e.g.
    # apple-m3) and then rejects it as an unknown target when compiling the
    # x86_64 slice.  Skip it on macOS entirely.
    if sys.platform != "darwin":
        extra_compile_args.insert(1, "-march=native")

    # The AES implementation uses OpenSSL loaded at runtime via dlopen —
    # there are no SSE / AES-NI intrinsics in the C source, so the x86-only
    # -maes/-msse2/-msse4.1 flags are not needed and would cause errors when
    # clang compiles the arm64 slice of a universal2 build.
    aesni_flags = [] if sys.platform == "darwin" else ["-maes", "-msse2", "-msse4.1"]

ext = Extension(
    "cryptogram._cryptogram",
    sources=["cryptogram/_cryptogram.c"],
    extra_compile_args=extra_compile_args + aesni_flags,
    # Link nothing extra — we use only Python.h and compiler intrinsics
)

setup(ext_modules=[ext])
