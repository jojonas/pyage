"""
Convert Ed25519 signing keys to X25519 encryption keys.

Module copied from https://github.com/lvzon/libsodium-python-examples/blob/master/libsodium.py
Originally released under Apache License by Levien van Zon (https://github.com/lvzon/)

----------------------------------------------------------------------------------------------

Wrap libsodium routines
Based on __init__.py in https://github.com/saltstack/libnacl
"""

# Import python libs
import ctypes
import os
import sys

# pylint: disable=C0103
# Import libnacl libs
from nacl import __version__  # noqa: F401

from age.utils.env import is_sphinx

__SONAMES = (18, 17, 13, 10, 5, 4)


def _get_nacl():  # noqa: C901
    """
    Locate the nacl c libs to use
    """
    # Import libsodium
    if sys.platform.startswith("win"):
        try:
            return ctypes.cdll.LoadLibrary("libsodium")
        except OSError:
            pass
        for soname_ver in __SONAMES:
            try:
                return ctypes.cdll.LoadLibrary("libsodium-{0}".format(soname_ver))
            except OSError:
                pass
        msg = "Could not locate nacl lib, searched for libsodium"
        raise OSError(msg)
    elif sys.platform.startswith("darwin"):
        try:
            return ctypes.cdll.LoadLibrary("libsodium.dylib")
        except OSError:
            pass
        try:
            libidx = __file__.find("lib")
            if libidx > 0:
                libpath = __file__[0 : libidx + 3] + "/libsodium.dylib"
                return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            msg = "Could not locate nacl lib, searched for libsodium"
            raise OSError(msg)
    else:
        try:
            return ctypes.cdll.LoadLibrary("libsodium.so")
        except OSError:
            pass
        try:
            return ctypes.cdll.LoadLibrary("/usr/local/lib/libsodium.so")
        except OSError:
            pass
        try:
            libidx = __file__.find("lib")
            if libidx > 0:
                libpath = __file__[0 : libidx + 3] + "/libsodium.so"
                return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            pass

        for soname_ver in __SONAMES:
            try:
                return ctypes.cdll.LoadLibrary("libsodium.so.{0}".format(soname_ver))
            except OSError:
                pass
        try:
            # fall back to shipped libsodium, trust os version first
            libpath = os.path.join(os.path.dirname(__file__), "libsodium.so")
            return ctypes.cdll.LoadLibrary(libpath)
        except OSError:
            pass
        msg = "Could not locate nacl lib, searched for libsodium.so, "
        for soname_ver in __SONAMES:
            msg += "libsodium.so.{0}, ".format(soname_ver)
        raise OSError(msg)


if not is_sphinx():
    nacl = _get_nacl()

    sodium_init = nacl.sodium_init
    sodium_init.res_type = ctypes.c_int
    if sodium_init() < 0:
        raise RuntimeError("sodium_init() call failed!")

    crypto_sign_ed25519_PUBLICKEYBYTES = nacl.crypto_sign_ed25519_publickeybytes()
    crypto_sign_ed25519_SECRETKEYBYTES = nacl.crypto_sign_ed25519_secretkeybytes()
    crypto_scalarmult_curve25519_BYTES = nacl.crypto_scalarmult_curve25519_bytes()

    crypto_core_ed25519_SCALARBYTES = nacl.crypto_core_ed25519_scalarbytes()
    crypto_core_ed25519_NONREDUCEDSCALARBYTES = nacl.crypto_core_ed25519_nonreducedscalarbytes()

else:
    # during documentation generation, ignore nacl
    nacl = None


def crypto_sign_ed25519_pk_to_curve25519(ed25519_pk: bytes) -> bytes:
    """
    Convert an Ed25519 public key to a Curve25519 public key
    """
    if len(ed25519_pk) != crypto_sign_ed25519_PUBLICKEYBYTES:
        raise TypeError("Invalid Ed25519 Key")

    curve25519_pk = ctypes.create_string_buffer(crypto_scalarmult_curve25519_BYTES)
    ret = nacl.crypto_sign_ed25519_pk_to_curve25519(curve25519_pk, ed25519_pk)
    if ret:
        raise RuntimeError("Failed to generate Curve25519 public key")
    return curve25519_pk.raw


def crypto_sign_ed25519_sk_to_curve25519(ed25519_sk: bytes) -> bytes:
    """
    Convert an Ed25519 secret key to a Curve25519 secret key
    """
    if len(ed25519_sk) != crypto_sign_ed25519_SECRETKEYBYTES:
        raise TypeError("Invalid Ed25519 Key")

    curve25519_sk = ctypes.create_string_buffer(crypto_scalarmult_curve25519_BYTES)
    ret = nacl.crypto_sign_ed25519_sk_to_curve25519(curve25519_sk, ed25519_sk)
    if ret:
        raise RuntimeError("Failed to generate Curve25519 secret key")
    return curve25519_sk.raw


def crypto_core_ed25519_scalar_reduce(s: bytes) -> bytes:
    if len(s) != crypto_core_ed25519_NONREDUCEDSCALARBYTES:
        raise TypeError("Invalid reduce() input")

    r = ctypes.create_string_buffer(crypto_core_ed25519_SCALARBYTES)
    ret = nacl.crypto_core_ed25519_scalar_reduce(r, s)
    if ret:
        raise RuntimeError("Failed to reduce scalar")
    return r.raw
