import typing

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

from age.utils.libsodium import crypto_core_ed25519_scalar_reduce

__all__ = [
    "x25519_scalarmult",
    "x25519_scalarmult_base",
    "x25519_reduce",
    "ECScalar",
    "ECPoint",
]


ECScalar = typing.NewType("ECScalar", bytes)
ECPoint = typing.NewType("ECPoint", bytes)


def x25519_scalarmult(secret_scalar: ECScalar, point: ECPoint) -> ECPoint:
    """Scalar multiplication of ``point`` with (secret) ``scalar``"""

    k = crypto_scalarmult(secret_scalar, point)
    assert any(k), "All-zeros-check failed (see RFC 7748, section 6.1)"
    return k


def x25519_scalarmult_base(scalar: ECScalar) -> ECPoint:
    return crypto_scalarmult_base(scalar)


def x25519_reduce(k: ECScalar) -> ECScalar:
    return crypto_core_ed25519_scalar_reduce(k)
