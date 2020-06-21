import typing

from nacl.bindings import (
    crypto_core_ed25519_scalar_reduce,
    crypto_scalarmult,
    crypto_scalarmult_base,
)

__all__ = ["x25519_scalarmult", "x25519_scalarmult_base", "x25519_reduce", "ECScalar", "ECPoint"]

ECScalar = typing.NewType("ECScalar", bytes)
"""Curve25519 scalar (commonly called `n`), as bytes instance of length 32"""

ECPoint = typing.NewType("ECPoint", bytes)
"""Curve25519 point (commonly called `P`), as bytes instance of length 32"""


def x25519_scalarmult(secret_scalar: ECScalar, point: ECPoint) -> ECPoint:
    """Scalar multiplication of ``point`` with (secret) ``scalar``

    :param secret_scalar: Scalar (integer) `n`, in byte representation (:class:`ECScalar`)
    :param point: Point on curve `P`, in byte representation (:class:`ECPoint`)
    :returns: New point on curve: :math:`nP = P + P + P + P + P + \\text{...}` (`n` times)
    """

    k = crypto_scalarmult(secret_scalar, point)
    assert any(k), "All-zeros-check failed (see RFC 7748, section 6.1)"
    return ECPoint(k)


def x25519_scalarmult_base(scalar: ECScalar) -> ECPoint:
    """Scalar multiplication of the ED25519 base point with `scalar`

    The base point according to the Curve25519 paper is :math:`P = 9`.
    This function is commonly used to generate a public key (point) from a private scalar.

    :param scalar: Scalar (integer) `n`, in byte representation (:class:`ECScalar`)
    :returns: Point on curve, commonly interpreted as public key (if `n` is the private key)
    """

    return ECPoint(crypto_scalarmult_base(scalar))


def x25519_reduce(k: ECScalar) -> ECScalar:
    """Reduce the scalar `k` in the Curve25519 field

    Corresponds to the following calculation:
    :math:`r = k % (2^252 + \\text{0x14DEF9DEA2F79CD65812631A5CF5D3ED})`

    :param k: Arbitrary scalar in bytes representation (:class:`ECScalar`)
    :returns: Reduced scalar in bytes representation (:class:`ECScalar`)
    """

    return ECScalar(crypto_core_ed25519_scalar_reduce(k))
