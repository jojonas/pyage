# Testing only the features that I've implemented for age specifically

import os

from age.utils.libsodium import crypto_core_ed25519_scalar_reduce


def test_reduce():
    ORDER = 2 ** 252 + 0x14DEF9DEA2F79CD65812631A5CF5D3ED

    x_bytes = os.urandom(64)

    x = int.from_bytes(x_bytes, byteorder="little")
    y_expected = x % ORDER

    reduce_output = crypto_core_ed25519_scalar_reduce(x_bytes)
    y_libsodium = int.from_bytes(reduce_output, byteorder="little")

    assert y_libsodium == y_expected
