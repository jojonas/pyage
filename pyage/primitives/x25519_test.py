from pyage.primitives import x25519


def test_vector1():
    """Test vector 1 from RFC 7748, sec. 5.2"""

    input_scalar = bytes.fromhex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
    input_u_coordinate = bytes.fromhex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")

    output_u_coordinate = bytes.fromhex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")

    assert x25519(input_scalar, input_u_coordinate) == output_u_coordinate


def test_vector2():
    """Test vector 2 from RFC 7748, sec. 5.2"""

    input_scalar = bytes.fromhex(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d")
    input_u_coordinate = bytes.fromhex(
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")

    output_u_coordinate = bytes.fromhex(
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957")

    assert x25519(input_scalar, input_u_coordinate) == output_u_coordinate


def test_repeated():
    k = bytes.fromhex(
        "0900000000000000000000000000000000000000000000000000000000000000")
    u = bytes(k)

    i = 0
    while i < 1:
        k, u = x25519(k, u), k
        i += 1

    assert i == 1
    assert k == bytes.fromhex(
        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")

    while i < 1000:
        k, u = x25519(k, u), k
        i += 1

    assert i == 1000
    assert k == bytes.fromhex(
        "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")

    # Computation intensive extension:

    # while i < 1000000:
    #     k, u = x25519(k, u), k
    #     i += 1

    # assert i == 1000000
    # assert k == bytes.fromhex(
    #     "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424")
