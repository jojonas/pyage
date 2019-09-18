from .eccsnacks_x25519 import scalarmult, pack, unpack, P as CURVE_25519_PRIME

__all__ = ["CURVE_25519_BASEPOINT", "x25519", "reduce"]

# according to RFC 7748, sec. 4.1
# hexadecimal: 0900000000000000000000000000000000000000000000000000000000000000
CURVE_25519_BASEPOINT: bytes = pack(9)


def x25519(secret: bytes, point: bytes) -> bytes:
    k = scalarmult(secret, point)
    assert any(k), "All-zeros-check failed (see RFC 7748, section 6.1)"
    return k


def reduce(k: bytes) -> bytes:
    return pack(unpack(k) % CURVE_25519_PRIME)
