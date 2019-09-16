from .eccsnacks_x25519 import scalarmult


def x25519(secret, point):
    k = scalarmult(secret, point)
    assert any(k), "All-zeros-check failed (see RFC 7748, section 6.1)"
    return k
