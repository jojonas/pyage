# Copyright (c) 2017 Pieter Wuille
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

"""Reference implementation for Bech32 and segwit addresses."""

# Changes by jojonas: compatability for python3, type hints

import typing

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
assert len(BECH32_CHARSET) == 32


def _debug_bin(v: int, bits: int = 8) -> str:
    binary = bin(v)[2:]
    while len(binary) < bits:
        binary = "0" + binary
    return binary


def _debug(value: typing.Iterable[int], frombits: int, tobits: int) -> None:
    data = ""
    for v in value:
        data += _debug_bin(v, frombits)
    ret = ""
    for i, d in enumerate(data):
        if i % tobits == 0:
            ret += "+"
        else:
            ret += " "
        ret += d
    print(ret)


def _bech32_polymod(values: typing.Iterable[int]) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> typing.List[int]:
    """Expand the HRP into values for checksum computation."""

    # upper 3 bits of HRP + "\x00" + lower 5 bits of HRP
    hrp_bytes = hrp.encode("ascii")
    return [x >> 5 for x in hrp_bytes] + [0] + [x & 31 for x in hrp_bytes]


def _bech32_verify_checksum(hrp: str, data: typing.Iterable[int]) -> bool:
    """Verify a checksum given HRP and converted data characters."""
    return _bech32_polymod(_bech32_hrp_expand(hrp) + list(data)) == 1


def _bech32_create_checksum(hrp: str, data: typing.Iterable[int]) -> typing.List[int]:
    """Compute the checksum values given HRP and data."""
    values = _bech32_hrp_expand(hrp) + list(data)
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(
    data: typing.Iterable[int], frombits: int, tobits: int, pad: bool = True
) -> typing.List[int]:
    """General power-of-2 base conversion."""

    # accumulator, will be filled later
    acc: int = 0

    # number of bits pushed to acc that have not yet been accounted for in ret
    bits: int = 0

    # return value
    ret: typing.List[int] = []

    # maximum value in the destination representation, e.g. tobits=5 => maxv=11111
    maxv = (1 << tobits) - 1

    # maximum value that the accumulator can have during the process.
    # e.g. from=5, to=8 => 12 (worst case: 7 in the acc, 5 are pushed => 12)
    max_acc = (1 << (frombits + tobits - 1)) - 1

    for value in data:
        # check whether the value is in bounds
        if value < 0 or (value >> frombits):
            raise ValueError("value out of range")

        # shift acc by the number of bits that will now be added,
        # then set the lowest bits using logical OR (|)
        # mask with max_acc, so we never have to reset acc
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits

        while bits >= tobits:
            # take bunches of tobits bits and append them to ret
            bits -= tobits
            ret.append((acc >> bits) & maxv)

    if pad:
        if bits:
            # there are still "uncommited" bits in acc, shift them to the upper end (tobits - bits)
            # = fill with zeros from the right, and commit them
            ret.append((acc << (tobits - bits)) & maxv)

    elif bits >= frombits:
        # there are still bits in acc, apparently more than one bunch of frombits, but less than one
        # bunch of tobits
        raise ValueError("illegal zero padding")

    elif (acc << (tobits - bits)) & maxv:
        # there are still bits in acc (less than one bunch of tobits), but they're not all zero
        raise ValueError("non-zero padding")

    return ret


def bech32_encode(hrp: str, payload: bytes) -> str:
    """Compute a Bech32 string given HRP and data values."""  #

    payload_base32 = _convertbits(payload, 8, 5, True)
    combined = list(payload_base32) + list(_bech32_create_checksum(hrp, payload_base32))
    combined_encoded = "".join(BECH32_CHARSET[i] for i in combined)

    return hrp + "1" + combined_encoded


def bech32_decode(bech: str) -> typing.Tuple[str, bytes]:
    """Validate a Bech32 string, and determine HRP and data."""

    if not (bech.upper() == bech or bech.lower() == bech):
        raise ValueError("Bech32 string must either be all-lowercase or all-uppercase")

    # normalize to lowercase
    bech = bech.lower()
    pos = bech.rfind("1")

    if pos == -1:
        raise ValueError("Bech32 separator '1' not found")

    hrp = bech[:pos]

    if not (1 <= len(hrp) <= 83):
        raise ValueError("invalid Bech32 HRP (human-readable-part) length")

    if any(ord(c) < 33 or ord(c) > 126 for c in hrp):
        raise ValueError("invalid character in Bech32 HRP (human-readable-part)")

    combined = bech[pos + 1 :]

    if len(combined) < 6:
        raise ValueError("invalid Bech32 payload length")

    if any(x not in BECH32_CHARSET for x in combined):
        raise ValueError("invalid Bech32 payload character")

    data = [BECH32_CHARSET.index(c) for c in combined]
    if not _bech32_verify_checksum(hrp, data):
        raise ValueError("Bech32 checksum validation failed")

    payload_base32 = data[:-6]

    payload = bytes(_convertbits(payload_base32, 5, 8, False))
    return (hrp, payload)
