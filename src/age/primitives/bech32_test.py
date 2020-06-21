#!/usr/bin/python3

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


"""Reference tests for segwit adresses"""

# Changes by jojonas: compatability for python3, conversion to pytest

import os

import pytest

import age.primitives.bech32 as bech32

VALID_CHECKSUM = [
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
]

INVALID_CHECKSUM = [
    " 1nwldj5",
    "\x7F" + "1axkwrx",
    "\x80" + "1eym55h",
    "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
    "pzry9x0s0muk",
    "1pzry9x0s0muk",
    "x1b4n0q5v",
    "li1dgmt3",
    "de1lg7wt\xff",
    "A1G7SGD8",
    "10a06t8",
    "1qzzfhee",
]


def test_valid_checksum():
    for test in VALID_CHECKSUM:
        print(test)
        hrp, _ = bech32.bech32_decode(test)
        assert hrp is not None


def test_invalid_checksum():
    for test in INVALID_CHECKSUM:
        with pytest.raises(ValueError):
            hrp, _ = bech32.bech32_decode(test)


def test_random_roundtrip():
    for i in range(10, 100):
        hrp = "test%d-" % i
        data = os.urandom(i)
        address = bech32.bech32_encode(hrp, data)
        print(address)
        decoded_hrp, decoded_data = bech32.bech32_decode(address)
        assert decoded_hrp == hrp
        assert decoded_data == data
