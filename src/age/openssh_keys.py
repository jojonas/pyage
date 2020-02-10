import collections
import io
import struct
import typing

import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms as cipher_algos
from cryptography.hazmat.primitives.ciphers import modes as cipher_modes

from age.utils.asciiarmor import read_ascii_armored

__all__ = ["load_openssh_private_key", "InvalidKeyFile", "WrongPassphrase"]

OPENSSH_MAGIC = b"openssh-key-v1\00"

AnyPrivateKey = typing.Union[
    rsa.RSAPrivateKey, dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey
]


class InvalidKeyFile(Exception):
    pass


class WrongPassphrase(Exception):
    pass


def _read_struct(stream: typing.BinaryIO, fmt: str) -> tuple:
    # read struct format from stream
    size = struct.calcsize(fmt)
    buf = stream.read(size)
    return struct.unpack(fmt, buf)


def _sshbuf_get_cstring(stream: typing.BinaryIO) -> bytes:
    (length,) = _read_struct(stream, ">I")  # read data in the format: 32-bit length, data[length]
    return stream.read(length)


def _sshbuf_get_bignum2(stream: typing.BinaryIO) -> int:
    data = _sshbuf_get_cstring(stream)

    # check
    # https://github.com/openssh/openssh-portable/blob/5a273a33ca1410351cb484af7db7c13e8b4e8e4e/sshbuf-getput-basic.c#L604
    if data[0] & 0x80:
        raise ValueError("Negative bignums are not supported")

    return int.from_bytes(data, byteorder="big")


def _deserialize_rsa_private_key(stream: typing.BinaryIO) -> rsa.RSAPrivateKey:
    rsa_n = _sshbuf_get_bignum2(stream)
    rsa_e = _sshbuf_get_bignum2(stream)
    rsa_d = _sshbuf_get_bignum2(stream)
    rsa_iqmp = _sshbuf_get_bignum2(stream)
    rsa_p = _sshbuf_get_bignum2(stream)
    rsa_q = _sshbuf_get_bignum2(stream)

    # Calculate Chinese remainder theorem coefficients
    # used to speed up calculations.
    # Luckily, our library provides functions to calculate these...

    rsa_dmp1 = rsa.rsa_crt_dmp1(rsa_d, rsa_p)  # dmp1 = d mod (p - 1)
    rsa_dmq1 = rsa.rsa_crt_dmq1(rsa_d, rsa_q)  # dmp2 = d mod (q - 1)

    public_numbers = rsa.RSAPublicNumbers(e=rsa_e, n=rsa_n)
    private_numbers = rsa.RSAPrivateNumbers(
        p=rsa_p,
        q=rsa_q,
        d=rsa_d,
        dmp1=rsa_dmp1,
        dmq1=rsa_dmq1,
        iqmp=rsa_iqmp,
        public_numbers=public_numbers,
    )
    return private_numbers.private_key(backend=default_backend())


def _deserialize_dsa_private_key(stream: typing.BinaryIO) -> dsa.DSAPrivateKey:
    dsa_p = _sshbuf_get_bignum2(stream)
    dsa_q = _sshbuf_get_bignum2(stream)
    dsa_g = _sshbuf_get_bignum2(stream)
    dsa_pub_key = _sshbuf_get_bignum2(stream)
    dsa_priv_key = _sshbuf_get_bignum2(stream)

    parameter_numbers = dsa.DSAParameterNumbers(p=dsa_p, q=dsa_q, g=dsa_g)
    public_numbers = dsa.DSAPublicNumbers(y=dsa_pub_key, parameter_numbers=parameter_numbers)
    private_numbers = dsa.DSAPrivateNumbers(x=dsa_priv_key, public_numbers=public_numbers)

    # ignoring mypy error that DSAPrivateNumbers does not have private_key() - it does.
    return private_numbers.private_key(backend=default_backend())  # type: ignore


def _deserialize_ecdsa_private_key(stream: typing.BinaryIO) -> ec.EllipticCurvePrivateKey:
    curve_name = _sshbuf_get_cstring(stream)

    curves: typing.Dict[bytes, typing.Type[ec.EllipticCurve]] = {
        b"nistp256": ec.SECP256R1,
        b"nistp521": ec.SECP521R1,
        b"nistp224": ec.SECP224R1,
    }

    if curve_name not in curves:
        raise InvalidKeyFile(f"Unsupported ECDSA curve {curve_name!r}")

    curve = curves[curve_name]

    ec_data = _sshbuf_get_cstring(stream)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve(), ec_data)
    public_numbers = public_key.public_numbers()

    exponent = _sshbuf_get_bignum2(stream)
    private_numbers = ec.EllipticCurvePrivateNumbers(
        private_value=exponent, public_numbers=public_numbers
    )
    return private_numbers.private_key(backend=default_backend())


def _deserialize_ed25519_private_key(stream: typing.BinaryIO) -> ed25519.Ed25519PrivateKey:
    # <32-bit public key> <64-bit: private key || public key>
    public_key_bytes = _sshbuf_get_cstring(stream)
    assert len(public_key_bytes) == 32
    private_key_bytes = _sshbuf_get_cstring(stream)
    assert len(private_key_bytes) == 64
    assert private_key_bytes[32:] == public_key_bytes
    return ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes[:32])


def _decrypt_key(
    encrypted: bytes,
    passphrase: bytes = None,
    ciphername: bytes = b"none",
    kdfname: bytes = b"none",
    kdf_metadata: bytes = b"",
) -> bytes:

    if ciphername == b"none":
        return encrypted

    if not passphrase:
        raise WrongPassphrase("Passphrase needed for decryption")

    if kdfname == b"none":
        raise InvalidKeyFile("Encrypted SSH key without KDF function name")

    if kdfname != b"bcrypt":
        raise InvalidKeyFile(f"Unsupported private key encryption KDF {kdfname!r}")

    Suite = collections.namedtuple(
        "Suite", ("algorithm", "mode", "key_bytes", "block_bytes", "iv_bytes")
    )
    suites: typing.Dict[bytes, Suite] = {
        b"aes256-ctr": Suite(cipher_algos.AES, cipher_modes.CTR, 32, 16, 16),
        b"aes192-ctr": Suite(cipher_algos.AES, cipher_modes.CTR, 24, 16, 16),
        b"aes128-ctr": Suite(cipher_algos.AES, cipher_modes.CTR, 16, 16, 16),
    }

    if ciphername not in suites:
        raise NotImplementedError(f"Unsupported private key encryption cipher {ciphername!r}")

    suite = suites[ciphername]

    kdf_stream = io.BytesIO(kdf_metadata)
    salt = _sshbuf_get_cstring(kdf_stream)
    (rounds,) = _read_struct(kdf_stream, ">I")

    # ignore_few_rounds prevents a warning when called with <50 rounds
    bcrypt_result = bcrypt.kdf(
        passphrase, salt, suite.key_bytes + suite.iv_bytes, rounds, ignore_few_rounds=True
    )
    key = bcrypt_result[: suite.key_bytes]
    iv = bcrypt_result[suite.key_bytes :]

    cipher = Cipher(algorithm=suite.algorithm(key), mode=suite.mode(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()

    return decrypted


def load_openssh_private_key(openssh_data: bytes, passphrase: bytes = None) -> AnyPrivateKey:
    """Load OpenSSH key in ""PEM"" format.

    The files look like PEM, but aren't. OpenSSH keys are "proprietary" and
    can be identified by the line "-----BEGIN OPENSSH PRIVATE KEY-----".
    """

    # Format documentation:
    # https://coolaj86.com/articles/the-openssh-private-key-format/
    # https://github.com/openssh/openssh-portable/blob/master/sshkey.c
    # sshkey_parse_private2, sshkey_private_deserialize, sshkey_private_serialize_opt

    file = io.StringIO(openssh_data.decode("ascii"))
    for label, decoded in read_ascii_armored(file, strict_line_length=False):
        if label == "OPENSSH PRIVATE KEY":
            break
    else:  # nobreak
        raise InvalidKeyFile("Missing OpenSSH header")

    if not decoded.startswith(OPENSSH_MAGIC):
        raise InvalidKeyFile("Invalid magic bytes")

    decoded = decoded[len(OPENSSH_MAGIC) :]

    decoded_stream = io.BytesIO(decoded)

    # read encryption attributes
    ciphername = _sshbuf_get_cstring(decoded_stream)
    kdfname = _sshbuf_get_cstring(decoded_stream)
    kdf_metadata = _sshbuf_get_cstring(decoded_stream)
    (key_count,) = _read_struct(decoded_stream, ">I")
    if key_count != 1:
        raise InvalidKeyFile("Only one private key per file supported")

    # skip public key
    _sshbuf_get_cstring(decoded_stream)
    (
        # read length of encrypted part (even if unencrypted file)
        encrypted_length,
    ) = _read_struct(decoded_stream, ">I")
    remaining_bytes = len(decoded) - decoded_stream.tell()

    # encrypted_length must exactly match the remaining data
    if remaining_bytes < encrypted_length:
        raise InvalidKeyFile("Private key truncated")
    elif remaining_bytes > encrypted_length:
        raise InvalidKeyFile("Trailing data")

    encrypted = decoded_stream.read(encrypted_length)
    decrypted = _decrypt_key(encrypted, passphrase, ciphername, kdfname, kdf_metadata)
    decrypted_stream = io.BytesIO(decrypted)

    # check bytes, can be used to verify passphrase
    check1, check2 = _read_struct(decrypted_stream, ">II")
    if check1 != check2:
        raise WrongPassphrase("Checksum mismatch")

    # retval
    # we don't do early returns because we need to validate the rest of the file (e.g. padding)
    key: typing.Optional[AnyPrivateKey] = None

    # read private key type
    key_type = _sshbuf_get_cstring(decrypted_stream)
    if key_type == b"ssh-rsa":
        key = _deserialize_rsa_private_key(decrypted_stream)
    elif key_type.startswith(b"ecdsa-"):
        key = _deserialize_ecdsa_private_key(decrypted_stream)
    elif key_type == b"ssh-dss":
        key = _deserialize_dsa_private_key(decrypted_stream)
    elif key_type == b"ssh-ed25519":
        key = _deserialize_ed25519_private_key(decrypted_stream)
    else:
        raise NotImplementedError(f"SSH key type {key_type!r} not implemented yet.")

    # discard key comment
    _sshbuf_get_cstring(decrypted_stream)

    # check deterministic padding: \x01\x02\x03\x04.. up til max. \x07
    for i in range(1, 8):
        try:
            (pad,) = _read_struct(decrypted_stream, "B")
        except struct.error:
            # EOF
            break
        if pad != i:
            raise InvalidKeyFile("Broken file padding")

    return key


# if __name__ == "__main__":
#     import sys
#     from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

#     data = sys.stdin.buffer.read()
#     key = load_openssh_private_key(data)
#     serialized = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())
#     sys.stdout.buffer.write(serialized)
