import datetime
import io
import os.path
import sys
from contextlib import contextmanager
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from pytest import raises

from age.cli import decrypt, encrypt, generate

TEST_KEY = "# created: 2019-11-10T10:00:00\n# age1we7j2tm5yqmhc0we94eg3jcdtu46069dlapzm8qkg90eef08ya6q90qz3l\nAGE-SECRET-KEY-1MZ6SR3NFE7KTRHXPWN6X966HSL8R53ZW459EZ42EWUX204AFJ90QHA8935\n"
TEST_KEY_PUBLIC = "age1we7j2tm5yqmhc0we94eg3jcdtu46069dlapzm8qkg90eef08ya6q90qz3l"
TEST_KEY_RAW = bytes.fromhex("d8b501c669cfacb1dcc174f462eb5787ce3a444ead0b915559770ca7d7a9915e")

TEST_PLAINTEXT = b"Hello World!"
TEST_CIPHERTEXT = (
    b"age-encryption.org/v1\n-> X25519 FMqeTTh7zPNXRuBAfaqsxrKKT4RF71pRWIlNuYPiQHA\nCtufbJCyj2JplnG6Rg3RHy6rJOUOE+Rqv8RGWoYWXlg\n--- gY9WMTjF1pksYSXC7xCFZGpiQH8frzkzKj1EG6Ql+gI\n"
    + bytes.fromhex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacb589584a3b51348f292714ab0d51537e404d9882f9b03aa3d7fedfd"
    )
)


@contextmanager
def should_exit(code=1):
    with raises(SystemExit) as wrapped_e:
        yield
    assert wrapped_e.type == SystemExit
    assert wrapped_e.value.code == code


def fake_random(n):
    # really bad random data
    return b"\xaa" * n


def test_generate(capsys):
    gen_func = "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate"

    with mock.patch(gen_func) as mock_generate, mock.patch("age.cli.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime.datetime(2019, 11, 10, 10, 00, 00)
        mock_datetime.side_effect = lambda *args, **kw: datetime.datetime(*args, **kw)
        mock_generate.return_value = X25519PrivateKey.from_private_bytes(TEST_KEY_RAW)

        generate()

        captured = capsys.readouterr()
        assert captured.out == TEST_KEY


def test_encrypt(capsysbinary, monkeypatch):
    with mock.patch("os.urandom", fake_random):
        encrypt(recipients=[TEST_KEY_PUBLIC], infile=io.BytesIO(TEST_PLAINTEXT))
        captured = capsysbinary.readouterr()
        assert captured.out == TEST_CIPHERTEXT


def test_encrypt_no_recipient(capsys):
    with should_exit(1):
        encrypt(infile=io.BytesIO(TEST_PLAINTEXT))
    captured = capsys.readouterr()
    assert captured.err != ""


def test_encrypt_to_tty():
    with mock.patch("sys.stdout", return_value=False):
        assert sys.stdout.isatty()
        with should_exit(1):
            encrypt([TEST_KEY_PUBLIC], infile=TEST_PLAINTEXT)


def test_decrypt(fs, capsysbinary):
    keys_filename = os.path.expanduser("~/.config/age/keys.txt")
    fs.create_file(keys_filename, contents=TEST_KEY)
    decrypt(infile=io.BytesIO(TEST_CIPHERTEXT))
    captured = capsysbinary.readouterr()
    assert captured.out == TEST_PLAINTEXT


def test_decrypt_from_file(fs, capsysbinary):
    keys_filename = os.path.expanduser("~/.config/age/keys.txt")
    fs.create_file(keys_filename, contents=TEST_KEY)

    ciphertext_filename = "/tmp/test.age"
    fs.create_file(ciphertext_filename, contents=TEST_CIPHERTEXT)

    with open(ciphertext_filename, "rb") as infile:
        decrypt(infile=infile)

    captured = capsysbinary.readouterr()
    assert captured.out == TEST_PLAINTEXT


def test_decrypt_to_file(fs):
    keys_filename = os.path.expanduser("~/.config/age/keys.txt")
    fs.create_file(keys_filename, contents=TEST_KEY)

    ciphertext_filename = "/tmp/test.age"
    fs.create_file(ciphertext_filename, contents=TEST_CIPHERTEXT)

    plaintext_filename = "/tmp/test.txt"
    with open(plaintext_filename, "wb") as outfile, open(ciphertext_filename, "rb") as infile:
        decrypt(outfile=outfile, infile=infile)

    with open(plaintext_filename, "rb") as plaintext_file:
        assert plaintext_file.read() == TEST_PLAINTEXT
