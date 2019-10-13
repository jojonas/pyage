import datetime
import os.path

from click.testing import CliRunner
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from age.cli import main


runner = CliRunner(mix_stderr=False)

TEST_KEY = "# created: 2019-11-10T10:00:00\n# pubkey:dn0lL3QgN3w92S1yiMsNXyun6K3_Qi2cFkFfnKXnJ3Q\nAGE_SECRET_KEY_2LUBxmnPrLHcwXT0YutXh846RE6tC5FVWXcMp9epkV4\n"
TEST_KEY_PUBLIC = "pubkey:dn0lL3QgN3w92S1yiMsNXyun6K3_Qi2cFkFfnKXnJ3Q"
TEST_KEY_RAW = bytes.fromhex("d8b501c669cfacb1dcc174f462eb5787ce3a444ead0b915559770ca7d7a9915e")

TEST_PLAINTEXT = b"Hello World!"
TEST_CIPHERTEXT = (
    b"This is a file encrypted with age-tool.com, version 1\n-> X25519 FMqeTTh7zPNXRuBAfaqsxrKKT4RF71pRWIlNuYPiQHA\nUsVP7CmlQh5YiCrnp69U9D09TNi4c3rIZ7rRYq8syaE\n--- Wg6sarbap6UrC0rkyj2pGYvXbQ9j1uVHSJQ7O6SyWDI\n"
    + bytes.fromhex(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaacb589584a3b51348f292714ab0d51537e404d9882f9b03aa3d7fedfd"
    )
)


def fake_random(n):
    # really bad random data
    return b"\xaa" * n


def test_generate():
    gen_func = "cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate"

    with mock.patch(gen_func) as mock_generate, mock.patch("age.cli.datetime") as mock_datetime:
        mock_datetime.now.return_value = datetime.datetime(2019, 11, 10, 10, 00, 00)
        mock_datetime.side_effect = lambda *args, **kw: datetime.datetime(*args, **kw)
        mock_generate.return_value = X25519PrivateKey.from_private_bytes(TEST_KEY_RAW)

        result = runner.invoke(main, ["generate"])
        assert result.exit_code == 0
        assert result.output == TEST_KEY


def test_encrypt():
    with mock.patch("os.urandom", fake_random):
        result = runner.invoke(main, ["encrypt", TEST_KEY_PUBLIC], input=TEST_PLAINTEXT)
        assert result.exit_code == 0
        print(result.stdout)
        print(result.stdout_bytes.hex())
        assert result.stdout_bytes == TEST_CIPHERTEXT


def test_encrypt_no_recipient():
    result = runner.invoke(main, ["encrypt"], input=TEST_PLAINTEXT)
    assert result.exit_code == 1
    # assert result.stderr != ""


def test_decrypt(fs):
    keys_filename = os.path.expanduser("~/.config/age/keys.txt")
    fs.create_file(keys_filename, contents=TEST_KEY)
    result = runner.invoke(main, ["decrypt"], input=TEST_CIPHERTEXT)
    assert result.exit_code == 0
    assert result.stdout_bytes == TEST_PLAINTEXT


def test_decrypt_from_file(fs):
    keys_filename = os.path.expanduser("~/.config/age/keys.txt")
    fs.create_file(keys_filename, contents=TEST_KEY)

    ciphertext_filename = "/tmp/test.age"
    fs.create_file(ciphertext_filename, contents=TEST_CIPHERTEXT)

    result = runner.invoke(main, ["decrypt", "-i", ciphertext_filename])
    assert result.exit_code == 0
    assert result.stdout_bytes == TEST_PLAINTEXT


def test_decrypt_to_file(fs):
    keys_filename = os.path.expanduser("~/.config/age/keys.txt")
    fs.create_file(keys_filename, contents=TEST_KEY)

    plaintext_filename = "/tmp/test.txt"
    fs.create_file(plaintext_filename, contents=TEST_CIPHERTEXT)

    result = runner.invoke(main, ["decrypt", "-o", plaintext_filename], input=TEST_CIPHERTEXT)

    with open(plaintext_filename, "rb") as plaintext_file:
        assert result.exit_code == 0
        assert plaintext_file.read() == TEST_PLAINTEXT
