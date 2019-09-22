#!/usr/bin/env python3

import datetime
import os
import stat
import sys

import click

from age.file import File, LockedFile
from age.keyloader import load_aliases, load_keys_txt, load_ssh_keys, resolve_public_key
from age.keys.agekey import AgePrivateKey
from age.keys.password import PasswordKey


@click.group()
def main():
    pass


@main.command()
@click.option("-i", "--infile", type=click.File("rb"), default=sys.stdin.buffer)
@click.option("-o", "--outfile", type=click.File("wb"), default=sys.stdout.buffer)
@click.option("-p", "--password", is_flag=True)
@click.argument("recipients", nargs=-1)
def encrypt(infile, outfile, password, recipients):
    """Encrypt data for the given recipients.

    \b
    RECIPIENTS can be a list of either:
        * aliases (from ~/.config/age/aliases.txt)
        * age public keys (starting with "pubkey:")
        * SSH public keys (starting with "ssh-rsa" or "ssh-ed25519")
        * Files with one key per line (no aliases allowed)
        * URLs to files with one key per line (no aliases allowed)
        * GitHub usernames (will fetch SSH public keys from https://github.com/USERNAME.keys)

    Plaintext data can be passed via the standard input stream or from a file.
    Encryption to the standard output stream is only allowed if the stream
    is not bound to a TTY, in any case an output file can be used.

    A password recipient can be added with the '-p' option. age will prompt
    for the password.

    Note that in this case, anyone in possession of the password can tamper
    with the message, therefore it is recommended to not mix password- and
    public key recipients.

    """
    if outfile is sys.stdout.buffer and sys.stdout.isatty():
        print("Refusing to encrypt to a TTY.", file=sys.stderr)
        sys.exit(1)

    aliases = load_aliases()

    age_file = File.new()

    for recipient in recipients:
        keys = resolve_public_key(recipient, aliases=aliases)
        for key in keys:
            age_file.add_recipient(key)

    if password:
        if recipients:
            print(
                "Using password recipient in addition to public keys. "
                + "Note that anyone in possession of the password can tamper with "
                + "the message content and recipient list.",
                file=sys.stderr,
            )
        password = click.prompt("Type passphrase", hide_input=True).encode("utf-8")
        age_file.add_recipient(PasswordKey(password))

    if not age_file.recipients:
        print("You must specify at least one recipient.", file=sys.stderr)
        sys.exit(1)

    age_file.serialize_header(outfile)
    age_file.encrypt(plaintext_stream=infile, ciphertext_stream=outfile)


@main.command()
@click.option("-i", "--infile", type=click.File("rb"), default=sys.stdin.buffer)
@click.option("-o", "--outfile", type=click.File("wb"), default=sys.stdout.buffer)
@click.option("-p", "--password", is_flag=True)
@click.argument("keyfiles", nargs=-1)
def decrypt(infile, outfile, password, keyfiles):
    """Decrypt a file encrypted with 'age encrypt'.

    Ciphertext can be passed from the standard input stream and from a file.
    Plaintext will by default be written to the standard output stream, but
    a filename can be specified.

    \b
    Decryption is attempted with keys from the following locations:
        * Age private keys from 'age generate' in file ~/.config/age/keys.txt
        * Private SSH keys at ~/.ssh/id_*
        * Age private keys in files passed via KEYFILES.

    If the '-p' switch is provided, age will prompt for a password and also
    attempt to decrypt the message with the given password.
    """
    locked_age_file = LockedFile.from_file(infile)

    keys = []
    keys.extend(load_keys_txt())
    keys.extend(load_ssh_keys())
    for keyfile in keyfiles:
        keys.extend(load_keys_txt(keyfile))

    if password:
        password = click.prompt("Type passphrase", hide_input=True).encode("utf-8")
        keys.append(PasswordKey(password))

    if not keys:
        print("No keys loaded.", file=sys.stderr)
        sys.exit(1)

    age_file = locked_age_file.unlock(keys)
    age_file.decrypt(infile, outfile)


@main.command()
@click.option(
    "-o", "--outfile", type=click.File("w"), default=sys.stdout, help="Keypair destination"
)
def generate(outfile):
    """Generate a new age private/public key pair.

    If no FILENAME is given, the command outputs the key pair to the standard output stream.

    If FILENAME exists, age will warn if the file permissions allow others to read, write or
    execute the file.
    """
    key = AgePrivateKey.generate()

    now = datetime.datetime.now()
    outfile.write(f"# created: {now:%Y-%m-%dT%H:%M:%S}\n")
    outfile.write("# " + key.public_key().public_string() + "\n")
    outfile.write(key.private_string() + "\n")

    if os.path.isfile(outfile.name):
        stat_result = os.stat(outfile.name)
        permissions = stat_result[stat.ST_MODE]
        if permissions & stat.S_IRWXO:
            print(
                f"Warning: The file permissions indicate that other users may have access to the key file '{outfile.name}'.",
                file=sys.stderr,
            )


if __name__ == "__main__":
    main()
