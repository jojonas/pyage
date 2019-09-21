#!/usr/bin/env python3

import datetime
import sys

import click

from age.file import File, LockedFile
from age.keyloader import resolve_public_key, load_keys_txt, load_ssh_keys
from age.keys.password import PasswordKey
from age.keys.agekey import AgePrivateKey


@click.group()
def cli():
    pass


@cli.command()
@click.option("-i", "--infile", type=click.File("rb"), default=sys.stdin.buffer)
@click.option("-o", "--outfile", type=click.File("wb"), default=sys.stdout.buffer)
@click.option("-p", "--password", is_flag=True)
@click.argument("recipients", nargs=-1)
def encrypt(infile, outfile, password, recipients):
    if outfile is sys.stdout.buffer and sys.stdout.isatty():
        print("Refusing to encrypt to a TTY.", file=sys.stderr)
        sys.exit(1)

    age_file = File.new()

    for recipient in recipients:
        keys = resolve_public_key(recipient)
        for key in keys:
            age_file.add_recipient(key)

    if password:
        password = click.prompt("Type passphrase:", hide_input=True).decode("utf-8")
        age_file.add_recipient(PasswordKey(password))

    age_file.serialize_header(outfile)
    age_file.encrypt(plaintext_stream=infile, ciphertext_stream=outfile)


@cli.command()
@click.option("-i", "--infile", type=click.File("rb"), default=sys.stdin.buffer)
@click.option("-o", "--outfile", type=click.File("wb"), default=sys.stdout.buffer)
@click.option("-p", "--password", is_flag=True)
@click.argument("keyfiles", nargs=-1)
def decrypt(infile, outfile, password, keyfiles):
    locked_age_file = LockedFile.from_file(infile)

    keys = []

    keys.extend(load_keys_txt())
    keys.extend(load_ssh_keys())
    for keyfile in keyfiles:
        keys.extend(load_keys_txt(keyfile))

    if password:
        password = click.prompt("Type passphrase:", hide_input=True).decode("utf-8")
        keys.append(PasswordKey(password))

    if not keys:
        print("No keys loaded.", file=sys.stderr)
        sys.exit(1)

    age_file = locked_age_file.unlock(keys)
    age_file.decrypt(infile, outfile)


@cli.command()
@click.option("-o", "--outfile", type=click.File("w"), default=sys.stdout)
def generate(outfile):
    key = AgePrivateKey.generate()

    now = datetime.datetime.now()
    outfile.write(f"# created: {now:%Y-%m-%dT%H:%M:%S}\n")
    outfile.write("# " + key.public_key().public_string() + "\n")
    outfile.write(key.private_string() + "\n")


if __name__ == "__main__":
    cli()
