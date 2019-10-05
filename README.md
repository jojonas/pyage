# pyage

pyage is an experimental implementation of @FiloSottile and @Benjojo12 's project "age".
The spec is currently available as seven-page Google doc at [age-tool.com](https://age-tool.com).

This project is still work-in-progress.

⚠️ pyage is not intended to be a secure age implementation!
My original intention was to better understand the spec, find mistakes early and provide a redundant implementation for validation. I'm not a cryptographer (IANAC) and did not (yet) spend any time on security (e.g. constant-time implementations).

So:
~~Use at your own risk.~~ *Do not use this project!*

## Installation
Install using pipenv:

    $ pipenv install --skip-lock

To remove pipenv installation:

    $ pipenv --rm

## What already works

### Key Generation

    $ age generate >> ~/.config/age/keys.txt

    $ cat ~/.config/age/keys.txt
    # created: 2019-09-21T23:04:02
    # pubkey:oHoXjKEvpxAgs9rY2YGbiEfKG5wcFo-WEb_u1Mi3hVQ
    AGE_SECRET_KEY_yBO1LGytPAYcGPw3Ptu7LJ0xvwO1K9B9itImkvZej3E


### Encryption to a public key

    $ echo "_o/" | age encrypt -o hello.age pubkey:oHoXjKEvpxAgs9rY2YGbiEfKG5wcFo-WEb_u1Mi3hVQ


### Decryption using default keys

    $ age decrypt -i hello.age
    _o/

### Encryption using a password

    $ echo 'Hello Password!' | age encrypt -p -o hello_password.age
    Type passphrase:

    $ age decrypt -p -i hello_password.age
    Type passphrase:
    Hello Password!

### Encryption to a GitHub user

    $ echo 'Hello GitHub!' | age encrypt -o hello_github.age github:jojonas

    $ age decrypt -i hello_github.age
    Hello GitHub!

### Encryption to an alias

    $ cat ~/.config/age/aliases.txt
    filippo: pubkey:jqmfMHBjlb7HoIjjTsCQ9NHIk_q53Uy_ZxmXBhdIpx4
    ben: pubkey:ZAE2ZnRdItykp0ncAZJ2FAzIIfTvmGcgIx/759QhnQw github:Benjojo
    jonas: pubkey:oHoXjKEvpxAgs9rY2YGbiEfKG5wcFo-WEb_u1Mi3hVQ github:jojonas

    $ echo 'Hello Alias!' | age encrypt -o hello_alias.age jonas

    $ head -n 29 hello_alias.age
    This is a file encrypted with age-tool.com, version 1
    -> X25519 rcRwcN5b4CRM9Yrs5BHk79jkBFZlyCeNEPT-q5BM5UY uqLE2n1jU_FSgM7EqB6w5k6StDasW_tDiLAB7yWiESE
    -> ssh-rsa LSAPYQ Fq6OA0fpQFmnZdEFwW2dBSKOHvl9LUnNWPD0-FjX5iVVUYcHQ3fxv4nNx
    [...]
    -> ssh-rsa tPGDUw oRVbWD4eJ2NzuomR9_0CPh13Ej4c2I2oE4O0wvNfjU5F2jQ9oiNLkSAqO
    [...]
    --- ChaChaPoly J94r7YaZLMSE2yvEkuFo9iPAhLPb-4GBBUyMyHhZy6E
    [...]


## Development
* Enforce PEP8 with [black](https://github.com/psf/black), [flake8](http://flake8.pycqa.org/en/latest/) and [isort](https://timothycrosley.github.io/isort/)
* Run unit tests ([pytest](https://docs.pytest.org/en/latest/)) with coverage testing
* Hint native types ([Python typing](https://docs.python.org/3/library/typing.html)), enforce with [mypy](http://mypy-lang.org/)
* Documentation with [Sphinx](https://www.sphinx-doc.org/en/master/)

## TODO
* Error handling
* Proper logging (to stderr)
