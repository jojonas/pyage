Workflows
=========

This section outlines a few of the typical workflows which can be achieved with
``age``. For further information on the different subcommands, see :ref:`usage`
below or call ``age`` with the ``--help`` option.


.. _examples-key-generation:

Key Generation
--------------

New age private keys can be generated with the ``age generate`` subcommand. By
default the key is printed to the standard output stream, but it can also
directly by stored in a file.

::

    $ age generate >> ~/.config/age/keys.txt

    $ cat ~/.config/age/keys.txt
    # created: 2019-09-21T23:04:02
    # pubkey:oHoXjKEvpxAgs9rY2YGbiEfKG5wcFo-WEb_u1Mi3hVQ
    AGE_SECRET_KEY_yBO1LGytPAYcGPw3Ptu7LJ0xvwO1K9B9itImkvZej3E


.. _examples-encryption:

Encryption to a public key
--------------------------

Public keys of recipients must be provided in the ``age encrypt`` command. The
simplest use case is to encrypt to an age public key starting with ``pubkey:``.

::

    $ echo "_o/" | age encrypt -o hello.age pubkey:oHoXjKEvpxAgs9rY2YGbiEfKG5wcFo-WEb_u1Mi3hVQ

.. _examples-decryption:

Decryption using default keys
-----------------------------

``age`` will try keys from several locations during decryption (see
:ref:`usage-decrypt`). The following example works because of the
``~/.config/age/keys.txt`` file we created earlier (see
:ref:`examples-key-generation`).

::

    $ age decrypt -i hello.age
    _o/


.. _examples-password:

Encryption using a password
---------------------------

Besides asymmetric cryptography, ``age`` can also encrypt to a password. The
same password is then required in order to decrypt the file. This can be seen
in the following example. Note that during the password prompt, entered
characters are not echoed to the terminal.

::

    $ echo 'Hello Password!' | age encrypt -p -o hello_password.age
    Type passphrase:

    $ age decrypt -p -i hello_password.age
    Type passphrase:
    Hello Password!


.. _examples-recipient-list:

Encryption to a list of recipients
----------------------------------

Instead of providing a public key directly, ``age`` can read recipients from a
file or an URL. Note that in this case, :ref:`aliases <examples-alias>` are
*not* further expanded.

::

    $ echo 'Hello file!' | age encrypt -o hello_recipients.age recipients.txt
    $ echo 'Hello URL!'  | age encrypt -o hello_recipients.age https://example.com/age-keys.txt


.. _examples-github:

Encryption to a GitHub user
---------------------------

GitHub serves the SSH public keys `configured
<https://help.github.com/en/articles/adding-a-new-ssh-key-to-your-github-account>`_
in your profile at the url ``https://github.com/USERNAME.keys``. ``age`` can
automatically read the keys at this URL if provided with the recipient
``github:USERNAME``.

In the following example, decryption works because the corresponding private
key is stored in at ``~/.ssh/id_rsa``.

::

    $ echo 'Hello GitHub!' | age encrypt -o hello_github.age github:jojonas

    $ age decrypt -i hello_github.age
    Hello GitHub!


.. _examples-alias:

Encryption to an alias
----------------------

Aliases can be configured in the file ``~/.config/age/aliases.txt``. The file
contains one alias per line. The line must start with the alias label followed
by a colon. After the colon, multiple keys, files, URLs or GitHub usernames can
be specified, separated by a space character.

::

    $ cat ~/.config/age/aliases.txt
    filippo: pubkey:jqmfMHBjlb7HoIjjTsCQ9NHIk_q53Uy_ZxmXBhdIpx4
    ben: pubkey:ZAE2ZnRdItykp0ncAZJ2FAzIIfTvmGcgIx/759QhnQw github:Benjojo
    jonas: pubkey:oHoXjKEvpxAgs9rY2YGbiEfKG5wcFo-WEb_u1Mi3hVQ github:jojonas

    $ echo 'Hello Alias!' | age encrypt -o hello_alias.age jonas


.. _usage:

Usage
=====

.. command-output:: age --help


.. _usage-encrypt:

Encryption
----------

.. command-output:: age encrypt --help


.. _usage-decrypt:

Decryption
----------

.. command-output:: age decrypt --help

.. _usage-generate:

Key Generation
--------------

.. command-output:: age generate --help
