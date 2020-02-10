.. _guides:

How-To Guides
=============

This section outlines a few of the typical workflows which can be achieved with
``age``. For further information on the different subcommands, see :ref:`usage`
or call ``age`` with the ``--help`` option.


.. _guide-key-generation:

Generate a Key Pair
-------------------

New age private keys can be generated with the ``age generate`` subcommand. By
default the key is printed to the standard output stream, but it can also
directly by stored in a file.

::

    $ pyage generate >> ~/.config/age/keys.txt

    $ cat ~/.config/age/keys.txt
    # created: 2020-02-10T13:34:27
    # age1luj4yjndx48me58dalx200cs65qg9jhtcehjylnp8h9e2c9gduqqq8kduu
    AGE-SECRET-KEY-1TPGEV9GPP6N39Z40RXTQQJMUHU40EJGDDWEFJDJFWVMY0F9FR9NSQRKGQL


.. _guide-encryption:

Encrypt to a Public Key
-----------------------

Public keys of recipients must be provided in the ``age encrypt`` command. The
simplest use case is to encrypt to an age public key starting with ``age1``.

::

    $ echo "_o/" | pyage encrypt -o hello.age age1luj4yjndx48me58dalx200cs65qg9jhtcehjylnp8h9e2c9gduqqq8kduu

.. _guide-decryption:

Decrypt Using a Private Key
---------------------------

``age`` will try private keys from several locations during decryption (see
:ref:`usage-decrypt`). The following example works because the private key is
stored at
``~/.config/age/keys.txt`` (see
:ref:`guide-key-generation`).

::

    $ pyage decrypt -i hello.age
    _o/


.. _guide-password:

Encrypt Using a Password
------------------------

Besides asymmetric cryptography, ``age`` can also encrypt to a password. The
same password is then required in order to decrypt the file. This can be seen
in the following example. Note that during the password prompt, entered
characters are not echoed to the terminal.

::

    $ echo 'Hello Password!' | pyage encrypt -p -o hello_password.age
    Type passphrase:

    $ pyage decrypt -p -i hello_password.age
    Type passphrase:
    Hello Password!


.. _guide-recipient-list:

Encrypt to a List of Recipients
-------------------------------

Instead of providing a public key directly, ``age`` can read recipients from a
file or an URL. Note that in this case, :ref:`aliases <guide-alias>` are
*not* further expanded.

::

    $ echo 'Hello file!' | pyage encrypt -o hello_recipients.age recipients.txt
    $ echo 'Hello URL!'  | pyage encrypt -o hello_recipients.age https://example.com/age-keys.txt


.. _guide-github:

Encrypt to a GitHub User
------------------------

GitHub serves the SSH public keys `configured
<https://help.github.com/en/articles/adding-a-new-ssh-key-to-your-github-account>`_
in your profile at the url ``https://github.com/USERNAME.keys``. ``age`` can
automatically read the keys at this URL if provided with the recipient
``github:USERNAME``.

In the following example, decryption works because the corresponding private
key is stored in at ``~/.ssh/id_rsa``.

::

    $ echo 'Hello GitHub!' | pyage encrypt -o hello_github.age github:jojonas

    $ pyage decrypt -i hello_github.age
    Hello GitHub!


.. _guide-alias:

Use Aliases
-----------

Aliases can be configured in the file ``~/.config/age/aliases.txt``. The file
contains one alias per line. The line must start with the alias label followed
by a colon. After the colon, multiple keys, files, URLs or GitHub usernames can
be specified, separated by a space character.

::

    $ cat ~/.config/age/aliases.txt
    filippo: age1luj4yjndx48me58dalx200cs65qnotarealkeyjylnp8h9e2c9gduqqq8kduu
    ben: age1luj4yjndx48me58dalx200cs65qnotarealkeyjylnp8h9e2c9gduqqq8kduu github:Benjojo
    jonas: age1luj4yjndx48me58dalx200cs65qg9jhtcehjylnp8h9e2c9gduqqq8kduu github:jojonas

    $ echo 'Hello Alias!' | pyage encrypt -o hello_alias.age jonas

