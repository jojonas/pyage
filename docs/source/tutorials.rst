.. _tutorials:

Tutorial
========

Installing Dependencies
-----------------------

To install *pyage*, you only need two dependencies: `Python 3
<https://www.python.org/downloads/>`_ and `pipenv
<https://github.com/pypa/pipenv#installation>`_. Both should be available from
your favorite package manager.

On Debian or Ubuntu, use:

::

    $ sudo apt install python3 pipenv

On Arch, install them as

::

    $ sudo pacman -S python python-pipenv

On Fedora, use

::

    $ sudo dnf install python3 pipenv


Installing pyage
----------------

Now, clone *pyage*'s public respository from `GitHub
<https://github.com/jojonas/pyage>`_:

::

    $ git clone https://github.com/jojonas/pyage.git


Install *pyage* locally:

::

    $ cd pyage
    $ pipenv install

In order to interact with *pyage*, start a "pipenv shell":

::

    $ pipenv shell

... now you're all set!


Generating a Key Pair
---------------------

It's like moving into an apartment: You get a new apartment address and a key.
And it's just as exciting!

::

    $ mkdir -p ~/.config/age
    $ age generate | tee ~/.config/age/keys.txt

You should see something like:

::

    # created: 2019-10-19T12:34:56
    # pubkey:Vn5D1ZdwXiEtO3xZ_81psWqTgEyngXZfiBH_4kddWS0
    AGE_SECRET_KEY_uBE1QNrUFq4dSrmKyAiDWKDd9HCuasETsF7RsIcuh2E

Take note of the part starting with ``pubkey:<gibberish>``. This is your public
key. It serves as your new "address" and you may distribute it to your friends
and family. But never show your ``AGE_SECRET_KEY_<gibberish>`` line to anyone,
this is your secret key 🔑!


Encrypt "Hello World"
---------------------

Let's create and encrypt our first file. Choose a file of your liking or
generate a tiny file as follows:

::

    $ echo "Hello World" > hello.txt

Encrypt the file to the public key obtained earlier:

::

    $ age encrypt -i hello.txt -o hello.age pubkey:Vn5D1ZdwXiEtO3xZ_81psWqTgEyngXZfiBH_4kddWS0

The encrypted file is now stored at ``hello.age``.


Decrypt ``hello.age``
---------------------

In order to decrypt the file, all you need to do is to call

::

    $ age decrypt -i hello.age

If all went well, your terminal will print out "Hello World". Hello!