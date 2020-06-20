.. _tutorials:

Tutorial
========

Installing pyage
----------------

Assuming `Python 3 <https://www.python.org/downloads/>`_ is already installed on
your system, you can now install *pyage* with Pip:

::

    $ pip install age


... and you're all set!


Generating a Key Pair
---------------------

It's like moving into an apartment: You get a new apartment address and a key.
And it's just as exciting!

::

    $ mkdir -p ~/.config/age
    $ pyage generate | tee ~/.config/age/keys.txt

You should see something like:

::

    # created: 2020-02-10T13:34:27
    # age1luj4yjndx48me58dalx200cs65qg9jhtcehjylnp8h9e2c9gduqqq8kduu
    AGE-SECRET-KEY-1TPGEV9GPP6N39Z40RXTQQJMUHU40EJGDDWEFJDJFWVMY0F9FR9NSQRKGQL

Take note of the part starting with ``age1<gibberish>``. This is your public
key. It serves as your new "address" and you may distribute it to your friends
and family. But never show your ``AGE-SECRET-KEY-<gibberish>`` line to anyone,
this is your secret key 🔑!


Encrypt "Hello World"
---------------------

Let's create and encrypt our first file. Choose a file of your liking or
generate a tiny file as follows:

::

    $ echo "Hello World" > hello.txt

Encrypt the file to the public key obtained earlier:

::

    $ pyage encrypt -i hello.txt -o hello.age age1luj4yjndx48me58dalx200cs65qg9jhtcehjylnp8h9e2c9gduqqq8kduu

The encrypted file is now stored at ``hello.age``.


Decrypt ``hello.age``
---------------------

In order to decrypt the file, all you need to do is to call

::

    $ pyage decrypt -i hello.age

If all went well, your terminal will print out "Hello World". Hello!
