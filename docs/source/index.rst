pyage
=====

.. image:: https://github.com/jojonas/pyage/workflows/Build%20and%20Test/badge.svg
  :target: https://github.com/jojonas/pyage/actions?workflow=Build+and+Test

.. image:: https://github.com/jojonas/pyage/workflows/Compatibility%20with%20FiloSottile/age/badge.svg
  :target: https://github.com/jojonas/pyage/actions?workflow=Compatibility%20with%20FiloSottile/age

.. image:: https://readthedocs.org/projects/pyage/badge/?version=latest
  :target: https://pyage.readthedocs.io/en/latest/?badge=latest

.. image:: https://img.shields.io/github/license/jojonas/pyage


Introduction
------------

*age* is a command line tool for file encryption. The project was started by
`Filippo Valsorda (@filosotille) <https://twitter.com/filosottile>`_ and `Ben
Cox (@benjojo12) <https://twitter.com/benjojo12>`_ at
`<https://age-encryption.org>`_. *pyage* is not an official implementation! Its goal
is rather to understand the usage and inner workings of *age*. A more
"official" version has been implemented by Filippo and is available `on his
github page <https://github.com/FiloSottile/age>`_.

The source code repository of this project can be found at `GitHub
<https://github.com/jojonas/pyage>`_.

About the documentation
-----------------------

This documentation is structured in four parts:

* :ref:`tutorials` should be your gateway into *pyage*. It's aimed
  to be a starting point, guiding you through the installation process to
  encrypting (and decrypting) your first file.

* :ref:`guides` explain some common day-to-day workflows and
  how to solve them using *pyage*. It's definitely more advanced than the
  :ref:`tutorials`, however, there is no need to know about the inner workings of
  *pyage*.

* :ref:`reference` describes the machinery behind *pyage*. It
  mostly consists of the API reference and should be your reference if you'd
  like to poke into *pyage*'s source code.

* :ref:`background` contains background information about *pyage*
  and *age* in general. It's goal is to shed some light into the design
  decision behind *age*.

Table of Contents
-----------------

.. toctree::
    :maxdepth: 2
    :caption: Contents:

    tutorials.rst
    guides.rst
    reference.rst
    background.rst
    development.rst


Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
