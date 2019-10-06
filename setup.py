# -*- coding: utf-8 -*-
"""Packaging logic for age."""
import os
import sys

import setuptools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))  # noqa

if __name__ == "__main__":
    setuptools.setup()
