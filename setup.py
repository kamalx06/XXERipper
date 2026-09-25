#!/usr/bin/env python3
"""
Compatibility shim for build tools that still require setup.py.

All real metadata is declared in pyproject.toml. This file exists so that
legacy tooling (stdeb, older pip, some CI systems) can still drive a build
through setuptools.
"""

from setuptools import setup

if __name__ == "__main__":
    setup()