"""Compatibility shim.

The canonical project metadata lives in ``pyproject.toml`` (PEP 621).
This file exists so that legacy tooling that expects a ``setup.py``
keeps working. The published version is defined in ``pyproject.toml``
and must match the release tag.
"""
from setuptools import setup

setup()
