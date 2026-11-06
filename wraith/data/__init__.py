"""Bundled data files: signatures, wordlists, discovery rules."""

from importlib import resources


def read_text(name: str) -> str:
    return resources.files(__name__).joinpath(name).read_text(encoding="utf-8")
