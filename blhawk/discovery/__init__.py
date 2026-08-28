"""Input and URL discovery."""

from __future__ import annotations

from .inputs import read_stdin, read_target_file, targets_from_scope
from .urls import extract_links

__all__ = ["extract_links", "read_stdin", "read_target_file", "targets_from_scope"]
