"""Structured, injection-resistant logging helpers.

User-controlled values (URLs, hostnames, response snippets) are sanitized
before logging so that a malicious target cannot forge log lines
(CR/LF/control-character log injection).
"""

from __future__ import annotations

import logging
import re
from typing import Any

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_CONFIGURED = False


def sanitize(value: Any, max_len: int = 512) -> str:
    """Return a single-line, control-character-free representation of ``value``."""
    text = str(value)
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    text = _CONTROL_CHARS.sub("", text)
    if len(text) > max_len:
        text = text[:max_len] + "...(truncated)"
    return text


def configure_logging(level: int = logging.WARNING) -> None:
    """Configure the root ``blhawk`` logger once."""
    global _CONFIGURED
    logger = logging.getLogger("blhawk")
    logger.setLevel(level)
    if not _CONFIGURED:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        _CONFIGURED = True
    else:
        for existing in logger.handlers:
            existing.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced child logger."""
    return logging.getLogger(f"blhawk.{name}")
