"""Generic soft-404 detection.

Some hosts return ``200 OK`` with a "not found" page for every path (a
catch-all). Trusting such a response would either produce false positives
(treating a live page as missing) or false negatives (treating a catch-all as
a live resource). We detect catch-alls by probing an unlikely random sibling
path and comparing it to the target response.
"""
from __future__ import annotations

import difflib
import re
import secrets
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_DIGITS = re.compile(r"\d+")
_WS = re.compile(r"\s+")


def random_control_url(url: str) -> str:
    """Return a sibling URL with an unlikely-to-exist random final segment."""
    parts = urlsplit(url)
    token = "blhawk-nonexistent-" + secrets.token_hex(8)
    base_path = parts.path.rstrip("/")
    if "/" in base_path:
        base_path = base_path.rsplit("/", 1)[0]
    control_path = f"{base_path}/{token}"
    return urlunsplit((parts.scheme, parts.netloc, control_path, "", ""))


def _normalize_body(text: str, max_len: int = 4000) -> str:
    text = text[:max_len].lower()
    text = _DIGITS.sub("", text)
    text = _WS.sub(" ", text)
    return text.strip()


def body_similarity(a: str, b: str) -> float:
    """Return a 0..1 similarity ratio between two response bodies."""
    na, nb = _normalize_body(a), _normalize_body(b)
    if not na and not nb:
        return 1.0
    return difflib.SequenceMatcher(None, na, nb).ratio()


@dataclass
class Soft404Result:
    is_catch_all: bool
    similarity: float
    control_status: int | None = None
    note: str = ""


class Soft404Detector:
    """Compares a target response with a random-path control response."""

    def __init__(self, similarity_threshold: float = 0.9) -> None:
        self.similarity_threshold = similarity_threshold

    def analyze(
        self,
        target_status: int,
        target_body: str,
        control_status: int,
        control_body: str,
    ) -> Soft404Result:
        # A catch-all is a host that returns a successful, near-identical page
        # for a path that cannot exist.
        if control_status == target_status and control_status in (200, 202, 203):
            similarity = body_similarity(target_body, control_body)
            if similarity >= self.similarity_threshold:
                return Soft404Result(
                    is_catch_all=True,
                    similarity=similarity,
                    control_status=control_status,
                    note="host returns near-identical 200 page for a random path",
                )
            return Soft404Result(False, similarity, control_status)
        return Soft404Result(False, 0.0, control_status)
