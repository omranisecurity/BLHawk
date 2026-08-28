"""A safe, SSRF-aware HTTP client.

Wraps :mod:`requests` with connection pooling, timeouts, a redirect cap,
a response-size cap, retry/backoff and — critically — an SSRF guard that is
re-checked on *every* redirect hop. Redirects are followed manually so the
guard cannot be bypassed by a redirect to an internal address.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import requests
from requests.adapters import HTTPAdapter

from .errors import PermanentError, RetryableError
from .logging import get_logger, sanitize
from .rate_limiter import RateLimiter
from .ssrf import ALLOWED_SCHEMES, SSRFGuard

_log = get_logger("http")

_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

DEFAULT_USER_AGENT = "BLHawk/1.0 (+https://github.com/omranisecurity/BLHawk)"


@dataclass
class HTTPResponse:
    """A minimal, safe view of an HTTP response."""

    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes = b""
    history: list[str] = field(default_factory=list)
    elapsed_ms: int = 0
    truncated: bool = False
    encoding: str | None = None

    @property
    def text(self) -> str:
        enc = self.encoding or "utf-8"
        try:
            return self.body.decode(enc, errors="replace")
        except (LookupError, TypeError):
            return self.body.decode("utf-8", errors="replace")

    def header(self, name: str, default: str = "") -> str:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


class SafeHTTPClient:
    def __init__(
        self,
        guard: SSRFGuard | None = None,
        rate_limiter: RateLimiter | None = None,
        timeout: float = 15.0,
        max_redirects: int = 5,
        max_bytes: int = 2_000_000,
        retries: int = 2,
        backoff_factor: float = 0.5,
        user_agent: str = DEFAULT_USER_AGENT,
        pool_size: int = 20,
    ) -> None:
        self.guard = guard or SSRFGuard()
        self.rate_limiter = rate_limiter
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.max_bytes = max_bytes
        self.retries = retries
        self.backoff_factor = backoff_factor
        self.user_agent = user_agent
        self._session = requests.Session()
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> SafeHTTPClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internal helpers ------------------------------------------------
    def _read_capped(self, resp: requests.Response, want_body: bool) -> tuple[bytes, bool]:
        if not want_body:
            resp.close()
            return b"", False
        chunks: list[bytes] = []
        total = 0
        truncated = False
        for chunk in resp.iter_content(chunk_size=16384):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= self.max_bytes:
                truncated = True
                break
        resp.close()
        return b"".join(chunks)[: self.max_bytes], truncated

    def _single_request(
        self, method: str, url: str, headers: dict[str, str], want_body: bool
    ) -> requests.Response:
        parts = urlsplit(url)
        if parts.scheme.lower() not in ALLOWED_SCHEMES:
            raise PermanentError(f"scheme not allowed: {sanitize(parts.scheme)}")
        host = parts.hostname or ""
        self.guard.enforce(host)
        if self.rate_limiter is not None:
            self.rate_limiter.acquire(host)
        try:
            return self._session.request(
                method,
                url,
                headers=headers,
                allow_redirects=False,
                stream=True,
                timeout=self.timeout,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            raise RetryableError(f"transient network error: {sanitize(exc)}") from exc
        except requests.RequestException as exc:
            raise PermanentError(f"request failed: {sanitize(exc)}") from exc

    def request(self, method: str, url: str) -> HTTPResponse:
        method = method.upper()
        want_body = method == "GET"
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        history: list[str] = []
        current = url
        start = time.monotonic()

        for _hop in range(self.max_redirects + 1):
            resp = self._request_with_retries(method, current, headers, want_body)
            status = resp.status_code
            location = resp.headers.get("Location")
            resp_headers = {k: v for k, v in resp.headers.items()}
            if status in _REDIRECT_STATUS and location:
                # Read/close the body of the redirect response before hopping.
                self._read_capped(resp, False)
                history.append(current)
                current = urljoin(current, location)
                continue
            body, truncated = self._read_capped(resp, want_body)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return HTTPResponse(
                url=current,
                status_code=status,
                headers=resp_headers,
                body=body,
                history=history,
                elapsed_ms=elapsed_ms,
                truncated=truncated,
                encoding=resp.encoding,
            )
        raise PermanentError(f"too many redirects (> {self.max_redirects})")

    def _request_with_retries(
        self, method: str, url: str, headers: dict[str, str], want_body: bool
    ) -> requests.Response:
        attempt = 0
        while True:
            try:
                resp = self._single_request(method, url, headers, want_body)
            except RetryableError:
                if attempt >= self.retries:
                    raise
                self._backoff(attempt)
                attempt += 1
                continue
            if resp.status_code in _RETRYABLE_STATUS and attempt < self.retries:
                self._read_capped(resp, False)
                self._backoff(attempt)
                attempt += 1
                continue
            return resp

    def _backoff(self, attempt: int) -> None:
        time.sleep(self.backoff_factor * (2 ** attempt))

    # -- convenience -----------------------------------------------------
    def get(self, url: str) -> HTTPResponse:
        return self.request("GET", url)

    def head(self, url: str) -> HTTPResponse:
        return self.request("HEAD", url)
