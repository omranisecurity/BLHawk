"""Code-hosting providers (GitHub, GitLab).

Deleted user/org/repo handles on code hosts are classic dangling-reference
sources: a re-registered handle can hijack references in docs, CI configs,
package manifests and redirects.
"""
from __future__ import annotations

from ..core.http_client import HTTPResponse
from ..core.models import Reclaimability, Severity
from .base import (
    STATE_BLOCKED,
    STATE_MISSING,
    STATE_PRESENT,
    STATE_UNKNOWN,
    InterpretResult,
    Provider,
    ProviderContext,
    StatusProvider,
)
from .registry import register

_RESERVED = {
    "about", "site", "features", "security", "enterprise", "pricing", "login",
    "join", "sponsors", "settings", "marketplace", "explore", "topics",
    "collections", "trending", "events", "help", "contact",
}


@register
class GitHubProvider(StatusProvider):
    name = "github"
    hosts = ("github.com",)
    resource_type = "user/org/repository"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.HIGH

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        identifier = self.extract_identifier(ctx.target.url)
        if identifier and identifier.lower() in _RESERVED:
            return InterpretResult(
                state=STATE_PRESENT,
                reclaimability=Reclaimability.IMPOSSIBLE,
                signals=[f"reserved-namespace={identifier}"],
                notes=["GitHub-owned/reserved path; not reclaimable"],
            )
        return super().interpret(resp, ctx)


@register
class BitbucketProvider(StatusProvider):
    name = "bitbucket"
    hosts = ("bitbucket.org",)
    resource_type = "user/workspace/repository"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.HIGH


@register
class GitLabProvider(Provider):
    name = "gitlab"
    hosts = ("gitlab.com",)
    resource_type = "user/group/project"
    default_reclaimability = Reclaimability.POSSIBLE
    default_severity = Severity.HIGH

    def interpret(self, resp: HTTPResponse, ctx: ProviderContext) -> InterpretResult:
        status = resp.status_code
        # GitLab redirects both missing *and* private resources to sign-in, so a
        # sign-in redirect is ambiguous and must NOT be reported as missing. The
        # HTTP client follows redirects, so inspect the final URL and the chain.
        landed_on_signin = "users/sign_in" in resp.url or any(
            "users/sign_in" in hop for hop in resp.history
        )
        if landed_on_signin:
            return InterpretResult(
                state=STATE_UNKNOWN,
                signals=["redirect->users/sign_in"],
                notes=["sign-in redirect is ambiguous: could be private or missing"],
            )
        if status == 404:
            return InterpretResult(state=STATE_MISSING, signals=["http-status=404"])
        if status == 200:
            return InterpretResult(state=STATE_PRESENT, signals=["http-status=200"])
        if status in (401, 403):
            return InterpretResult(state=STATE_BLOCKED, signals=[f"http-status={status}"])
        return InterpretResult(state=STATE_UNKNOWN, signals=[f"http-status={status}"])
