"""Exception hierarchy and error classification for BLHawk.

Errors are split into *retryable* (transient, worth retrying with backoff)
and *permanent* (retrying will not help) so the scan engine can make sound
decisions instead of blindly retrying everything.
"""
from __future__ import annotations


class BLHawkError(Exception):
    """Base class for all BLHawk errors."""


class ConfigError(BLHawkError):
    """Raised when user configuration or input is invalid."""


class ScopeError(BLHawkError):
    """Raised for scope parsing / validation problems."""


class ProviderError(BLHawkError):
    """Raised when a provider cannot process a target."""


class SSRFBlockedError(BLHawkError):
    """Raised when a request target resolves to a blocked address."""


class RetryableError(BLHawkError):
    """Transient error; the operation may succeed if retried."""


class PermanentError(BLHawkError):
    """Non-transient error; retrying will not help."""


class ResponseTooLargeError(PermanentError):
    """Raised when a response exceeds the configured size limit."""
