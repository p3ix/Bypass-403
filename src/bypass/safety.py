from __future__ import annotations

import ipaddress
import random
import re
import time
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
}
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "bearer",
    "code",
    "jwt",
    "key",
    "password",
    "refresh_token",
    "session",
    "sig",
    "signature",
    "state",
    "token",
}
REDACTED = "<redacted>"


@dataclass(frozen=True)
class ScopePolicy:
    allowed_hosts: tuple[str, ...] = ()
    allowed_suffixes: tuple[str, ...] = ()
    deny_private_ip: bool = True
    allow_cross_host_redirects: bool = False


@dataclass
class RequestThrottle:
    rate_per_second: float = 0.0
    jitter_ms: int = 0
    backoff_ms: int = 1000
    _next_request_at: float = field(default=0.0, init=False)
    _backoff_until: float = field(default=0.0, init=False)

    def before_request(self) -> None:
        now = time.monotonic()
        wait_for = max(self._next_request_at, self._backoff_until) - now
        if wait_for > 0:
            time.sleep(wait_for)
        if self.jitter_ms > 0:
            time.sleep(random.uniform(0, self.jitter_ms / 1000))
        if self.rate_per_second > 0:
            self._next_request_at = time.monotonic() + (1 / self.rate_per_second)

    def after_response(self, status_code: int) -> None:
        if status_code in {429, 503}:
            self._backoff_until = max(
                self._backoff_until,
                time.monotonic() + max(self.backoff_ms, 250) / 1000,
            )


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _is_literal_private_host(host: str) -> bool:
    normalized = _normalize_host(host)
    if not normalized:
        return False
    if normalized == "localhost" or normalized.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_url_in_scope(url: str, policy: ScopePolicy) -> tuple[bool, str | None]:
    parsed = urlsplit(url)
    host = _normalize_host(parsed.hostname or "")
    if not host:
        return False, "host_missing"
    if policy.deny_private_ip and _is_literal_private_host(host):
        return False, "private_host_blocked"
    if policy.allowed_hosts:
        allowed = {_normalize_host(x) for x in policy.allowed_hosts if x.strip()}
        if host in allowed:
            return True, None
    if policy.allowed_suffixes:
        suffixes = tuple(_normalize_host(x).lstrip(".") for x in policy.allowed_suffixes if x.strip())
        for suffix in suffixes:
            if host == suffix or host.endswith(f".{suffix}"):
                return True, None
    if policy.allowed_hosts or policy.allowed_suffixes:
        return False, "scope_mismatch"
    return True, None


def is_redirect_target_allowed(from_url: str, to_url: str, policy: ScopePolicy) -> tuple[bool, str | None]:
    allowed, reason = is_url_in_scope(to_url, policy)
    if not allowed:
        return False, reason
    if policy.allow_cross_host_redirects:
        return True, None
    from_host = _normalize_host(urlsplit(from_url).hostname or "")
    to_host = _normalize_host(urlsplit(to_url).hostname or "")
    if from_host != to_host:
        return False, "cross_host_redirect_blocked"
    return True, None


def sanitize_url(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.query:
        return url
    items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS:
            items.append((key, REDACTED))
        else:
            items.append((key, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(items, doseq=True), parsed.fragment))


def redact_headers(headers: dict[str, str] | None) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for key, value in (headers or {}).items():
        redacted[key] = REDACTED if key.lower() in SENSITIVE_HEADER_NAMES else value
    return redacted


def redact_text(value: str) -> str:
    text = value
    text = re.sub(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+", r"\1 " + REDACTED, text)
    text = re.sub(r"(?i)\b(token|secret|session|password)=([^&\s]+)", r"\1=" + REDACTED, text)
    return text
