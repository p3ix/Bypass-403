from __future__ import annotations

import asyncio
import random
import re
import time
from dataclasses import dataclass, field


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


@dataclass
class AsyncHostThrottle:
    rate_per_second: float = 0.0
    jitter_ms: int = 0
    backoff_ms: int = 1000
    _next_request_at: dict[str, float] = field(default_factory=dict, init=False)
    _backoff_until: dict[str, float] = field(default_factory=dict, init=False)
    _locks: dict[str, asyncio.Lock] = field(default_factory=dict, init=False)

    def _lock_for(self, host_key: str) -> asyncio.Lock:
        lock = self._locks.get(host_key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[host_key] = lock
        return lock

    async def before_request(self, host_key: str) -> None:
        if not host_key:
            host_key = "default"
        async with self._lock_for(host_key):
            now = time.monotonic()
            wait_for = max(
                self._next_request_at.get(host_key, 0.0),
                self._backoff_until.get(host_key, 0.0),
            ) - now
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            if self.jitter_ms > 0:
                await asyncio.sleep(random.uniform(0, self.jitter_ms / 1000))
            if self.rate_per_second > 0:
                self._next_request_at[host_key] = time.monotonic() + (1 / self.rate_per_second)

    async def after_response(self, host_key: str, status_code: int) -> None:
        if status_code not in {429, 503}:
            return
        if not host_key:
            host_key = "default"
        async with self._lock_for(host_key):
            self._backoff_until[host_key] = max(
                self._backoff_until.get(host_key, 0.0),
                time.monotonic() + max(self.backoff_ms, 250) / 1000,
            )


def sanitize_url(url: str) -> str:
    from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
