from __future__ import annotations

import httpx


def make_client(
    timeout: float,
    verify: bool,
    follow_redirects: bool,
    proxy: str | None = None,
    http2: bool = False,
) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        proxy=proxy,
        http2=http2,
    )
