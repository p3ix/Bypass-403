from __future__ import annotations

import httpx


def make_client(
    timeout: float,
    verify: bool,
    follow_redirects: bool,
    http2: bool = False,
    proxy: str | None = None,
) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        http2=http2,
        proxy=proxy,
    )


def make_async_client(
    timeout: float,
    verify: bool,
    follow_redirects: bool,
    http2: bool = False,
    proxy: str | None = None,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        http2=http2,
        proxy=proxy,
    )
