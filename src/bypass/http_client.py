from __future__ import annotations

import httpx


def make_client(
    timeout: float,
    verify: bool,
    follow_redirects: bool,
    http2: bool = False,
) -> httpx.Client:
    return httpx.Client(
        timeout=timeout,
        verify=verify,
        follow_redirects=follow_redirects,
        http2=http2,
    )
