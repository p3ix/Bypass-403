from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def protocol_payloads() -> list[tuple[str, Payload]]:
    return [
        (
            "http1_0",
            Payload(
                id="proto_http1_0",
                category=PayloadCategory.PROTOCOL,
                label="HTTP/1.0 transport",
            ),
        ),
        (
            "http1_1",
            Payload(
                id="proto_http1_1",
                category=PayloadCategory.PROTOCOL,
                label="HTTP/1.1 transport",
            ),
        ),
        (
            "http2",
            Payload(
                id="proto_http2",
                category=PayloadCategory.PROTOCOL,
                label="HTTP/2 transport",
            ),
        ),
    ]
