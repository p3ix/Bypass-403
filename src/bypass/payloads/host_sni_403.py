from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def host_sni_payloads(
    *,
    canonical_host: str,
    custom_hosts: list[str] | None = None,
) -> list[tuple[dict[str, str], Payload]]:
    hosts = [canonical_host, "localhost", "127.0.0.1", f"{canonical_host}:443", f"{canonical_host}:8443"]
    for h in custom_hosts or []:
        v = h.strip()
        if v and v not in hosts:
            hosts.append(v)
    hosts = hosts[:18]

    out: list[tuple[dict[str, str], Payload]] = []
    for idx, host in enumerate(hosts, start=1):
        candidates: list[tuple[dict[str, str], str, str]] = [
            ({"Host": host}, f"host_main_{idx}", f"Host: {host}"),
            ({"X-Forwarded-Host": host}, f"host_xfh_{idx}", f"X-Forwarded-Host: {host}"),
            ({"X-Host": host}, f"host_xhost_{idx}", f"X-Host: {host}"),
            ({"Forwarded": f"for=127.0.0.1;host={host};proto=https"}, f"host_forwarded_{idx}", f"Forwarded host={host}"),
            ({":authority": host}, f"host_authority_{idx}", f":authority: {host}"),
            ({"host": host}, f"host_lower_{idx}", f"host lowercase: {host}"),
            ({"Host": host, "X-Forwarded-Host": host}, f"host_dual_{idx}", f"Host + X-Forwarded-Host: {host}"),
            ({"Host": f"{host}."}, f"host_trailing_dot_{idx}", f"Host trailing dot: {host}."),
            ({":authority": f"{host}:443"}, f"host_authority_443_{idx}", f":authority: {host}:443"),
            ({"Host": host, ":authority": host}, f"host_host_authority_{idx}", f"Host + :authority: {host}"),
            ({"Host": "localhost", "X-Forwarded-Host": host}, f"host_localhost_xfh_{idx}", f"Host localhost + XFH {host}"),
            ({"Host": host, "X-Original-Host": "localhost"}, f"host_xorig_local_{idx}", f"Host {host} + X-Original-Host localhost"),
        ]
        for hdrs, pid, label in candidates:
            out.append(
                (
                    hdrs,
                    Payload(
                        id=pid,
                        category=PayloadCategory.HOST,
                        label=label,
                        metadata={"host": host},
                    ),
                )
            )
    return out
