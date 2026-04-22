from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def method_payloads() -> list[tuple[str, dict[str, str], Payload]]:
    """
    Devuelve estrategias por método:
    - (method, headers_extra, payload)
    """
    raw: list[tuple[str, dict[str, str], str, str]] = [
        ("GET", {}, "m_get", "GET baseline method"),
        ("HEAD", {}, "m_head", "HEAD method"),
        ("OPTIONS", {}, "m_options", "OPTIONS method"),
        ("POST", {}, "m_post", "POST method"),
        ("PUT", {}, "m_put", "PUT method"),
        ("PATCH", {}, "m_patch", "PATCH method"),
        ("DELETE", {}, "m_delete", "DELETE method"),
        ("PROPFIND", {}, "m_propfind", "PROPFIND method"),
        ("TRACE", {}, "m_trace", "TRACE method"),
        ("get", {}, "m_get_lower", "get lowercase method"),
        ("pOsT", {}, "m_post_mixed_case", "pOsT mixed-case method"),
        ("POST", {"X-HTTP-Method-Override": "GET"}, "m_override_get", "POST + X-HTTP-Method-Override: GET"),
        ("POST", {"X-HTTP-Method-Override": "PUT"}, "m_override_put", "POST + X-HTTP-Method-Override: PUT"),
        ("POST", {"X-Method-Override": "GET"}, "m_x_method_override_get", "POST + X-Method-Override: GET"),
        ("POST", {"X-HTTP-Method": "DELETE"}, "m_x_http_method_delete", "POST + X-HTTP-Method: DELETE"),
    ]
    out: list[tuple[str, dict[str, str], Payload]] = []
    for method, headers, pid, label in raw:
        out.append(
            (
                method,
                headers,
                Payload(
                    id=pid,
                    category=PayloadCategory.METHOD,
                    label=label,
                    metadata={"method": method, "headers": dict(headers)},
                ),
            )
        )
    return out
