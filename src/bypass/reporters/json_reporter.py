from __future__ import annotations

import json
from pathlib import Path

from bypass.models import AnalysisResult, BaselineSnapshot, TryResult
from bypass.safety import redact_headers, redact_text, sanitize_url


def export_json(
    output_path: str,
    target_url: str,
    baseline: BaselineSnapshot,
    rows: list[tuple[TryResult, AnalysisResult]],
) -> None:
    data = {
        "target_url": sanitize_url(target_url),
        "baseline": {
            "status_code": baseline.status_code,
            "body_length": baseline.body_length,
            "body_sample": redact_text(baseline.body_sample),
            "body_title": redact_text(baseline.body_title),
            "content_type": baseline.content_type,
            "calibration": baseline.calibration,
            "response_headers": redact_headers(baseline.response_headers),
        },
        "results": [
            {
                "method": r.spec.method,
                "url": sanitize_url(r.spec.url),
                "headers": redact_headers(r.spec.headers),
                "status_code": r.status_code,
                "body_length": r.body_length,
                "final_url": sanitize_url(r.final_url),
                "error": redact_text(r.error or "") or None,
                "target_type": r.spec.target_type,
                "family": r.spec.family,
                "response_headers": redact_headers(r.response_headers),
                "www_authenticate": redact_text(r.response_headers.get("www-authenticate", "")) or None,
                "payloads": {
                    "path": r.spec.path_payload.label if r.spec.path_payload else None,
                    "header": r.spec.header_payload.label if r.spec.header_payload else None,
                    "method": r.spec.method_payload.label if r.spec.method_payload else None,
                    "query": r.spec.query_payload.label if r.spec.query_payload else None,
                    "protocol": r.spec.protocol_payload.label if r.spec.protocol_payload else None,
                    "host": r.spec.host_payload.label if r.spec.host_payload else None,
                    "smuggling": r.spec.smuggling_payload.label if r.spec.smuggling_payload else None,
                },
                "analysis": {
                    "interesting": a.interesting,
                    "confidence": a.confidence,
                    "score": a.score,
                    "reasons": a.reasons,
                },
            }
            for r, a in rows
        ],
    }
    Path(output_path).write_text(json.dumps(data, ensure_ascii=True, indent=2), encoding="utf-8")
