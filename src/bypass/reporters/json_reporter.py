from __future__ import annotations

import json
from pathlib import Path

from bypass.models import AnalysisResult, BaselineSnapshot, TryResult


def export_json(
    output_path: str,
    target_url: str,
    baseline: BaselineSnapshot,
    rows: list[tuple[TryResult, AnalysisResult]],
) -> None:
    data = {
        "target_url": target_url,
        "baseline": {
            "status_code": baseline.status_code,
            "body_length": baseline.body_length,
            "body_sample": baseline.body_sample,
            "calibration": baseline.calibration,
        },
        "results": [
            {
                "method": r.spec.method,
                "url": r.spec.url,
                "headers": dict(r.spec.headers),
                "status_code": r.status_code,
                "body_length": r.body_length,
                "final_url": r.final_url,
                "error": r.error,
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
