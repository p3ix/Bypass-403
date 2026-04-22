from __future__ import annotations

import csv
from pathlib import Path

from bypass.models import AnalysisResult, TryResult


def export_csv(output_path: str, rows: list[tuple[TryResult, AnalysisResult]]) -> None:
    path = Path(output_path)
    with path.open("w", encoding="utf-8", newline="") as fp:
        writer = csv.writer(fp)
        writer.writerow(
            [
                "method",
                "url",
                "status_code",
                "body_length",
                "final_url",
                "error",
                "path_payload",
                "header_payload",
                "method_payload",
                "query_payload",
                "protocol_payload",
                "host_payload",
                "smuggling_payload",
                "interesting",
                "confidence",
                "score",
                "reasons",
            ]
        )
        for r, a in rows:
            writer.writerow(
                [
                    r.spec.method,
                    r.spec.url,
                    r.status_code,
                    r.body_length,
                    r.final_url,
                    r.error or "",
                    r.spec.path_payload.label if r.spec.path_payload else "",
                    r.spec.header_payload.label if r.spec.header_payload else "",
                    r.spec.method_payload.label if r.spec.method_payload else "",
                    r.spec.query_payload.label if r.spec.query_payload else "",
                    r.spec.protocol_payload.label if r.spec.protocol_payload else "",
                    r.spec.host_payload.label if r.spec.host_payload else "",
                    r.spec.smuggling_payload.label if r.spec.smuggling_payload else "",
                    a.interesting,
                    a.confidence,
                    a.score,
                    "|".join(a.reasons),
                ]
            )
