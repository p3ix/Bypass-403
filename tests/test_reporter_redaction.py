import json
from pathlib import Path

from bypass.models import AnalysisResult, BaselineSnapshot, RequestSpec, TryResult
from bypass.reporters.csv_reporter import export_csv
from bypass.reporters.json_reporter import export_json


def _sample_row() -> tuple[TryResult, AnalysisResult]:
    result = TryResult(
        spec=RequestSpec(
            method="GET",
            url="https://example.com/admin?token=abc123",
            headers={
                "Authorization": "Bearer secret-token",
                "X-Test": "ok",
            },
        ),
        status_code=200,
        body_length=123,
        final_url="https://example.com/admin?access_token=zzz",
        error="token=hunter2",
        response_headers={
            "www-authenticate": "Bearer realm=secret",
            "set-cookie": "session=abcd",
        },
    )
    analysis = AnalysisResult(True, "high", ["status_changed"], score=80)
    return result, analysis


def test_export_json_redacts_sensitive_fields(tmp_path: Path) -> None:
    fp = tmp_path / "out.json"
    baseline = BaselineSnapshot(
        status_code=403,
        body_length=9,
        body_sample="Bearer topsecret token=123",
        response_headers={"set-cookie": "session=abcd"},
    )
    export_json(str(fp), "https://example.com/admin?api_key=123", baseline, [_sample_row()])
    data = json.loads(fp.read_text(encoding="utf-8"))

    assert "<redacted>" in data["target_url"]
    assert data["baseline"]["response_headers"]["set-cookie"] == "<redacted>"
    assert data["results"][0]["headers"]["Authorization"] == "<redacted>"
    assert "<redacted>" in data["results"][0]["url"]
    assert "<redacted>" in data["results"][0]["final_url"]
    assert "<redacted>" in data["results"][0]["error"]


def test_export_csv_redacts_sensitive_url_and_error(tmp_path: Path) -> None:
    fp = tmp_path / "out.csv"
    export_csv(str(fp), [_sample_row()])
    content = fp.read_text(encoding="utf-8")

    assert "abc123" not in content
    assert "hunter2" not in content
    assert "<redacted>" in content
