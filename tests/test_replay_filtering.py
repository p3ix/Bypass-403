import json
from pathlib import Path

from typer.testing import CliRunner

from bypass.cli import app

runner = CliRunner()


def test_replay_filters_by_confidence(tmp_path: Path) -> None:
    sample = {
        "results": [
            {
                "method": "GET",
                "url": "https://example.com/admin",
                "headers": {},
                "analysis": {"confidence": "low", "interesting": True, "score": 40, "reasons": []},
            },
            {
                "method": "GET",
                "url": "https://example.com/admin",
                "headers": {},
                "analysis": {"confidence": "high", "interesting": True, "score": 90, "reasons": []},
            },
        ]
    }
    fp = tmp_path / "sample.json"
    fp.write_text(json.dumps(sample), encoding="utf-8")
    result = runner.invoke(
        app,
        ["replay", str(fp), "--min-confidence", "high", "--max-targets", "1"],
    )
    assert result.exit_code == 0
    assert "1 findings" in result.stdout
