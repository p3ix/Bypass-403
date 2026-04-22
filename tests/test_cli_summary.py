from bypass.cli import _rank_interesting_rows, _summarize_rows
from bypass.models import AnalysisResult, RequestSpec, TryResult


def _row(status: int, size: int) -> tuple[TryResult, AnalysisResult]:
    tr = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com/admin", headers={}),
        status_code=status,
        body_length=size,
        final_url="https://example.com/admin",
    )
    ar = AnalysisResult(interesting=True, confidence="low", reasons=[], score=10)
    return tr, ar


def test_summarize_rows_groups_status_and_lengths() -> None:
    rows = [_row(403, 100), _row(403, 100), _row(403, 120), _row(200, 900), _row(-1, 0)]
    grouped = _summarize_rows(rows)
    assert grouped[403]["normal_bytes"] == 100
    assert grouped[403]["normal_count"] == 2
    assert grouped[403]["different_count"] == 1
    assert grouped[403]["different_values"] == [120]
    assert grouped[200]["normal_bytes"] == 900
    assert grouped[-1]["normal_bytes"] == 0


def test_rank_interesting_rows_prioritizes_status_and_delta() -> None:
    b_status = 403
    b_len = 100
    r1 = _row(403, 140)
    r1[1].score = 40
    r2 = _row(200, 110)
    r2[1].score = 40
    ranked = _rank_interesting_rows(
        b_status,
        b_len,
        [r1, r2],
        top_limit=5,
        top_min_score=0,
    )
    assert ranked[0][0].status_code == 200
