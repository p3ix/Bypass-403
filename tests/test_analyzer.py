from bypass.analyzers.response_diff import analyze_result
from bypass.models import BaselineSnapshot, RequestSpec, TryResult


def test_analyzer_marks_high_confidence_on_status_and_length_change() -> None:
    baseline = BaselineSnapshot(status_code=403, body_length=100, body_sample="forbidden")
    result = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com/admin", headers={}),
        status_code=200,
        body_length=280,
        final_url="https://example.com/admin",
    )
    analysis = analyze_result(baseline, result, body_sample="welcome")
    assert analysis.interesting is True
    assert analysis.confidence == "high"
    assert analysis.score >= 70
    assert "status_changed" in analysis.reasons


def test_analyzer_marks_not_interesting_when_identical() -> None:
    baseline = BaselineSnapshot(status_code=403, body_length=100, body_sample="forbidden")
    result = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com/admin", headers={}),
        status_code=403,
        body_length=100,
        final_url="https://example.com/admin",
    )
    analysis = analyze_result(baseline, result, body_sample="forbidden")
    assert analysis.interesting is False
    assert analysis.score == 0


def test_analyzer_penalizes_soft403_marker_without_hard_changes() -> None:
    baseline = BaselineSnapshot(status_code=403, body_length=120, body_sample="forbidden")
    result = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com/admin", headers={}),
        status_code=403,
        body_length=120,
        final_url="https://example.com/admin",
    )
    analysis = analyze_result(baseline, result, body_sample="access denied by waf")
    assert analysis.interesting is False
    assert analysis.score == 0
