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


def test_analyzer_detects_www_authenticate_shift() -> None:
    baseline = BaselineSnapshot(
        status_code=403,
        body_length=100,
        body_sample="forbidden",
        response_headers={"www-authenticate": ""},
    )
    result = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com", headers={}),
        status_code=401,
        body_length=100,
        final_url="https://example.com",
        response_headers={"www-authenticate": 'Basic realm="admin"'},
    )
    analysis = analyze_result(baseline, result, body_sample="auth required")
    assert analysis.interesting is True
    assert "www_authenticate_changed" in analysis.reasons
    assert "auth_challenge_detected" in analysis.reasons


def test_analyzer_boosts_title_and_location_change() -> None:
    baseline = BaselineSnapshot(
        status_code=403,
        body_length=120,
        body_sample="<html><title>Forbidden</title>denied</html>",
        response_headers={"location": "", "content-type": "text/html"},
        body_title="Forbidden",
        content_type="text/html",
    )
    result = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com/private", headers={}),
        status_code=302,
        body_length=140,
        final_url="https://example.com/login",
        response_headers={"location": "/login", "content-type": "text/html"},
    )
    analysis = analyze_result(baseline, result, body_sample="<html><title>Login</title>redirect</html>")
    assert analysis.interesting is True
    assert "title_changed" in analysis.reasons
    assert "location_changed" in analysis.reasons


def test_analyzer_penalizes_high_similarity_same_status() -> None:
    baseline = BaselineSnapshot(status_code=403, body_length=100, body_sample="forbidden blocked by waf")
    result = TryResult(
        spec=RequestSpec(method="GET", url="https://example.com/admin", headers={}),
        status_code=403,
        body_length=102,
        final_url="https://example.com/admin",
    )
    analysis = analyze_result(baseline, result, body_sample="forbidden blocked by waf")
    assert analysis.interesting is False
    assert "body_similarity_high" in analysis.reasons
