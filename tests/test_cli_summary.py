from bypass.cli import _header_diff_text, _rank_interesting_rows, _summarize_rows, tryresult_to_curl
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
        b_status, b_len, [r1, r2],
        top_limit=5, top_min_score=0,
    )
    assert ranked[0][0].status_code == 200


def test_rank_interesting_rows_prioritizes_auth_and_redirect_signals() -> None:
    b_status = 403
    b_len = 100
    r_plain = _row(200, 110)
    r_plain[1].score = 60
    r_plain[1].reasons = ["status_changed"]
    r_auth = _row(302, 108)
    r_auth[1].score = 45
    r_auth[1].reasons = [
        "status_improved_to_3xx",
        "location_changed",
        "www_authenticate_changed",
        "auth_challenge_detected",
    ]
    ranked = _rank_interesting_rows(
        b_status, b_len, [r_plain, r_auth],
        top_limit=5, top_min_score=0,
    )
    assert ranked[0][0].status_code == 302


def test_tryresult_to_curl_includes_url_and_header() -> None:
    spec = RequestSpec(
        method="GET",
        url="https://example.com/admin%2f",
        headers={"X-Test": "1"},
    )
    r = TryResult(spec=spec, status_code=200, body_length=10, final_url=spec.url)
    line = tryresult_to_curl(r, insecure=True, follow_redirects=True, max_time=5.0)
    assert "curl" in line
    assert "-k" in line
    assert "-L" in line
    assert "--max-time" in line
    assert "5" in line
    assert "X-Test" in line
    assert "example.com" in line
    assert "-H 'X-Test: 1'" in line


def test_tryresult_to_curl_body_uses_base64_pipe() -> None:
    spec = RequestSpec(
        method="POST",
        url="https://example.com/x",
        headers={"C": "3", "A": "1"},
        body=b"ab",
    )
    r = TryResult(spec=spec, status_code=200, body_length=2, final_url=spec.url)
    line = tryresult_to_curl(r)
    assert "printf" in line
    assert "base64" in line
    assert "--data-binary" in line
    assert "ab" not in line


def test_tryresult_to_curl_http1_0_hint() -> None:
    spec = RequestSpec(
        method="GET",
        url="https://example.com/",
        headers={},
        protocol_hint="http1_0",
    )
    r = TryResult(spec=spec, status_code=200, body_length=0, final_url=spec.url)
    line = tryresult_to_curl(r)
    assert "--http1.0" in line


def test_header_diff_text_reports_add_change_remove() -> None:
    base = {"A": "1", "B": "2"}
    cur = {"A": "9", "C": "3"}
    out = _header_diff_text(cur, base, limit=10)
    assert "~A=9" in out
    assert "-B" in out
    assert "+C=3" in out
