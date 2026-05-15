from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import bypass.engine as engine
import pytest
from bypass.engine import (
    AGGRESSIVE_PROFILE,
    ConnectOverride,
    _apply_smuggling_heuristics,
    _apply_connect_override,
    _detect_stack_profile,
    _host_key,
    _raw_request_bytes,
    _raw_followup_request,
    _raw_sni_for_spec,
    _spec_priority_tuple,
    _stack_family_priority,
    _verification_success,
    _uses_raw_transport,
    _baseline_body_for_method,
    _baseline_key_for_spec,
    _build_specs,
    _dedupe_specs,
    compute_dynamic_length_delta,
    run_probe,
)
from bypass.models import AnalysisResult, BaselineSnapshot, RequestSpec, TryResult


def test_dynamic_length_delta_uses_floor_for_empty() -> None:
    assert compute_dynamic_length_delta([], 70) == 70


def test_dynamic_length_delta_grows_with_spread() -> None:
    delta = compute_dynamic_length_delta([100, 120, 420, 450], 40)
    assert delta > 40


def test_build_specs_includes_all_families() -> None:
    specs = _build_specs(
        "https://admin.example.com/admin",
        methods=["GET"],
        domain_mode=True,
    )
    assert any(s.target_type == "domain" for s in specs)
    assert any(s.family == "auth-challenge" for s in specs)
    assert any(s.path_payload is not None for s in specs)
    assert any(s.header_payload is not None for s in specs)
    assert any(s.method_payload is not None for s in specs)
    assert any(s.protocol_payload is not None for s in specs)
    assert any(s.host_payload is not None for s in specs)
    assert any(s.smuggling_payload is not None for s in specs)


def test_dedupe_specs_removes_equivalent_requests() -> None:
    original = [
        RequestSpec(method="GET", url="https://example.com/admin", headers={"X-Test": "1"}),
        RequestSpec(method="GET", url="https://example.com/admin", headers={"x-test": "1"}),
        RequestSpec(method="POST", url="https://example.com/admin", headers={"X-Test": "1"}),
    ]
    deduped = _dedupe_specs(original)
    assert len(deduped) == 2


def test_baseline_key_tracks_method_protocol_and_family() -> None:
    spec = RequestSpec(
        method="POST",
        url="https://example.com/admin",
        headers={},
        protocol_hint="http2",
        family="auth-challenge",
    )
    assert _baseline_key_for_spec(spec) == ("POST", "http2", "auth-challenge")


def test_baseline_body_for_write_methods_uses_empty_json() -> None:
    assert _baseline_body_for_method("POST") == b"{}"
    assert _baseline_body_for_method("GET") is None


def test_build_specs_respects_combine_limit() -> None:
    specs = _build_specs(
        "https://example.com/admin",
        methods=["GET", "POST"],
        bypass_ips=["127.0.0.1", "10.0.0.1"],
    )
    assert len(specs) <= AGGRESSIVE_PROFILE.combine_limit


def test_detect_stack_profile_cloudflare() -> None:
    profile = _detect_stack_profile(
        server_header="cloudflare",
        content_type="text/html",
        body_sample="Attention Required! | Cloudflare",
    )
    assert profile == "cloudflare"


def test_stack_family_priority_prefers_path_for_iis() -> None:
    priorities = _stack_family_priority("iis")
    assert priorities["path"] < priorities["headers"]


def test_apply_connect_override_rewrites_connection_and_preserves_host() -> None:
    url, headers = _apply_connect_override(
        "https://target.tld/admin",
        {},
        [ConnectOverride("target.tld", 443, "127.0.0.1", 8443)],
    )
    assert url == "https://127.0.0.1:8443/admin"
    assert headers["Host"] == "target.tld"


def test_apply_connect_override_keeps_payload_host_header() -> None:
    url, headers = _apply_connect_override(
        "https://target.tld/admin",
        {"Host": "internal.target.tld"},
        [ConnectOverride("target.tld", 443, "127.0.0.1", 443)],
    )
    assert url == "https://127.0.0.1/admin"
    assert headers["Host"] == "internal.target.tld"


def test_raw_request_bytes_preserves_duplicate_header_lines() -> None:
    spec = RequestSpec(
        method="POST",
        url="https://example.com/admin",
        headers={"Content-Length": "4"},
        raw_header_lines=[
            ("Content-Length", "4"),
            ("Content-Length", "5"),
            ("Transfer-Encoding", "chunked"),
        ],
        body=b"0\r\n\r\n",
    )
    raw = _raw_request_bytes(spec, "example.com")
    assert raw.count(b"Content-Length: ") == 2
    assert b"Transfer-Encoding: chunked\r\n" in raw
    assert raw.endswith(b"\r\n\r\n0\r\n\r\n")


def test_raw_followup_request_uses_same_host() -> None:
    raw = _raw_followup_request("example.com")
    assert raw.startswith(b"GET / HTTP/1.1\r\n")
    assert b"Host: example.com\r\n" in raw
    assert raw.endswith(b"\r\n\r\n")


def test_raw_sni_uses_host_payload_metadata() -> None:
    specs = _build_specs(
        "https://target.example/admin",
        methods=["GET"],
        host_fuzz_values=["internal.example"],
        domain_mode=True,
        max_vhost_payloads=80,
    )
    spec = next(
        s for s in specs
        if s.host_payload is not None and s.host_payload.metadata.get("host") == "internal.example"
    )
    assert _raw_sni_for_spec(spec, "target.example") == "internal.example"
    assert _uses_raw_transport(spec) is True


def test_smuggling_heuristic_requires_evidence() -> None:
    spec = RequestSpec(method="POST", url="https://example.com/admin", headers={})
    spec.smuggling_payload = next(p for _, _, p in engine.smuggling_lite_payloads())
    result = TryResult(spec=spec, status_code=400, body_length=20, final_url=spec.url)
    analysis = AnalysisResult(False, "none", [], score=0)
    _apply_smuggling_heuristics(spec, result, analysis)
    assert analysis.interesting is False


def test_smuggling_heuristic_boosts_reuse_response() -> None:
    spec = RequestSpec(method="POST", url="https://example.com/admin", headers={})
    spec.smuggling_payload = next(
        p for _, _, p in engine.smuggling_lite_payloads()
        if p.metadata.get("reuse_connection")
    )
    result = TryResult(
        spec=spec,
        status_code=200,
        body_length=20,
        final_url=spec.url,
        response_headers={"x-bypass-raw-reuse-response": "1"},
    )
    analysis = AnalysisResult(False, "none", [], score=0)
    _apply_smuggling_heuristics(spec, result, analysis)
    assert analysis.interesting is True
    assert analysis.confidence == "medium"
    assert "smuggling_reuse_response" in analysis.reasons


def test_host_key_includes_default_port() -> None:
    assert _host_key("https://example.com/admin") == "example.com:443"
    assert _host_key("http://example.com:8080/admin") == "example.com:8080"


def test_spec_priority_tuple_uses_stack_family_priority() -> None:
    path_spec = RequestSpec(method="GET", url="https://example.com/a", headers={})
    host_spec = RequestSpec(
        method="GET",
        url="https://example.com/b",
        headers={},
        family="host",
    )
    priorities = _stack_family_priority("cloudflare")
    assert _spec_priority_tuple(host_spec, priorities) < _spec_priority_tuple(path_spec, priorities)


def test_verification_success_requires_reproduced_signal() -> None:
    spec = RequestSpec(method="GET", url="https://example.com/admin", headers={})
    original = TryResult(spec=spec, status_code=200, body_length=1000, final_url=spec.url)
    current = TryResult(spec=spec, status_code=200, body_length=1030, final_url=spec.url)
    fresh_baseline = BaselineSnapshot(
        status_code=403,
        body_length=120,
        calibration={"length_delta": 40},
    )
    ok, reason = _verification_success(
        original,
        current,
        fresh_baseline,
        AnalysisResult(True, "high", ["status_changed"], score=80),
        profile=AGGRESSIVE_PROFILE,
    )
    assert ok is True
    assert reason == "verification_reproduced"


def test_verification_success_rejects_baseline_match() -> None:
    spec = RequestSpec(method="GET", url="https://example.com/admin", headers={})
    original = TryResult(spec=spec, status_code=200, body_length=1000, final_url=spec.url)
    current = TryResult(spec=spec, status_code=403, body_length=120, final_url=spec.url)
    fresh_baseline = BaselineSnapshot(
        status_code=403,
        body_length=120,
        calibration={"length_delta": 40},
    )
    ok, reason = _verification_success(
        original,
        current,
        fresh_baseline,
        AnalysisResult(False, "none", [], score=0),
        profile=AGGRESSIVE_PROFILE,
    )
    assert ok is False
    assert reason == "verification_not_interesting"


def test_run_probe_uses_async_queue_against_local_server(monkeypatch) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/open":
                body = b"open"
                self.send_response(200)
            else:
                body = b"forbidden"
                self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: object) -> None:
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError:
        pytest.skip("sandbox blocks local sockets")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"

    def fake_specs(*_args: object, **_kwargs: object) -> list[RequestSpec]:
        return [
            RequestSpec(method="GET", url=f"{base}/open", headers={}, family="headers"),
            RequestSpec(method="GET", url=f"{base}/closed", headers={}, family="headers"),
        ]

    monkeypatch.setattr(engine, "_build_specs", fake_specs)
    try:
        baseline, rows = run_probe(
            f"{base}/admin",
            concurrency=2,
            calibration_samples=1,
            timeout=2,
            verify_findings=False,
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()

    assert baseline.calibration["queue"] == "async-priority"
    assert baseline.calibration["concurrency"] == 2
    assert len(rows) == 2
    assert any(r.status_code == 200 and a.interesting for r, a in rows)
