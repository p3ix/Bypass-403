from bypass.engine import SAFE_PROFILE, _build_specs, _fetch_http10


def test_protocol_mode_generates_http10_http11_http2() -> None:
    specs = _build_specs(
        "https://example.com/admin",
        mode="protocol",
        combine=False,
        methods=["GET"],
        profile=SAFE_PROFILE,
        bypass_ips=None,
        guided_combos=False,
    )
    hints = {s.protocol_hint for s in specs}
    assert "http1_0" in hints
    assert "http1_1" in hints
    assert "http2" in hints


def test_fetch_http10_rejects_invalid_url() -> None:
    st, ln, _, _, err = _fetch_http10("GET", "not-a-url", {}, timeout=1.0, verify=True)
    assert st == -1
    assert ln == 0
    assert err is not None


def test_all_mode_includes_both_methods_and_protocol_families() -> None:
    specs = _build_specs(
        "https://example.com/admin",
        mode="all",
        combine=False,
        methods=["GET"],
        profile=SAFE_PROFILE,
        bypass_ips=None,
        guided_combos=False,
    )
    assert any(s.path_payload is not None or s.header_payload is not None or s.query_payload is not None for s in specs)
    assert any(s.method_payload is not None for s in specs)
    assert any(s.protocol_payload is not None for s in specs)
    assert any(s.host_payload is not None for s in specs)
    assert any(s.smuggling_payload is not None for s in specs)
