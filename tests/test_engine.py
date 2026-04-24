from bypass.engine import (
    SAFE_PROFILE,
    _baseline_body_for_method,
    _baseline_key_for_spec,
    _build_specs,
    _dedupe_specs,
    compute_dynamic_length_delta,
)
from bypass.models import RequestSpec


def test_dynamic_length_delta_uses_floor_for_empty() -> None:
    assert compute_dynamic_length_delta([], 70) == 70


def test_dynamic_length_delta_grows_with_spread() -> None:
    delta = compute_dynamic_length_delta([100, 120, 420, 450], 40)
    assert delta > 40


def test_build_specs_domain_mode_adds_auth_family() -> None:
    specs = _build_specs(
        "https://admin.example.com",
        mode="all",
        combine=False,
        methods=["GET"],
        profile=SAFE_PROFILE,
        domain_mode=True,
        auth_challenges=True,
        guided_combos=False,
    )
    assert any(s.target_type == "domain" for s in specs)
    assert any(s.family == "auth-challenge" for s in specs)


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
