from bypass.engine import SAFE_PROFILE, _build_specs, compute_dynamic_length_delta


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
