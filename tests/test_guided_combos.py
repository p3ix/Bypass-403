from bypass.engine import AGGRESSIVE_PROFILE, SAFE_PROFILE, _build_specs


def test_guided_combos_opt_in_adds_more_specs() -> None:
    target = "https://example.com/admin"
    base_specs = _build_specs(
        target,
        mode="both",
        combine=False,
        methods=["GET"],
        profile=SAFE_PROFILE,
        bypass_ips=None,
        guided_combos=False,
    )
    combo_specs = _build_specs(
        target,
        mode="both",
        combine=False,
        methods=["GET"],
        profile=SAFE_PROFILE,
        bypass_ips=None,
        guided_combos=True,
    )
    assert len(combo_specs) > len(base_specs)


def test_guided_combos_respects_profile_limits() -> None:
    target = "https://example.com/admin"
    specs = _build_specs(
        target,
        mode="both",
        combine=True,
        methods=["GET", "POST"],
        profile=AGGRESSIVE_PROFILE,
        bypass_ips=["127.0.0.1", "10.0.0.1"],
        guided_combos=True,
    )
    assert len(specs) <= AGGRESSIVE_PROFILE.combine_limit
