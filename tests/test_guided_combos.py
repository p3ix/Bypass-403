from bypass.engine import AGGRESSIVE_PROFILE, _build_specs


def test_guided_combos_are_included_by_default() -> None:
    target = "https://example.com/admin"
    specs = _build_specs(target, methods=["GET"])
    has_combo = any(
        s.path_payload is not None and s.header_payload is not None
        for s in specs
    )
    assert has_combo


def test_build_specs_respects_combine_limit() -> None:
    target = "https://example.com/admin"
    specs = _build_specs(
        target,
        methods=["GET", "POST"],
        bypass_ips=["127.0.0.1", "10.0.0.1"],
    )
    assert len(specs) <= AGGRESSIVE_PROFILE.combine_limit
