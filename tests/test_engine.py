from bypass.engine import compute_dynamic_length_delta


def test_dynamic_length_delta_uses_floor_for_empty() -> None:
    assert compute_dynamic_length_delta([], 70) == 70


def test_dynamic_length_delta_grows_with_spread() -> None:
    delta = compute_dynamic_length_delta([100, 120, 420, 450], 40)
    assert delta > 40
