from bypass.payloads.smuggling_lite import smuggling_lite_payloads


def test_smuggling_lite_includes_cl_te_conflicts() -> None:
    rows = smuggling_lite_payloads()
    ids = [p.id for _, _, p in rows]
    headers = [h for h, _, _ in rows]
    assert any("cl_te" in i for i in ids)
    assert any("Content-Length" in h and "Transfer-Encoding" in h for h in headers)
