from bypass.payloads.host_sni_403 import host_sni_payloads


def test_host_sni_contains_authority_and_forwarded_host() -> None:
    rows = host_sni_payloads(canonical_host="example.com", custom_hosts=["internal.example.com"])
    labels = [p.label for _, p in rows]
    headers = [h for h, _ in rows]
    assert any(":authority" in x for x in labels)
    assert any("Forwarded host=" in x for x in labels)
    assert any(":authority" in h for h in headers)
