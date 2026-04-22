from bypass.payloads.host_sni_403 import host_sni_payloads
from bypass.payloads.headers_403 import default_header_sets
from bypass.payloads.methods_403 import method_payloads
from bypass.payloads.paths_403 import path_mutations
from bypass.payloads.protocols_403 import protocol_payloads
from bypass.payloads.query_403 import query_mutations
from bypass.payloads.smuggling_lite import smuggling_lite_payloads


def test_paths_payloads_have_baseline_and_dedup() -> None:
    rows = path_mutations("/admin/panel")
    ids = [payload.id for _, payload in rows]
    paths = [path for path, _ in rows]
    assert "path_baseline" in ids
    assert len(paths) == len(set(paths))
    assert len(rows) >= 20


def test_headers_payloads_count() -> None:
    rows = default_header_sets("/admin", "example.com", "https")
    assert len(rows) >= 50


def test_methods_payloads_override_and_trace() -> None:
    rows = method_payloads()
    labels = [payload.label for _, _, payload in rows]
    methods = [method for method, _, _ in rows]
    assert any("TRACE" in label for label in labels)
    assert any("Override" in label or "override" in label for label in labels)
    assert any(m != m.upper() for m in methods)


def test_query_payloads_generated() -> None:
    rows = query_mutations("https://example.com/admin")
    assert len(rows) >= 7


def test_protocol_payloads_have_http10_http11_and_http2() -> None:
    rows = protocol_payloads()
    ids = [p.id for _, p in rows]
    assert "proto_http1_0" in ids
    assert "proto_http1_1" in ids
    assert "proto_http2" in ids


def test_host_sni_payloads_generated() -> None:
    rows = host_sni_payloads(canonical_host="example.com", custom_hosts=["api.example.com"])
    assert len(rows) >= 10


def test_smuggling_payloads_generated() -> None:
    rows = smuggling_lite_payloads()
    assert len(rows) >= 4
