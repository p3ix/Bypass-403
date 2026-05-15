from typer.testing import CliRunner

from bypass.cli import _build_connect_overrides, _merge_headers, _parse_raw_request, app

runner = CliRunner()


def test_list_command_works() -> None:
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "Path mutations" in result.stdout


def test_probe_help_shows_options() -> None:
    result = runner.invoke(app, ["probe", "--help"])
    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--rate" in result.stdout
    assert "--concurrency" in result.stdout
    assert "--verify" in result.stdout
    assert "--no-verify" in result.stdout
    assert "--verify-attempts" in result.stdout
    assert "--verify-limit" in result.stdout
    assert "--top" in result.stdout
    assert "-k" in result.stdout
    assert "--method" in result.stdout
    assert "--header" in result.stdout
    assert "--cookie" in result.stdout
    assert "--proxy" in result.stdout
    assert "--raw-request" in result.stdout
    assert "--resolve" in result.stdout
    assert "--connect-to" in result.stdout
    assert "--user-agent" in result.stdout
    assert "--body" in result.stdout
    assert "--content-type" in result.stdout
    assert "--host" in result.stdout


def test_batch_help_works() -> None:
    result = runner.invoke(app, ["batch", "--help"])
    assert result.exit_code == 0
    assert "--out-dir" in result.stdout


def test_replay_help_works() -> None:
    result = runner.invoke(app, ["replay", "--help"])
    assert result.exit_code == 0
    assert "--min-confidence" in result.stdout
    assert "--max-targets" in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "bypass" in result.stdout.lower() or "usage" in result.stdout.lower()


def test_merge_headers_parses_repeated_header_options() -> None:
    headers = _merge_headers(["X-Test: one", "Authorization: Bearer abc"])
    assert headers == {"X-Test": "one", "Authorization": "Bearer abc"}


def test_raw_request_uses_host_and_body(tmp_path) -> None:
    req = tmp_path / "request.txt"
    req.write_bytes(
        b"POST /admin?debug=1 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b"{\"x\":1}"
    )
    url, method, headers, body = _parse_raw_request(str(req), None)
    assert url == "https://example.com/admin?debug=1"
    assert method == "POST"
    assert headers["Content-Type"] == "application/json"
    assert body == b"{\"x\":1}"


def test_connect_override_parsing_supports_resolve_and_connect_to() -> None:
    rows = _build_connect_overrides(
        ["target.tld:443:127.0.0.1"],
        ["api.target.tld:8443:10.0.0.5:9443"],
    )
    assert rows[0].host == "target.tld"
    assert rows[0].connect_host == "127.0.0.1"
    assert rows[0].connect_port == 443
    assert rows[1].host == "api.target.tld"
    assert rows[1].port == 8443
    assert rows[1].connect_port == 9443
