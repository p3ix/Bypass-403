from __future__ import annotations

import base64
import json
import shlex
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from bypass import __version__
from bypass.engine import run_probe
from bypass.models import AnalysisResult, TryResult
from bypass.reporters.csv_reporter import export_csv
from bypass.reporters.json_reporter import export_json
from bypass.safety import sanitize_url

app = typer.Typer(
    name="bypass",
    help="403/401 bypass toolkit for bug bounty.",
    no_args_is_help=True,
)
console = Console()


def _status_bucket(status_code: int) -> str:
    if status_code < 0:
        return "err"
    if 200 <= status_code < 300:
        return "2xx"
    if 300 <= status_code < 400:
        return "3xx"
    if 400 <= status_code < 500:
        return "4xx"
    if 500 <= status_code < 600:
        return "5xx"
    return "other"


def _payload_label(r: TryResult) -> str:
    labels = [
        r.spec.path_payload.label if r.spec.path_payload else "—",
        r.spec.header_payload.label if r.spec.header_payload else "—",
        r.spec.method_payload.label if r.spec.method_payload else "—",
        r.spec.query_payload.label if r.spec.query_payload else "—",
        r.spec.protocol_payload.label if r.spec.protocol_payload else "—",
        r.spec.host_payload.label if r.spec.host_payload else "—",
        r.spec.smuggling_payload.label if r.spec.smuggling_payload else "—",
    ]
    return " + ".join(x for x in labels if x != "—") or "—"


def _http_code_style(code: int) -> str:
    if code < 0:
        return "red"
    if 200 <= code < 300:
        return "bold green"
    if 300 <= code < 400:
        return "bold cyan"
    if 400 <= code < 500:
        return "bold yellow"
    if 500 <= code < 600:
        return "bold red"
    return "white"


def _confidence_badge_style(conf: str) -> str:
    if conf == "high":
        return "bold green"
    if conf == "medium":
        return "bold yellow"
    if conf == "low":
        return "cyan"
    return "dim"


def _top_index_style(i: int) -> str:
    if i == 0:
        return "bold #FFD700"
    if i == 1:
        return "bold #C0C0C0"
    if i == 2:
        return "bold #CD7F32"
    return "bold white"


def _delta_style(delta: int) -> str:
    if delta >= 5000:
        return "bold red"
    if delta >= 500:
        return "bold yellow"
    if delta >= 50:
        return "white"
    return "dim"


def tryresult_to_curl(
    r: TryResult,
    *,
    insecure: bool = False,
    follow_redirects: bool = False,
    max_time: float = 0.0,
) -> str:
    s = r.spec
    curl_args: list[str] = ["curl", "-sS"]
    if insecure:
        curl_args.append("-k")
    if follow_redirects:
        curl_args.append("-L")
    if max_time > 0:
        mt = int(max_time) if max_time == int(max_time) else max_time
        curl_args.extend(["--max-time", str(mt)])

    if s.protocol_hint == "http1_0":
        curl_args.append("--http1.0")
    elif s.protocol_hint == "http2":
        curl_args.append("--http2")

    m = s.method.upper()
    if s.body or m not in ("GET", "HEAD"):
        curl_args.extend(["-X", m])
    elif m == "HEAD":
        curl_args.extend(["-X", "HEAD"])

    for key in sorted(s.headers, key=str.lower):
        val = s.headers[key]
        curl_args.extend(["-H", f"{key}: {val}"])

    if s.body:
        b64 = base64.b64encode(s.body).decode("ascii")
        body_curl = list(curl_args)
        body_curl.extend(["--data-binary", "@-"])
        body_curl.append(s.url)
        return f"printf '%s' {shlex.quote(b64)} | base64 -d | {shlex.join(body_curl)}"

    curl_args.append(s.url)
    return shlex.join(curl_args)


def _text_pair_status(b: int, c: int) -> Text:
    t = Text()
    t.append(f"{b}", style="dim")
    t.append("→", style="white")
    t.append(f"{c}", style=_http_code_style(c))
    return t


def _text_pair_bytes(baseline_len: int, cur_len: int) -> Text:
    t = Text()
    t.append(f"{baseline_len}", style="dim")
    t.append("→", style="white")
    t.append(
        f"{cur_len}",
        style="bold yellow" if cur_len != baseline_len else "white",
    )
    return t


def _text_conf_score(a: AnalysisResult) -> Text:
    t = Text()
    t.append(a.confidence, style=_confidence_badge_style(a.confidence))
    t.append("/", style="dim")
    t.append(str(a.score), style="bold" if a.score >= 50 else "dim")
    return t


def _header_diff_text(
    current_headers: dict[str, str],
    baseline_headers: dict[str, str] | None = None,
    *,
    limit: int = 4,
) -> str:
    base = baseline_headers or {}
    keys = sorted(set(base) | set(current_headers), key=str.lower)
    changes: list[str] = []
    for k in keys:
        b = base.get(k)
        c = current_headers.get(k)
        if b is None and c is not None:
            changes.append(f"+{k}={c}")
        elif b is not None and c is None:
            changes.append(f"-{k}")
        elif b != c and c is not None:
            changes.append(f"~{k}={c}")
    if not changes:
        return "sin cambios"
    shown = changes[: max(0, limit)]
    if len(changes) > len(shown):
        shown.append(f"...(+{len(changes) - len(shown)} más)")
    return " | ".join(shown)


def _status_priority(baseline_status: int, status_code: int) -> int:
    if status_code < 0:
        return 0
    if status_code in (200, 201, 202, 204):
        return 120
    if 300 <= status_code < 400:
        return 90
    if baseline_status != status_code:
        return 60
    return 0


def _rank_interesting_rows(
    baseline_status: int,
    baseline_len: int,
    rows: list[tuple[TryResult, AnalysisResult]],
    *,
    top_limit: int,
    top_min_score: int,
) -> list[tuple[TryResult, AnalysisResult, int, int]]:
    ranked: list[tuple[TryResult, AnalysisResult, int, int]] = []
    for r, a in rows:
        if r.error:
            continue
        if a.score < top_min_score:
            continue
        delta = abs(r.body_length - baseline_len)
        rank = a.score + _status_priority(baseline_status, r.status_code) + min(delta // 10, 60)
        ranked.append((r, a, delta, rank))
    ranked.sort(key=lambda x: (x[3], x[1].score, x[2]), reverse=True)
    return ranked[: max(0, top_limit)]


def _print_top_bypasses(
    baseline_status: int,
    baseline_len: int,
    rows: list[tuple[TryResult, AnalysisResult]],
    *,
    top_limit: int,
    top_min_score: int,
    insecure: bool,
    follow_redirects: bool,
    timeout: float,
    baseline_request_headers: dict[str, str] | None = None,
    baseline_response_headers: dict[str, str] | None = None,
) -> None:
    top = _rank_interesting_rows(
        baseline_status, baseline_len, rows,
        top_limit=top_limit, top_min_score=top_min_score,
    )
    if not top:
        return
    table = Table(
        title="Top bypasses",
        title_style="bold yellow",
        show_header=True,
        header_style="bold magenta",
        border_style="dim",
    )
    table.add_column("#", justify="right", style="dim")
    table.add_column("Score", justify="right")
    table.add_column("Status", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Delta", justify="right")
    table.add_column("Family", max_width=14)
    table.add_column("Payload", max_width=42, overflow="ellipsis")
    table.add_column("Conf/Score", justify="right")
    for idx, (r, a, delta, comp_rank) in enumerate(top):
        table.add_row(
            Text(str(idx + 1), style=_top_index_style(idx)),
            Text(str(comp_rank), style=_top_index_style(idx)),
            _text_pair_status(baseline_status, r.status_code),
            _text_pair_bytes(baseline_len, r.body_length),
            Text(str(delta), style=_delta_style(delta)),
            Text(r.spec.family or "general", style="cyan"),
            Text(_payload_label(r), style="white"),
            _text_conf_score(a),
        )
    console.print(table)
    console.print()
    console.print("[bold green]Curl para reproducir:[/]")
    for idx, (r, a, delta, comp_rank) in enumerate(top):
        cmd = tryresult_to_curl(r, insecure=insecure, follow_redirects=follow_redirects, max_time=timeout)
        smug = r.spec.smuggling_payload is not None
        line = Text()
        line.append(f"#{idx + 1} ", style=_top_index_style(idx))
        line.append(f"(rank {comp_rank}) ", style="dim")
        line.append(a.confidence, style=_confidence_badge_style(a.confidence))
        line.append(f" · Δ{delta} B", style="dim")
        console.print(line)
        if smug:
            console.print("  [dim]smuggling-lite probe; curl may differ from raw bytes sent[/]")
        hd = _header_diff_text(r.spec.headers, baseline_request_headers, limit=4)
        console.print(f"  [dim]Headers:[/] {hd}")
        console.print(Text(f"  {cmd}", style="green"), soft_wrap=True)
        if idx < len(top) - 1:
            console.print()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"bypass {__version__}")
        raise typer.Exit(0)


@app.callback()
def _app_callback(
    version: Annotated[bool, typer.Option("--version", "-V", help="Show version and exit", callback=_version_callback, is_eager=True)] = False,
) -> None:
    pass


@app.command("probe", hidden=True)
def probe(
    url: Annotated[str, typer.Argument(help="Target URL (e.g. https://target.tld/admin)")],
    insecure: Annotated[bool, typer.Option("-k", help="Skip TLS verification")] = False,
    follow: Annotated[bool, typer.Option("-L", help="Follow redirects")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Request timeout (seconds)")] = 15.0,
    method: Annotated[list[str] | None, typer.Option("--method", help="HTTP method (repeatable)")] = None,
    bypass_ip: Annotated[list[str] | None, typer.Option("--bypass-ip", help="Extra IP for XFF payloads (repeatable)")] = None,
    host: Annotated[list[str] | None, typer.Option("--host", help="Extra host for Host/SNI fuzzing (repeatable)")] = None,
    output_json: Annotated[str | None, typer.Option("--json", help="Export results to JSON file")] = None,
    output_csv: Annotated[str | None, typer.Option("--csv", help="Export results to CSV file")] = None,
    all_results: Annotated[bool, typer.Option("--all", help="Show all results (not just interesting)")] = False,
    rate_limit: Annotated[float, typer.Option("--rate", help="Max requests per second (0 = unlimited)")] = 0.0,
    top_limit: Annotated[int, typer.Option("--top", help="Max entries in Top bypasses table")] = 10,
    quiet: Annotated[bool, typer.Option("-q", "--quiet", help="Only show Top bypasses (skip full table)")] = False,
) -> None:
    """Probe a URL for 403/401 bypass. Runs all techniques in aggressive mode."""

    methods = method if method else ["GET"]
    progress_stats = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "err": 0}
    progress_bar = Progress(
        TextColumn("[bold cyan]Scanning"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("• {task.completed}/{task.total}"),
        TextColumn("• 2xx={task.fields[t2xx]} 3xx={task.fields[t3xx]} 4xx={task.fields[t4xx]} 5xx={task.fields[t5xx]} err={task.fields[terr]}"),
        TimeElapsedColumn(),
        transient=True,
    )
    with progress_bar:
        task_id = progress_bar.add_task("requests", total=1, t2xx=0, t3xx=0, t4xx=0, t5xx=0, terr=0)

        def on_progress(done: int, total: int, tr: TryResult, _analysis: AnalysisResult) -> None:
            bucket = _status_bucket(tr.status_code if tr.error is None else -1)
            if bucket in progress_stats:
                progress_stats[bucket] += 1
            if progress_bar.tasks[task_id].total != total:
                progress_bar.update(task_id, total=total)
            progress_bar.update(
                task_id, completed=done,
                t2xx=progress_stats["2xx"], t3xx=progress_stats["3xx"],
                t4xx=progress_stats["4xx"], t5xx=progress_stats["5xx"],
                terr=progress_stats["err"],
            )

        base, results = run_probe(
            url,
            methods=methods,
            timeout=timeout,
            verify=not insecure,
            follow_redirects=follow,
            bypass_ips=bypass_ip or None,
            host_fuzz_values=host or None,
            calibration_samples=5,
            progress_callback=on_progress,
            rate_limit=rate_limit,
        )

    filter_interesting = not all_results
    if base.status_code < 0 and filter_interesting:
        filter_interesting = False
        console.print(
            "[yellow]Could not get baseline (TLS/network/DNS error); showing all results.[/]"
        )

    visible_rows = [(r, a) for r, a in results if (a.interesting or not filter_interesting)]

    console.print(
        f"\n[bold]Baseline[/] {url} → {base.status_code} [dim]({base.body_length} B)[/]"
    )
    if base.calibration.get("enabled"):
        console.print(
            f"[dim]Calibration: samples={base.calibration.get('samples_ok')} "
            f"dominant={base.calibration.get('dominant_status')} "
            f"avg_len={base.calibration.get('avg_length')} "
            f"delta={base.calibration.get('length_delta')}[/]"
        )

    _print_top_bypasses(
        base.status_code, base.body_length, visible_rows,
        top_limit=top_limit, top_min_score=35,
        insecure=insecure, follow_redirects=follow, timeout=timeout,
        baseline_request_headers={},
        baseline_response_headers=base.response_headers,
    )

    if not quiet:
        if not visible_rows and filter_interesting:
            console.print(
                "[yellow]No interesting results. Use --all to see everything.[/]"
            )
        elif visible_rows:
            table = Table(title="Results", show_lines=False)
            table.add_column("Method", style="cyan", no_wrap=True)
            table.add_column("Code", justify="right")
            table.add_column("Bytes", justify="right")
            table.add_column("Payload", max_width=44)
            table.add_column("URL", max_width=56)
            for r, analysis in visible_rows:
                payload_label = _payload_label(r)
                if r.error:
                    code = f"err ({r.error[:20]}…)" if len(r.error) > 20 else f"err ({r.error})"
                else:
                    code = str(r.status_code)
                table.add_row(
                    r.spec.method, code, str(r.body_length),
                    f"{payload_label} [{analysis.confidence}:{analysis.score}]",
                    r.final_url,
                )
            console.print(table)

    if output_json:
        export_json(output_json, url, base, visible_rows)
        console.print(f"[green]JSON →[/] {output_json}")
    if output_csv:
        export_csv(output_csv, visible_rows)
        console.print(f"[green]CSV →[/] {output_csv}")

    console.print(
        f"[dim]Requests: {len(results)} · Shown: {len(visible_rows)} · "
        f"Interesting: {sum(1 for _, a in results if a.interesting)}[/]"
    )


@app.command("batch")
def batch(
    input_file: Annotated[str, typer.Argument(help="File with URLs (one per line)")],
    insecure: Annotated[bool, typer.Option("-k", help="Skip TLS verification")] = False,
    follow: Annotated[bool, typer.Option("-L", help="Follow redirects")] = False,
    timeout: Annotated[float, typer.Option("--timeout")] = 15.0,
    method: Annotated[list[str] | None, typer.Option("--method")] = None,
    bypass_ip: Annotated[list[str] | None, typer.Option("--bypass-ip")] = None,
    host: Annotated[list[str] | None, typer.Option("--host")] = None,
    all_results: Annotated[bool, typer.Option("--all")] = False,
    out_dir: Annotated[str, typer.Option("--out-dir", help="Output directory")] = "out",
    rate_limit: Annotated[float, typer.Option("--rate")] = 0.0,
) -> None:
    """Run bypass scan against a list of URLs from a file."""
    urls = [line.strip() for line in Path(input_file).read_text(encoding="utf-8").splitlines() if line.strip()]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    summary: list[dict[str, object]] = []
    methods = method if method else ["GET"]

    with Progress(
        TextColumn("[bold magenta]Batch"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("• {task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task_id = progress.add_task("targets", total=max(1, len(urls)))
        for idx, url in enumerate(urls, start=1):
            base, rows = run_probe(
                url,
                methods=methods,
                timeout=timeout,
                verify=not insecure,
                follow_redirects=follow,
                bypass_ips=bypass_ip or None,
                host_fuzz_values=host or None,
                rate_limit=rate_limit,
            )
            visible_rows = [(r, a) for r, a in rows if (a.interesting or all_results)]
            stem = f"target_{idx:03d}"
            json_path = str(Path(out_dir) / f"{stem}.json")
            csv_path = str(Path(out_dir) / f"{stem}.csv")
            export_json(json_path, url, base, visible_rows)
            export_csv(csv_path, visible_rows)
            summary.append({
                "url": sanitize_url(url),
                "baseline_status": base.status_code,
                "total_requests": len(rows),
                "interesting": len(visible_rows),
                "json": json_path,
                "csv": csv_path,
            })
            progress.update(task_id, completed=idx)
            interesting_count = sum(1 for _, a in rows if a.interesting)
            console.print(f"[cyan]{idx}/{len(urls)}[/] {url} → {base.status_code} · {interesting_count} interesting")

    summary_path = Path(out_dir) / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
    console.print(f"[green]Summary →[/] {summary_path}")


@app.command("replay")
def replay(
    input_json: Annotated[str, typer.Argument(help="JSON file from --json output")],
    insecure: Annotated[bool, typer.Option("-k")] = False,
    follow: Annotated[bool, typer.Option("-L")] = False,
    timeout: Annotated[float, typer.Option("--timeout")] = 15.0,
    min_confidence: Annotated[str, typer.Option("--min-confidence", help="Minimum confidence: low, medium, high")] = "medium",
    max_targets: Annotated[int, typer.Option("--max-targets")] = 50,
    rate_limit: Annotated[float, typer.Option("--rate")] = 0.0,
) -> None:
    """Replay interesting findings from a previous scan."""
    from bypass.http_client import make_client
    from bypass.payloads.headers_403 import default_header_sets
    from bypass.payloads.methods_403 import method_payloads
    from urllib.parse import urljoin

    conf_order = {"none": 0, "low": 1, "medium": 2, "high": 3}
    data = json.loads(Path(input_json).read_text(encoding="utf-8"))
    results = data.get("results", [])

    filtered = []
    for item in results:
        analysis = item.get("analysis", {})
        conf = str(analysis.get("confidence", "none"))
        if conf_order.get(conf, 0) < conf_order.get(min_confidence, 2):
            continue
        filtered.append(item)
    filtered = filtered[: max(0, max_targets)]

    from bypass.safety import RequestThrottle
    throttle = RequestThrottle(rate_per_second=max(rate_limit, 0.0))

    attempt_rows: list[tuple[str, str, dict[str, str], str]] = []
    for item in filtered:
        base_url = item.get("url")
        if not base_url:
            continue
        base_method = str(item.get("method", "GET")).upper()
        base_headers = item.get("headers") or {}
        if not isinstance(base_headers, dict):
            base_headers = {}
        attempt_rows.append((base_method, base_url, dict(base_headers), "original"))

        for m, extra_headers, payload in method_payloads():
            attempt_rows.append((m, base_url, {**dict(base_headers), **extra_headers}, f"method:{payload.id}"))

        u = urlsplit(base_url)
        path = u.path or "/"
        host_val = u.netloc.split("@")[-1].split(":")[0] if u.netloc else ""
        scheme = u.scheme or "https"
        for hdrs, hp in default_header_sets(path, host_val, scheme)[:6]:
            attempt_rows.append((base_method, base_url, {**dict(base_headers), **hdrs}, f"header:{hp.id}"))

    with make_client(timeout, not insecure, False) as client:
        table = Table(title="Replay", show_lines=False)
        table.add_column("Method")
        table.add_column("Code")
        table.add_column("Bytes")
        table.add_column("Source", max_width=30)
        table.add_column("URL", max_width=60)
        for method_str, url, headers, source in attempt_rows:
            try:
                active_method = method_str
                active_url = url
                for _hop in range(6):
                    throttle.before_request()
                    response = client.request(active_method, active_url, headers=headers, follow_redirects=False)
                    throttle.after_response(response.status_code)
                    if not follow or not response.is_redirect:
                        break
                    location = response.headers.get("location")
                    if not location:
                        break
                    next_url = str(urljoin(str(response.url), location))
                    if response.status_code in {301, 302, 303} and active_method.upper() not in {"GET", "HEAD"}:
                        active_method = "GET"
                    active_url = next_url
                else:
                    raise RuntimeError("too_many_redirects")
                table.add_row(
                    active_method, str(response.status_code),
                    str(len(response.content or b"")), source, str(response.url),
                )
            except Exception as exc:
                table.add_row(method_str, "err", "0", source, f"{url} ({exc})")
        console.print(f"[dim]Replay: {len(filtered)} findings · {len(attempt_rows)} attempts[/]")
        console.print(table)


@app.command("list")
def list_payloads() -> None:
    """Show loaded payload catalog sizes."""
    from bypass.payloads.auth_401 import auth_challenge_payloads
    from bypass.payloads.headers_403 import default_header_sets
    from bypass.payloads.host_sni_403 import host_sni_payloads
    from bypass.payloads.methods_403 import method_payloads
    from bypass.payloads.paths_403 import path_mutations
    from bypass.payloads.protocols_403 import protocol_payloads
    from bypass.payloads.smuggling_lite import smuggling_lite_payloads

    p = path_mutations("/ejemplo/ruta")
    m = method_payloads()
    proto = protocol_payloads()
    hostset = host_sni_payloads(canonical_host="example.com", custom_hosts=None)
    authset = auth_challenge_payloads()
    smuggle = smuggling_lite_payloads()
    h = default_header_sets("/ejemplo/ruta", "example.com", "https")
    console.print(
        f"[bold]Payload catalogs[/]\n"
        f"  · Path mutations: {len(p)}\n"
        f"  · Header sets: {len(h)}\n"
        f"  · Method strategies: {len(m)}\n"
        f"  · Protocol variants: {len(proto)}\n"
        f"  · Host/SNI payloads: {len(hostset)}\n"
        f"  · Auth probes (401): {len(authset)}\n"
        f"  · Smuggling-lite: {len(smuggle)}"
    )


if __name__ == "__main__":
    app()
