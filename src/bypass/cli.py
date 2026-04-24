from __future__ import annotations

import base64
import json
import shlex
from collections import Counter
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from bypass import __version__
from bypass.engine import run_probe
from bypass.models import AnalysisResult, TryResult
from bypass.payloads.headers_403 import default_header_sets
from bypass.payloads.host_sni_403 import host_sni_payloads
from bypass.payloads.methods_403 import method_payloads
from bypass.payloads.paths_403 import path_mutations
from bypass.payloads.protocols_403 import protocol_payloads
from bypass.payloads.smuggling_lite import smuggling_lite_payloads
from bypass.reporters.csv_reporter import export_csv
from bypass.reporters.json_reporter import export_json

app = typer.Typer(
    name="bypass",
    help="Herramienta de bypass de ruta y cabeceras (403, ACL de proxy) para pruebas autorizadas.",
    no_args_is_help=True,
)
console = Console()
CONF_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


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


def _summarize_rows(rows: list[tuple[TryResult, AnalysisResult]]) -> dict[int, dict[str, object]]:
    by_status: dict[int, list[int]] = {}
    for r, _ in rows:
        status = int(r.status_code)
        if status not in by_status:
            by_status[status] = []
        by_status[status].append(int(r.body_length))
    out: dict[int, dict[str, object]] = {}
    for status, lengths in by_status.items():
        freq = Counter(lengths)
        normal_bytes, normal_count = max(freq.items(), key=lambda x: (x[1], -x[0]))
        outliers = sorted([x for x in lengths if x != normal_bytes])
        out[status] = {
            "count": len(lengths),
            "normal_bytes": normal_bytes,
            "normal_count": normal_count,
            "different_count": len(outliers),
            "different_values": sorted(set(outliers)),
        }
    return out


def _print_summary_table(rows: list[tuple[TryResult, AnalysisResult]]) -> None:
    grouped = _summarize_rows(rows)
    if not grouped:
        return
    table = Table(title="Resumen de tamano normal vs diferencias", show_lines=False)
    table.add_column("Status", justify="right")
    table.add_column("Count", justify="right")
    table.add_column("Bytes normal", justify="right")
    table.add_column("Repite", justify="right")
    table.add_column("Difieren", justify="right")
    table.add_column("Valores diferentes", max_width=36)
    for status in sorted(grouped.keys()):
        item = grouped[status]
        diff_vals = item["different_values"]
        diff_text = ",".join(str(x) for x in diff_vals[:6]) if diff_vals else "—"
        if isinstance(diff_vals, list) and len(diff_vals) > 6:
            diff_text += ",..."
        table.add_row(
            str(status),
            str(item["count"]),
            str(item["normal_bytes"]),
            str(item["normal_count"]),
            str(item["different_count"]),
            diff_text,
        )
    console.print(table)


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
    """
    Línea de shell lista para copiar: reproduce método, URL, cabeceras y cuerpo (vía base64) lo más fiel
    posible a `RequestSpec` (p. ej. -k/-L y --http1.0/--http2 alineados con el probe).
    Probes de smuggling crudos pueden requerir herramientas de bajo nivel; aquí se refleja lo que curl puede enviar.
    """
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


def _print_top_interesting_section(
    baseline_status: int,
    baseline_len: int,
    rows: list[tuple[TryResult, AnalysisResult]],
    *,
    top_limit: int,
    top_min_score: int,
    insecure: bool,
    follow_redirects: bool,
    timeout: float,
    baseline_headers: dict[str, str] | None = None,
) -> None:
    top = _rank_interesting_rows(
        baseline_status,
        baseline_len,
        rows,
        top_limit=top_limit,
        top_min_score=top_min_score,
    )
    if not top:
        return
    table = Table(
        title="Top bypasses interesantes",
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
    table.add_column("Payload", max_width=42, overflow="ellipsis")
    table.add_column("Conf/Score", justify="right")
    for idx, (r, a, delta, comp_rank) in enumerate(top):
        table.add_row(
            Text(str(idx + 1), style=_top_index_style(idx)),
            Text(str(comp_rank), style=_top_index_style(idx)),
            _text_pair_status(baseline_status, r.status_code),
            _text_pair_bytes(baseline_len, r.body_length),
            Text(str(delta), style=_delta_style(delta)),
            Text(_payload_label(r), style="white"),
            _text_conf_score(a),
        )
    console.print(table)
    console.print("[bold green]Curl para reproducir (copiar y pegar)[/] [dim]· ajusta -k/-L según tu entorno[/]")
    for idx, (r, a, delta, comp_rank) in enumerate(top):
        cmd = tryresult_to_curl(
            r,
            insecure=insecure,
            follow_redirects=follow_redirects,
            max_time=timeout,
        )
        smug = r.spec.smuggling_payload is not None
        line = Text()
        line.append(f"#{idx + 1} ", style=_top_index_style(idx))
        line.append(f"(rank {comp_rank}) ", style="dim")
        line.append("· ", style="dim")
        line.append(a.confidence, style=_confidence_badge_style(a.confidence))
        line.append(f" · Δ{delta} B", style="dim")
        console.print(line)
        if smug:
            console.print("  [dim]Nota: smuggling-lite; curl puede no coincidir byte a byte con el raw enviado.[/]")
        console.print(f"[dim]URL exacta:[/] {r.spec.url}")
        hd = _header_diff_text(r.spec.headers, baseline_headers, limit=4)
        console.print(f"[dim]Headers diff:[/] {hd}")
        console.print(Text(cmd, style="green"), soft_wrap=True)
        if idx < len(top) - 1:
            console.print()


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"bypass-tool {__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option("--version", "-V", help="Muestra la versión y sale.", callback=_version_callback, is_eager=True),
    ] = False,
) -> None:
    pass


@app.command("probe")
def probe(
    url: Annotated[str, typer.Argument(help="URL completa a probar, p.ej. https://host/recurso")],
    mode: Annotated[
        Literal["path", "headers", "both", "methods", "query", "protocol", "host", "smuggling", "all"],
        typer.Option("--mode", help="path, headers, both, methods, query, protocol, host, smuggling o all"),
    ] = "both",
    combine: Annotated[
        bool,
        typer.Option(help="Combina cada ruta con cada set de cabeceras (más lento)"),
    ] = False,
    method: Annotated[
        list[str] | None,
        typer.Option(
            "--method",
            help="Método HTTP (repetir para varios). Predeterminado: GET",
        ),
    ] = None,
    follow: Annotated[
        bool,
        typer.Option("-L", help="Seguir redirecciones (por defecto no)"),
    ] = False,
    insecure: Annotated[
        bool,
        typer.Option("-k", help="No verificar certificado TLS (solo laboratorio)"),
    ] = False,
    timeout: Annotated[float, typer.Option(help="Timeout por petición (s)")] = 15.0,
    profile: Annotated[
        Literal["safe", "aggressive"],
        typer.Option("--profile", help="safe: conservador, aggressive: más cobertura"),
    ] = "safe",
    all_results: Annotated[
        bool,
        typer.Option(
            "--all",
            help="Mostrar todos los resultados (por defecto solo filas con cambio respecto al baseline)",
        ),
    ] = False,
    output_json: Annotated[str | None, typer.Option("--json", help="Exportar resultados a JSON")] = None,
    output_csv: Annotated[str | None, typer.Option("--csv", help="Exportar resultados a CSV")] = None,
    calibrate: Annotated[
        bool,
        typer.Option("--calibrate/--no-calibrate", help="Auto-calibrar tolerancia por objetivo"),
    ] = True,
    calibration_samples: Annotated[
        int,
        typer.Option("--calibration-samples", help="Numero de requests de calibracion"),
    ] = 3,
    bypass_ip: Annotated[
        list[str] | None,
        typer.Option("--bypass-ip", help="IP/host para inyectar en payloads XFF (repetible)"),
    ] = None,
    guided_combos: Annotated[
        bool,
        typer.Option("--guided-combos/--no-guided-combos", help="Activar combinaciones guiadas de tecnicas"),
    ] = False,
    host_fuzz: Annotated[
        bool,
        typer.Option("--host-fuzz/--no-host-fuzz", help="Activar fuzzing extendido Host/SNI/:authority"),
    ] = False,
    host_fuzz_value: Annotated[
        list[str] | None,
        typer.Option("--host-fuzz-value", help="Host/authority extra para fuzzing (repetible)"),
    ] = None,
    smuggling_lite: Annotated[
        bool,
        typer.Option("--smuggling-lite/--no-smuggling-lite", help="Activar probes de smuggling-lite"),
    ] = False,
    smuggling_limit: Annotated[
        int,
        typer.Option("--smuggling-limit", help="Maximo de probes smuggling por target"),
    ] = 20,
    top_limit: Annotated[
        int,
        typer.Option("--top-limit", help="Maximo de hallazgos en Top bypasses"),
    ] = 10,
    top_min_score: Annotated[
        int,
        typer.Option("--top-min-score", help="Score minimo para entrar al Top"),
    ] = 35,
) -> None:
    """Envía el catálogo de bypass sobre la URL indicada (solo en alcances que te autorice el propietario)."""
    filter_interesting = not all_results
    methods = method if method else ["GET"]
    progress_stats = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "err": 0}
    progress_bar = Progress(
        TextColumn("[bold cyan]Probe"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("• done {task.completed}/{task.total}"),
        TextColumn("• 2xx={task.fields[t2xx]} 3xx={task.fields[t3xx]} 4xx={task.fields[t4xx]} 5xx={task.fields[t5xx]} err={task.fields[terr]}"),
        TimeElapsedColumn(),
        transient=True,
    )
    with progress_bar:
        task_id = progress_bar.add_task(
            "requests",
            total=1,
            t2xx=0,
            t3xx=0,
            t4xx=0,
            t5xx=0,
            terr=0,
        )

        def on_progress(done: int, total: int, tr, _analysis) -> None:
            bucket = _status_bucket(tr.status_code if tr.error is None else -1)
            if bucket in progress_stats:
                progress_stats[bucket] += 1
            if progress_bar.tasks[task_id].total != total:
                progress_bar.update(task_id, total=total)
            progress_bar.update(
                task_id,
                completed=done,
                t2xx=progress_stats["2xx"],
                t3xx=progress_stats["3xx"],
                t4xx=progress_stats["4xx"],
                t5xx=progress_stats["5xx"],
                terr=progress_stats["err"],
            )

        base, results = run_probe(
            url,
            mode=mode,
            combine=combine,
            profile_name=profile,
            methods=methods,
            timeout=timeout,
            verify=not insecure,
            follow_redirects=follow,
            auto_calibrate=calibrate,
            calibration_samples=calibration_samples,
            bypass_ips=bypass_ip or [],
            guided_combos=guided_combos,
            enable_host_fuzz=host_fuzz,
            host_fuzz_values=host_fuzz_value or [],
            enable_smuggling_lite=smuggling_lite,
            smuggling_limit=smuggling_limit,
            progress_callback=on_progress,
        )
    if base.status_code < 0 and filter_interesting:
        filter_interesting = False
        console.print(
            "[yellow]No se pudo obtener baseline (TLS, red, DNS, etc.); "
            "se muestran [bold]todos[/] los resultados.[/]"
        )

    table = Table(title="Resultados de probe", show_lines=False)
    table.add_column("Método", style="cyan", no_wrap=True)
    table.add_column("Código", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Ruta o cabecera", max_width=40)
    table.add_column("URL", max_width=56)

    shown = 0
    visible_rows = [(r, a) for r, a in results if (a.interesting or not filter_interesting)]
    for r, analysis in visible_rows:
        payload_label = _payload_label(r)
        if r.error:
            code = f"err ({r.error[:20]}…)" if len(r.error) > 20 else f"err ({r.error})"
        else:
            code = str(r.status_code)
        table.add_row(
            r.spec.method,
            code,
            str(r.body_length),
            f"{payload_label} [{analysis.confidence}:{analysis.score}]",
            r.final_url,
        )
        shown += 1

    console.print(
        f"[bold]Baseline[/] GET {url} → {base.status_code} [dim]({base.body_length} B)[/]"
    )
    if base.calibration.get("enabled"):
        console.print(
            "[dim]Calibracion: "
            f"samples={base.calibration.get('samples_ok')} "
            f"status_dom={base.calibration.get('dominant_status')} "
            f"avg_len={base.calibration.get('avg_length')} "
            f"delta={base.calibration.get('length_delta')}[/]"
        )
    if shown == 0 and filter_interesting:
        console.print(
            "[yellow]Ningún resultado pasa el filtro heurístico. Usa [bold]--all[/] para listar todo o revisa el baseline.[/]"
        )
    else:
        console.print(table)
    if output_json:
        export_json(output_json, url, base, visible_rows)
        console.print(f"[green]JSON exportado en[/] {output_json}")
    if output_csv:
        export_csv(output_csv, visible_rows)
        console.print(f"[green]CSV exportado en[/] {output_csv}")
    _print_summary_table(visible_rows)
    _print_top_interesting_section(
        base.status_code,
        base.body_length,
        visible_rows,
        top_limit=top_limit,
        top_min_score=top_min_score,
        insecure=insecure,
        follow_redirects=follow,
        timeout=timeout,
        baseline_headers={},
    )
    smuggle_hits = sum(1 for _, a in visible_rows if "smuggling_suspected" in a.reasons)
    host_hits = sum(1 for r, _ in visible_rows if r.spec.host_payload is not None)
    if host_hits or smuggle_hits:
        console.print(
            f"[dim]Host/SNI intents: {host_hits} · Smuggling suspected: {smuggle_hits}[/]"
        )
    console.print(
        f"[dim]Peticiones: {len(results)} · Mostradas: {shown} · modo={mode} combine={combine} "
        f"profile={profile} · "
        f"DevSec: solo usos legales y con permiso.[/]"
    )


@app.command("batch")
def batch(
    input_file: Annotated[str, typer.Argument(help="Archivo con URLs (una por línea)")],
    mode: Annotated[
        Literal["path", "headers", "both", "methods", "query", "protocol", "host", "smuggling", "all"],
        typer.Option("--mode"),
    ] = "both",
    profile: Annotated[Literal["safe", "aggressive"], typer.Option("--profile")] = "safe",
    timeout: Annotated[float, typer.Option(help="Timeout por petición (s)")] = 15.0,
    insecure: Annotated[bool, typer.Option("-k", help="No verificar certificado TLS")] = False,
    follow: Annotated[bool, typer.Option("-L", help="Seguir redirecciones")] = False,
    all_results: Annotated[bool, typer.Option("--all", help="Mostrar todos los resultados")] = False,
    out_dir: Annotated[str, typer.Option("--out-dir", help="Directorio para exportes")] = "out",
    calibrate: Annotated[bool, typer.Option("--calibrate/--no-calibrate")] = True,
    calibration_samples: Annotated[int, typer.Option("--calibration-samples")] = 3,
    bypass_ip: Annotated[list[str] | None, typer.Option("--bypass-ip")] = None,
    guided_combos: Annotated[bool, typer.Option("--guided-combos/--no-guided-combos")] = False,
    host_fuzz: Annotated[bool, typer.Option("--host-fuzz/--no-host-fuzz")] = False,
    host_fuzz_value: Annotated[list[str] | None, typer.Option("--host-fuzz-value")] = None,
    smuggling_lite: Annotated[bool, typer.Option("--smuggling-lite/--no-smuggling-lite")] = False,
    smuggling_limit: Annotated[int, typer.Option("--smuggling-limit")] = 20,
) -> None:
    urls = [line.strip() for line in Path(input_file).read_text(encoding="utf-8").splitlines() if line.strip()]
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    summary: list[dict[str, object]] = []
    with Progress(
        TextColumn("[bold magenta]Batch"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("• targets {task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task_id = progress.add_task("targets", total=max(1, len(urls)))
        for idx, url in enumerate(urls, start=1):
            base, rows = run_probe(
                url,
                mode=mode,
                profile_name=profile,
                timeout=timeout,
                verify=not insecure,
                follow_redirects=follow,
                auto_calibrate=calibrate,
                calibration_samples=calibration_samples,
                bypass_ips=bypass_ip or [],
                guided_combos=guided_combos,
                enable_host_fuzz=host_fuzz,
                host_fuzz_values=host_fuzz_value or [],
                enable_smuggling_lite=smuggling_lite,
                smuggling_limit=smuggling_limit,
            )
            visible_rows = [(r, a) for r, a in rows if (a.interesting or all_results)]
            stem = f"target_{idx:03d}"
            json_path = str(Path(out_dir) / f"{stem}.json")
            csv_path = str(Path(out_dir) / f"{stem}.csv")
            export_json(json_path, url, base, visible_rows)
            export_csv(csv_path, visible_rows)
            summary.append(
                {
                    "url": url,
                    "baseline_status": base.status_code,
                    "calibration": base.calibration,
                    "total_requests": len(rows),
                    "interesting_rows": len(visible_rows),
                    "json": json_path,
                    "csv": csv_path,
                }
            )
            progress.update(task_id, completed=idx)
            console.print(f"[cyan]{idx}/{len(urls)}[/] {url} -> {len(visible_rows)} resultados")
    summary_path = Path(out_dir) / "summary.json"
    summary_path.write_text(json.dumps(summary, ensure_ascii=True, indent=2), encoding="utf-8")
    console.print(f"[green]Resumen batch:[/] {summary_path}")


@app.command("replay")
def replay(
    input_json: Annotated[str, typer.Argument(help="JSON generado por --json o batch")],
    timeout: Annotated[float, typer.Option(help="Timeout por petición (s)")] = 15.0,
    insecure: Annotated[bool, typer.Option("-k", help="No verificar certificado TLS")] = False,
    follow: Annotated[bool, typer.Option("-L", help="Seguir redirecciones")] = False,
    min_confidence: Annotated[
        Literal["low", "medium", "high"],
        typer.Option("--min-confidence", help="Rejugar solo hallazgos desde esta confianza"),
    ] = "medium",
    max_targets: Annotated[int, typer.Option("--max-targets", help="Limite de hallazgos a rejugar")] = 50,
    replay_methods: Annotated[bool, typer.Option("--replay-methods/--no-replay-methods")] = True,
    replay_headers: Annotated[bool, typer.Option("--replay-headers/--no-replay-headers")] = True,
    header_limit: Annotated[int, typer.Option("--header-limit", help="Cuantos header payloads probar por hallazgo")] = 6,
) -> None:
    from bypass.http_client import make_client

    data = json.loads(Path(input_json).read_text(encoding="utf-8"))
    if "results" in data:
        results = data["results"]
    else:
        typer.echo("Formato de replay no valido")
        raise typer.Exit(1)
    filtered = []
    for item in results:
        analysis = item.get("analysis", {})
        conf = str(analysis.get("confidence", "none"))
        if CONF_ORDER.get(conf, 0) < CONF_ORDER[min_confidence]:
            continue
        filtered.append(item)
    filtered = filtered[: max(0, max_targets)]

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

        if replay_methods:
            for m, extra_headers, payload in method_payloads():
                attempt_rows.append((m, base_url, {**dict(base_headers), **extra_headers}, f"method:{payload.id}"))

        if replay_headers:
            u = urlsplit(base_url)
            path = u.path or "/"
            host = u.netloc.split("@")[-1].split(":")[0] if u.netloc else ""
            scheme = u.scheme or "https"
            for hdrs, hp in default_header_sets(path, host, scheme)[: max(0, header_limit)]:
                attempt_rows.append(
                    (base_method, base_url, {**dict(base_headers), **hdrs}, f"header:{hp.id}")
                )

    with make_client(timeout, not insecure, follow) as client:
        table = Table(title="Replay resultados", show_lines=False)
        table.add_column("Metodo")
        table.add_column("Codigo")
        table.add_column("Bytes")
        table.add_column("Origen", max_width=30)
        table.add_column("URL", max_width=60)
        for method, url, headers, source in attempt_rows:
            try:
                response = client.request(method, url, headers=headers)
                table.add_row(
                    method,
                    str(response.status_code),
                    str(len(response.content or b"")),
                    source,
                    str(response.url),
                )
            except Exception as exc:
                table.add_row(method, "err", "0", source, f"{url} ({exc})")
        console.print(
            f"[dim]Replay hallazgos filtrados: {len(filtered)} · intents totales: {len(attempt_rows)}[/]"
        )
        console.print(table)


@app.command("list")
def list_payloads() -> None:
    """Muestra el número de entradas cargadas en cada catálogo (fase 403)."""
    from urllib.parse import urlsplit

    p = path_mutations("/ejemplo/ruta")
    m = method_payloads()
    proto = protocol_payloads()
    u = "https://example.com/ejemplo/ruta"
    host = urlsplit(u).netloc
    hostset = host_sni_payloads(canonical_host=host, custom_hosts=None)
    smuggle = smuggling_lite_payloads()
    h = default_header_sets("/ejemplo/ruta", host, "https")
    console.print(
        f"[bold]Catálogos 403 (referencia de ejemplo en /ejemplo/ruta)[/]\n"
        f"  · Mutaciones de ruta: {len(p)}\n"
        f"  · Sets de cabeceras: {len(h)}\n"
        f"  · Estrategias de métodos: {len(m)}\n"
        f"  · Estrategias de protocolo: {len(proto)}\n"
        f"  · Estrategias Host/SNI: {len(hostset)}\n"
        f"  · Probes smuggling-lite: {len(smuggle)}"
    )


if __name__ == "__main__":
    app()
