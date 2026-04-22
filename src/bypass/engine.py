from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import http.client
from statistics import pstdev
from typing import Callable
from urllib.parse import urlsplit, urlunsplit
import ssl

import httpx

from bypass.analyzers.response_diff import AnalyzerConfig, analyze_result
from bypass.http_client import make_client
from bypass.models import AnalysisResult, BaselineSnapshot, Payload, RequestSpec, TryResult
from bypass.payloads.headers_403 import default_header_sets
from bypass.payloads.host_sni_403 import host_sni_payloads
from bypass.payloads.methods_403 import method_payloads
from bypass.payloads.paths_403 import all_path_variants
from bypass.payloads.protocols_403 import protocol_payloads
from bypass.payloads.query_403 import query_mutations
from bypass.payloads.smuggling_lite import smuggling_lite_payloads


@dataclass
class RuntimeProfile:
    name: str
    combine_limit: int
    length_delta: int


SAFE_PROFILE = RuntimeProfile(name="safe", combine_limit=500, length_delta=70)
AGGRESSIVE_PROFILE = RuntimeProfile(name="aggressive", combine_limit=5000, length_delta=40)


def compute_dynamic_length_delta(lengths: list[int], floor: int) -> int:
    if not lengths:
        return floor
    if len(lengths) == 1:
        return max(floor, 20)
    # Delta dinamico: variabilidad observada + margen minimo.
    spread = int(pstdev(lengths) * 2) + 20
    return max(floor, spread)


def _calibration_urls(target_url: str, samples: int) -> list[str]:
    u = urlsplit(target_url)
    base = (u.path or "/").rstrip("/")
    prefix = base if base else "/"
    return [
        f"{u.scheme}://{u.netloc}{prefix}/.bypass-cal-{i}-notfound-zz"
        for i in range(1, samples + 1)
    ]


def _calibrate_target(
    client: httpx.Client,
    target_url: str,
    headers: dict[str, str],
    *,
    samples: int,
    floor_delta: int,
) -> dict[str, object]:
    statuses: list[int] = []
    lengths: list[int] = []
    for url in _calibration_urls(target_url, samples):
        st, ln, _, _, err = _fetch(client, "GET", url, headers)
        if err:
            continue
        statuses.append(st)
        lengths.append(ln)
    if not statuses:
        return {"enabled": False, "samples_ok": 0, "length_delta": floor_delta}
    dominant_status = Counter(statuses).most_common(1)[0][0]
    avg_length = int(sum(lengths) / len(lengths)) if lengths else 0
    return {
        "enabled": True,
        "samples_ok": len(statuses),
        "dominant_status": dominant_status,
        "avg_length": avg_length,
        "length_delta": compute_dynamic_length_delta(lengths, floor_delta),
    }


def _fetch(
    client: httpx.Client,
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: bytes | None = None,
) -> tuple[int, int, str, str, str | None]:
    h = dict(headers or {})
    try:
        r = client.request(method, url, headers=h, content=body)
        content = r.content or b""
        body_sample = content[:400].decode("utf-8", errors="replace")
        return r.status_code, len(content), str(r.url), body_sample, None
    except Exception as e:
        return -1, 0, url, "", str(e)


def _fetch_http10(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    *,
    timeout: float,
    verify: bool,
    body: bytes | None = None,
) -> tuple[int, int, str, str, str | None]:
    try:
        u = urlsplit(url)
        if not u.scheme or not u.netloc:
            return -1, 0, url, "", "invalid_url"
        path_q = u.path or "/"
        if u.query:
            path_q = f"{path_q}?{u.query}"
        hdrs = dict(headers or {})
        if "Host" not in hdrs and u.netloc:
            hdrs["Host"] = u.netloc
        if u.scheme == "https":
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(u.netloc, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(u.netloc, timeout=timeout)
        conn._http_vsn = 10
        conn._http_vsn_str = "HTTP/1.0"
        conn.request(method, path_q, body=body, headers=hdrs)
        resp = conn.getresponse()
        raw = resp.read() or b""
        sample = raw[:400].decode("utf-8", errors="replace")
        conn.close()
        return int(resp.status), len(raw), url, sample, None
    except Exception as e:
        return -1, 0, url, "", str(e)


def _build_specs(
    target_url: str,
    *,
    mode: str,
    combine: bool,
    methods: list[str],
    profile: RuntimeProfile,
    bypass_ips: list[str] | None = None,
    guided_combos: bool = False,
    enable_host_fuzz: bool = False,
    host_fuzz_values: list[str] | None = None,
    enable_smuggling_lite: bool = False,
    smuggling_limit: int = 20,
) -> list[RequestSpec]:
    u = urlsplit(target_url)
    host = u.netloc.split("@")[-1].split(":")[0] if u.netloc else ""
    base_path = u.path or "/"
    scheme = u.scheme or "https"
    path_variants = all_path_variants(target_url)
    header_sets = default_header_sets(base_path, host, scheme, bypass_ips=bypass_ips)
    method_sets = method_payloads()
    proto_sets = protocol_payloads()
    query_sets = query_mutations(target_url)
    host_sets = host_sni_payloads(canonical_host=host or "localhost", custom_hosts=host_fuzz_values)
    smuggle_sets = smuggling_lite_payloads()
    specs: list[RequestSpec] = []
    guided_added = 0

    def _url_with_path_override(path_override: str) -> str:
        p = path_override if path_override.startswith("/") else f"/{path_override}"
        return urlunsplit((u.scheme, u.netloc, p, u.query, u.fragment))

    def add(
        method: str,
        url: str,
        hdrs: dict[str, str],
        path_p: Payload | None,
        header_p: Payload | None,
    ) -> None:
        specs.append(
            RequestSpec(
                method=method,
                url=url,
                headers=hdrs,
                path_payload=path_p,
                header_payload=header_p,
                method_payload=None,
            )
        )

    requested_mode = mode
    modes_to_run = [mode]
    if requested_mode == "all":
        modes_to_run = ["both", "methods", "protocol", "host", "smuggling"]

    for m in methods:
        for active_mode in modes_to_run:
            if active_mode == "path":
                if combine:
                    for pv in path_variants:
                        for hdr_dict, hp in header_sets:
                            add(m, pv.full_url, hdr_dict, pv.payload, hp)
                else:
                    for pv in path_variants:
                        add(m, pv.full_url, {}, pv.payload, None)

            elif active_mode == "headers":
                for hdr_dict, hp in header_sets:
                    request_url = target_url
                    override_path = hp.metadata.get("request_path_override")
                    if isinstance(override_path, str) and override_path:
                        request_url = _url_with_path_override(override_path)
                    add(m, request_url, hdr_dict, None, hp)

            elif active_mode == "both":
                if combine:
                    for pv in path_variants:
                        for hdr_dict, hp in header_sets:
                            add(m, pv.full_url, hdr_dict, pv.payload, hp)
                else:
                    for pv in path_variants:
                        add(m, pv.full_url, {}, pv.payload, None)
                    for hdr_dict, hp in header_sets:
                        request_url = target_url
                        override_path = hp.metadata.get("request_path_override")
                        if isinstance(override_path, str) and override_path:
                            request_url = _url_with_path_override(override_path)
                        add(m, request_url, hdr_dict, None, hp)

            elif active_mode == "methods":
                for method_name, hdrs, mp in method_sets:
                    specs.append(
                        RequestSpec(
                            method=method_name,
                            url=target_url,
                            headers=hdrs,
                            path_payload=None,
                            header_payload=None,
                            method_payload=mp,
                            body=b"{}" if method_name in {"POST", "PUT", "PATCH"} else None,
                        )
                    )

            elif active_mode == "query":
                for q_url, qp in query_sets:
                    specs.append(
                        RequestSpec(
                            method=m,
                            url=q_url,
                            headers={},
                            query_payload=qp,
                        )
                    )
            elif active_mode == "protocol":
                for proto_hint, pp in proto_sets:
                    specs.append(
                        RequestSpec(
                            method=m,
                            url=target_url,
                            headers={},
                            protocol_payload=pp,
                            protocol_hint=proto_hint,
                        )
                    )
            elif active_mode == "host" and (enable_host_fuzz or requested_mode in {"host", "all"}):
                for hdrs, hp in host_sets:
                    specs.append(
                        RequestSpec(
                            method=m,
                            url=target_url,
                            headers=hdrs,
                            host_payload=hp,
                        )
                    )
            elif active_mode == "smuggling" and (enable_smuggling_lite or requested_mode in {"smuggling", "all"}):
                for hdrs, body, sp in smuggle_sets[: max(1, smuggling_limit)]:
                    specs.append(
                        RequestSpec(
                            method="POST",
                            url=target_url,
                            headers=hdrs,
                            body=body,
                            smuggling_payload=sp,
                        )
                    )

            if active_mode == "both":
                for q_url, qp in query_sets:
                    specs.append(
                        RequestSpec(
                            method=m,
                            url=q_url,
                            headers={},
                            query_payload=qp,
                        )
                    )
                if guided_combos:
                    # 1) path high-yield + header local-ip
                    key_paths = [pv for pv in path_variants if pv.payload.id in {"midpath_iis", "encoded_slash_mid", "double_encoded_traversal"}]
                    key_headers = [x for x in header_sets if x[1].id in {"h_x_forwarded_for", "h_x_real_ip", "h_x_orig_url_on_root", "h_x_rewrite_url_on_root"}]
                    for pv in key_paths[:3]:
                        for hdr_dict, hp in key_headers[:4]:
                            specs.append(
                                RequestSpec(
                                    method=m,
                                    url=pv.full_url,
                                    headers=hdr_dict,
                                    path_payload=pv.payload,
                                    header_payload=hp,
                                )
                            )
                            guided_added += 1
                    # 2) method-override + path encoded
                    encoded_paths = [pv for pv in path_variants if "encode" in pv.payload.id or "nullbyte" in pv.payload.id]
                    override_methods = [mm for mm in method_sets if "override" in mm[2].id]
                    for pv in encoded_paths[:2]:
                        for method_name, mhdrs, mp in override_methods[:3]:
                            specs.append(
                                RequestSpec(
                                    method=method_name,
                                    url=pv.full_url,
                                    headers=mhdrs,
                                    path_payload=pv.payload,
                                    method_payload=mp,
                                    body=b"{}" if method_name.upper() in {"POST", "PUT", "PATCH"} else None,
                                )
                            )
                            guided_added += 1

    combo_limit = 40 if profile.name == "safe" else 120
    if guided_combos and guided_added > combo_limit:
        specs = specs[: profile.combine_limit + combo_limit]
    if len(specs) > profile.combine_limit:
        specs = specs[: profile.combine_limit]
    return specs


def run_probe(
    target_url: str,
    *,
    mode: str = "both",
    combine: bool = False,
    profile_name: str = "safe",
    methods: list[str] | None = None,
    timeout: float = 15.0,
    verify: bool = True,
    follow_redirects: bool = False,
    proxy: str | None = None,
    extra_headers: dict[str, str] | None = None,
    bypass_ips: list[str] | None = None,
    guided_combos: bool = False,
    enable_host_fuzz: bool = False,
    host_fuzz_values: list[str] | None = None,
    enable_smuggling_lite: bool = False,
    smuggling_limit: int = 20,
    auto_calibrate: bool = True,
    calibration_samples: int = 3,
    progress_callback: Callable[[int, int, TryResult, AnalysisResult], None] | None = None,
) -> tuple[BaselineSnapshot, list[tuple[TryResult, AnalysisResult]]]:
    profile = AGGRESSIVE_PROFILE if profile_name == "aggressive" else SAFE_PROFILE
    methods = [x.upper() for x in (methods or ["GET"])]
    base_hdrs: dict[str, str] = dict(extra_headers or {})
    specs = _build_specs(
        target_url,
        mode=mode,
        combine=combine,
        methods=methods,
        profile=profile,
        bypass_ips=bypass_ips,
        guided_combos=guided_combos,
        enable_host_fuzz=enable_host_fuzz,
        host_fuzz_values=host_fuzz_values,
        enable_smuggling_lite=enable_smuggling_lite,
        smuggling_limit=smuggling_limit,
    )
    for s in specs:
        s.headers = {**base_hdrs, **s.headers}

    with make_client(timeout, verify, follow_redirects, proxy) as client:
        st, ln, _, baseline_sample, err = _fetch(client, "GET", target_url, base_hdrs)
        if err:
            st, ln = -1, 0
        calibration = (
            _calibrate_target(
                client,
                target_url,
                base_hdrs,
                samples=max(1, calibration_samples),
                floor_delta=profile.length_delta,
            )
            if auto_calibrate
            else {"enabled": False, "samples_ok": 0, "length_delta": profile.length_delta}
        )
        baseline = BaselineSnapshot(
            status_code=st,
            body_length=ln,
            body_sample=baseline_sample,
            calibration=calibration,
        )
        effective_delta = int(calibration.get("length_delta", profile.length_delta))

        results: list[tuple[TryResult, AnalysisResult]] = []
        total = len(specs)
        for idx, s in enumerate(specs, start=1):
            if s.protocol_hint == "http2":
                with make_client(timeout, verify, follow_redirects, proxy, http2=True) as pclient:
                    st2, ln2, final, body_sample, err2 = _fetch(
                        pclient, s.method, s.url, s.headers, s.body
                    )
            elif s.protocol_hint == "http1_0":
                st2, ln2, final, body_sample, err2 = _fetch_http10(
                    s.method,
                    s.url,
                    s.headers,
                    timeout=timeout,
                    verify=verify,
                    body=s.body,
                )
            else:
                st2, ln2, final, body_sample, err2 = _fetch(client, s.method, s.url, s.headers, s.body)
            tr = TryResult(spec=s, status_code=st2, body_length=ln2, final_url=final, error=err2)
            ar = analyze_result(
                baseline,
                tr,
                body_sample=body_sample,
                config=AnalyzerConfig(length_delta=effective_delta),
            )
            if s.smuggling_payload and tr.status_code in {400, 411, 413, 426, 431, 500, 501, 502, 503, 504}:
                if "smuggling_suspected" not in ar.reasons:
                    ar.reasons.append("smuggling_suspected")
                ar.score = max(ar.score, 55)
                ar.interesting = True
                ar.confidence = "medium" if ar.confidence == "none" else ar.confidence
            results.append((tr, ar))
            if progress_callback:
                progress_callback(idx, total, tr, ar)

    return baseline, results


def interesting(
    baseline: BaselineSnapshot,
    r: TryResult,
    *,
    length_delta: int = 50,
) -> bool:
    if not r.ok_response:
        return False
    if r.status_code != baseline.status_code:
        return True
    if abs(r.body_length - baseline.body_length) >= length_delta:
        return True
    return False
