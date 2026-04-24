from __future__ import annotations

from dataclasses import dataclass
from collections import Counter
import http.client
import hashlib
from statistics import pstdev
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit
import ssl
import re

import httpx

from bypass.analyzers.response_diff import AnalyzerConfig, analyze_result
from bypass.http_client import make_client
from bypass.models import AnalysisResult, BaselineSnapshot, Payload, RequestSpec, TryResult
from bypass.payloads.auth_401 import auth_challenge_payloads
from bypass.payloads.domain_403 import domain_header_payloads
from bypass.payloads.headers_403 import default_header_sets
from bypass.payloads.host_sni_403 import host_sni_payloads
from bypass.payloads.methods_403 import method_payloads
from bypass.payloads.paths_403 import all_path_variants
from bypass.payloads.protocols_403 import protocol_payloads
from bypass.payloads.query_403 import query_mutations
from bypass.payloads.smuggling_lite import smuggling_lite_payloads
from bypass.safety import RequestThrottle, ScopePolicy, is_redirect_target_allowed, is_url_in_scope


@dataclass
class RuntimeProfile:
    name: str
    combine_limit: int
    length_delta: int


SAFE_PROFILE = RuntimeProfile(name="safe", combine_limit=500, length_delta=70)
AGGRESSIVE_PROFILE = RuntimeProfile(name="aggressive", combine_limit=5000, length_delta=40)
BaselineKey = tuple[str, str, str]


def _extract_title(body_sample: str) -> str:
    if not body_sample:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body_sample, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return " ".join(m.group(1).split())[:160]


def _spec_family_name(spec: RequestSpec) -> str:
    if spec.family:
        return spec.family
    if spec.smuggling_payload is not None:
        return "smuggling"
    if spec.host_payload is not None:
        return "host"
    if spec.protocol_payload is not None:
        return "protocol"
    if spec.method_payload is not None:
        return "methods"
    if spec.query_payload is not None:
        return "query"
    if spec.header_payload is not None:
        return "headers"
    if spec.path_payload is not None:
        return "path"
    return "general"


def _baseline_key_for_spec(spec: RequestSpec) -> BaselineKey:
    return (
        spec.method.upper(),
        spec.protocol_hint or "http1_1",
        _spec_family_name(spec),
    )


def _baseline_transport_key(method: str, protocol_hint: str | None) -> tuple[str, str]:
    return (method.upper(), protocol_hint or "http1_1")


def _baseline_body_for_method(method: str) -> bytes | None:
    return b"{}" if method.upper() in {"POST", "PUT", "PATCH"} else None


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
    method: str = "GET",
    body: bytes | None = None,
    protocol_hint: str | None = None,
    timeout: float = 15.0,
    verify: bool = True,
    proxy: str | None = None,
    scope_policy: ScopePolicy | None = None,
    follow_redirects: bool = False,
    throttle: RequestThrottle | None = None,
) -> dict[str, object]:
    statuses: list[int] = []
    lengths: list[int] = []
    for url in _calibration_urls(target_url, samples):
        if protocol_hint == "http2":
            with make_client(timeout, verify, False, proxy, http2=True) as pclient:
                st, ln, _, _, _, err = _fetch(
                    pclient,
                    method,
                    url,
                    headers,
                    body,
                    scope_policy=scope_policy,
                    follow_redirects=follow_redirects,
                    throttle=throttle,
                )
        elif protocol_hint == "http1_0":
            st, ln, _, _, _, err = _fetch_http10(
                method,
                url,
                headers,
                timeout=timeout,
                verify=verify,
                body=body,
                scope_policy=scope_policy,
                throttle=throttle,
            )
        else:
            st, ln, _, _, _, err = _fetch(
                client,
                method,
                url,
                headers,
                body,
                scope_policy=scope_policy,
                follow_redirects=follow_redirects,
                throttle=throttle,
            )
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
    scope_policy: ScopePolicy | None = None,
    follow_redirects: bool = False,
    throttle: RequestThrottle | None = None,
    max_redirects: int = 5,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    h = dict(headers or {})
    try:
        active_url = url
        active_method = method
        active_body = body
        max_hops = max_redirects if follow_redirects else 0
        for redirect_hop in range(max_hops + 1):
            if scope_policy is not None:
                allowed, reason = is_url_in_scope(active_url, scope_policy)
                if not allowed:
                    return -1, 0, active_url, "", {}, reason
            if throttle is not None:
                throttle.before_request()
            request = client.build_request(active_method, active_url, headers=h, content=active_body)
            r = client.send(request, follow_redirects=False)
            if throttle is not None:
                throttle.after_response(r.status_code)
            if not follow_redirects or not r.is_redirect:
                break
            if redirect_hop >= max_hops:
                return -1, 0, active_url, "", {}, "too_many_redirects"
            location = r.headers.get("location")
            if not location:
                break
            next_url = str(urljoin(str(r.url), location))
            if scope_policy is not None:
                allowed, reason = is_redirect_target_allowed(active_url, next_url, scope_policy)
                if not allowed:
                    return -1, 0, next_url, "", {}, reason
            if r.status_code in {301, 302, 303} and active_method.upper() not in {"GET", "HEAD"}:
                active_method = "GET"
                active_body = None
            active_url = next_url
        content = r.content or b""
        body_sample = content[:400].decode("utf-8", errors="replace")
        resp_headers = {
            "www-authenticate": r.headers.get("www-authenticate", ""),
            "location": r.headers.get("location", ""),
            "server": r.headers.get("server", ""),
            "content-type": r.headers.get("content-type", ""),
        }
        return r.status_code, len(content), str(r.url), body_sample, resp_headers, None
    except Exception as e:
        return -1, 0, url, "", {}, str(e)


def _fetch_http10(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    *,
    timeout: float,
    verify: bool,
    body: bytes | None = None,
    scope_policy: ScopePolicy | None = None,
    throttle: RequestThrottle | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    try:
        u = urlsplit(url)
        if not u.scheme or not u.netloc:
            return -1, 0, url, "", {}, "invalid_url"
        if scope_policy is not None:
            allowed, reason = is_url_in_scope(url, scope_policy)
            if not allowed:
                return -1, 0, url, "", {}, reason
        path_q = u.path or "/"
        if u.query:
            path_q = f"{path_q}?{u.query}"
        hdrs = dict(headers or {})
        if "Host" not in hdrs and u.netloc:
            hdrs["Host"] = u.netloc
        if throttle is not None:
            throttle.before_request()
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
        if throttle is not None:
            throttle.after_response(int(resp.status))
        resp_headers = {
            "www-authenticate": resp.getheader("www-authenticate", "") or "",
            "location": resp.getheader("location", "") or "",
            "server": resp.getheader("server", "") or "",
            "content-type": resp.getheader("content-type", "") or "",
        }
        return int(resp.status), len(raw), url, sample, resp_headers, None
    except Exception as e:
        return -1, 0, url, "", {}, str(e)


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
    domain_mode: bool = False,
    auth_challenges: bool = False,
    max_vhost_payloads: int = 30,
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
    if domain_mode:
        host_sets = host_sets[: max(1, max_vhost_payloads)]
    smuggle_sets = smuggling_lite_payloads()
    domain_sets = domain_header_payloads(host or "localhost") if domain_mode else []
    auth_sets = auth_challenge_payloads() if auth_challenges else []
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
                if domain_mode:
                    for hdrs, hp in domain_sets:
                        specs.append(
                            RequestSpec(
                                method=m,
                                url=target_url,
                                headers=hdrs,
                                header_payload=hp,
                                family=str(hp.metadata.get("family", "redirect")),
                                target_type="domain",
                            )
                        )

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
                            family=str(hp.metadata.get("family", "vhost")),
                            target_type="domain" if domain_mode else "path",
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
                            family="smuggling",
                            target_type="domain" if domain_mode else "path",
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
                            target_type="domain" if domain_mode else "path",
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
    if auth_challenges:
        for m in methods:
            for hdrs, ap in auth_sets:
                specs.append(
                    RequestSpec(
                        method=m,
                        url=target_url,
                        headers=hdrs,
                        header_payload=ap,
                        family="auth-challenge",
                        target_type="domain" if domain_mode else "path",
                    )
                )
    if guided_combos and guided_added > combo_limit:
        specs = specs[: profile.combine_limit + combo_limit]
    if len(specs) > profile.combine_limit:
        specs = specs[: profile.combine_limit]
    return _dedupe_specs(specs)


def _spec_fingerprint(spec: RequestSpec) -> tuple[object, ...]:
    header_items = tuple(sorted((k.lower(), v) for k, v in spec.headers.items()))
    body_digest = hashlib.sha256(spec.body or b"").hexdigest() if spec.body is not None else ""
    return (
        spec.method.upper(),
        spec.url,
        header_items,
        spec.protocol_hint or "",
        body_digest,
        spec.target_type,
    )


def _dedupe_specs(specs: list[RequestSpec]) -> list[RequestSpec]:
    deduped: list[RequestSpec] = []
    seen: set[tuple[object, ...]] = set()
    for spec in specs:
        fp = _spec_fingerprint(spec)
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(spec)
    return deduped


def _fetch_baseline_snapshot(
    client: httpx.Client,
    *,
    target_url: str,
    headers: dict[str, str],
    method: str,
    timeout: float,
    verify: bool,
    follow_redirects: bool,
    proxy: str | None,
    profile: RuntimeProfile,
    auto_calibrate: bool,
    calibration_samples: int,
    protocol_hint: str | None,
    scope_policy: ScopePolicy | None,
    throttle: RequestThrottle,
) -> BaselineSnapshot:
    body = _baseline_body_for_method(method)
    if protocol_hint == "http2":
        with make_client(timeout, verify, False, proxy, http2=True) as pclient:
            st, ln, _, baseline_sample, baseline_resp_headers, err = _fetch(
                pclient,
                method,
                target_url,
                headers,
                body,
                scope_policy=scope_policy,
                follow_redirects=follow_redirects,
                throttle=throttle,
            )
            calibration = (
                _calibrate_target(
                    pclient,
                    target_url,
                    headers,
                    samples=max(1, calibration_samples),
                    floor_delta=profile.length_delta,
                    method=method,
                    body=body,
                    protocol_hint=protocol_hint,
                    timeout=timeout,
                    verify=verify,
                    proxy=proxy,
                    scope_policy=scope_policy,
                    follow_redirects=follow_redirects,
                    throttle=throttle,
                )
                if auto_calibrate
                else {"enabled": False, "samples_ok": 0, "length_delta": profile.length_delta}
            )
    elif protocol_hint == "http1_0":
        st, ln, _, baseline_sample, baseline_resp_headers, err = _fetch_http10(
            method,
            target_url,
            headers,
            timeout=timeout,
            verify=verify,
            body=body,
            scope_policy=scope_policy,
            throttle=throttle,
        )
        calibration = (
            _calibrate_target(
                client,
                target_url,
                headers,
                samples=max(1, calibration_samples),
                floor_delta=profile.length_delta,
                method=method,
                body=body,
                protocol_hint=protocol_hint,
                timeout=timeout,
                verify=verify,
                proxy=proxy,
                scope_policy=scope_policy,
                follow_redirects=follow_redirects,
                throttle=throttle,
            )
            if auto_calibrate
            else {"enabled": False, "samples_ok": 0, "length_delta": profile.length_delta}
        )
    else:
        st, ln, _, baseline_sample, baseline_resp_headers, err = _fetch(
            client,
            method,
            target_url,
            headers,
            body,
            scope_policy=scope_policy,
            follow_redirects=follow_redirects,
            throttle=throttle,
        )
        calibration = (
            _calibrate_target(
                client,
                target_url,
                headers,
                samples=max(1, calibration_samples),
                floor_delta=profile.length_delta,
                method=method,
                body=body,
                protocol_hint=protocol_hint,
                timeout=timeout,
                verify=verify,
                proxy=proxy,
                scope_policy=scope_policy,
                follow_redirects=follow_redirects,
                throttle=throttle,
            )
            if auto_calibrate
            else {"enabled": False, "samples_ok": 0, "length_delta": profile.length_delta}
        )
    if err:
        st, ln = -1, 0
    return BaselineSnapshot(
        status_code=st,
        body_length=ln,
        body_sample=baseline_sample,
        calibration=calibration,
        response_headers=baseline_resp_headers,
        body_title=_extract_title(baseline_sample),
        content_type=baseline_resp_headers.get("content-type", ""),
    )


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
    domain_mode: bool = False,
    auth_challenges: bool = False,
    max_vhost_payloads: int = 30,
    auto_calibrate: bool = True,
    calibration_samples: int = 3,
    progress_callback: Callable[[int, int, TryResult, AnalysisResult], None] | None = None,
    scope_policy: ScopePolicy | None = None,
    rate_limit: float = 0.0,
    jitter_ms: int = 0,
    backoff_ms: int = 1000,
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
        domain_mode=domain_mode,
        auth_challenges=auth_challenges,
        max_vhost_payloads=max_vhost_payloads,
    )
    for s in specs:
        s.headers = {**base_hdrs, **s.headers}

    throttle = RequestThrottle(
        rate_per_second=max(rate_limit, 0.0),
        jitter_ms=max(jitter_ms, 0),
        backoff_ms=max(backoff_ms, 0),
    )

    with make_client(timeout, verify, False, proxy) as client:
        baseline = _fetch_baseline_snapshot(
            client,
            target_url=target_url,
            headers=base_hdrs,
            method="GET",
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
            proxy=proxy,
            profile=profile,
            auto_calibrate=auto_calibrate,
            calibration_samples=calibration_samples,
            protocol_hint=None,
            scope_policy=scope_policy,
            throttle=throttle,
        )
        baseline_cache: dict[BaselineKey, BaselineSnapshot] = {
            ("GET", "http1_1", "general"): baseline,
        }
        transport_baseline_cache: dict[tuple[str, str], BaselineSnapshot] = {
            _baseline_transport_key("GET", None): baseline,
        }

        results: list[tuple[TryResult, AnalysisResult]] = []
        total = len(specs)
        for idx, s in enumerate(specs, start=1):
            baseline_key = _baseline_key_for_spec(s)
            active_baseline = baseline_cache.get(baseline_key)
            if active_baseline is None:
                transport_key = _baseline_transport_key(s.method, s.protocol_hint)
                active_baseline = transport_baseline_cache.get(transport_key)
                if active_baseline is None:
                    active_baseline = _fetch_baseline_snapshot(
                        client,
                        target_url=target_url,
                        headers=base_hdrs,
                        method=s.method,
                        timeout=timeout,
                        verify=verify,
                        follow_redirects=follow_redirects,
                        proxy=proxy,
                        profile=profile,
                        auto_calibrate=auto_calibrate,
                        calibration_samples=calibration_samples,
                        protocol_hint=s.protocol_hint,
                        scope_policy=scope_policy,
                        throttle=throttle,
                    )
                    transport_baseline_cache[transport_key] = active_baseline
                baseline_cache[baseline_key] = active_baseline
            if s.protocol_hint == "http2":
                with make_client(timeout, verify, False, proxy, http2=True) as pclient:
                    st2, ln2, final, body_sample, resp_headers, err2 = _fetch(
                        pclient,
                        s.method,
                        s.url,
                        s.headers,
                        s.body,
                        scope_policy=scope_policy,
                        follow_redirects=follow_redirects,
                        throttle=throttle,
                    )
            elif s.protocol_hint == "http1_0":
                st2, ln2, final, body_sample, resp_headers, err2 = _fetch_http10(
                    s.method,
                    s.url,
                    s.headers,
                    timeout=timeout,
                    verify=verify,
                    body=s.body,
                    scope_policy=scope_policy,
                    throttle=throttle,
                )
            else:
                st2, ln2, final, body_sample, resp_headers, err2 = _fetch(
                    client,
                    s.method,
                    s.url,
                    s.headers,
                    s.body,
                    scope_policy=scope_policy,
                    follow_redirects=follow_redirects,
                    throttle=throttle,
                )
            tr = TryResult(
                spec=s,
                status_code=st2,
                body_length=ln2,
                final_url=final,
                error=err2,
                response_headers=resp_headers,
            )
            ar = analyze_result(
                active_baseline,
                tr,
                body_sample=body_sample,
                config=AnalyzerConfig(
                    length_delta=int(active_baseline.calibration.get("length_delta", profile.length_delta))
                ),
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
