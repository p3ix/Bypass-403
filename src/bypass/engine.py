from __future__ import annotations

import asyncio
import hashlib
import http.client
import re
import socket
import ssl
from collections import Counter
from dataclasses import dataclass
from statistics import pstdev
from typing import Callable
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from bypass.analyzers.response_diff import AnalyzerConfig, analyze_result
from bypass.http_client import make_async_client, make_client
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
from bypass.safety import AsyncHostThrottle, RequestThrottle

DEFAULT_BYPASS_IPS = ["127.0.0.1", "::1", "10.0.0.1", "192.168.0.1", "0.0.0.0"]
COMBINE_LIMIT = 5000
LENGTH_DELTA = 40


@dataclass
class RuntimeProfile:
    name: str
    combine_limit: int
    length_delta: int


AGGRESSIVE_PROFILE = RuntimeProfile(name="aggressive", combine_limit=COMBINE_LIMIT, length_delta=LENGTH_DELTA)


@dataclass(frozen=True)
class ConnectOverride:
    host: str
    port: int
    connect_host: str
    connect_port: int


class PartialScanInterrupted(Exception):
    def __init__(self, results: list[tuple[TryResult, AnalysisResult]]) -> None:
        super().__init__("scan_interrupted")
        self.results = results


def _extract_title(body_sample: str) -> str:
    if not body_sample:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body_sample, flags=re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return " ".join(m.group(1).split())[:160]


def _detect_stack_profile(*, server_header: str, content_type: str, body_sample: str) -> str:
    s = (server_header or "").lower()
    ct = (content_type or "").lower()
    body = (body_sample or "").lower()
    blob = " ".join([s, ct, body])
    if any(x in blob for x in ("cloudflare", "__cf_bm", "cf-ray", "attention required")):
        return "cloudflare"
    if any(x in blob for x in ("akamai", "ak_bmsc", "ghost", "akamaighost")):
        return "akamai"
    if any(x in blob for x in ("nginx", "openresty")):
        return "nginx"
    if any(x in blob for x in ("iis", "asp.net", "x-aspnet-version", "microsoft-iis")):
        return "iis"
    if any(x in blob for x in ("envoy", "kong", "x-amzn", "api gateway", "apigw")):
        return "api-gateway"
    return "generic"


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


BaselineKey = tuple[str, str, str]


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


def _default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def _netloc(host: str, port: int, scheme: str) -> str:
    if ":" in host and not host.startswith("["):
        host_part = f"[{host}]"
    else:
        host_part = host
    return host_part if port == _default_port(scheme) else f"{host_part}:{port}"


def _has_header(headers: dict[str, str], name: str) -> bool:
    return any(k.lower() == name.lower() for k in headers)


def _header_value(headers: dict[str, str], name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _host_without_port(value: str) -> str:
    host = (value or "").strip()
    if not host:
        return ""
    if host.startswith("[") and "]" in host:
        return host[1:host.index("]")]
    if ":" in host and host.count(":") == 1:
        return host.rsplit(":", 1)[0]
    return host.rstrip(".")


def _apply_connect_override(
    url: str,
    headers: dict[str, str],
    connect_overrides: list[ConnectOverride] | None,
) -> tuple[str, dict[str, str]]:
    if not connect_overrides:
        return url, headers
    u = urlsplit(url)
    host = u.hostname
    if not host:
        return url, headers
    port = u.port or _default_port(u.scheme)
    for override in connect_overrides:
        if override.host.lower() != host.lower() or override.port != port:
            continue
        hdrs = dict(headers)
        original_host = _netloc(host, port, u.scheme)
        if not _has_header(hdrs, "host") and not _has_header(hdrs, ":authority"):
            hdrs["Host"] = original_host
        new_url = urlunsplit((
            u.scheme,
            _netloc(override.connect_host, override.connect_port, u.scheme),
            u.path,
            u.query,
            u.fragment,
        ))
        return new_url, hdrs
    return url, headers


def _connect_target(
    url: str,
    connect_overrides: list[ConnectOverride] | None,
) -> tuple[str, int, str, int]:
    u = urlsplit(url)
    host = u.hostname or ""
    port = u.port or _default_port(u.scheme)
    for override in connect_overrides or []:
        if override.host.lower() == host.lower() and override.port == port:
            return host, port, override.connect_host, override.connect_port
    return host, port, host, port


def _raw_header_lines_for_spec(spec: RequestSpec, default_host: str) -> list[tuple[str, str]]:
    source = spec.raw_header_lines or list(spec.headers.items())
    lines: list[tuple[str, str]] = []
    has_host = False
    authority_value = ""
    for key, value in source:
        if key.lower() == ":authority":
            authority_value = value
            continue
        if key.lower() == "host":
            has_host = True
        lines.append((key, value))
    if not has_host:
        lines.insert(0, ("Host", authority_value or default_host))
    if not any(k.lower() == "user-agent" for k, _ in lines):
        lines.append(("User-Agent", "bypass-tool/raw"))
    if not any(k.lower() == "connection" for k, _ in lines):
        lines.append(("Connection", "close"))
    if spec.body and not any(k.lower() == "content-length" for k, _ in lines):
        lines.append(("Content-Length", str(len(spec.body))))
    return lines


def _raw_sni_for_spec(spec: RequestSpec, original_host: str) -> str:
    host_header = _header_value(spec.headers, "host") or _header_value(spec.headers, ":authority")
    meta_host = ""
    if spec.host_payload is not None:
        meta = spec.host_payload.metadata.get("host")
        if isinstance(meta, str):
            meta_host = meta
    return _host_without_port(host_header or meta_host or original_host)


def _raw_request_bytes(spec: RequestSpec, default_host: str) -> bytes:
    u = urlsplit(spec.url)
    path_q = u.path or "/"
    if u.query:
        path_q = f"{path_q}?{u.query}"
    head = [f"{spec.method} {path_q} HTTP/1.1"]
    for key, value in _raw_header_lines_for_spec(spec, default_host):
        head.append(f"{key}: {value}")
    return ("\r\n".join(head) + "\r\n\r\n").encode("iso-8859-1", errors="replace") + (spec.body or b"")


def _parse_raw_response(data: bytes, final_url: str) -> tuple[int, int, str, str, dict[str, str], str | None]:
    if not data:
        return -1, 0, final_url, "", {}, "empty_response"
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1", errors="replace").splitlines()
    if not lines:
        return -1, 0, final_url, "", {}, "invalid_response"
    status_parts = lines[0].split()
    try:
        status = int(status_parts[1])
    except (IndexError, ValueError):
        return -1, 0, final_url, "", {}, "invalid_status_line"
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        low = key.strip().lower()
        if low in {"www-authenticate", "location", "server", "content-type"}:
            headers[low] = value.strip()
    body_sample = body[:400].decode("utf-8", errors="replace")
    return status, len(body), final_url, body_sample, headers, None


def _recv_raw_response(sock: socket.socket, *, max_bytes: int = 1024 * 1024) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while total < max_bytes:
        try:
            chunk = sock.recv(min(65536, max_bytes - total))
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        data = b"".join(chunks)
        head, marker, body = data.partition(b"\r\n\r\n")
        if marker:
            m = re.search(rb"(?im)^content-length:\s*(\d+)\s*$", head)
            if m and len(body) >= int(m.group(1)):
                break
            if re.search(rb"(?im)^connection:\s*close\s*$", head):
                continue
    return b"".join(chunks)


def _fetch_raw_spec(
    spec: RequestSpec,
    *,
    timeout: float,
    verify_tls: bool,
    throttle: RequestThrottle | None = None,
    connect_overrides: list[ConnectOverride] | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    u = urlsplit(spec.url)
    if not u.scheme or not u.hostname:
        return -1, 0, spec.url, "", {}, "invalid_url"
    original_host, original_port, connect_host, connect_port = _connect_target(
        spec.url, connect_overrides
    )
    default_host = _netloc(original_host, original_port, u.scheme)
    request_bytes = _raw_request_bytes(spec, default_host)
    sni = _raw_sni_for_spec(spec, original_host)
    try:
        if throttle is not None:
            throttle.before_request()
        raw_sock = socket.create_connection((connect_host, connect_port), timeout=timeout)
        raw_sock.settimeout(timeout)
        with raw_sock:
            active_sock: socket.socket | ssl.SSLSocket = raw_sock
            if u.scheme == "https":
                ctx = ssl.create_default_context()
                if not verify_tls:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                active_sock = ctx.wrap_socket(raw_sock, server_hostname=sni or None)
            active_sock.sendall(request_bytes)
            data = _recv_raw_response(active_sock)
        parsed = _parse_raw_response(data, spec.url)
        if throttle is not None:
            throttle.after_response(parsed[0])
        return parsed
    except Exception as e:
        return -1, 0, spec.url, "", {}, f"raw_socket:{e}"


async def _fetch_raw_spec_async(
    spec: RequestSpec,
    *,
    timeout: float,
    verify_tls: bool,
    throttle: AsyncHostThrottle | None = None,
    connect_overrides: list[ConnectOverride] | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    host_key = _host_key(spec.url)
    if throttle is not None:
        await throttle.before_request(host_key)
    result = await asyncio.to_thread(
        _fetch_raw_spec,
        spec,
        timeout=timeout,
        verify_tls=verify_tls,
        throttle=None,
        connect_overrides=connect_overrides,
    )
    if throttle is not None:
        await throttle.after_response(host_key, result[0])
    return result


def _uses_raw_transport(spec: RequestSpec) -> bool:
    return spec.smuggling_payload is not None or (
        spec.host_payload is not None and spec.protocol_hint in {None, "http1_1"}
    )


def compute_dynamic_length_delta(lengths: list[int], floor: int) -> int:
    if not lengths:
        return floor
    if len(lengths) == 1:
        return max(floor, 20)
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
    follow_redirects: bool = False,
    throttle: RequestThrottle | None = None,
    proxy: str | None = None,
    connect_overrides: list[ConnectOverride] | None = None,
) -> dict[str, object]:
    statuses: list[int] = []
    lengths: list[int] = []
    for url in _calibration_urls(target_url, samples):
        if protocol_hint == "http2":
            with make_client(timeout, verify, False, http2=True, proxy=proxy) as pclient:
                st, ln, _, _, _, err = _fetch(
                    pclient, method, url, headers, body,
                    follow_redirects=follow_redirects, throttle=throttle,
                    connect_overrides=connect_overrides,
                )
        elif protocol_hint == "http1_0":
            st, ln, _, _, _, err = _fetch_http10(
                method, url, headers, timeout=timeout, verify=verify, body=body, throttle=throttle,
                connect_overrides=connect_overrides,
            )
        else:
            st, ln, _, _, _, err = _fetch(
                client, method, url, headers, body,
                follow_redirects=follow_redirects, throttle=throttle,
                connect_overrides=connect_overrides,
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
    follow_redirects: bool = False,
    throttle: RequestThrottle | None = None,
    max_redirects: int = 5,
    connect_overrides: list[ConnectOverride] | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    h = dict(headers or {})
    try:
        active_url = url
        active_method = method
        active_body = body
        max_hops = max_redirects if follow_redirects else 0
        for redirect_hop in range(max_hops + 1):
            if throttle is not None:
                throttle.before_request()
            request_url, request_headers = _apply_connect_override(active_url, h, connect_overrides)
            request = client.build_request(
                active_method, request_url, headers=request_headers, content=active_body
            )
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


def _host_key(url: str) -> str:
    u = urlsplit(url)
    host = u.hostname or ""
    port = u.port or _default_port(u.scheme or "https")
    return f"{host.lower()}:{port}" if host else "default"


async def _fetch_async(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str] | None,
    body: bytes | None = None,
    follow_redirects: bool = False,
    throttle: AsyncHostThrottle | None = None,
    max_redirects: int = 5,
    connect_overrides: list[ConnectOverride] | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    h = dict(headers or {})
    try:
        active_url = url
        active_method = method
        active_body = body
        max_hops = max_redirects if follow_redirects else 0
        for redirect_hop in range(max_hops + 1):
            host_key = _host_key(active_url)
            if throttle is not None:
                await throttle.before_request(host_key)
            request_url, request_headers = _apply_connect_override(active_url, h, connect_overrides)
            request = client.build_request(
                active_method, request_url, headers=request_headers, content=active_body
            )
            r = await client.send(request, follow_redirects=False)
            if throttle is not None:
                await throttle.after_response(host_key, r.status_code)
            if not follow_redirects or not r.is_redirect:
                break
            if redirect_hop >= max_hops:
                return -1, 0, active_url, "", {}, "too_many_redirects"
            location = r.headers.get("location")
            if not location:
                break
            next_url = str(urljoin(str(r.url), location))
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
    throttle: RequestThrottle | None = None,
    connect_overrides: list[ConnectOverride] | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    try:
        hdrs = dict(headers or {})
        request_url, hdrs = _apply_connect_override(url, hdrs, connect_overrides)
        u = urlsplit(request_url)
        if not u.scheme or not u.netloc:
            return -1, 0, url, "", {}, "invalid_url"
        path_q = u.path or "/"
        if u.query:
            path_q = f"{path_q}?{u.query}"
        if not _has_header(hdrs, "host") and u.netloc:
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


async def _fetch_http10_async(
    method: str,
    url: str,
    headers: dict[str, str] | None,
    *,
    timeout: float,
    verify: bool,
    body: bytes | None = None,
    throttle: AsyncHostThrottle | None = None,
    connect_overrides: list[ConnectOverride] | None = None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    host_key = _host_key(url)
    if throttle is not None:
        await throttle.before_request(host_key)
    result = await asyncio.to_thread(
        _fetch_http10,
        method,
        url,
        headers,
        timeout=timeout,
        verify=verify,
        body=body,
        throttle=None,
        connect_overrides=connect_overrides,
    )
    if throttle is not None:
        await throttle.after_response(host_key, result[0])
    return result


def _build_specs(
    target_url: str,
    *,
    methods: list[str],
    bypass_ips: list[str] | None = None,
    host_fuzz_values: list[str] | None = None,
    smuggling_limit: int = 40,
    domain_mode: bool = False,
    max_vhost_payloads: int = 40,
) -> list[RequestSpec]:
    u = urlsplit(target_url)
    host = u.netloc.split("@")[-1].split(":")[0] if u.netloc else ""
    base_path = u.path or "/"
    scheme = u.scheme or "https"

    ips = bypass_ips if bypass_ips else DEFAULT_BYPASS_IPS
    path_variants = all_path_variants(target_url)
    header_sets = default_header_sets(base_path, host, scheme, bypass_ips=ips)
    method_sets = method_payloads()
    proto_sets = protocol_payloads()
    query_sets = query_mutations(target_url)
    host_sets = host_sni_payloads(canonical_host=host or "localhost", custom_hosts=host_fuzz_values)
    if domain_mode:
        host_sets = host_sets[: max(1, max_vhost_payloads)]
    smuggle_sets = smuggling_lite_payloads()
    domain_sets = domain_header_payloads(host or "localhost") if domain_mode else []
    auth_sets = auth_challenge_payloads()
    specs: list[RequestSpec] = []

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
                method=method, url=url, headers=hdrs,
                path_payload=path_p, header_payload=header_p,
            )
        )

    for m in methods:
        # Path + Header combos
        for pv in path_variants:
            for hdr_dict, hp in header_sets:
                add(m, pv.full_url, hdr_dict, pv.payload, hp)

        # Headers alone (with path overrides)
        for hdr_dict, hp in header_sets:
            request_url = target_url
            override_path = hp.metadata.get("request_path_override")
            if isinstance(override_path, str) and override_path:
                request_url = _url_with_path_override(override_path)
            add(m, request_url, hdr_dict, None, hp)

        # Domain headers
        if domain_mode:
            for hdrs, hp in domain_sets:
                specs.append(RequestSpec(
                    method=m, url=target_url, headers=hdrs,
                    header_payload=hp, family=str(hp.metadata.get("family", "redirect")),
                    target_type="domain",
                ))

        # Methods
        for method_name, hdrs, mp in method_sets:
            specs.append(RequestSpec(
                method=method_name, url=target_url, headers=hdrs,
                method_payload=mp,
                body=b"{}" if method_name in {"POST", "PUT", "PATCH"} else None,
            ))

        # Query mutations
        for q_url, qp in query_sets:
            specs.append(RequestSpec(method=m, url=q_url, headers={}, query_payload=qp))

        # Protocol variants
        for proto_hint, pp in proto_sets:
            specs.append(RequestSpec(
                method=m, url=target_url, headers={},
                protocol_payload=pp, protocol_hint=proto_hint,
            ))

        # Host/SNI fuzzing
        for hdrs, hp in host_sets:
            specs.append(RequestSpec(
                method=m, url=target_url, headers=hdrs,
                host_payload=hp, family=str(hp.metadata.get("family", "vhost")),
                target_type="domain" if domain_mode else "path",
            ))

        # Smuggling
        for hdrs, body, sp in smuggle_sets[: max(1, smuggling_limit)]:
            raw_header_lines = sp.metadata.get("raw_headers")
            specs.append(RequestSpec(
                method="POST", url=target_url, headers=hdrs,
                body=body, smuggling_payload=sp, family="smuggling",
                raw_header_lines=raw_header_lines if isinstance(raw_header_lines, list) else None,
                target_type="domain" if domain_mode else "path",
            ))

        # Auth challenges
        for hdrs, ap in auth_sets:
            specs.append(RequestSpec(
                method=m, url=target_url, headers=hdrs,
                header_payload=ap, family="auth-challenge",
                target_type="domain" if domain_mode else "path",
            ))

        # Guided combos: high-yield path + local-ip headers
        key_paths = [pv for pv in path_variants if pv.payload.id in {
            "midpath_iis", "encoded_slash_mid", "double_encoded_traversal",
        }]
        key_headers = [x for x in header_sets if x[1].id in {
            "h_x_forwarded_for", "h_x_real_ip", "h_x_orig_url_on_root", "h_x_rewrite_url_on_root",
        }]
        for pv in key_paths[:3]:
            for hdr_dict, hp in key_headers[:4]:
                specs.append(RequestSpec(
                    method=m, url=pv.full_url, headers=hdr_dict,
                    path_payload=pv.payload, header_payload=hp,
                ))

        # Guided combos: method-override + encoded paths
        encoded_paths = [pv for pv in path_variants if "encode" in pv.payload.id or "nullbyte" in pv.payload.id]
        override_methods = [mm for mm in method_sets if "override" in mm[2].id]
        for pv in encoded_paths[:2]:
            for method_name, mhdrs, mp in override_methods[:3]:
                specs.append(RequestSpec(
                    method=method_name, url=pv.full_url, headers=mhdrs,
                    path_payload=pv.payload, method_payload=mp,
                    body=b"{}" if method_name.upper() in {"POST", "PUT", "PATCH"} else None,
                ))

    if len(specs) > COMBINE_LIMIT:
        specs = specs[:COMBINE_LIMIT]
    return _dedupe_specs(specs)


def _stack_family_priority(stack_profile: str) -> dict[str, int]:
    # Lower value means executed earlier.
    if stack_profile == "cloudflare":
        return {
            "host": 0,
            "headers": 1,
            "query": 2,
            "path": 3,
            "protocol": 4,
            "methods": 5,
            "smuggling": 6,
            "auth-challenge": 7,
            "general": 8,
        }
    if stack_profile == "akamai":
        return {
            "headers": 0,
            "host": 1,
            "path": 2,
            "query": 3,
            "methods": 4,
            "protocol": 5,
            "smuggling": 6,
            "auth-challenge": 7,
            "general": 8,
        }
    if stack_profile == "nginx":
        return {
            "path": 0,
            "headers": 1,
            "host": 2,
            "query": 3,
            "methods": 4,
            "protocol": 5,
            "smuggling": 6,
            "auth-challenge": 7,
            "general": 8,
        }
    if stack_profile == "iis":
        return {
            "path": 0,
            "methods": 1,
            "headers": 2,
            "host": 3,
            "query": 4,
            "protocol": 5,
            "smuggling": 6,
            "auth-challenge": 7,
            "general": 8,
        }
    if stack_profile == "api-gateway":
        return {
            "host": 0,
            "headers": 1,
            "auth-challenge": 2,
            "query": 3,
            "path": 4,
            "methods": 5,
            "protocol": 6,
            "smuggling": 7,
            "general": 8,
        }
    return {
        "path": 0,
        "headers": 1,
        "host": 2,
        "query": 3,
        "methods": 4,
        "protocol": 5,
        "smuggling": 6,
        "auth-challenge": 7,
        "general": 8,
    }


def _spec_fingerprint(spec: RequestSpec) -> tuple[object, ...]:
    header_items = tuple(sorted((k.lower(), v) for k, v in spec.headers.items()))
    raw_header_items = tuple((k.lower(), v) for k, v in spec.raw_header_lines or [])
    body_digest = hashlib.sha256(spec.body or b"").hexdigest() if spec.body is not None else ""
    return (
        spec.method.upper(),
        spec.url,
        header_items,
        raw_header_items,
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
    profile: RuntimeProfile,
    calibration_samples: int,
    protocol_hint: str | None,
    throttle: RequestThrottle,
    proxy: str | None,
    connect_overrides: list[ConnectOverride] | None,
    body_override: bytes | None = None,
) -> BaselineSnapshot:
    body = body_override if body_override is not None else _baseline_body_for_method(method)
    if protocol_hint == "http2":
        with make_client(timeout, verify, False, http2=True, proxy=proxy) as pclient:
            st, ln, _, baseline_sample, baseline_resp_headers, err = _fetch(
                pclient, method, target_url, headers, body,
                follow_redirects=follow_redirects, throttle=throttle,
                connect_overrides=connect_overrides,
            )
            calibration = _calibrate_target(
                pclient, target_url, headers,
                samples=max(1, calibration_samples), floor_delta=profile.length_delta,
                method=method, body=body, protocol_hint=protocol_hint,
                timeout=timeout, verify=verify,
                follow_redirects=follow_redirects, throttle=throttle,
                proxy=proxy, connect_overrides=connect_overrides,
            )
    elif protocol_hint == "http1_0":
        st, ln, _, baseline_sample, baseline_resp_headers, err = _fetch_http10(
            method, target_url, headers, timeout=timeout, verify=verify, body=body, throttle=throttle,
            connect_overrides=connect_overrides,
        )
        calibration = _calibrate_target(
            client, target_url, headers,
            samples=max(1, calibration_samples), floor_delta=profile.length_delta,
            method=method, body=body, protocol_hint=protocol_hint,
            timeout=timeout, verify=verify,
            follow_redirects=follow_redirects, throttle=throttle,
            proxy=proxy, connect_overrides=connect_overrides,
        )
    else:
        st, ln, _, baseline_sample, baseline_resp_headers, err = _fetch(
            client, method, target_url, headers, body,
            follow_redirects=follow_redirects, throttle=throttle,
            connect_overrides=connect_overrides,
        )
        calibration = _calibrate_target(
            client, target_url, headers,
            samples=max(1, calibration_samples), floor_delta=profile.length_delta,
            method=method, body=body, protocol_hint=protocol_hint,
            timeout=timeout, verify=verify,
            follow_redirects=follow_redirects, throttle=throttle,
            proxy=proxy, connect_overrides=connect_overrides,
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


def _spec_priority_tuple(spec: RequestSpec, family_priority: dict[str, int]) -> tuple[int, str, str]:
    return (
        family_priority.get(_spec_family_name(spec), 50),
        spec.method,
        spec.url,
    )


def _verification_length_tolerance(original_len: int, baseline: BaselineSnapshot, profile: RuntimeProfile) -> int:
    calibrated = int(baseline.calibration.get("length_delta", profile.length_delta))
    dynamic = max(120, int(max(original_len, 1) * 0.10))
    return max(calibrated, dynamic)


def _same_status_bucket(left: int, right: int) -> bool:
    if left < 0 or right < 0:
        return left == right
    return left // 100 == right // 100


def _verification_success(
    original: TryResult,
    current: TryResult,
    fresh_baseline: BaselineSnapshot,
    current_analysis: AnalysisResult,
    *,
    profile: RuntimeProfile,
) -> tuple[bool, str]:
    if current.error:
        return False, "verification_request_error"
    if not current_analysis.interesting:
        return False, "verification_not_interesting"
    if current.status_code == fresh_baseline.status_code:
        return False, "verification_matches_fresh_baseline"
    if not _same_status_bucket(original.status_code, current.status_code):
        return False, "verification_status_bucket_changed"
    tolerance = _verification_length_tolerance(original.body_length, fresh_baseline, profile)
    if abs(original.body_length - current.body_length) > tolerance:
        return False, "verification_length_drift"
    return True, "verification_reproduced"


def _verify_fetch(
    client: httpx.Client,
    spec: RequestSpec,
    *,
    timeout: float,
    verify_tls: bool,
    follow_redirects: bool,
    throttle: RequestThrottle,
    proxy: str | None,
    connect_overrides: list[ConnectOverride] | None,
) -> tuple[int, int, str, str, dict[str, str], str | None]:
    if _uses_raw_transport(spec):
        return _fetch_raw_spec(
            spec,
            timeout=timeout,
            verify_tls=verify_tls,
            throttle=throttle,
            connect_overrides=connect_overrides,
        )
    if spec.protocol_hint == "http2":
        with make_client(timeout, verify_tls, False, http2=True, proxy=proxy) as pclient:
            return _fetch(
                pclient, spec.method, spec.url, spec.headers, spec.body,
                follow_redirects=follow_redirects, throttle=throttle,
                connect_overrides=connect_overrides,
            )
    if spec.protocol_hint == "http1_0":
        return _fetch_http10(
            spec.method, spec.url, spec.headers,
            timeout=timeout, verify=verify_tls, body=spec.body, throttle=throttle,
            connect_overrides=connect_overrides,
        )
    return _fetch(
        client, spec.method, spec.url, spec.headers, spec.body,
        follow_redirects=follow_redirects, throttle=throttle,
        connect_overrides=connect_overrides,
    )


def _verification_candidates(
    rows: list[tuple[TryResult, AnalysisResult]],
    limit: int,
) -> list[tuple[TryResult, AnalysisResult]]:
    candidates = [(r, a) for r, a in rows if a.interesting and not r.error]
    candidates.sort(key=lambda item: (item[1].score, item[0].body_length), reverse=True)
    return candidates[: max(0, limit)]


def _verify_findings(
    client: httpx.Client,
    target_url: str,
    rows: list[tuple[TryResult, AnalysisResult]],
    *,
    base_headers: dict[str, str],
    timeout: float,
    verify_tls: bool,
    follow_redirects: bool,
    profile: RuntimeProfile,
    calibration_samples: int,
    rate_limit: float,
    attempts: int,
    limit: int,
    proxy: str | None,
    connect_overrides: list[ConnectOverride] | None,
) -> None:
    if attempts <= 0 or limit <= 0:
        return
    throttle = RequestThrottle(
        rate_per_second=max(rate_limit, 0.0),
        jitter_ms=0,
        backoff_ms=1000,
    )
    for original, analysis in _verification_candidates(rows, limit):
        successes = 0
        seen_reasons: list[str] = []
        active_attempts = max(1, attempts)
        for _ in range(active_attempts):
            fresh_baseline = _fetch_baseline_snapshot(
                client,
                target_url=target_url,
                headers=base_headers,
                method=original.spec.method,
                timeout=timeout,
                verify=verify_tls,
                follow_redirects=follow_redirects,
                profile=profile,
                calibration_samples=max(1, calibration_samples),
                protocol_hint=original.spec.protocol_hint,
                throttle=throttle,
                proxy=proxy,
                connect_overrides=connect_overrides,
                body_override=original.spec.body,
            )
            st, ln, final, body_sample, resp_headers, err = _verify_fetch(
                client,
                original.spec,
                timeout=timeout,
                verify_tls=verify_tls,
                follow_redirects=follow_redirects,
                throttle=throttle,
                proxy=proxy,
                connect_overrides=connect_overrides,
            )
            current = TryResult(
                spec=original.spec,
                status_code=st,
                body_length=ln,
                final_url=final,
                error=err,
                response_headers=resp_headers,
            )
            current_analysis = analyze_result(
                fresh_baseline,
                current,
                body_sample=body_sample,
                config=AnalyzerConfig(
                    length_delta=int(
                        fresh_baseline.calibration.get("length_delta", profile.length_delta)
                    )
                ),
            )
            ok, reason = _verification_success(
                original,
                current,
                fresh_baseline,
                current_analysis,
                profile=profile,
            )
            if ok:
                successes += 1
            if reason not in seen_reasons:
                seen_reasons.append(reason)

        threshold = (active_attempts // 2) + 1
        analysis.verification_attempts = active_attempts
        analysis.verification_successes = successes
        analysis.verified = successes >= threshold
        analysis.verification_reasons = seen_reasons
        if analysis.verified:
            if "verified_reproducible" not in analysis.reasons:
                analysis.reasons.append("verified_reproducible")
            analysis.score += 10
            if analysis.confidence == "low":
                analysis.confidence = "medium"
        else:
            if "verification_failed" not in analysis.reasons:
                analysis.reasons.append("verification_failed")


async def _run_specs_async(
    specs: list[RequestSpec],
    transport_baseline_cache: dict[tuple[str, str], BaselineSnapshot],
    *,
    family_priority: dict[str, int],
    timeout: float,
    verify: bool,
    follow_redirects: bool,
    profile: RuntimeProfile,
    progress_callback: Callable[[int, int, TryResult, AnalysisResult], None] | None,
    rate_limit: float,
    concurrency: int,
    proxy: str | None,
    connect_overrides: list[ConnectOverride] | None,
) -> list[tuple[TryResult, AnalysisResult]]:
    total = len(specs)
    results: list[tuple[TryResult, AnalysisResult]] = []
    queue: asyncio.PriorityQueue[
        tuple[tuple[int, str, str], int, RequestSpec | None, BaselineSnapshot | None]
    ] = asyncio.PriorityQueue()
    for seq, spec in enumerate(specs):
        baseline = transport_baseline_cache[_baseline_transport_key(spec.method, spec.protocol_hint)]
        queue.put_nowait((_spec_priority_tuple(spec, family_priority), seq, spec, baseline))

    worker_count = max(1, min(concurrency, total or 1))
    for seq in range(worker_count):
        queue.put_nowait(((999, "", ""), total + seq, None, None))

    throttle = AsyncHostThrottle(
        rate_per_second=max(rate_limit, 0.0),
        jitter_ms=0,
        backoff_ms=1000,
    )
    done = 0

    try:
        async with (
            make_async_client(timeout, verify, False, proxy=proxy) as client,
            make_async_client(timeout, verify, False, http2=True, proxy=proxy) as http2_client,
        ):

            async def worker() -> None:
                nonlocal done
                while True:
                    _, _, spec, active_baseline = await queue.get()
                    try:
                        if spec is None or active_baseline is None:
                            return
                        if _uses_raw_transport(spec):
                            st2, ln2, final, body_sample, resp_headers, err2 = await _fetch_raw_spec_async(
                                spec,
                                timeout=timeout,
                                verify_tls=verify,
                                throttle=throttle,
                                connect_overrides=connect_overrides,
                            )
                        elif spec.protocol_hint == "http2":
                            st2, ln2, final, body_sample, resp_headers, err2 = await _fetch_async(
                                http2_client, spec.method, spec.url, spec.headers, spec.body,
                                follow_redirects=follow_redirects, throttle=throttle,
                                connect_overrides=connect_overrides,
                            )
                        elif spec.protocol_hint == "http1_0":
                            st2, ln2, final, body_sample, resp_headers, err2 = await _fetch_http10_async(
                                spec.method, spec.url, spec.headers,
                                timeout=timeout, verify=verify, body=spec.body, throttle=throttle,
                                connect_overrides=connect_overrides,
                            )
                        else:
                            st2, ln2, final, body_sample, resp_headers, err2 = await _fetch_async(
                                client, spec.method, spec.url, spec.headers, spec.body,
                                follow_redirects=follow_redirects, throttle=throttle,
                                connect_overrides=connect_overrides,
                            )

                        tr = TryResult(
                            spec=spec, status_code=st2, body_length=ln2,
                            final_url=final, error=err2, response_headers=resp_headers,
                        )
                        ar = analyze_result(
                            active_baseline, tr, body_sample=body_sample,
                            config=AnalyzerConfig(
                                length_delta=int(
                                    active_baseline.calibration.get(
                                        "length_delta", profile.length_delta
                                    )
                                )
                            ),
                        )
                        if spec.smuggling_payload and tr.status_code in {
                            400, 411, 413, 426, 431, 500, 501, 502, 503, 504,
                        }:
                            if "smuggling_suspected" not in ar.reasons:
                                ar.reasons.append("smuggling_suspected")
                            ar.score = max(ar.score, 55)
                            ar.interesting = True
                            ar.confidence = "medium" if ar.confidence == "none" else ar.confidence
                        results.append((tr, ar))
                        done += 1
                        if progress_callback:
                            progress_callback(done, total, tr, ar)
                    finally:
                        queue.task_done()

            tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
            try:
                await queue.join()
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError as exc:
        raise PartialScanInterrupted(results) from exc

    return results


def run_probe(
    target_url: str,
    *,
    methods: list[str] | None = None,
    timeout: float = 15.0,
    verify: bool = True,
    follow_redirects: bool = False,
    extra_headers: dict[str, str] | None = None,
    bypass_ips: list[str] | None = None,
    host_fuzz_values: list[str] | None = None,
    smuggling_limit: int = 40,
    domain_mode: bool = False,
    max_vhost_payloads: int = 40,
    calibration_samples: int = 5,
    progress_callback: Callable[[int, int, TryResult, AnalysisResult], None] | None = None,
    rate_limit: float = 0.0,
    body: bytes | None = None,
    proxy: str | None = None,
    connect_overrides: list[ConnectOverride] | None = None,
    concurrency: int = 20,
    verify_findings: bool = True,
    verify_attempts: int = 3,
    verify_limit: int = 20,
) -> tuple[BaselineSnapshot, list[tuple[TryResult, AnalysisResult]]]:
    profile = AGGRESSIVE_PROFILE
    methods = [x.upper() for x in (methods or ["GET"])]
    base_hdrs: dict[str, str] = dict(extra_headers or {})

    throttle = RequestThrottle(
        rate_per_second=max(rate_limit, 0.0),
        jitter_ms=0,
        backoff_ms=1000,
    )

    with make_client(timeout, verify, False, proxy=proxy) as client:
        baseline = _fetch_baseline_snapshot(
            client,
            target_url=target_url,
            headers=base_hdrs,
            method=methods[0] if body is not None and methods else "GET",
            timeout=timeout,
            verify=verify,
            follow_redirects=follow_redirects,
            profile=profile,
            calibration_samples=calibration_samples,
            protocol_hint=None,
            throttle=throttle,
            proxy=proxy,
            connect_overrides=connect_overrides,
            body_override=body,
        )
        stack_profile = _detect_stack_profile(
            server_header=baseline.response_headers.get("server", ""),
            content_type=baseline.response_headers.get("content-type", ""),
            body_sample=baseline.body_sample,
        )
        baseline.calibration["stack_profile"] = stack_profile
        specs = _build_specs(
            target_url,
            methods=methods,
            bypass_ips=bypass_ips,
            host_fuzz_values=host_fuzz_values,
            smuggling_limit=smuggling_limit,
            domain_mode=domain_mode,
            max_vhost_payloads=max_vhost_payloads,
        )
        family_priority = _stack_family_priority(stack_profile)
        specs.sort(
            key=lambda s: _spec_priority_tuple(s, family_priority)
        )
        for s in specs:
            s.headers = {**base_hdrs, **s.headers}
            if body is not None and s.body is None:
                s.body = body
        baseline_method = methods[0] if body is not None and methods else "GET"
        baseline_cache: dict[BaselineKey, BaselineSnapshot] = {
            (baseline_method.upper(), "http1_1", "general"): baseline,
        }
        transport_baseline_cache: dict[tuple[str, str], BaselineSnapshot] = {
            _baseline_transport_key(baseline_method, None): baseline,
        }

        total = len(specs)
        try:
            for s in specs:
                baseline_key = _baseline_key_for_spec(s)
                if baseline_key in baseline_cache:
                    continue
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
                        profile=profile,
                        calibration_samples=calibration_samples,
                        protocol_hint=s.protocol_hint,
                        throttle=throttle,
                        proxy=proxy,
                        connect_overrides=connect_overrides,
                        body_override=body,
                    )
                    transport_baseline_cache[transport_key] = active_baseline
                baseline_cache[baseline_key] = active_baseline

            baseline.calibration["concurrency"] = max(1, int(concurrency))
            baseline.calibration["queue"] = "async-priority"
            results = asyncio.run(
                _run_specs_async(
                    specs,
                    transport_baseline_cache,
                    family_priority=family_priority,
                    timeout=timeout,
                    verify=verify,
                    follow_redirects=follow_redirects,
                    profile=profile,
                    progress_callback=progress_callback,
                    rate_limit=rate_limit,
                    concurrency=max(1, int(concurrency)),
                    proxy=proxy,
                    connect_overrides=connect_overrides,
                )
            )
            if verify_findings:
                baseline.calibration["verification"] = {
                    "enabled": True,
                    "attempts": max(1, int(verify_attempts)),
                    "limit": max(0, int(verify_limit)),
                }
                _verify_findings(
                    client,
                    target_url,
                    results,
                    base_headers=base_hdrs,
                    timeout=timeout,
                    verify_tls=verify,
                    follow_redirects=follow_redirects,
                    profile=profile,
                    calibration_samples=calibration_samples,
                    rate_limit=rate_limit,
                    attempts=max(1, int(verify_attempts)),
                    limit=max(0, int(verify_limit)),
                    proxy=proxy,
                    connect_overrides=connect_overrides,
                )
            else:
                baseline.calibration["verification"] = {"enabled": False}
        except PartialScanInterrupted as exc:
            baseline.calibration["interrupted"] = True
            results = exc.results
            baseline.calibration["partial_results"] = len(results)
            baseline.calibration["planned_total"] = total
        except KeyboardInterrupt:
            baseline.calibration["interrupted"] = True
            results = []
            baseline.calibration["partial_results"] = 0
            baseline.calibration["planned_total"] = total

    return baseline, results
