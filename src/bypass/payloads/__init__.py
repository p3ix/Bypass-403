"""Definición y extensión de catálogos de payloads (rutas, cabeceras, etc.)."""

from bypass.payloads import headers_403, host_sni_403, methods_403, paths_403, protocols_403, query_403, smuggling_lite

__all__ = [
    "headers_403",
    "host_sni_403",
    "methods_403",
    "paths_403",
    "protocols_403",
    "query_403",
    "smuggling_lite",
]
