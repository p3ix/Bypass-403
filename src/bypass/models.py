from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PayloadCategory(str, Enum):
    PATH = "path"
    HEADER = "header"
    METHOD = "method"
    QUERY = "query"
    PROTOCOL = "protocol"
    HOST = "host"
    SMUGGLING = "smuggling"


@dataclass(frozen=True)
class Payload:
    id: str
    category: PayloadCategory
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.id}: {self.label}"


@dataclass
class PathMutatorResult:
    path: str
    payload: Payload
    full_url: str


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str]
    path_payload: Payload | None = None
    header_payload: Payload | None = None
    method_payload: Payload | None = None
    query_payload: Payload | None = None
    protocol_payload: Payload | None = None
    host_payload: Payload | None = None
    smuggling_payload: Payload | None = None
    protocol_hint: str | None = None
    body: bytes | None = None
    family: str | None = None
    target_type: str = "path"


@dataclass
class TryResult:
    spec: RequestSpec
    status_code: int
    body_length: int
    final_url: str
    error: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)

    @property
    def ok_response(self) -> bool:
        return self.error is None


@dataclass
class BaselineSnapshot:
    status_code: int
    body_length: int
    body_sample: str = ""
    server_header: str = ""
    calibration: dict[str, Any] = field(default_factory=dict)
    response_headers: dict[str, str] = field(default_factory=dict)
    body_title: str = ""
    content_type: str = ""


@dataclass
class AnalysisResult:
    interesting: bool
    confidence: str
    reasons: list[str]
    score: int = 0
