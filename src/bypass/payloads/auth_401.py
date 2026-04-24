from __future__ import annotations

import base64

from bypass.models import Payload, PayloadCategory


def auth_challenge_payloads() -> list[tuple[dict[str, str], Payload]]:
    """
    Probes seguros de autenticacion para endpoints 401/403.
    No incluyen credenciales reales; solo variantes tipicas de challenge/edge behavior.
    """
    basic_guest = base64.b64encode(b"guest:guest").decode("ascii")
    basic_blank = base64.b64encode(b":").decode("ascii")
    rows: list[tuple[dict[str, str], Payload]] = [
        (
            {"Authorization": f"Basic {basic_blank}"},
            Payload(
                id="auth_basic_blank",
                category=PayloadCategory.HEADER,
                label="Authorization Basic vacío",
                metadata={"family": "auth-challenge", "auth_scheme": "Basic"},
            ),
        ),
        (
            {"Authorization": f"Basic {basic_guest}"},
            Payload(
                id="auth_basic_guest",
                category=PayloadCategory.HEADER,
                label="Authorization Basic guest:guest",
                metadata={"family": "auth-challenge", "auth_scheme": "Basic"},
            ),
        ),
        (
            {"Authorization": "Bearer test"},
            Payload(
                id="auth_bearer_test",
                category=PayloadCategory.HEADER,
                label="Authorization Bearer test",
                metadata={"family": "auth-challenge", "auth_scheme": "Bearer"},
            ),
        ),
        (
            {"Authorization": "Bearer null"},
            Payload(
                id="auth_bearer_null",
                category=PayloadCategory.HEADER,
                label="Authorization Bearer null",
                metadata={"family": "auth-challenge", "auth_scheme": "Bearer"},
            ),
        ),
        (
            {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAKAO5CAAAADw=="},
            Payload(
                id="auth_ntlm_negotiate",
                category=PayloadCategory.HEADER,
                label="Authorization NTLM negotiate",
                metadata={"family": "auth-challenge", "auth_scheme": "NTLM"},
            ),
        ),
        (
            {"Authorization": "Negotiate YIIBgQYGKwYBBQUCoIIBdTCCAXECAQ6i"},
            Payload(
                id="auth_negotiate_probe",
                category=PayloadCategory.HEADER,
                label="Authorization Negotiate probe",
                metadata={"family": "auth-challenge", "auth_scheme": "Negotiate"},
            ),
        ),
    ]
    return rows

