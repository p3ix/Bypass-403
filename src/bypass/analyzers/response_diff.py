from __future__ import annotations

from dataclasses import dataclass

from bypass.models import AnalysisResult, BaselineSnapshot, TryResult


@dataclass
class AnalyzerConfig:
    length_delta: int = 50
    min_interesting_score: int = 35
    soft_403_tokens: tuple[str, ...] = (
        "access denied",
        "forbidden",
        "request blocked",
        "not authorized",
        "waf",
    )


def analyze_result(
    baseline: BaselineSnapshot,
    result: TryResult,
    *,
    body_sample: str = "",
    config: AnalyzerConfig | None = None,
) -> AnalysisResult:
    cfg = config or AnalyzerConfig()
    reasons: list[str] = []
    if result.error:
        return AnalysisResult(False, "none", ["request_error"], score=0)

    score = 0
    if result.status_code != baseline.status_code:
        reasons.append("status_changed")
        score += 45
    if abs(result.body_length - baseline.body_length) >= cfg.length_delta:
        reasons.append("length_changed")
        score += 25

    body_low = (body_sample or "").lower()
    if body_low:
        if any(token in body_low for token in cfg.soft_403_tokens):
            reasons.append("soft_403_marker")
            score -= 20
        if baseline.body_sample and body_low != baseline.body_sample.lower():
            reasons.append("body_sample_changed")
            score += 30

    # Calibracion: cuando el target tiene un status dominante de bloqueo, premiar salida de ese estado.
    dom_status = baseline.calibration.get("dominant_status")
    if isinstance(dom_status, int) and result.status_code != dom_status:
        reasons.append("deviates_from_calibration_status")
        score += 15

    # Si sigue en el mismo status y aparece firma de bloqueo, evitar sobrevalorar diffs de body.
    if (
        result.status_code == baseline.status_code
        and "length_changed" not in reasons
        and "soft_403_marker" in reasons
    ):
        return AnalysisResult(False, "none", reasons, score=0)

    # Si solo hay marcador de soft-403 y no hay cambios duros, no interesa.
    hard_signals = [r for r in reasons if r not in {"soft_403_marker"}]
    if not hard_signals:
        return AnalysisResult(False, "none", [], score=0)

    if score < 0:
        score = 0

    confidence = "low"
    if score >= 70:
        confidence = "high"
    elif score >= 45:
        confidence = "medium"
    interesting = score >= cfg.min_interesting_score
    return AnalysisResult(interesting, confidence if interesting else "none", reasons, score=score)
