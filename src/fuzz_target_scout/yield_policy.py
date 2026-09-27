from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def evaluate_campaign_yield(
    probe_run: dict[str, Any],
    progress: dict[str, Any],
    pipeline: dict[str, Any],
) -> dict[str, Any] | None:
    """Return a target-rotation decision when a campaign is demonstrably low yield."""
    if not bool(pipeline.get("low_yield_rotation_enabled", True)):
        return None
    minimum_seconds = max(0, int(pipeline.get("low_yield_min_seconds", 7200)))
    completed_seconds = max(0.0, float(progress.get("completed_seconds") or 0))
    if completed_seconds < minimum_seconds:
        return None

    baseline_edges = _metric(probe_run, "coverage_edges")
    baseline_features = _metric(probe_run, "coverage_features")
    best_edges = baseline_edges
    best_features = baseline_features
    accounted = 0.0
    last_advance_at = 0.0
    for session in progress.get("sessions") or []:
        if not isinstance(session, dict):
            continue
        duration = _session_duration(session)
        accounted += duration
        edges = _metric(session, "coverage_edges")
        features = _metric(session, "coverage_features")
        if edges > best_edges or features > best_features:
            last_advance_at = min(completed_seconds, accounted)
            best_edges = max(best_edges, edges)
            best_features = max(best_features, features)

    # Older progress files did not store an accounted duration per session.
    # Their aggregate completion time is still authoritative.
    trailing_stagnation = max(0.0, completed_seconds - last_advance_at)
    edge_growth = max(0, best_edges - baseline_edges)
    feature_growth = max(0, best_features - baseline_features)
    minimum_edges = max(0, int(pipeline.get("low_yield_min_coverage_edges", 750)))
    minimum_growth = max(0, int(pipeline.get("low_yield_min_edge_growth", 16)))
    minimum_feature_growth = max(
        0, int(pipeline.get("low_yield_min_feature_growth", 64))
    )
    stagnation_seconds = max(
        minimum_seconds,
        int(pipeline.get("low_yield_stagnation_seconds", 21600)),
    )
    reason = None
    if (
        best_edges < minimum_edges
        and edge_growth < minimum_growth
        and feature_growth < minimum_feature_growth
    ):
        reason = "shallow_reach"
    elif trailing_stagnation >= stagnation_seconds:
        reason = "coverage_stagnation"
    if reason is None:
        return None
    return {
        "schema_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "decision": "rotate_target",
        "reason": reason,
        "metrics": {
            "completed_seconds": round(completed_seconds, 3),
            "baseline_edges": baseline_edges,
            "best_edges": best_edges,
            "edge_growth": edge_growth,
            "baseline_features": baseline_features,
            "best_features": best_features,
            "feature_growth": feature_growth,
            "trailing_stagnation_seconds": round(trailing_stagnation, 3),
        },
        "thresholds": {
            "minimum_seconds": minimum_seconds,
            "minimum_coverage_edges": minimum_edges,
            "minimum_edge_growth": minimum_growth,
            "minimum_feature_growth": minimum_feature_growth,
            "stagnation_seconds": stagnation_seconds,
        },
    }


def _metric(value: dict[str, Any], name: str) -> int:
    return max(0, int(value.get(name) or 0))


def _session_duration(session: dict[str, Any]) -> float:
    accounted = session.get("accounted_seconds")
    if accounted is not None:
        return max(0.0, float(accounted or 0))
    if session.get("status") == "interrupted":
        return max(0.0, float(session.get("elapsed_seconds") or 0))
    return max(0.0, float(session.get("requested_seconds") or 0))
