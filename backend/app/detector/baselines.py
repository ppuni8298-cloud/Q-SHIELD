"""Transparent statistical baseline calculations (sliding windows, Median/MAD, percentiles, per-entity profiles).

Zero AI/ML, zero learned parameters, zero embeddings. Every formula is deterministic and inspectable.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
import math
from statistics import median
from typing import Sequence

from backend.app.detector.ingestion import NormalizedDetectorEvent


def compute_percentile(values: Sequence[float], pct: float) -> float | None:
    """Linear-interpolated percentile over sorted finite numeric samples."""
    if not values:
        return None
    s = sorted(float(v) for v in values)
    if len(s) == 1:
        return s[0]
    rank = (len(s) - 1) * (pct / 100.0)
    lo = int(math.floor(rank))
    hi = int(math.ceil(rank))
    if lo == hi:
        return s[lo]
    return s[lo] + (s[hi] - s[lo]) * (rank - lo)


def compute_median_and_mad(values: Sequence[float]) -> tuple[float, float]:
    """Compute sample median and Median Absolute Deviation (MAD = median(|x - median(x)|))."""
    if not values:
        return 0.0, 0.0
    vals = [float(v) for v in values]
    med = float(median(vals))
    abs_devs = [abs(x - med) for x in vals]
    mad = float(median(abs_devs))
    return med, mad


def modified_z_score(value: float, *, med: float, mad: float) -> float:
    """NIST / Iglewicz-Hoaglin modified Z-score: 0.6745 * (x - median) / MAD."""
    if mad <= 0.0:
        return 0.0 if value <= med else float("inf")
    return 0.6745 * (float(value) - med) / mad


@dataclass(frozen=True)
class ActorBaselineProfile:
    actor_id: str
    total_events: int
    allowed_count: int
    denied_count: int
    denied_ratio: float
    normal_services: frozenset[str]
    normal_categories: frozenset[str]


def compute_actor_baselines(events: Sequence[NormalizedDetectorEvent]) -> dict[str, ActorBaselineProfile]:
    """Build transparent per-identity statistical & categorical profiles over early/allow behavior."""
    by_actor: dict[str, list[NormalizedDetectorEvent]] = defaultdict(list)
    for ev in events:
        by_actor[ev.actor_id].append(ev)

    profiles: dict[str, ActorBaselineProfile] = {}
    for actor_id, actor_evs in by_actor.items():
        allowed = [e for e in actor_evs if e.outcome in ("ALLOW", "SUCCESS")]
        denied = [e for e in actor_evs if e.outcome in ("DENY", "FAIL", "FAILED", "ERROR")]
        denom = len(allowed) + len(denied)
        ratio = (len(denied) / denom) if denom > 0 else 0.0

        # Normal services / categories observed during allowed/routine activity (excluding elevated probes)
        svc_counts: dict[str, int] = defaultdict(int)
        cat_counts: dict[str, int] = defaultdict(int)
        for e in allowed:
            svc_counts[e.target_service] += 1
            cat_counts[e.resource_category] += 1
        profiles[actor_id] = ActorBaselineProfile(
            actor_id=actor_id,
            total_events=len(actor_evs),
            allowed_count=len(allowed),
            denied_count=len(denied),
            denied_ratio=round(ratio, 4),
            normal_services=frozenset(svc for svc, cnt in svc_counts.items() if cnt >= 1),
            normal_categories=frozenset(cat for cat, cnt in cat_counts.items() if cnt >= 1),
        )
    return profiles


def sliding_window_clusters(
    events: Sequence[NormalizedDetectorEvent],
    *,
    window_sec: int,
    min_count: int,
) -> list[list[NormalizedDetectorEvent]]:
    """Identify maximal non-overlapping sliding-window bursts of size >= min_count ordered by corrected time."""
    if len(events) < min_count:
        return []
    ordered = sorted(events, key=lambda e: (e.corrected_event_time_utc, e.event_id))
    win = timedelta(seconds=window_sec)
    clusters: list[list[NormalizedDetectorEvent]] = []
    i = 0
    while i < len(ordered):
        j = i
        while j < len(ordered) and (ordered[j].corrected_event_time_utc - ordered[i].corrected_event_time_utc) <= win:
            j += 1
        span = ordered[i:j]
        if len(span) >= min_count:
            clusters.append(span)
            i = j  # non-overlapping cluster emission for clean deduplication
        else:
            i += 1
    return clusters
