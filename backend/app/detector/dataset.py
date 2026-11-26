"""Reproducible seeded synthetic detection evaluation dataset generator (seed=20261126).

Generates a balanced, multi-scenario labelled benchmark covering:
- Routine benign activity, legitimate retries, benign delayed delivery, documented clock offsets,
  approved role changes, and isolated single denials
- Attack scenarios: brute-force auth failures, identity switching, unapproved privilege escalation,
  revoked identity/device access, post-rotation old-key cutoff probing, excessive reads,
  multi-category probing, lateral movement graphs, node staleness/propagation failures,
  malicious replay, reused event_id, sequence inversion, and unexplained clock skew.

Labels live strictly in LabeledScenario truth metadata and NEVER enter detector scoring inputs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import random
from typing import Any

EVAL_DATASET_NAME = "qshield-synthetic-eval-benchmark"
EVAL_DATASET_VERSION = "qshield.eval.v1"
EVAL_DEFAULT_SEED = 20261126


@dataclass(frozen=True)
class EvaluationScenarioTruth:
    scenario_id: str
    category: str
    is_attack: bool
    expected_rule_prefixes: tuple[str, ...]
    start_time_utc: datetime
    event_ids: tuple[str, ...]


@dataclass(frozen=True)
class SyntheticEvaluationDataset:
    dataset_name: str
    dataset_version: str
    seed: int
    events: list[dict[str, Any]]
    approvals: list[dict[str, Any]]
    scenarios: list[EvaluationScenarioTruth]
    benign_event_ids: frozenset[str]


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def generate_synthetic_evaluation_dataset(seed: int = EVAL_DEFAULT_SEED) -> SyntheticEvaluationDataset:
    """Deterministically generate labeled evaluation events across benign & attack scenarios."""
    rng = random.Random(seed)
    base_time = datetime(2026, 11, 26, 10, 0, 0, tzinfo=timezone.utc)
    events: list[dict[str, Any]] = []
    approvals: list[dict[str, Any]] = []
    scenarios: list[EvaluationScenarioTruth] = []
    benign_ids: set[str] = set()

    ev_counter = 0

    def _next_id(prefix: str = "eval-evt") -> str:
        nonlocal ev_counter
        ev_counter += 1
        return f"{prefix}-{ev_counter:05d}"

    cursor = base_time

    # 1. Benign Routine Normal Activity (30 scenarios, 3 events each = 90 events)
    for b in range(30):
        st = cursor + timedelta(minutes=2 * b)
        actor = f"synth-user-normal-{b:02d}"
        dev = f"synth-dev-normal-{b:02d}"
        sess = f"synth-sess-normal-{b:02d}"
        sc_ids: list[str] = []
        for k, (src, tgt, act) in enumerate([("portal", "identity", "sign_in"), ("portal", "catalog", "read"), ("reports", "catalog", "read")]):
            eid = _next_id()
            sc_ids.append(eid)
            benign_ids.add(eid)
            t = st + timedelta(seconds=k * 5 + rng.randint(0, 2))
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(t),
                    "received_time_utc": _iso(t + timedelta(milliseconds=120)),
                    "source_clock_offset_ms": 0,
                    "actor_id": actor,
                    "device_id": dev,
                    "session_id": sess,
                    "resource_id": f"res-norm-{b % 5}",
                    "resource_category": "catalog_standard",
                    "source_service": src,
                    "target_service": tgt,
                    "action": act,
                    "outcome": "ALLOW",
                    "reason_code": "ALLOW_AUTHORIZED",
                    "correlation_id": f"corr-norm-{b:02d}",
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-routine-{b:02d}", "routine_benign", False, (), st, tuple(sc_ids)))

    # 2. Benign Legitimate Retries (8 scenarios, 2 events each = 16 events; same payload with is_retry_hint <= 2)
    cursor += timedelta(minutes=80)
    for r in range(8):
        st = cursor + timedelta(minutes=r)
        actor = f"synth-user-retry-{r:02d}"
        dev = f"synth-dev-retry-{r:02d}"
        sess = f"synth-sess-retry-{r:02d}"
        sc_ids = []
        for k in range(2):
            eid = _next_id()
            sc_ids.append(eid)
            benign_ids.add(eid)
            t = st + timedelta(seconds=k * 2)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(t),
                    "received_time_utc": _iso(t + timedelta(milliseconds=150)),
                    "source_clock_offset_ms": 0,
                    "actor_id": actor,
                    "device_id": dev,
                    "session_id": sess,
                    "resource_id": f"res-retry-{r}",
                    "resource_category": "catalog_standard",
                    "source_service": "portal",
                    "target_service": "catalog",
                    "action": "read",
                    "outcome": "ALLOW",
                    "reason_code": "RETRY_TRANSIENT_TIMEOUT" if k > 0 else "ALLOW_AUTHORIZED",
                    "is_retry_hint": k > 0,
                    "correlation_id": f"corr-retry-{r:02d}",
                    "payload": {"tx_seq": r},
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-retry-{r:02d}", "benign_retry", False, (), st, tuple(sc_ids)))

    # 3. Benign Approved Role Changes (6 scenarios, 1 event each = 6 events)
    cursor += timedelta(minutes=20)
    for a in range(6):
        st = cursor + timedelta(minutes=2 * a)
        actor = f"synth-user-appr-{a:02d}"
        app_id = f"chg-appr-{a:02d}"
        approvals.append(
            {
                "approval_id": app_id,
                "approved_by": "synth-admin",
                "subject": actor,
                "operation": "grant_role",
                "role": "report-reader",
                "scope": ["reports"],
                "valid_from_utc": _iso(st - timedelta(seconds=10)),
                "valid_until_utc": _iso(st + timedelta(minutes=10)),
            }
        )
        eid = _next_id()
        benign_ids.add(eid)
        events.append(
            {
                "event_id": eid,
                "event_time_utc": _iso(st),
                "received_time_utc": _iso(st + timedelta(milliseconds=90)),
                "source_clock_offset_ms": 0,
                "actor_id": actor,
                "device_id": f"synth-dev-appr-{a:02d}",
                "session_id": f"synth-sess-appr-{a:02d}",
                "source_service": "admin-console",
                "target_service": "identity",
                "event_type": "ROLE_CHANGED",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "report-reader",
                "approval_id": app_id,
                "outcome": "ALLOW",
                "reason_code": "ROLE_UPDATED",
                "correlation_id": f"corr-appr-{a:02d}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-approved-{a:02d}", "approved_role_change", False, (), st, (eid,)))

    # 4. Benign Delayed Delivery & Documented Clock Offset + Isolated Single Denial (16 scenarios, 2 events/isolated = 26 events)
    cursor += timedelta(minutes=20)
    for d in range(8):
        st = cursor + timedelta(minutes=d)
        actor = f"synth-user-delay-{d:02d}"
        # Delayed arrival within 5000ms + known clock offset +2000ms
        e_early = _next_id()
        e_late = _next_id()
        e_off = _next_id()
        benign_ids.update((e_early, e_late, e_off))
        # Deliver later event before earlier (1s apart <= 5s tolerance)
        events.append(
            {
                "event_id": e_late,
                "event_time_utc": _iso(st + timedelta(seconds=2)),
                "received_time_utc": _iso(st + timedelta(seconds=2, milliseconds=150)),
                "source_clock_offset_ms": 0,
                "actor_id": actor,
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "outcome": "ALLOW",
                "reason_code": "ALLOW_AUTHORIZED",
                "correlation_id": f"corr-delay-{d}",
            }
        )
        events.append(
            {
                "event_id": e_early,
                "event_time_utc": _iso(st + timedelta(seconds=1)),
                "received_time_utc": _iso(st + timedelta(seconds=3)),
                "source_clock_offset_ms": 0,
                "actor_id": actor,
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "outcome": "ALLOW",
                "reason_code": "ALLOW_AUTHORIZED",
                "correlation_id": f"corr-delay-{d}",
            }
        )
        events.append(
            {
                "event_id": e_off,
                "event_time_utc": _iso(st + timedelta(seconds=12)),
                "received_time_utc": _iso(st + timedelta(seconds=10, milliseconds=200)),
                "source_clock_offset_ms": 2000,
                "actor_id": actor,
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "outcome": "ALLOW",
                "reason_code": "ALLOW_AUTHORIZED",
                "correlation_id": f"corr-offset-{d}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-temporal-{d:02d}", "benign_delay_clock_offset", False, (), st, (e_late, e_early, e_off)))

    for iso_i in range(8):
        st = cursor + timedelta(minutes=10 + iso_i)
        eid = _next_id()
        benign_ids.add(eid)
        events.append(
            {
                "event_id": eid,
                "event_time_utc": _iso(st),
                "received_time_utc": _iso(st + timedelta(milliseconds=100)),
                "source_clock_offset_ms": 0,
                "actor_id": f"synth-user-isolated-{iso_i:02d}",
                "device_id": f"synth-dev-iso-{iso_i:02d}",
                "session_id": f"synth-sess-iso-{iso_i:02d}",
                "resource_id": f"res-billing-{iso_i}",
                "source_service": "portal",
                "target_service": "billing",
                "action": "read",
                "outcome": "DENY",
                "reason_code": "DENY_ROLE_PERMISSION_DENIED",
                "correlation_id": f"corr-iso-{iso_i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-isolated-{iso_i:02d}", "isolated_benign_denial", False, (), st, (eid,)))

    # ------------------------------------------------------------------
    # ATTACK SCENARIOS (10 attack scenario categories, 5 scenarios each = 50 attacks)
    # ------------------------------------------------------------------
    cursor += timedelta(minutes=30)

    # A1. Brute-force Auth Failures (5 scenarios * 5 events = 25)
    for i in range(5):
        st = cursor + timedelta(minutes=3 * i)
        actor = f"synth-atk-brute-{i:02d}"
        sc_ids = []
        for k in range(5):
            eid = _next_id()
            sc_ids.append(eid)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(st + timedelta(seconds=k * 4)),
                    "received_time_utc": _iso(st + timedelta(seconds=k * 4, milliseconds=80)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-brute-{i:02d}",
                    "source_service": "portal",
                    "target_service": "identity",
                    "event_type": "AUTH_LOGIN_FAILED",
                    "action": "demo_login",
                    "outcome": "DENY",
                    "reason_code": "IDENTITY_INACTIVE_OR_UNKNOWN",
                    "correlation_id": f"corr-brute-{i}-{k}",
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-bruteforce-{i:02d}", "brute_force_auth", True, ("RULE-ID-001",), st, tuple(sc_ids)))

    # A2. Revoked Device Access (5 scenarios * 1-2 events)
    cursor += timedelta(minutes=20)
    for i in range(5):
        st = cursor + timedelta(minutes=2 * i)
        eid = _next_id()
        events.append(
            {
                "event_id": eid,
                "event_time_utc": _iso(st),
                "received_time_utc": _iso(st + timedelta(milliseconds=50)),
                "actor_id": f"synth-atk-revdev-actor-{i:02d}",
                "device_id": f"synth-dev-lost-{i:02d}",
                "source_service": "portal",
                "target_service": "vault",
                "action": "read",
                "outcome": "DENY",
                "reason_code": "DENY_DEVICE_REVOKED",
                "correlation_id": f"corr-revdev-{i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-revoked-device-{i:02d}", "revoked_device_access", True, ("RULE-DEV-001",), st, (eid,)))

    # A3. Lateral Movement Graph Traversal (5 scenarios * 3 multi-hop unexpected edges)
    cursor += timedelta(minutes=15)
    for i in range(5):
        st = cursor + timedelta(minutes=3 * i)
        actor = f"synth-svc-worker-{i:02d}"
        sess = f"synth-sess-lat-{i:02d}"
        sc_ids = []
        for k, (src, tgt, act) in enumerate([("reports", "billing", "read"), ("billing", "archive", "read"), ("archive", "identity", "list_roles")]):
            eid = _next_id()
            sc_ids.append(eid)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(st + timedelta(seconds=k * 3)),
                    "received_time_utc": _iso(st + timedelta(seconds=k * 3, milliseconds=60)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-lat-{i:02d}",
                    "session_id": sess,
                    "source_service": src,
                    "target_service": tgt,
                    "action": act,
                    "outcome": "DENY",
                    "reason_code": "DENY_ROLE_PERMISSION_DENIED",
                    "correlation_id": f"corr-lat-{i}",
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-lateral-{i:02d}", "lateral_movement", True, ("RULE-LAT-001", "RULE-LAT-002"), st, tuple(sc_ids)))

    # A4. Malicious Replay Attempts (5 scenarios * 4 duplicates without retry hint)
    cursor += timedelta(minutes=20)
    for i in range(5):
        st = cursor + timedelta(minutes=2 * i)
        actor = f"synth-atk-replay-{i:02d}"
        sc_ids = []
        for k in range(4):
            eid = _next_id()
            sc_ids.append(eid)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(st + timedelta(seconds=k * 2)),
                    "received_time_utc": _iso(st + timedelta(seconds=k * 2, milliseconds=40)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-rep-{i:02d}",
                    "session_id": f"synth-sess-rep-{i:02d}",
                    "resource_id": f"res-rep-{i}",
                    "source_service": "portal",
                    "target_service": "catalog",
                    "action": "decrypt_resource",
                    "outcome": "DENY" if k > 0 else "ALLOW",
                    "reason_code": "REPLAY_DETECTED" if k > 0 else "DECRYPTION_AUTHORIZED",
                    "correlation_id": f"corr-rep-{i}",
                    "payload": {"msg_seq": 100 + i},
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-replay-{i:02d}", "malicious_replay", True, ("RULE-TMP-001",), st, tuple(sc_ids)))

    # A5. Unexplained Clock Skew (5 scenarios)
    cursor += timedelta(minutes=15)
    for i in range(5):
        st = cursor + timedelta(minutes=2 * i)
        eid = _next_id()
        events.append(
            {
                "event_id": eid,
                "event_time_utc": _iso(st + timedelta(seconds=25)),  # 25s ahead with 0 documented offset
                "received_time_utc": _iso(st),
                "source_clock_offset_ms": 0,
                "actor_id": f"synth-atk-skew-{i:02d}",
                "source_service": "portal",
                "target_service": "catalog",
                "action": "read",
                "outcome": "ALLOW",
                "reason_code": "ALLOW_AUTHORIZED",
                "correlation_id": f"corr-skew-{i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-clock-skew-{i:02d}", "unexplained_clock_skew", True, ("RULE-TMP-004",), st, (eid,)))

    # A6. Node Convergence / Stale Failures (5 scenarios)
    cursor += timedelta(minutes=15)
    for i in range(5):
        st = cursor + timedelta(minutes=2 * i)
        eid = _next_id()
        events.append(
            {
                "event_id": eid,
                "event_time_utc": _iso(st),
                "received_time_utc": _iso(st + timedelta(milliseconds=90)),
                "actor_id": f"synth-atk-stale-{i:02d}",
                "node_id": f"node-{(i % 3) + 1}",
                "source_service": "node_simulator",
                "target_service": "vault",
                "event_type": "STALE_NODE_DENIAL",
                "action": "node_access:read",
                "outcome": "DENY",
                "reason_code": "DENY_NODE_STALE_TRUST_STATE",
                "latency_ms": 1400 + i * 200,
                "correlation_id": f"corr-stale-{i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-stale-node-{i:02d}", "node_convergence_failure", True, ("RULE-NOD-002",), st, (eid,)))

    # A7. Unusual Excessive Resource Access (5 scenarios * 12 reads)
    cursor += timedelta(minutes=15)
    for i in range(5):
        st = cursor + timedelta(minutes=3 * i)
        actor = f"synth-atk-exfil-{i:02d}"
        sc_ids = []
        for k in range(12):
            eid = _next_id()
            sc_ids.append(eid)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(st + timedelta(seconds=k * 3)),
                    "received_time_utc": _iso(st + timedelta(seconds=k * 3, milliseconds=40)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-exfil-{i:02d}",
                    "session_id": f"synth-sess-exfil-{i:02d}",
                    "resource_id": f"res-exfil-{k:02d}",
                    "resource_category": "catalog_standard",
                    "source_service": "portal",
                    "target_service": "catalog",
                    "action": "read",
                    "outcome": "ALLOW",
                    "reason_code": "ALLOW_AUTHORIZED",
                    "correlation_id": f"corr-exfil-{i}-{k}",
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-excessive-reads-{i:02d}", "unusual_resource_access", True, ("RULE-RES-001",), st, tuple(sc_ids)))

    # A8. Unapproved Privilege Escalation (5 scenarios * 2 events)
    cursor += timedelta(minutes=20)
    for i in range(5):
        st = cursor + timedelta(minutes=2 * i)
        actor = f"synth-atk-priv-{i:02d}"
        e1 = _next_id()
        e2 = _next_id()
        events.append(
            {
                "event_id": e1,
                "event_time_utc": _iso(st),
                "received_time_utc": _iso(st + timedelta(milliseconds=50)),
                "actor_id": actor,
                "device_id": f"synth-dev-priv-{i:02d}",
                "session_id": f"synth-sess-priv-{i:02d}",
                "source_service": "admin-console",
                "target_service": "identity",
                "event_type": "ROLE_CHANGED",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "operator",
                "outcome": "ALLOW",
                "reason_code": "ROLE_UPDATED",
                "correlation_id": f"corr-priv-{i}",
            }
        )
        events.append(
            {
                "event_id": e2,
                "event_time_utc": _iso(st + timedelta(seconds=4)),
                "received_time_utc": _iso(st + timedelta(seconds=4, milliseconds=50)),
                "actor_id": actor,
                "device_id": f"synth-dev-priv-{i:02d}",
                "session_id": f"synth-sess-priv-{i:02d}",
                "source_service": "portal",
                "target_service": "reports",
                "action": "read",
                "outcome": "ALLOW",
                "reason_code": "ALLOW_AUTHORIZED",
                "correlation_id": f"corr-priv-{i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-priv-esc-{i:02d}", "privilege_escalation", True, ("RULE-ID-003",), st, (e1, e2)))

    # ------------------------------------------------------------------
    # VARIED BORDERLINE & HARDER SCENARIOS (no threshold gaming)
    # ------------------------------------------------------------------
    # B6. Benign Approved Multi-Service Workflow (3 scenarios, 2 events each = 6 benign events)
    cursor += timedelta(minutes=20)
    for i in range(3):
        st = cursor + timedelta(minutes=2 * i)
        actor = f"synth-user-wf-{i:02d}"
        approvals.append(
            {
                "approval_id": f"chg-wf-{i:02d}",
                "approved_by": "synth-admin",
                "subject": actor,
                "operation": "grant_role",
                "scope": ["partner_analytics", "ledger_export"],
                "valid_from_utc": _iso(st - timedelta(minutes=5)),
                "valid_until_utc": _iso(st + timedelta(minutes=15)),
            }
        )
        e1 = _next_id()
        e2 = _next_id()
        benign_ids.update((e1, e2))
        events.extend(
            [
                {
                    "event_id": e1,
                    "event_time_utc": _iso(st),
                    "received_time_utc": _iso(st + timedelta(milliseconds=80)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-wf-{i:02d}",
                    "session_id": f"synth-sess-wf-{i:02d}",
                    "source_service": "portal",
                    "target_service": "partner_analytics",
                    "action": "read",
                    "outcome": "ALLOW",
                    "reason_code": "ALLOW_AUTHORIZED",
                    "correlation_id": f"corr-wf-{i}",
                },
                {
                    "event_id": e2,
                    "event_time_utc": _iso(st + timedelta(seconds=5)),
                    "received_time_utc": _iso(st + timedelta(seconds=5, milliseconds=80)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-wf-{i:02d}",
                    "session_id": f"synth-sess-wf-{i:02d}",
                    "source_service": "partner_analytics",
                    "target_service": "ledger_export",
                    "action": "read",
                    "outcome": "ALLOW",
                    "reason_code": "ALLOW_AUTHORIZED",
                    "correlation_id": f"corr-wf-{i}",
                },
            ]
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-workflow-{i:02d}", "approved_custom_workflow", False, (), st, (e1, e2)))

    # B7. Benign Transient Typo Recovery (3 scenarios, 4 events each = 12 benign events: 3 failures < 4 threshold + 1 allow)
    cursor += timedelta(minutes=15)
    for i in range(3):
        st = cursor + timedelta(minutes=2 * i)
        actor = f"synth-user-typo-{i:02d}"
        sc_ids: list[str] = []
        for k in range(3):
            eid = _next_id()
            sc_ids.append(eid)
            benign_ids.add(eid)
            t = st + timedelta(seconds=k * 10)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(t),
                    "received_time_utc": _iso(t + timedelta(milliseconds=60)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-typo-{i:02d}",
                    "source_service": "portal",
                    "target_service": "identity",
                    "event_type": "AUTH_LOGIN_FAILED",
                    "action": "sign_in",
                    "outcome": "DENY",
                    "reason_code": "AUTH_BAD_CREDENTIALS",
                    "correlation_id": f"corr-typo-{i}",
                }
            )
        eid_ok = _next_id()
        sc_ids.append(eid_ok)
        benign_ids.add(eid_ok)
        t_ok = st + timedelta(seconds=35)
        events.append(
            {
                "event_id": eid_ok,
                "event_time_utc": _iso(t_ok),
                "received_time_utc": _iso(t_ok + timedelta(milliseconds=60)),
                "actor_id": actor,
                "device_id": f"synth-dev-typo-{i:02d}",
                "source_service": "portal",
                "target_service": "identity",
                "action": "sign_in",
                "outcome": "ALLOW",
                "reason_code": "ALLOW_AUTHORIZED",
                "correlation_id": f"corr-typo-{i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-benign-typo-{i:02d}", "benign_typo_recovery", False, (), st, tuple(sc_ids)))

    # A9. Expired Approval Window Role Change (3 scenarios, 1 event each = 3 attack events)
    cursor += timedelta(minutes=15)
    for i in range(3):
        st = cursor + timedelta(minutes=2 * i)
        actor = f"synth-atk-expchg-{i:02d}"
        app_id = f"chg-exp-{i:02d}"
        approvals.append(
            {
                "approval_id": app_id,
                "approved_by": "synth-admin",
                "subject": actor,
                "operation": "grant_role",
                "role": "operator",
                "valid_from_utc": _iso(st - timedelta(minutes=10)),
                "valid_until_utc": _iso(st),  # exclusive expiry == ev time -> invalid!
            }
        )
        eid = _next_id()
        events.append(
            {
                "event_id": eid,
                "event_time_utc": _iso(st),
                "received_time_utc": _iso(st + timedelta(milliseconds=50)),
                "actor_id": actor,
                "device_id": f"synth-dev-expchg-{i:02d}",
                "session_id": f"synth-sess-expchg-{i:02d}",
                "source_service": "admin-console",
                "target_service": "identity",
                "event_type": "ROLE_CHANGED",
                "action": "role_change",
                "role_before": "viewer",
                "role_after": "operator",
                "approval_id": app_id,
                "outcome": "ALLOW",
                "reason_code": "ROLE_UPDATED",
                "correlation_id": f"corr-expchg-{i}",
            }
        )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-expired-approval-{i:02d}", "expired_approval_escalation", True, ("RULE-ID-003",), st, (eid,)))

    # A10. Slow-Drip Credential Probing Across >300s Window (3 scenarios, 4 events * 180s apart = 12 attack events)
    # Intentionally spans 540s so default 300s window misses it (honest FN showcasing single-window limitation).
    cursor += timedelta(minutes=20)
    for i in range(3):
        st = cursor + timedelta(minutes=12 * i)
        actor = f"synth-atk-slowdrip-{i:02d}"
        sc_ids = []
        for k in range(4):
            eid = _next_id()
            sc_ids.append(eid)
            t = st + timedelta(seconds=k * 180)
            events.append(
                {
                    "event_id": eid,
                    "event_time_utc": _iso(t),
                    "received_time_utc": _iso(t + timedelta(milliseconds=70)),
                    "actor_id": actor,
                    "device_id": f"synth-dev-slow-{i:02d}",
                    "source_service": "portal",
                    "target_service": "identity",
                    "event_type": "AUTH_LOGIN_FAILED",
                    "action": "sign_in",
                    "outcome": "DENY",
                    "reason_code": "AUTH_BAD_CREDENTIALS",
                    "correlation_id": f"corr-slow-{i}-{k}",
                }
            )
        scenarios.append(EvaluationScenarioTruth(f"sc-atk-slowdrip-{i:02d}", "slow_drip_auth_probing", True, ("RULE-ID-001",), st, tuple(sc_ids)))

    return SyntheticEvaluationDataset(
        dataset_name=EVAL_DATASET_NAME,
        dataset_version=EVAL_DATASET_VERSION,
        seed=seed,
        events=events,
        approvals=approvals,
        scenarios=scenarios,
        benign_event_ids=frozenset(benign_ids),
    )
