"""Configurable thresholds, baseline constants, and explicit rule catalog for the deterministic detector."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

DEFAULT_RULE_SET_VERSION = "1.0.0"

DEFAULT_ALLOWED_SERVICE_EDGES: tuple[tuple[str, str], ...] = (
    ("portal", "identity"),
    ("portal", "catalog"),
    ("portal", "auth"),
    ("portal", "vault"),
    ("portal", "reports"),
    ("reports", "catalog"),
    ("admin-console", "identity"),
    ("control-plane", "identity"),
    ("control-plane", "node"),
    ("control-plane", "vault"),
)

ROLE_PRIVILEGE_RANK: dict[str, int] = {
    "viewer": 1,
    "owner": 1,
    "service-reader": 1,
    "report-reader": 2,
    "auditor": 2,
    "security_operator": 3,
    "operator": 3,
    "admin": 4,
}


@dataclass(frozen=True)
class DetectorRuleSpec:
    rule_id: str
    category: str
    title: str
    severity: str
    base_weight: float
    recommended_response: str
    description: str


RULE_CATALOG: dict[str, DetectorRuleSpec] = {
    "RULE-ID-001": DetectorRuleSpec(
        rule_id="RULE-ID-001",
        category="IDENTITY_AUTH",
        title="Repeated authentication failures in sliding window",
        severity="HIGH",
        base_weight=0.80,
        recommended_response="Investigate identity credential abuse and inspect source device telemetry.",
        description="Triggers when denied/failed auth events for an actor >= auth_failure_threshold within auth_failure_window_sec.",
    ),
    "RULE-ID-002": DetectorRuleSpec(
        rule_id="RULE-ID-002",
        category="IDENTITY_AUTH",
        title="Rapid identity switching from same device/source",
        severity="HIGH",
        base_weight=0.78,
        recommended_response="Suspend shared source device pending review and verify actor bindings.",
        description="Triggers when distinct actor_ids >= identity_switch_threshold share a source device within identity_switch_window_sec.",
    ),
    "RULE-ID-003": DetectorRuleSpec(
        rule_id="RULE-ID-003",
        category="IDENTITY_AUTH",
        title="Unapproved privilege or role escalation",
        severity="CRITICAL",
        base_weight=0.92,
        recommended_response="Review unapproved role change evidence and obtain human authorization before reverting privilege.",
        description="Flags role change or privilege grant lacking a valid change-control approval covering subject, role, and timestamp.",
    ),
    "RULE-ID-004": DetectorRuleSpec(
        rule_id="RULE-ID-004",
        category="IDENTITY_AUTH",
        title="Revoked or disabled identity attempting access",
        severity="HIGH",
        base_weight=0.88,
        recommended_response="Investigate compromised token/caller attempting post-revocation identity use.",
        description="Flags repeated post-revocation/disabled identity access denials.",
    ),
    "RULE-ID-005": DetectorRuleSpec(
        rule_id="RULE-ID-005",
        category="IDENTITY_AUTH",
        title="Access outside actor baseline authorization scope",
        severity="MEDIUM",
        base_weight=0.68,
        recommended_response="Verify whether identity authorization scope changed legitimately.",
        description="Flags actor access targeting services outside historical per-identity baseline.",
    ),
    "RULE-DEV-001": DetectorRuleSpec(
        rule_id="RULE-DEV-001",
        category="DEVICE_SESSION",
        title="Revoked device attempting protected access",
        severity="CRITICAL",
        base_weight=0.90,
        recommended_response="Investigate physical loss/theft and verify replacement device re-enrollment audit trail.",
        description="Triggers on access/login attempts from an explicitly REVOKED device.",
    ),
    "RULE-DEV-002": DetectorRuleSpec(
        rule_id="RULE-DEV-002",
        category="DEVICE_SESSION",
        title="Unusual actor cardinality bound to a single device",
        severity="MEDIUM",
        base_weight=0.70,
        recommended_response="Audit device enrollment ownership bindings and revoke anomalous device sessions.",
        description="Triggers when distinct identities per device exceed device_identity_threshold.",
    ),
    "RULE-DEV-003": DetectorRuleSpec(
        rule_id="RULE-DEV-003",
        category="DEVICE_SESSION",
        title="Suspicious session creation burst",
        severity="HIGH",
        base_weight=0.76,
        recommended_response="Review session issuance burst and revoke excessive sessions with confirmation.",
        description="Triggers when login/session creation count >= session_burst_threshold within session_burst_window_sec.",
    ),
    "RULE-DEV-004": DetectorRuleSpec(
        rule_id="RULE-DEV-004",
        category="DEVICE_SESSION",
        title="Repeated use of expired or revoked sessions",
        severity="HIGH",
        base_weight=0.80,
        recommended_response="Investigate stolen session token replay and verify device trust state.",
        description="Triggers when SESSION_EXPIRED/SESSION_REVOKED denials repeat >= 2 times for an actor/session.",
    ),
    "RULE-DEV-005": DetectorRuleSpec(
        rule_id="RULE-DEV-005",
        category="DEVICE_SESSION",
        title="Unusual session activity using pre-cutoff key post-rotation",
        severity="HIGH",
        base_weight=0.84,
        recommended_response="Trigger authorized key review and inspect client session key rotation compliance.",
        description="Triggers when repeated OLD_KEY_CUTOFF_DENIAL / DENY_NODE_OLD_KEY_CUTOFF denials occur post-rotation.",
    ),
    "RULE-RES-001": DetectorRuleSpec(
        rule_id="RULE-RES-001",
        category="RESOURCE_ACCESS",
        title="Excessive protected-resource reads above baseline",
        severity="HIGH",
        base_weight=0.82,
        recommended_response="Inspect bulk resource reads for data exfiltration and review actor session.",
        description="Triggers on read rate >= excessive_reads_threshold in window OR modified MAD Z-score >= mad_z_threshold.",
    ),
    "RULE-RES-002": DetectorRuleSpec(
        rule_id="RULE-RES-002",
        category="RESOURCE_ACCESS",
        title="Rapid access across unrelated resource categories",
        severity="MEDIUM",
        base_weight=0.72,
        recommended_response="Review cross-category resource enumeration with resource owners.",
        description="Triggers when distinct resource categories >= category_diversity_threshold within category_window_sec.",
    ),
    "RULE-RES-003": DetectorRuleSpec(
        rule_id="RULE-RES-003",
        category="RESOURCE_ACCESS",
        title="Anomalous denied-to-allowed access ratio",
        severity="MEDIUM",
        base_weight=0.74,
        recommended_response="Investigate authorization probing by caller identity.",
        description="Triggers when denied/(denied+allowed) >= denied_to_allowed_ratio_threshold over min_ratio_samples.",
    ),
    "RULE-RES-004": DetectorRuleSpec(
        rule_id="RULE-RES-004",
        category="RESOURCE_ACCESS",
        title="Repeated attempts after authorization denial",
        severity="HIGH",
        base_weight=0.78,
        recommended_response="Review repeated denied attempts on protected resource.",
        description="Triggers on >= post_denial_retry_threshold denials targeting same resource within post_denial_window_sec.",
    ),
    "RULE-LAT-001": DetectorRuleSpec(
        rule_id="RULE-LAT-001",
        category="LATERAL_MOVEMENT",
        title="Multi-hop unexpected service-graph lateral movement",
        severity="CRITICAL",
        base_weight=0.90,
        recommended_response="Review lateral movement graph evidence and suspend compromised service/session after authorization.",
        description="Detects >= lateral_min_unexpected_hops unexpected directed service edges within lateral_window_sec; ignores isolated single denials.",
    ),
    "RULE-LAT-002": DetectorRuleSpec(
        rule_id="RULE-LAT-002",
        category="LATERAL_MOVEMENT",
        title="Sequential probing across privilege tiers",
        severity="HIGH",
        base_weight=0.82,
        recommended_response="Review cross-privilege probing evidence across target services.",
        description="Detects sequential probing of resources/services with distinct authorization requirements.",
    ),
    "RULE-LAT-003": DetectorRuleSpec(
        rule_id="RULE-LAT-003",
        category="LATERAL_MOVEMENT",
        title="Identity pivot from shared source following denials",
        severity="HIGH",
        base_weight=0.84,
        recommended_response="Investigate shared device/source identity pivot and isolate affected sessions.",
        description="Detects repeated denials under identity A followed within window by probes under identity B from same device.",
    ),
    "RULE-NOD-001": DetectorRuleSpec(
        rule_id="RULE-NOD-001",
        category="NODE_REVOCATION",
        title="Persistent post-revocation access hammering across nodes",
        severity="HIGH",
        base_weight=0.82,
        recommended_response="Verify node enforcement status and revoke remaining session tokens.",
        description="Detects persistent access attempts across nodes after revocation (>= 3 denials post-revocation).",
    ),
    "RULE-NOD-002": DetectorRuleSpec(
        rule_id="RULE-NOD-002",
        category="NODE_REVOCATION",
        title="Stale node or delayed convergence beyond tolerance",
        severity="HIGH",
        base_weight=0.80,
        recommended_response="Recheck node convergence and inspect network/partition state.",
        description="Detects STALE_NODE_DENIAL, UNSYNCHRONIZED nodes, or convergence lag exceeding stale_node_threshold_ms.",
    ),
    "RULE-NOD-003": DetectorRuleSpec(
        rule_id="RULE-NOD-003",
        category="NODE_REVOCATION",
        title="Conflicting node trust state or repeated propagation failures",
        severity="HIGH",
        base_weight=0.82,
        recommended_response="Recheck failing simulated node inbox and restart/re-sync node.",
        description="Detects repeated DROP_EVENTS/PROCESSING_ERROR propagation failures or divergent node convergence states.",
    ),
    "RULE-NOD-004": DetectorRuleSpec(
        rule_id="RULE-NOD-004",
        category="NODE_REVOCATION",
        title="Unexpected revocation-event ordering or rollback attempt",
        severity="HIGH",
        base_weight=0.84,
        recommended_response="Inspect audit ledger and revocation signer authenticity.",
        description="Detects out-of-order revocation sequence delivery or STALE_IGNORED rollback attempts.",
    ),
    "RULE-TMP-001": DetectorRuleSpec(
        rule_id="RULE-TMP-001",
        category="REPLAY_TEMPORAL",
        title="Malicious duplicate or replay pattern",
        severity="HIGH",
        base_weight=0.86,
        recommended_response="Inspect replay target session and revoke replayed session upon human authorization.",
        description="Detects duplicate/replay bursts exceeding max_legitimate_retries, post-revocation replay, or cross-actor event replay (excluding benign transient retries).",
    ),
    "RULE-TMP-002": DetectorRuleSpec(
        rule_id="RULE-TMP-002",
        category="REPLAY_TEMPORAL",
        title="Reused event identifier with divergent contents",
        severity="CRITICAL",
        base_weight=0.92,
        recommended_response="Verify audit ledger integrity and investigate event forgery.",
        description="Detects identical event_id appearing across events with different actor, action, target, or payload digest.",
    ),
    "RULE-TMP-003": DetectorRuleSpec(
        rule_id="RULE-TMP-003",
        category="REPLAY_TEMPORAL",
        title="Anomalous out-of-order sequence or arrival inversion",
        severity="MEDIUM",
        base_weight=0.70,
        recommended_response="Inspect collector timestamps vs raw source timestamps preserving uncertain_order.",
        description="Flags sequence inversions or event ordering anomalies exceeding bounded reorder_window_ms (does not flag minor benign delayed delivery).",
    ),
    "RULE-TMP-004": DetectorRuleSpec(
        rule_id="RULE-TMP-004",
        category="REPLAY_TEMPORAL",
        title="Unexplained clock skew beyond configured tolerance",
        severity="HIGH",
        base_weight=0.78,
        recommended_response="Audit NTP/clock calibration of source component and verify raw/corrected timelines.",
        description="Flags unexplained skew |event_time - source_clock_offset - received_time| > clock_skew_tolerance_ms or impossible future timestamps; documented offsets stay benign.",
    ),
    "RULE-TMP-005": DetectorRuleSpec(
        rule_id="RULE-TMP-005",
        category="REPLAY_TEMPORAL",
        title="Anomalous event burst inconsistent with simulation clock",
        severity="MEDIUM",
        base_weight=0.72,
        recommended_response="Investigate automated script/replay burst against simulation clock timeline.",
        description="Detects >= sim_burst_threshold events within <= 1s or sim_clock regression.",
    ),
}


@dataclass
class DetectorConfig:
    rule_set_version: str = DEFAULT_RULE_SET_VERSION
    auth_failure_threshold: int = 4
    auth_failure_window_sec: int = 300
    identity_switch_threshold: int = 3
    identity_switch_window_sec: int = 180
    device_identity_threshold: int = 3
    device_identity_window_sec: int = 600
    session_burst_threshold: int = 5
    session_burst_window_sec: int = 120
    expired_revoked_session_threshold: int = 2
    excessive_reads_threshold: int = 10
    excessive_reads_window_sec: int = 120
    mad_z_threshold: float = 3.5
    percentile_threshold: float = 95.0
    denied_to_allowed_ratio_threshold: float = 0.60
    min_ratio_samples: int = 5
    post_denial_retry_threshold: int = 3
    post_denial_window_sec: int = 180
    category_diversity_threshold: int = 3
    category_window_sec: int = 180
    lateral_min_unexpected_hops: int = 2
    lateral_window_sec: int = 300
    stale_node_threshold_ms: int = 500
    prop_failure_threshold: int = 2
    clock_skew_tolerance_ms: int = 1500
    reorder_window_ms: int = 5000
    max_legitimate_retries: int = 2
    sim_burst_threshold: int = 8
    sim_burst_window_ms: int = 1000
    allowed_service_edges: tuple[tuple[str, str], ...] = DEFAULT_ALLOWED_SERVICE_EDGES
    approvals: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["allowed_service_edges"] = [list(e) for e in self.allowed_service_edges]
        return d
