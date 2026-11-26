"""Independent tests for Phase 4 3-7 logical node simulator, revocation propagation, convergence, and fail-closed access."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from backend.app.db.models import NodeAcknowledgement, RevocationEvent
from backend.app.db.session import create_session_factory
from backend.app.services.seed import DEMO_SYNTHETIC_TOKENS


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_node_count_boundaries_min_max_invalid(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]

    # Minimum supported: 3 nodes
    r3 = client.post(
        "/api/v1/nodes/configure",
        json={"node_count": 3, "latencies_ms": [10, 20, 30], "reason": "Min node boundary"},
        headers=_auth(secops_tok),
    )
    assert r3.status_code == 200 and len(r3.json()) == 3

    # Maximum supported: 7 nodes
    r7 = client.post(
        "/api/v1/nodes/configure",
        json={"node_count": 7, "reason": "Max node boundary"},
        headers=_auth(secops_tok),
    )
    assert r7.status_code == 200 and len(r7.json()) == 7
    assert len({n["node_id"] for n in r7.json()}) == 7

    # Invalid node counts rejected
    for bad_count in (0, 1, 2, 8, 12):
        bad = client.post(
            "/api/v1/nodes/configure",
            json={"node_count": bad_count, "reason": "Invalid node count"},
            headers=_auth(secops_tok),
        )
        assert bad.status_code in (400, 422)


def test_unauthorized_revocation_rejected(client: TestClient) -> None:
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    auditor_tok = DEMO_SYNTHETIC_TOKENS["sess-auditor-valid"]
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]

    for tok in (alex_tok, auditor_tok):
        resp = client.post(
            "/api/v1/revocations",
            json={
                "subject_type": "device",
                "subject_id": "dev-blair-trusted",
                "reason": "Unauthorized attempt",
                "confirmation": True,
            },
            headers=_auth(tok),
        )
        assert resp.status_code == 403

    # Missing confirmation rejected
    unconfirmed = client.post(
        "/api/v1/revocations",
        json={
            "subject_type": "device",
            "subject_id": "dev-alex-trusted",
            "reason": "Missing confirmation",
            "confirmation": False,
        },
        headers=_auth(secops_tok),
    )
    assert unconfirmed.status_code == 400


def test_propagation_convergence_measurement_and_independent_node_state(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    blair_tok = DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]

    # Configure 4 nodes with deterministic latencies
    cfg = client.post(
        "/api/v1/nodes/configure",
        json={"node_count": 4, "latencies_ms": [10, 25, 60, 100], "reason": "Deterministic 4-node test"},
        headers=_auth(secops_tok),
    )
    assert cfg.status_code == 200

    # Before revocation, Alex can access resource through any converged node
    for nid in ("node-1", "node-2", "node-3", "node-4"):
        ok = client.post(
            f"/api/v1/nodes/{nid}/access",
            json={"resource_id": "res-alex-brief", "action": "read"},
            headers=_auth(alex_tok),
        )
        assert ok.status_code == 200 and ok.json()["decision"] == "ALLOW"

    # Issue device revocation with deterministic clock 1000ms
    rev = client.post(
        "/api/v1/revocations",
        json={
            "subject_type": "device",
            "subject_id": "dev-alex-trusted",
            "reason": "Lost device test",
            "confirmation": True,
            "sim_clock_ms": 1000,
            "auto_propagate": True,
        },
        headers=_auth(secops_tok),
    )
    assert rev.status_code == 201
    conv = rev.json()["convergence"]
    assert conv["total_nodes"] == 4
    assert conv["converged_nodes"] == 4
    assert conv["unsynchronized_nodes"] == 0
    assert conv["converged"] is True
    assert conv["convergence_time_ms"] == 100
    assert conv["p50_ms"] is not None and conv["p95_ms"] is not None and conv["p99_ms"] is not None

    # Every node retained independent local revocation state
    nodes = client.get("/api/v1/nodes", headers=_auth(secops_tok)).json()
    assert all("dev-alex-trusted" in n["local_revocations"]["device"] for n in nodes)

    # Revoked device denied across every node; peer Blair still succeeds on every node
    for nid in ("node-1", "node-2", "node-3", "node-4"):
        assert (
            client.post(
                f"/api/v1/nodes/{nid}/access",
                json={"resource_id": "res-alex-brief", "action": "read"},
                headers=_auth(alex_tok),
            ).status_code
            == 401  # Bound session also revoked at central state
        )
        assert (
            client.post(
                f"/api/v1/nodes/{nid}/access",
                json={"resource_id": "res-blair-ledger", "action": "read"},
                headers=_auth(blair_tok),
            ).status_code
            == 200
        )


def test_offline_nodes_partial_propagation_catchup_and_stale_fail_closed(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    blair_tok = DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]

    client.post(
        "/api/v1/nodes/configure",
        json={"node_count": 5, "latencies_ms": [10, 20, 30, 40, 50], "reason": "5-node offline test"},
        headers=_auth(secops_tok),
    )

    # Take node-3 and node-5 offline/partitioned BEFORE revocation
    client.post(
        "/api/v1/nodes/node-3/availability",
        json={"available": False, "fault_mode": "OFFLINE", "reason": "Simulated link loss"},
        headers=_auth(secops_tok),
    )
    client.post(
        "/api/v1/nodes/node-5/availability",
        json={"available": False, "fault_mode": "PARTITIONED", "reason": "Simulated partition"},
        headers=_auth(secops_tok),
    )

    # Issue revocation for Blair's device without touching Alex
    rev = client.post(
        "/api/v1/revocations",
        json={
            "subject_type": "device",
            "subject_id": "dev-blair-trusted",
            "reason": "Blair device lost while 2 nodes offline",
            "confirmation": True,
            "sim_clock_ms": 5000,
            "auto_propagate": True,
        },
        headers=_auth(secops_tok),
    )
    assert rev.status_code == 201
    partial = rev.json()["convergence"]
    ev_id = rev.json()["event"]["event_id"]

    # Partial propagation MUST NOT be reported as complete
    assert partial["converged"] is False
    assert partial["convergence_time_ms"] is None
    assert partial["converged_nodes"] == 3
    assert partial["unsynchronized_nodes"] == 2

    # Offline nodes visibly unsynchronized in sync endpoint
    sync_n3 = client.get("/api/v1/nodes/node-3/sync", headers=_auth(secops_tok)).json()
    assert sync_n3["node"]["sync_status"] == "UNSYNCHRONIZED"
    assert sync_n3["pending_inbox_count"] == 1

    # Offline node-3 and partitioned node-5 fail closed even for unaffected Alex!
    assert (
        client.post(
            "/api/v1/nodes/node-3/access",
            json={"resource_id": "res-alex-brief", "action": "read"},
            headers=_auth(alex_tok),
        ).status_code
        == 403
    )
    # Meanwhile converged node-1 allows unaffected Alex and denies revoked Blair
    assert (
        client.post(
            "/api/v1/nodes/node-1/access",
            json={"resource_id": "res-alex-brief", "action": "read"},
            headers=_auth(alex_tok),
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/api/v1/nodes/node-1/access",
            json={"resource_id": "res-blair-ledger", "action": "read"},
            headers=_auth(blair_tok),
        ).status_code
        == 401
    )

    # Reconnect node-3 at sim_clock_ms=5400 (still not caught up until propagate runs -> stale fail-closed!)
    client.post(
        "/api/v1/nodes/node-3/availability",
        json={"available": True, "fault_mode": "NONE", "reason": "Link restored, before catch-up"},
        headers=_auth(secops_tok),
    )
    stale_deny = client.post(
        "/api/v1/nodes/node-3/access",
        json={"resource_id": "res-alex-brief", "action": "read"},
        headers=_auth(alex_tok),
    )
    assert stale_deny.status_code == 403
    assert stale_deny.json()["error"]["code"] == "DENY_NODE_STALE_TRUST_STATE"

    # Reconnect node-5 as well and run deterministic catch-up propagation at sim_clock_ms=6000
    client.post(
        "/api/v1/nodes/node-5/availability",
        json={"available": True, "fault_mode": "NONE", "reason": "Partition healed"},
        headers=_auth(secops_tok),
    )
    prop = client.post("/api/v1/nodes/propagate", json={"sim_clock_ms": 6000}, headers=_auth(secops_tok))
    assert prop.status_code == 200

    final = client.get(f"/api/v1/revocations/events/{ev_id}/convergence", headers=_auth(secops_tok)).json()
    assert final["converged"] is True
    assert final["converged_nodes"] == 5
    # node-5 enforced at 6000 + 50ms latency - 5000ms start = 1050ms
    assert final["convergence_time_ms"] == 1050


def test_duplicate_idempotency_out_of_order_and_node_restart(client: TestClient, db_engine) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]

    # Issue seq 1 and seq 2
    ev1 = client.post(
        "/api/v1/revocations",
        json={"subject_type": "device", "subject_id": "dev-alex-pending", "reason": "seq 1", "confirmation": True, "sim_clock_ms": 1000},
        headers=_auth(secops_tok),
    ).json()["event"]
    ev2 = client.post(
        "/api/v1/revocations",
        json={"subject_type": "device", "subject_id": "dev-alex-suspended", "reason": "seq 2", "confirmation": True, "sim_clock_ms": 2000},
        headers=_auth(secops_tok),
    ).json()["event"]

    # Replay ev2 (duplicate delivery) -> DUPLICATE_IGNORED and ack count stays 1 per node
    dup = client.post(
        "/api/v1/nodes/propagate",
        json={"sim_clock_ms": 2500, "replay_event_id": ev2["event_id"]},
        headers=_auth(secops_tok),
    ).json()
    assert all(o["outcome"] == "DUPLICATE_IGNORED" for o in dup["outcomes"])

    factory = create_session_factory(db_engine)
    with factory() as db:
        ack_count = len(
            db.scalars(select(NodeAcknowledgement).where(NodeAcknowledgement.operation_id == ev2["event_id"])).all()
        )
        assert ack_count == 3

    # Out-of-order replay of ev1 after ev2 -> STALE_IGNORED and nodes keep last_event_seq == 2 & ev2 revocation
    ooo = client.post(
        "/api/v1/nodes/propagate",
        json={"sim_clock_ms": 2600, "deliver_out_of_order": True, "replay_event_id": ev1["event_id"]},
        headers=_auth(secops_tok),
    ).json()
    assert all(o["outcome"] == "STALE_IGNORED" for o in ooo["outcomes"])
    nodes = client.get("/api/v1/nodes", headers=_auth(secops_tok)).json()
    for n in nodes:
        assert n["last_event_seq"] == 2
        assert "dev-alex-suspended" in n["local_revocations"]["device"]

    # Restart node-1 -> persisted local revocations & epoch survive reload
    restarted = client.post("/api/v1/nodes/node-1/restart", headers=_auth(secops_tok)).json()
    assert restarted["last_event_seq"] == 2
    assert "dev-alex-suspended" in restarted["local_revocations"]["device"]
    assert restarted["sync_status"] == "CONVERGED"
    assert client.post("/api/v1/nodes/node-1/access", json={"resource_id": "res-alex-brief"}, headers=_auth(alex_tok)).status_code == 200


def test_revoked_actor_key_session_and_faulty_nodes_fail_closed_without_leaks(
    client: TestClient, db_engine
) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    alex_tok = DEMO_SYNTHETIC_TOKENS["sess-alex-valid"]
    blair_tok = DEMO_SYNTHETIC_TOKENS["sess-blair-valid"]

    # Encrypt Alex's resource first so we also test zero plaintext leakage after revocation!
    secret_text = "Phase4-Confidential-Payload-XYZ"
    assert (
        client.post(
            "/api/v1/resources/res-alex-brief/encrypt",
            json={"plaintext": secret_text},
            headers=_auth(alex_tok),
        ).status_code
        == 201
    )

    # 1. Node with DROP_EVENTS / PROCESSING_ERROR never claims convergence
    client.post(
        "/api/v1/nodes/node-2/availability",
        json={"available": True, "fault_mode": "DROP_EVENTS", "reason": "Drop fault"},
        headers=_auth(secops_tok),
    )
    client.post(
        "/api/v1/nodes/node-3/availability",
        json={"available": True, "fault_mode": "PROCESSING_ERROR", "reason": "Processing fault"},
        headers=_auth(secops_tok),
    )

    # 2. Revoke key-v1-active across nodes
    rev_key = client.post(
        "/api/v1/revocations",
        json={"subject_type": "key", "subject_id": "key-v1-active", "reason": "Key compromise", "confirmation": True, "sim_clock_ms": 3000},
        headers=_auth(secops_tok),
    )
    assert rev_key.status_code == 201
    assert rev_key.json()["convergence"]["converged"] is False

    # Node-1 (converged) denies encrypted decrypt because key-v1-active is revoked locally & centrally
    d_key = client.post(
        "/api/v1/nodes/node-1/access",
        json={"resource_id": "res-alex-brief", "action": "read", "decrypt": True},
        headers=_auth(alex_tok),
    )
    assert d_key.status_code == 403 and secret_text not in d_key.text

    # Node-2 (dropped) and Node-3 (failed) also fail closed with zero plaintext leaked
    for nid in ("node-2", "node-3"):
        d_fault = client.post(
            f"/api/v1/nodes/{nid}/access",
            json={"resource_id": "res-alex-brief", "action": "read", "decrypt": True},
            headers=_auth(alex_tok),
        )
        assert d_fault.status_code == 403 and secret_text not in d_fault.text

    # 3. Heal node-2 and node-3, test tampered RevocationEvent signature fails node processing
    client.post("/api/v1/nodes/node-2/availability", json={"available": True, "fault_mode": "NONE", "reason": "Heal"}, headers=_auth(secops_tok))
    client.post("/api/v1/nodes/node-3/availability", json={"available": True, "fault_mode": "NONE", "reason": "Heal"}, headers=_auth(secops_tok))
    client.post("/api/v1/nodes/propagate", json={"sim_clock_ms": 3500}, headers=_auth(secops_tok))

    # Tamper a newly queued event's SHA-256 digest before propagation -> nodes reject signature
    ev_unprop = client.post(
        "/api/v1/revocations",
        json={"subject_type": "session", "subject_id": "sess-blair-valid", "reason": "Session revoke", "confirmation": True, "sim_clock_ms": 4000, "auto_propagate": False},
        headers=_auth(secops_tok),
    ).json()["event"]

    # Blair's revoked session immediately denied everywhere
    assert client.post("/api/v1/nodes/node-1/access", json={"resource_id": "res-blair-ledger"}, headers=_auth(blair_tok)).status_code == 401

    factory = create_session_factory(db_engine)
    with factory() as db:
        db.execute(
            text("UPDATE revocation_events SET integrity_sha256 = '0000tampered' WHERE event_id = :eid"),
            {"eid": ev_unprop["event_id"]},
        )
        db.commit()

    prop_bad = client.post("/api/v1/nodes/propagate", json={"sim_clock_ms": 4100}, headers=_auth(secops_tok)).json()
    assert all(o["outcome"] == "FAILED_SIGNATURE" for o in prop_bad["outcomes"])

    # 4. Revoke actor (user-alex) via predefined/direct flow
    # First clear stale failed event via fresh node configure
    client.post("/api/v1/nodes/configure", json={"node_count": 3, "reason": "Clean cluster"}, headers=_auth(secops_tok))
    with factory() as db:
        bad_ev = db.get(RevocationEvent, ev_unprop["event_id"])
        if bad_ev:
            db.delete(bad_ev)
            db.commit()
    client.post("/api/v1/nodes/propagate", json={"sim_clock_ms": 4200}, headers=_auth(secops_tok))

    rev_actor = client.post(
        "/api/v1/revocations",
        json={"subject_type": "actor", "subject_id": "user-alex", "reason": "Actor compromised", "confirmation": True, "sim_clock_ms": 5000},
        headers=_auth(secops_tok),
    )
    assert rev_actor.status_code == 201 and rev_actor.json()["convergence"]["converged"] is True
    assert client.post("/api/v1/nodes/node-1/access", json={"resource_id": "res-alex-brief"}, headers=_auth(alex_tok)).status_code in (401, 403)
    node1 = client.get("/api/v1/nodes/node-1", headers=_auth(secops_tok)).json()
    assert "user-alex" in node1["local_revocations"]["actor"]


def test_predefined_node_scenarios_api(client: TestClient) -> None:
    secops_tok = DEMO_SYNTHETIC_TOKENS["sess-secops-valid"]
    for name, expected_status in (
        ("offline_and_catchup", "COMPLETED"),
        ("multi_offline", "PARTIAL"),
        ("duplicate_and_out_of_order", "COMPLETED"),
        ("drop_and_processing_failure", "PARTIAL"),
    ):
        resp = client.post(f"/api/v1/nodes/scenarios/{name}", headers=_auth(secops_tok))
        assert resp.status_code == 200, (name, resp.text)
        assert resp.json()["status"] == expected_status
