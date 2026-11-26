"""Runtime offline / network-isolation verification tests (REQ-SEC-001).

Blocks socket connections and urllib openers at runtime inside an isolated child process
to prove neither track4_service.py nor the Q-SHIELD backend requires internet/network access.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parents[2]
ADAPTER_ENTRY = REPO_ROOT / "track4_service.py"


def test_track4_adapter_runs_offline_with_sockets_blocked() -> None:
    """Block AF_INET/AF_INET6 socket creation in child process while running setup/read/revoke/audit."""
    runner = f"""
import socket, sys, runpy

def _deny_net(*args, **kwargs):
    raise OSError("NETWORK_BLOCKED_OFFLINE_TEST")

socket.socket = _deny_net
socket.create_connection = _deny_net
sys.path.insert(0, {str(REPO_ROOT)!r})
runpy.run_path({str(ADAPTER_ENTRY)!r}, run_name="__main__")
"""
    with tempfile.TemporaryDirectory() as td:
        env = os.environ.copy()
        env["TRACK4_STATE_DIR"] = td

        requests_and_checks = [
            (
                {
                    "op": "setup",
                    "owners": {"asset-1": "offline-user"},
                    "contents": {"asset-1": "offline-secret-body"},
                    "disabled": [],
                    "key_material": "synthetic-offline-demo-key-material",
                },
                lambda r: r.get("ready") is True,
            ),
            (
                {"op": "read", "actor": "offline-user", "asset": "asset-1", "request_id": "off-req-1"},
                lambda r: r.get("decision") == "allow" and r.get("body") == "offline-secret-body",
            ),
            (
                {"op": "revoke", "actor": "offline-user"},
                lambda r: isinstance(r, dict) and "error" not in r,
            ),
            (
                {"op": "read", "actor": "offline-user", "asset": "asset-1", "request_id": "off-req-2"},
                lambda r: r.get("decision") == "deny",
            ),
            (
                {"op": "audit", "request_id": "off-req-2"},
                lambda r: r.get("request_id") == "off-req-2" and r.get("decision") == "deny",
            ),
        ]

        for req, check_fn in requests_and_checks:
            proc = subprocess.run(
                [sys.executable, "-c", runner],
                input=(json.dumps(req) + "\n").encode("utf-8"),
                capture_output=True,
                env=env,
                timeout=10,
                check=False,
            )
            assert proc.returncode == 0, f"Offline adapter failed for {req}: {proc.stderr.decode('utf-8', 'replace')}"
            resp = json.loads(proc.stdout.decode("utf-8"))
            assert check_fn(resp), f"Unexpected offline adapter response for {req}: {resp}"


def test_backend_workflows_execute_with_network_monkeypatched(client: TestClient, monkeypatch) -> None:
    """Patch socket.create_connection and urllib.request.urlopen to fail on outbound network use."""
    import urllib.request

    def _deny(*args, **kwargs):
        raise RuntimeError("OUTBOUND_NETWORK_FORBIDDEN")

    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(urllib.request, "urlopen", _deny)

    # Full health -> ready -> selftest -> login -> encrypt -> decrypt flow succeeds completely offline
    assert client.get("/api/v1/health").status_code == 200
    assert client.get("/api/v1/ready").json()["ready"] is True

    sec_login = client.post("/api/v1/auth/demo-login", json={"actor_id": "user-secops", "device_id": "dev-secops-trusted"})
    assert sec_login.status_code == 200
    assert (
        client.get("/api/v1/crypto/selftest", headers={"Authorization": f"Bearer {sec_login.json()['access_token']}"}).json()["passed"]
        is True
    )

    login = client.post("/api/v1/auth/demo-login", json={"actor_id": "user-alex", "device_id": "dev-alex-trusted"})
    assert login.status_code == 200
    tok = login.json()["access_token"]
    hdr = {"Authorization": f"Bearer {tok}"}

    enc = client.post("/api/v1/resources/res-alex-brief/encrypt", json={"plaintext": "Offline protected payload"}, headers=hdr)
    assert enc.status_code == 201

    dec = client.post("/api/v1/resources/res-alex-brief/decrypt", headers=hdr)
    assert dec.status_code == 200
    assert dec.json()["plaintext"] == "Offline protected payload"
