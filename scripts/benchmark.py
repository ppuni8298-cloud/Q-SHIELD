"""Real performance & reliability benchmark suite (REQ-PERF-001).

Measures actual timing via time.perf_counter_ns with warmups, >=100 samples for lightweight ops,
memory delta/peak via tracemalloc, and exports reports/benchmarks/latest.{json,csv,md}.
Zero fabricated targets or placeholder metrics.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import secrets
import sys
import tempfile
import time
import tracemalloc
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy.orm import Session

from backend.app.audit.ledger import append_audit_event
from backend.app.audit.verifier import verify_ledger_db
from backend.app.auth.service import demo_login
from backend.app.backups.service import create_backup, verify_backup
from backend.app.crypto.aead import AES256GCMProvider
from backend.app.crypto.kdf import derive_key_hkdf_sha256
from backend.app.crypto.keystore import LocalEncryptedKeyStore
from backend.app.crypto.mldsa import MLDSA65Provider
from backend.app.crypto.mlkem import MLKEM768Provider
from backend.app.db.models import BenchmarkRun, User, utc_now
from backend.app.db.session import create_db_engine, create_session_factory
from backend.app.detector.dataset import generate_synthetic_evaluation_dataset
from backend.app.detector.evaluation import evaluate_benchmark_dataset
from backend.app.messaging.message_service import receive_and_decrypt_message, send_encrypted_message
from backend.app.messaging.session_manager import establish_messaging_session
from backend.app.policy.engine import ZeroTrustPolicyEngine
from backend.app.revocation.coordinator import issue_revocation_event
from backend.app.schemas.policy import PolicyEvalRequest
from backend.app.services.seed import seed_database
from backend.tests.conftest import run_alembic_upgrade


def _percentile(sorted_vals: list[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return round(sorted_vals[0], 4)
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(idx)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return round(sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (idx - lo), 4)


def _measure(
    name: str,
    category: str,
    samples: int,
    warmup: int,
    fn: Callable[[], None],
) -> dict[str, Any]:
    errors = 0
    for _ in range(warmup):
        try:
            fn()
        except Exception:
            errors += 1

    lat_ms: list[float] = []
    tracemalloc.start()
    start_all = time.perf_counter_ns()
    for _ in range(samples):
        t0 = time.perf_counter_ns()
        try:
            fn()
        except Exception:
            errors += 1
        lat_ms.append((time.perf_counter_ns() - t0) / 1_000_000.0)
    total_sec = max((time.perf_counter_ns() - start_all) / 1_000_000_000.0, 1e-9)
    _curr_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    lat_ms.sort()
    return {
        "operation": name,
        "category": category,
        "samples": samples,
        "warmup": warmup,
        "median_ms": _percentile(lat_ms, 50.0),
        "p95_ms": _percentile(lat_ms, 95.0),
        "min_ms": round(lat_ms[0], 4) if lat_ms else 0.0,
        "max_ms": round(lat_ms[-1], 4) if lat_ms else 0.0,
        "throughput_ops_sec": round(samples / total_sec, 2),
        "peak_traced_kib": round(peak_mem / 1024.0, 2),
        "errors": errors,
    }


def run_benchmark_suite(*, persist_db: Session | None = None, write_reports: bool = True) -> dict[str, Any]:
    """Execute full empirical benchmark suite and return structured report."""
    run_id = f"bench-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
    results: list[dict[str, Any]] = []

    # 1. Cryptographic micro-benchmarks (100+ samples each)
    pk_kem, sk_kem = MLKEM768Provider.generate_keypair()
    results.append(
        _measure(
            "ml_kem_768_encap_decap",
            "Cryptography",
            120,
            10,
            lambda: MLKEM768Provider.decapsulate(sk_kem, MLKEM768Provider.encapsulate(pk_kem)[0]),
        )
    )

    pk_dsa, sk_dsa = MLDSA65Provider.generate_keypair()
    msg_dsa = b"qshield-benchmark-audit-payload"
    results.append(
        _measure(
            "ml_dsa_65_sign_verify",
            "Cryptography",
            100,
            5,
            lambda: MLDSA65Provider.verify(pk_dsa, msg_dsa, MLDSA65Provider.sign(sk_dsa, msg_dsa)),
        )
    )

    ikm = secrets.token_bytes(32)
    results.append(
        _measure(
            "hkdf_sha256_derive",
            "Cryptography",
            200,
            20,
            lambda: derive_key_hkdf_sha256(ikm, salt=b"bench-salt", purpose="messaging", context={"s": 1}),
        )
    )

    aes_key = AES256GCMProvider.generate_dek()
    aead = AES256GCMProvider()
    pt_1k = b"A" * 1024
    pt_64k = b"B" * 65536
    results.append(
        _measure(
            "aes_256_gcm_1kib_roundtrip",
            "Cryptography",
            200,
            10,
            lambda: (lambda pair: aead.decrypt(aes_key, pair[0], pair[1], b"aad-1k"))(aead.encrypt(aes_key, pt_1k, b"aad-1k")),
        )
    )
    results.append(
        _measure(
            "aes_256_gcm_64kib_roundtrip",
            "Cryptography",
            100,
            5,
            lambda: (lambda pair: aead.decrypt(aes_key, pair[0], pair[1], b"aad-64k"))(aead.encrypt(aes_key, pt_64k, b"aad-64k")),
        )
    )

    # 2. Full DB/Control-plane benchmarks in isolated temp SQLite workspace
    with tempfile.TemporaryDirectory(prefix="qshield-bench-") as td_str:
        td = Path(td_str)
        url = run_alembic_upgrade(td / "bench.sqlite3")
        eng = create_db_engine(url, busy_timeout_ms=5000, wal_mode=True)
        fac = create_session_factory(eng)
        ks = LocalEncryptedKeyStore(td / "ks")
        bdir = td / "backups"
        try:
            with fac() as db:
                seed_database(db, reset=True, keystore=ks, backup_dir=bdir)
                engine = ZeroTrustPolicyEngine()

                results.append(
                    _measure(
                        "zero_trust_10step_policy_eval",
                        "Authorization",
                        120,
                        10,
                        lambda: engine.evaluate(
                            db,
                            PolicyEvalRequest(
                                actor_id="user-alex",
                                session_id="sess-alex-valid",
                                device_id="dev-alex-trusted",
                                resource_id="res-alex-brief",
                                action="read",
                            ),
                            correlation_id="corr-bench-pol",
                            record_decision=False,
                        ),
                    )
                )

                results.append(
                    _measure(
                        "auth_demo_login",
                        "Authentication",
                        100,
                        5,
                        lambda: demo_login(
                            db, actor_id="user-alex", device_id="dev-alex-trusted", correlation_id="corr-bench-auth"
                        ),
                    )
                )

                audit_idx = [0]

                def _do_audit() -> None:
                    audit_idx[0] += 1
                    append_audit_event(
                        db,
                        event_type="BENCH_EVENT",
                        event_category="AUDIT",
                        actor_id="user-secops",
                        action="bench_append",
                        target_type="bench",
                        target_id=f"b-{audit_idx[0]}",
                        outcome="ALLOW",
                        reason_code="OK",
                        correlation_id="corr-bench-aud",
                        source_component="bench_runner",
                    )

                results.append(_measure("audit_ledger_append", "Audit", 100, 5, _do_audit))
                results.append(_measure("audit_ledger_verify_chain", "Audit", 30, 3, lambda: verify_ledger_db(db)))

                sess, _, _ = establish_messaging_session(
                    db,
                    ks,
                    initiator_id="user-alex",
                    initiator_device_id="dev-alex-trusted",
                    recipient_id="user-blair",
                    recipient_device_id="dev-blair-trusted",
                    ttl_seconds=7200,
                    correlation_id="corr-bench-msg-sess",
                )

                def _msg_roundtrip() -> None:
                    m, _ = send_encrypted_message(
                        db,
                        ks,
                        session_id=sess.id,
                        sender_id="user-alex",
                        sender_device_id="dev-alex-trusted",
                        plaintext="benchmark encrypted payload",
                        correlation_id="corr-bench-msg",
                    )
                    receive_and_decrypt_message(
                        db,
                        ks,
                        message_id=m.message_id,
                        caller_id="user-blair",
                        caller_device_id="dev-blair-trusted",
                        correlation_id="corr-bench-msg",
                    )

                results.append(_measure("e2e_message_send_receive", "Messaging", 30, 3, _msg_roundtrip))

                secops = db.get(User, "user-secops")
                assert secops is not None
                results.append(
                    _measure(
                        "revocation_propagation_3nodes",
                        "Revocation",
                        15,
                        2,
                        lambda: issue_revocation_event(
                            db,
                            ks,
                            subject_type="session",
                            subject_id="sess-alex-revoked",
                            reason="Bench propagation",
                            confirmation=True,
                            acting_user=secops,
                            correlation_id="corr-bench-rev",
                        ),
                    )
                )

                results.append(
                    _measure(
                        "backup_create_and_verify",
                        "Backup",
                        10,
                        1,
                        lambda: verify_backup(
                            db,
                            ks,
                            create_backup(db, ks, backup_dir=bdir, actor_id="user-secops").backup_id,
                            actor_id="user-secops",
                        ),
                    )
                )
        finally:
            eng.dispose()

    # 3. Deterministic Detector Benchmark (322 events, 26 rules)
    ds = generate_synthetic_evaluation_dataset()
    results.append(
        _measure(
            "detector_322_events_26_rules",
            "ThreatDetector",
            30,
            3,
            lambda: evaluate_benchmark_dataset(ds),
        )
    )

    env_meta = {
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "cpu_count": os.cpu_count() or 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }

    report = {
        "run_id": run_id,
        "environment": env_meta,
        "workload_notes": "Measured empirically via time.perf_counter_ns on isolated SQLite WAL database & in-process crypto primitives.",
        "results": results,
    }

    if write_reports:
        rep_dir = ROOT / "reports" / "benchmarks"
        rep_dir.mkdir(parents=True, exist_ok=True)
        (rep_dir / "latest.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

        with (rep_dir / "latest.csv").open("w", encoding="utf-8", newline="") as fh:
            fields = ["operation", "category", "samples", "warmup", "median_ms", "p95_ms", "min_ms", "max_ms", "throughput_ops_sec", "peak_traced_kib", "errors"]
            writer = csv.DictWriter(fh, fieldnames=fields)
            writer.writeheader()
            for r in results:
                writer.writerow(r)

        md_lines = [
            f"# Q-SHIELD Empirical Performance Benchmarks (`{run_id}`)",
            "",
            f"- **Python:** `{env_meta['python_version']}` | **Platform:** `{env_meta['platform']}` | **CPUs:** `{env_meta['cpu_count']}`",
            f"- **Measured At:** `{env_meta['generated_at_utc']}`",
            "",
            "| Operation | Category | Samples | Median (ms) | P95 (ms) | Throughput (ops/s) | Peak Traced (KiB) | Errors |",
            "|---|---|---:|---:|---:|---:|---:|---:|",
        ]
        for r in results:
            md_lines.append(
                f"| `{r['operation']}` | {r['category']} | {r['samples']} | {r['median_ms']} | {r['p95_ms']} | {r['throughput_ops_sec']} | {r['peak_traced_kib']} | {r['errors']} |"
            )
        (rep_dir / "latest.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")

    if persist_db is not None:
        persist_db.add(
            BenchmarkRun(
                run_id=run_id,
                environment_metadata=json.dumps(env_meta, separators=(",", ":")),
                operation="full_benchmark_suite",
                stats_json=json.dumps(report, separators=(",", ":")),
                created_at=utc_now(),
            )
        )
        persist_db.commit()

    return report


if __name__ == "__main__":
    rep = run_benchmark_suite(write_reports=True)
    print(f"Benchmark suite complete: {rep['run_id']} ({len(rep['results'])} operations)")
    for row in rep["results"]:
        print(f"  {row['operation']:32s} median={row['median_ms']:8.4f}ms  p95={row['p95_ms']:8.4f}ms  ops/s={row['throughput_ops_sec']:10.2f}  err={row['errors']}")
