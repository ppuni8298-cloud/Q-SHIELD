# Q-SHIELD — Security & Threat Model (Phase 0)

**Scope:** Synthetic identities, synthetic protected resources, local modular monolith, and deterministic 3–7 simulated nodes. Never target external systems or organizer infrastructure.

---

## 1. Protected Assets & Security Properties

| Asset | Security Property | Storage / Handling Boundary |
|---|---|---|
| Synthetic protected files & E2E message payloads | Confidentiality, Integrity, Authorized-Only Availability | Encrypted at rest (AES-256-GCM DEK/envelope) and in messaging AAD; never returned in deny/error responses or logs. |
| User, device & session identities | Authenticity, Binding, Non-Forging | SQLite normalized tables; session tokens stored hashed; device state versioned (`PENDING`, `TRUSTED`, `SUSPENDED`, `REVOKED`). |
| Cryptographic keys & key versions | Confidentiality (private/KEK/DEK), Integrity, Non-Reactivation | Encrypted local demo key store / sandbox-only path; `key_metadata` stores IDs/versions/states only; no secrets in API/UI/logs/repo. |
| Authorization policies & permissions | Integrity, Fail-Closed Enforcement | Backend 10-step zero-trust policy engine; zero frontend-only enforcement. |
| Node trust & revocation tombstones | Freshness, Monotonicity, Durability | `node_registry`, `node_acknowledgements`, `revocation_tombstones` surviving restarts and stale restores. |
| Backup archives & manifests | Integrity, Authenticity, Anti-Rollback | Signed/authenticated manifest + SHA-256 checksums + epoch validation against newer revocation tombstones. |
| Audit event ledger & checkpoints | Append-Only Integrity, Boundary Isolation, Secrecy | Canonical JSON + SHA-256 hash chain + optional ML-DSA checkpoints; secrets redacted; actor/action from server context. |
| Detector inputs & alerts | Integrity, Explainability, Bounded Memory | Schema-validated ingestion; bounded time window; rule/graph explanations without ML black boxes. |

---

## 2. Adversary Classes

1. **Unauthorized External/Unauthenticated Caller:** No valid session or owns no resource; attempts direct API/adapter reads or malformed input injection.
2. **Finder of a Lost Trusted Device:** Possesses a previously `TRUSTED` device credential/session before or right around operator revocation.
3. **Compromised Valid Identity / Stolen Session:** Holds valid credentials for one peer/role and attempts unauthorized privilege escalation, cross-peer session resumption, or lateral traversal across services.
4. **Malicious or Compromised Operator:** Attempts unauthorized role grants, secret exfiltration via logs/exports, or tampering with audit/backups.
5. **Stale / Partitioned Simulated Node:** Holds an outdated key version or misses revocation updates during partition/latency.
6. **Storage / Process Fault Adversary (Crash & Tamper):** Process crashes mid-rotation/revocation, or local storage/backup/audit files are corrupted/mutated in controlled tests.

---

## 3. Trust Boundaries

1. **Browser <-> FastAPI Backend:** Untrusted client input; all authn/authz, input validation, rate limiting, CORS/CSRF, and policy decisions enforced server-side.
2. **Toolkit Worker <-> Root Adapter (`track4_service.py`) <-> `$TRACK4_STATE_DIR`:** Single JSON stdin/stdout boundary; `stdout` strictly protocol output, `stderr` sanitized, state isolated to writable temp directory.
3. **User/Device <-> Zero-Trust Policy Engine:** Evaluates identity, session binding, device state, RBAC/ownership, key version, and incident status in strict order.
4. **Central Control Plane <-> Simulated Nodes:** Nodes verify authenticated/signed control events and monotonic epoch/sequence before applying state.
5. **Key Store <-> Cryptographic Vault:** Private/symmetric keys stay inside crypto provider boundary; callers receive key IDs, versions, ciphertexts, or HMAC proofs only.
6. **Event Ingestion <-> Audit Ledger & Detector:** Untrusted text normalized/escaped; actor/action resolved from authenticated server context; raw timestamps preserved separately from clock-corrected timelines.
7. **Sender <-> E2E Messaging Channel <-> Recipient:** Recipient binding, AAD integrity, replay sequence, and payload AEAD verified before releasing plaintext.

---

## 4. Threat Matrix (17 Required Threat Scenarios)

| ID | Threat / Attack Scenario | Potential Impact | Security Control | Implementation Module | Planned Verification Test |
|---|---|---|---|---|---|
| **TM-01** | **Stolen Device:** Finder uses a previously `TRUSTED` device after owner/operator reports device lost. | Unauthorized read of protected files or session continuation. | Operator revokes device (`REVOKED`), creates durable tombstone, revokes active device sessions, propagates to nodes; replacement re-enrollment issues new credential while old credential stays permanently blocked. | Device Registry, Revocation Coordinator, Policy Engine, Node Simulator | `tests/security/test_lost_device.py` + `validate.py` |
| **TM-02** | **Compromised Credentials / Unauthorized Escalation:** Attacker or malicious user grants self `operator`/`admin` role or accesses unapproved endpoints. | Full control-plane takeover or cross-tenant data access. | Backend RBAC on every endpoint, self-escalation forbidden, operator actions require role+reason+confirmation, detector flags unapproved privilege changes (`evt-008` pattern). | Identity & Access Policy, Explainable Detector | `tests/security/test_rbac_escalation.py` + `tests/detector/test_privilege_escalation.py` |
| **TM-03** | **Unauthorized Reads (Adapter & Vault):** Disabled user, non-owner, or pending/suspended device requests `read`, `protected_read`, or `/resources/{id}/access`. | Disclosure of protected file body, key material, or metadata snippets. | Ordered 10-step zero-trust pipeline; fail-closed `deny` returning no body/metadata/key; `validate.py` and API deny-leakage assertions. | Core Trust & AuthZ Engine, Root Adapter, Vault | `tests/adapter/test_contract.py` + `tests/security/test_vault_authz.py` |
| **TM-04** | **Stale Authorization / Stale Cache:** Read overlaps key rotation cutoff or revocation, or cached permission outlives revocation. | Old key or revoked actor succeeds post-cutoff (`old_key_post_cutoff > 0`). | Zero grace period default after `COMMIT`/`CUTOFF`; atomic DB state/epoch version checks; no unversioned cache; read-vs-revoke transactional locking. | Key Lifecycle, Revocation Coordinator, Policy Engine | `tests/security/test_race_revoke_read.py` + `tests/recovery/test_rotation_cutoff.py` |
| **TM-05** | **Delayed Revocation / Partitioned Node:** Simulated node lags or is partitioned during revocation broadcast. | Split-brain access where lagging node still honors revoked credential. | Nodes track `current_epoch`/ack; unreachable/lagging nodes marked `not converged` and configured to fail closed; convergence lag (`last_node_enforced_at - revoke_started_at`) measured. | Revocation Coordinator, Simulated Nodes | `tests/recovery/test_node_convergence_partition.py` |
| **TM-06** | **Replayed Messages:** Attacker resends previously captured valid E2E ciphertext or adapter/API message. | Duplicate state execution or message spoofing. | Receiver maintains durable `replay_records` ledger (`recipient`, `session`, `message_id`, `sequence`); duplicate IDs or repeated/stale sequences rejected before decrypt/delivery. | Secure Messaging & Session Manager | `tests/messaging/test_replay_and_binding.py` |
| **TM-07** | **Tampered / Injected Audit Records:** Attacker edits, deletes, reorders audit rows, or injects `\n`/JSON-like text in untrusted fields to forge actor/event. | Loss of forensic integrity or forged compliance records. | Canonical JSON serialization + SHA-256 hash chain + optional ML-DSA checkpoints; CR/LF/control char escaping; server-side actor/action enums; strict chain verifier. | Audit & Evidence Engine | `tests/security/test_audit_integrity_injection.py` |
| **TM-08** | **Malformed Events / Inputs:** Truncated JSON, NaN, oversized payloads, path traversal IDs (`../../etc/passwd`), bad Base64/key sizes in `protected_read` or detector CSV. | Crashes, path traversal, or secret stack-trace leakage. | Strict Pydantic/schema validation, `allow_nan=False`, opaque string validation (no filesystem path interpolation), bounded payload sizes, sanitized `stderr`/HTTP errors. | Root Adapter, REST API, Detector Parser | `tests/adapter/test_malformed.py` + `tests/detector/test_malformed_events.py` |
| **TM-09** | **Clock Manipulation / Skew:** Source clocks skewed forward/backward (`+2000ms` as in `evt-015`) or events arrive out of order (`evt-014` before `evt-013`). | False lateral-movement alerts, missed time-window detections, or corrupted forensic timelines. | Preserve raw `event_time_utc` and `received_time_utc`; apply configured/measured `source_clock_offset_ms`; configurable bounded reorder window (`5s` default); flag `uncertain_order` when intervals overlap. | Deterministic Threat Detector | `tests/detector/test_clock_skew_reordering.py` |
| **TM-10** | **Node Failures (Crash / Partition / Out-of-Order Control Msg):** Simulated node drops offline, restarts, or receives stale epoch update after newer revocation. | Node reverts to trusting revoked key or reports false convergence. | Monotonic epoch/sequence verification per node; stale/out-of-order updates ignored; partitioned nodes report `not converged` and fail closed; reconciliation restores tombstones. | Simulated Nodes, Revocation Coordinator | `tests/recovery/test_node_faults.py` |
| **TM-11** | **Process Crashes Mid-Operation:** Backend or adapter process crashes during `PREPARE`, backup, node ack, pre-`COMMIT`, post-`COMMIT`, `RETIRE`, or post-tombstone. | Half-rotated key state, lost revocation, or corrupted DB file. | SQLite WAL + atomic transactions + durable `rotation_operations` journal + `revocation_tombstones`; deterministic recovery rules never reactivate revoked/compromised keys. | Key Lifecycle, Crash Recovery Manager | `tests/recovery/test_crash_matrix.py` |
| **TM-12** | **Backup Tampering / Stale Backup Restore:** Attacker flips bytes in backup, substitutes wrong key/truncated file, or restores pre-revocation backup. | Unverified/corrupt key loaded or revoked actor/key resurrected. | Authenticated/signed `backup_manifests` + SHA-256 digest verification before load; reject tampered/wrong-key/incomplete/stale backups; tombstones survive restore. | Backup Manager, Recovery Manager | `tests/recovery/test_backup_integrity.py` |
| **TM-13** | **Key Exposure / Secret Leakage:** `key_material`, `shared_secret`, private keys, DEKs, or tokens printed in `stdout`, `stderr`, API responses, DB metadata, or repo. | Compromise of cryptographic confidentiality and validator failure (`fake key stays out of output`). | No secrets in `key_metadata` or logs; redaction filter on structured logging/audit export; encrypted local key store / sandbox isolation; secret scanning in `security_checks.sh`. | Cryptographic Vault, Adapter, Audit, Config | `tests/security/test_secret_leakage.py` + `validate.py` |
| **TM-14** | **Lateral Movement with Valid Credentials:** Compromised service account (`svc-report-worker`) traverses unexpected service edges (`reports -> billing -> archive -> identity`). | Silent privilege discovery and unauthorized cross-service access. | Time-windowed directed service-edge graph + role/scope allowlist; flags multi-hop unexpected paths (`evt-010..012`) while suppressing isolated denials (`evt-020`) and approved admin paths. | Deterministic Threat Detector | `tests/detector/test_lateral_movement.py` |
| **TM-15** | **Unauthorized Session Resumption:** Different actor/device attempts to present another peer's valid session/resumption token ID. | Session hijacking across peers. | Resumption tokens cryptographically protected, expiry-checked, and bound to `(actor_id, device_id, peer_id)`; fresh 10-step policy check on resume; cross-identity reuse fails closed. | Session Manager, Policy Engine | `tests/messaging/test_session_resumption.py` |
| **TM-16** | **Information Leakage via Recipient/AAD Tampering:** Attacker alters recipient header or ciphertext/nonce/tag in E2E message or `protected_read`. | Wrong party decrypts message or oracle leak reveals plaintext. | Recipient identity checked against verified policy & authenticated AAD before decryption; AEAD tag failure releases zero plaintext and logs sanitized failure. | Secure Messaging, Crypto Vault | `tests/messaging/test_replay_and_binding.py` + `tests/crypto/test_aead_tamper.py` |
| **TM-17** | **Local Simulator DoS / Resource Exhaustion:** Oversized event batches, unbounded graph state, massive stdout/file reads, or login brute-force in local prototype. | Memory exhaustion, >64 KiB adapter failure, or >8s timeout. | Bounded detector graph window & max payload caps; streaming/chunked file AEAD; auth rate limiting; `validate.py` 64 KiB & timeout compliance checks. | Detector, Vault, REST API, Root Adapter | `tests/security/test_bounds_and_ratelimit.py` + `scripts/benchmark.py` |

---

## 5. Honest Limitations & Scope Exclusions

- **No Hardware Security Module (HSM):** Keys are stored in a local encrypted demo keystore or documented sandbox path; if an attacker gains full root/OS access to the host machine and master keystore passphrase, local keys are exposed.
- **Simulated Distributed Nodes, Not Real Consensus:** The 3–7 nodes run inside a deterministic local simulator backed by SQLite, not Raft/Paxos across physical hosts.
- **Hash-Chain Limits:** A SHA-256 hash chain detects after-the-fact log alteration by an unprivileged viewer, but if an attacker controls both the SQLite database AND the local ML-DSA checkpoint signing key, they could rewrite and re-sign the chain.
- **Deterministic Detector Boundaries (Phase 7):** The Phase 7 detector operates strictly via deterministic rules, statistical thresholds, and service-edge graphs (zero AI/ML/LLM). Live `audit_ledger` detection fails closed (`409 AUDIT_CHAIN_INVALID`) if `verify_ledger_db` detects tampering; however, slow-drip attacks spanning beyond configured sliding windows or attacks using stolen legitimate credentials within approved normal service graphs may evade single-window rules without operator threshold tuning. Alerts remain advisory only (`recommended_response` never triggers automatic revocation).
- **Plaintext Post-Copy Reality:** Once an authorized user legitimately downloads/decrypts plaintext, the system cannot retract copies made outside the control plane.
- **Forward Secrecy Claim Boundary:** Forward secrecy will only be claimed if a vetted ephemeral KEM + per-session/message ratchet with key erasure is implemented and verified by a long-term-key-only compromise test; otherwise it will be explicitly documented as `not proven` / `partial`.
- **Synthetic Evidence Boundary:** Passing `validate.py` and synthetic dataset benchmarks demonstrates prototype correctness under test assumptions, not production certification.
