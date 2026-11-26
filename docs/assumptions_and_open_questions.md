# Assumptions, Source Conflicts & Open Questions (Phase 0)

**Purpose:** Document every ambiguity, apparent conflict between official sources, environment constraint, architectural assumption, and open question discovered during Phase 0 without silently inventing or dropping any organizer requirement.

---

## 1. Apparent Conflicts / Tensions Between Official Sources & Proposed Resolutions

### Conflict 1: Official Judging Container Dependencies (`stdlib + pqcrypto==0.4.0`) vs. Prescribed Web Stack (`FastAPI + Pydantic + SQLAlchemy + cryptography`)
- **Source A (`Track-4-Toolkit/docs/adapter-v1.md` L11 & Master PDF p.3):**  
  > "The judging runtime is an offline Linux container with Python 3.12, `pqcrypto==0.4.0` and Node.js 24.11.1. Its root filesystem is read-only. ... The worker does not install dependencies from a submission during a run."
- **Source B (Master PDF Sec 3, p.4):**  
  > "Backend: Python 3.12 + FastAPI + Pydantic v2 + SQLAlchemy 2 + Alembic. ... Use `cryptography` library for AES-GCM/HKDF if supported in environment... Offline judge adapter must not require frontend or external services."
- **Exact Tension:**  
  If the root `track4_service.py` adapter imports `fastapi`, `pydantic`, `sqlalchemy`, or `cryptography` when executed inside the organizer's judging container, it will fail with `ModuleNotFoundError` because the judging container only guarantees Python 3.12 stdlib, `pqcrypto==0.4.0`, and Node.js 24.11.1, and does NOT run `pip install` on submission dependencies.
- **Proposed Resolution (Preserves Both Requirements):**  
  Design a **two-layer import boundary** inside the modular monolith:
  1. **Zero-3P-Dependency Adapter Core (`backend/app/adapter_core/` or `qshield_core/`):** Implements the 5 toolkit operations (`setup`, `read`, `revoke`, `audit`, `protected_read`), SQLite persistence (via stdlib `sqlite3` with WAL, `PRAGMA foreign_keys=ON`, transactions), HMAC-SHA-256 / HKDF-SHA-256 / SHA-256 (via stdlib `hmac` / `hashlib`), and ML-KEM-768 encapsulation (via `pqcrypto==0.4.0` ONLY). `track4_service.py` imports ONLY this zero-3P-dependency core.
  2. **Full Control Plane API (`backend/app/`):** Uses FastAPI, Pydantic v2, SQLAlchemy 2, Alembic, and `cryptography` (AES-256-GCM) for the rich web dashboard, multi-node simulator, messaging lab, detector, and benchmarks, sharing the same SQLite database schema/conventions where applicable.
  - This guarantees `track4_service.py` runs in the stripped-down offline judging container AND the full FastAPI/React platform satisfies every Master Build Prompt feature.

### Conflict 2: Local Machine Python Version (`3.11.9`) vs. Target Runtime (`Python 3.12`) & Missing `pqcrypto==0.4.0`
- **Source (`docs/adapter-v1.md` L11 & PDF p.3-4):** Judging runtime uses **Python 3.12** and **`pqcrypto==0.4.0`**.
- **Actual Local Environment Observed (Task 2):**
  - Installed Python: `Python 3.11.9` (Microsoft Store `WindowsApps` package).
  - Installed `Node.js`: `v24.11.1` (exact match).
  - Missing locally: Python `3.12`, `pqcrypto==0.4.0`, `alembic`, `pytest-cov`, `hypothesis`.
  - Additionally, Windows Store Python (`WindowsApps\python.exe`) is blocked inside the terminal sandbox (`The file cannot be accessed by the system`), requiring unsandboxed execution or a standard local Python 3.12 install / `.venv`.
- **Proposed Resolution:**
  - Before starting Phase 1/3, install **Python 3.12** (standard installer or via `py install 3.12` / `uv`, placed in project `.venv` without altering unrelated global tools) and verify **`pqcrypto==0.4.0`** wheel availability and exact ML-KEM-768 / ML-DSA API signatures on Windows and Linux.
  - Keep all code compatible with Python 3.12 syntax and stdlib features.

### Conflict 3: `audit` Operation Response on Unknown `request_id`
- **Source A (`Track-4-Toolkit/validate.py` L118-119):**  
  `if request["op"] in {"read", "audit"} and response.get("decision") not in ("allow", "deny"): raise ValidationError("format", ...)`
- **Source B (`Track-4-Toolkit/demo/python/team_app.py` L23 & `demo/node/team_app.cjs` L19-20):**  
  Returns `{"error": "unknown_request"}` (with NO `"decision"` key) when `request_id` is not found in `events`.
- **Proposed Resolution:**  
  For any recorded `read` `request_id`, `audit` returns `{"request_id": request_id, "decision": "<allow|deny>", ...}` (satisfying `validate.py` L118 and L157). For an unknown `request_id` (not tested by `validate.py`, only by adversarial tests), return `{"request_id": request_id, "decision": "deny", "error": "unknown_request"}` OR document clearly why `"decision": "deny"` is included or omitted—wait: including `"decision": "deny"` alongside `"error": "unknown_request"` satisfies BOTH fail-closed semantics AND `validate.py` L118's structural invariant (`decision in ("allow", "deny")` for `op == "audit"`)! We will verify this against `docs/adapter-v1.md` before Phase 1 coding.

### Conflict 4: Root `threat-model.json` File (`docs/adapter-v1.md`) vs. Section 19 Repository Structure
- **Source A (`docs/adapter-v1.md` L51-55):**  
  "For a matching implementation, the worker recognizes these two fields in a root-level `threat-model.json`: `{"asset":"protected-resource","boundary":"identity-check"}`. Use them only when they accurately describe the design."
- **Source B (Master PDF Sec 19, p.20):** Lists `docs/threat_model.md` but omits root `threat-model.json`.
- **Proposed Resolution:**  
  Because Q-SHIELD's protected assets include `"protected-resource"` and its primary trust boundary enforces `"identity-check"` (among additional controls), evaluate in Phase 10/11 whether adding root `threat-model.json` (`{"asset":"protected-resource","boundary":"identity-check"}`) accurately represents the design without overclaiming. Do not include it blindly without verifying accuracy.

### Conflict 5: Toolkit `README.md` External Link (`rentry.co/uio6w6kn`) & Submission Format
- **Source A (`Track-4-Toolkit/README.md` L44-46 & `templates/two-page-brief.md`):**  
  References `https://rentry.co/uio6w6kn` for official track rules/scoring; states submission is public GitHub repo URL + 2-page project brief PDF (max 2 pages, ~350 words/page, with 1-page threat model + 5-min fallback demo link; evidence sheet stays in repo and must NOT be attached as a 3rd submission item).
- **Source B (Master PDF p.1-2, Sec 23–24):** Matches the 12 goals, 100-point Stage 1 rubric, and 2-page brief structure verbatim.
- **Open Question:** Verify `https://rentry.co/uio6w6kn` (if accessible to user/team) prior to final Phase 11 submission to ensure no last-minute organizer rule updates were posted after toolkit `v1.0.0`.

---

## 2. Cryptographic & Protocol Assumptions / Open Questions

1. **Exact `pqcrypto==0.4.0` API surface (VERIFIED in Phase 1):**
   - Installed `pqcrypto==0.4.0` in `.venv` (Python 3.12.10, `cp312-win_amd64` wheel) and inspected `pqcrypto.kem.ml_kem_768` source directly:
     - `ALGORITHM == "ml_kem_768"`
     - `PUBLIC_KEY_SIZE == 1184`, `SECRET_KEY_SIZE == 2400`, `CIPHERTEXT_SIZE == 1088`, `PLAINTEXT_SIZE == 32`
     - Functions: `generate_keypair() -> (pk, sk)`, `encrypt(pk) -> (ciphertext, shared_secret)`, `decrypt(sk, ciphertext) -> shared_secret`.
   - Also confirmed `pqcrypto.sign` provides `ml_dsa_44`, `ml_dsa_65`, `ml_dsa_87` (detailed API inspection scheduled for Phase 3 `docs/crypto_design.md`).
2. **`protected_read` statefulness / persistence (IMPLEMENTED in Phase 1):**
   - `docs/adapter-v1.md` states `protected_read` takes `actor`, `asset`, `challenge`, `public_key` and enforces application access policy. In Phase 1, `protected_read` enforces ownership and revocation against the persisted SQLite state without altering the required `{"ciphertext", "proof"}` output schema.
3. **`protected_read` and `audit` response shapes on deny/error (IMPLEMENTED & TESTED in Phase 1):**
   - On `protected_read` denial (disabled/revoked actor, wrong owner, missing asset) or invalid input (empty challenge, malformed standard Base64, wrong public key length `!= 1184`), `track4_service.py` fails closed and returns `{"decision": "deny"}` (with safe error tag on malformed inputs, zero protected body/key/secret leakage) and exit code `0`, preventing callers from confusing security denials with process crashes.
   - On `audit` for an unknown `request_id`, `track4_service.py` returns `{"request_id": request_id, "decision": "deny", "error": "unknown_request"}`, satisfying both fail-closed semantics and `validate.py`'s requirement that `audit` responses carry `"decision"` in `("allow", "deny")`.
   - On unparseable/non-JSON-dict/NaN/oversized (`>16 MiB`) `stdin` or `>64 KiB` `stdout`, `track4_service.py` emits nothing to `stdout`, writes a sanitized single-line diagnostic to `stderr`, and exits with code `1` (matching `starters/python/track4_service.py`).
4. **Forward Secrecy (Goal 10) Feasibility:**
   - Goal 10 explicitly states: *"Implement a defensible protocol/library-based design or explicitly mark as not proven; never make false claims."*
   - If `pqcrypto==0.4.0` ML-KEM-768 ephemeral encapsulation + HKDF-SHA-256 per-message/per-epoch ratcheting with explicit zeroization of prior ratchet/session keys in memory & DB is implemented and passes the long-term-key-only compromise test, we can document the exact protocol scope and assumptions (e.g., Python GC caveats for memory zeroization). If not, we MUST honestly mark Forward Secrecy as `partial` or `not proven`.
5. **SQLite Concurrency & Read-Only Root in Judging Container:**
   - Adapter persistence uses SQLite (or atomic JSON + SQLite) inside `TRACK4_STATE_DIR` / OS temp dir. Must handle concurrent calls safely (`PRAGMA busy_timeout`, `BEGIN IMMEDIATE`, WAL mode or rollback journal in temp dir) and never attempt to write to the read-only submission root.
6. **Windows vs Linux Parity:**
   - Development runs on Windows (`win32`), whereas the judging container is **offline Linux**. File path handling (`pathlib`), `os.chmod` caveats on Windows, `fsync` semantics, and line endings (`LF` in `.sh` scripts) must be tested so Linux container execution works without Windows-specific assumptions.
7. **Playwright / Browser E2E Dependencies:**
   - Check in Phase 9 whether Playwright browsers can be installed offline or locally without violating offline runtime rules for the shipped product. (Dev/test tools are allowed during build/test; only the submitted *runtime* product must be offline-first with zero AI/ML.)

---

## 3. Design Decisions Adopted for Phase 1+

1. **Root Adapter Language:** Python (`track4_service.py`), per Master PDF Sec 2 ("Prefer `track4_service.py` unless starter indicates material reason to choose Node").
2. **Modular Monolith + Zero-3P-Dependency Core:** Split pure Python stdlib + `pqcrypto==0.4.0` adapter/vault core from the FastAPI/SQLAlchemy/React web control plane so `track4_service.py` never fails on missing web packages in the judging container.
3. **Zero Grace Period by Default:** Key rotation defaults to zero grace period after `COMMIT`/`CUTOFF`, with optional explicit simulation toggle (off by default) for controlled grace-period observation.
4. **Deterministic No-ML Detection:** All anomaly, privilege-escalation, and lateral-movement detection uses explicit rule sets, approved change-ticket matching, statistical baseline counts, and time-windowed directed service graphs—zero ML libraries imported in backend runtime (`scikit-learn`, `torch`, `transformers`, etc. installed globally on this machine MUST NEVER be added to Q-SHIELD dependencies).
