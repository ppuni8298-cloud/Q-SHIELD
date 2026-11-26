# Q-SHIELD — Phase 7 Requirement Traceability Audit (All 51 Rows)

**Audit Source:** [docs/requirement_traceability.csv](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/docs/requirement_traceability.csv) (`51` requirements)  
**Post-Phase 7 Distribution:** `Tested and passed = 35`, `Implemented = 5`, `Not yet tested = 11`

---

## 1. All 11 `Not yet tested` Requirements (Why Untested, Owner Phase, Verification Plan)

| Requirement ID | Responsible Phase | Needs Phase 7 Test? | Why Not Tested Yet | Concrete Verification Plan |
|---|---|---|---|---|
| `REQ-TK-013` | Phase 10 (Submission) | No | Optional root `threat-model.json` metadata artifact is authored/validated only after Phases 8–10 stabilize final claims. | Author `threat-model.json` aligned with `docs/threat_model.md` and validate JSON schema against `Track-4-Toolkit/docs/adapter-v1.md` (`TEST-SUB-001`). |
| `REQ-CORE-009` | Phase 8 (Messaging) | No | E2E messaging endpoints (`/api/v1/messages/*`) and durable replay ledger are strictly Phase 8 scope. | Implement Phase 8 AEAD recipient-bound messaging + replay ledger; run recipient/AAD/replay pytest suite (`TEST-MSG-001`). |
| `REQ-CORE-010` | Phase 8 (Messaging) | No | Forward-secrecy ephemeral/ratchet protocol & long-term-key compromise test are Phase 8 scope. | Implement or explicitly scope protocol in `docs/crypto_design.md`; run long-term-key compromise test (`TEST-MSG-002`). |
| `REQ-CORE-011` | Phase 8 (Messaging) | No | Message loss/reordering recovery simulator belongs to Phase 8. | Implement `/api/v1/messages/{id}/simulate-loss, /simulate-reorder` and test complete vs incomplete recovery (`TEST-MSG-003`). |
| `REQ-CORE-012` | Phase 8 (Messaging) | No | Protected peer-bound session resumption belongs to Phase 8. | Implement `/api/v1/auth/session/resume` & `/messages/{id}/resume`; verify peer-binding & cross-identity rejection (`TEST-MSG-004`). |
| `REQ-UI-001` | Phase 9 (Frontend) | No | React + TypeScript + Vite console (14 pages) belongs to Phase 9. | Build frontend console + run Playwright E2E smoke test asserting zero console errors (`TEST-E2E-001`). |
| `REQ-UI-002` | Phase 9 (Frontend) | No | 14 one-click resettable demo scenarios UI + orchestrator belong to Phase 9. | Implement `/api/v1/simulation/*` + Simulation UI verifying honest `PASS/FAIL/PARTIAL/NOT RUN` (`TEST-INT-006`). |
| `REQ-PERF-001` | Phase 10 (Benchmarks) | No | Empirical `scripts/benchmark.py` latency/CPU/RSS/convergence lab belongs to Phase 10. | Run `scripts/benchmark.py` using `perf_counter_ns` against live backend; export `reports/benchmarks/latest.json` (`TEST-PERF-001`). |
| `REQ-SEC-001` | Phase 10 (Hardening) | Partially verified in Phase 7 (`AI_ML_IMPORT_HITS: []`); full gate Phase 10 | Phase 7 verified zero AI/ML imports (`test_no_ai_ml_runtime_dependencies_in_detector_modules` + AST scan), but network-disabled execution & full OAuth/external isolation gate stays Phase 10. | Run clean offline/network-disabled integration & static security suite (`TEST-SEC-010`) so status only becomes `Tested and passed` once full gate passes. |
| `REQ-SEC-002` | Phase 10 (Hardening) | No | Full static analysis, dependency vulnerability audit, and clean-venv install rehearsal belong to Phase 10. | Run `scripts/security_checks.sh`, dependency audit, and clean offline `.venv` reinstall + full suite (`TEST-SEC-011`). |
| `REQ-SUB-001` | Phase 10 (Submission) | No | Final README, evidence sheet, 2-page PDF brief, and walkthrough demo script depend on all Phases 1–10 finishing. | Complete Master Acceptance Gate review + build 2-page brief PDF + verify `templates/evidence-sheet.md` (`TEST-SUB-002`). |

---

## 2. All 5 `Implemented` Requirements (Partial Scope Transparently Tracked)

- `REQ-CORE-013` (*Proof-Carrying Trust Change*): Phase 6 ML-DSA-65 audit receipts tested (`TEST` passed); Phase 9/10 `/api/v1/incidents/{id}/receipt` pending.
- `REQ-ID-004` (*Hashed session tokens + login rate limiting*): Token hashing & binding tested in Phase 2; login brute-force rate-limiting scheduled for Phase 10 hardening.
- `REQ-ID-005` (*Offline synthetic demo auth + optional OAuth + login UI*): Offline synthetic auth backend tested in Phase 2; frontend login UI deferred to Phase 9.
- `REQ-DATA-001` (*Practice data, seeded generator, 6 JSONL fixtures*): Toolkit `practice/` + seeded generator (`backend/app/detector/dataset.py`) + entity renaming tested in Phase 7; standalone 6 JSONL fixture files in `datasets/` deferred/optional.
- `REQ-API-001` (*FastAPI `/api/v1` endpoints*): Phases 2–7 routes & OpenAPI schemas typed and tested; Phases 8–10 routes pending.
