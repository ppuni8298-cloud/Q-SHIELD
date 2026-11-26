# Q-SHIELD — Curated JSONL Evaluation Fixtures

All **6 curated fixtures** exercise specific Phase 7 deterministic detector & parser capabilities without hardcoded actor or service names:

1. `benign_admin.jsonl` — Authorized administrative role change covered by change approval metadata (`no alerts`).
2. `privilege_escalation.jsonl` — Unapproved privilege escalation without valid approval window (`RULE-ID-003`).
3. `lateral_movement.jsonl` — Multi-hop unexpected service traversal `reports -> billing -> archive` (`RULE-LAT-001`) paired with an isolated single denial excluded from lateral movement.
4. `clock_skew_reordered.jsonl` — Out-of-order delayed delivery within `5000ms` (`uncertain_order=True`) plus documented `+2000ms` offset (`no false positive`) vs unexplained `+25s` skew (`RULE-TMP-004`).
5. `replay_recipient_tamper.jsonl` — Repeated replay pattern (`REPLAY_DETECTED`, `RULE-TMP-001`) and reused `event_id` with divergent content (`RULE-TMP-002`).
6. `malformed.jsonl` — Intentionally malformed JSON / NaN / truncated lines mixed with valid records; verifies safe fail-closed skipping with warnings rather than crashes.
