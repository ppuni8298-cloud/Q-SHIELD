# Q-SHIELD — Phase 8 Simulated Delivery Reliability & Fault Handling

**Module:** [backend/app/messaging/delivery_simulator.py](file:///c:/Users/ADMIN/OneDrive/Pictures/Desktop/q%20shield/backend/app/messaging/delivery_simulator.py) (`MessageDelivery` / `message_deliveries`)

---

## 1. Simulated Modes & Guarantees

Using existing simulated `node_registry` nodes (`node-1..node-3` default, zero real network brokers):
- **`NORMAL`:** Queues encrypted envelope on the lowest-latency healthy node, tracks attempts, delivers once, and records explicit recipient acknowledgement (`ACKED`).
- **`PACKET_LOSS` (Bounded Retries):** Simulates `drop_attempts` transient drops up to configurable `max_retries` (default `3`, max `20`). If `drop_attempts < max_retries`, packet recovers to `IN_TRANSIT` / `DELAYED`; if `drop_attempts >= max_retries`, transitions explicitly to terminal **`DEAD_LETTER` (`DELIVERY_RETRY_EXHAUSTED`)**. **Does NOT claim guaranteed delivery under unlimited packet loss.**
- **`DELAY`:** Tracks `simulated_delay_ms`; encrypted message still obeys strict `expires_at` enforcement on receive (`DENY_MESSAGE_EXPIRED` if expired while queued).
- **`REORDER` (`POST /api/v1/messages/simulate-reorder`):** Bounded arrival reorder buffer (`buffer_capacity = 32`). Validates metadata/AAD integrity via `verify_message_integrity_only`, discards duplicates/missing/tampered envelopes with explicit reason codes (`DUPLICATE_IN_ARRIVAL_STREAM`, `MISSING_OR_UNKNOWN_MESSAGE`, `UNSUPPORTED_SCHEMA`, `AEAD_INTEGRITY_FAILED`), sorts valid buffered messages by canonical `(session_generation, sequence)`, and delivers exclusively valid authenticated messages in sequence order.
- **`NODE_DISCONNECT`:** Simulates relay node outage (`available=False`, `health="OFFLINE"`), rejecting routed sends (`503 NODE_DISCONNECTED`) until reconnected.
- **Idempotent Acknowledgements (`POST /api/v1/messages/{id}/ack`):** First ack transitions `ack_count = 1`, `status = "ACKED"`; subsequent acks record `duplicate_acks_ignored += 1`, emit `MSG_DUPLICATE_ACK_IGNORED`, and return `duplicate_ack_ignored=True` without double-counting.
- **Duplicate Delivery Protection:** Re-delivering an already accepted message hits durable `ReplayRecord` (`409 REPLAY_DETECTED`) before decryption.
