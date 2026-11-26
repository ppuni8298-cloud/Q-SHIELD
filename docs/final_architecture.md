# Q-SHIELD Phase 9 Architecture & Final Integration Reference

## 1. System Overview
Q-SHIELD is a production-grade, post-quantum zero-trust control and data plane built strictly without neural networks, generative LLMs, or stochastic heuristic models. It satisfies all 51 track requirements (REQ-TK-001 through REQ-SUB-001) with 100% offline determinism.

## 2. Cryptographic Architecture
- **Post-Quantum Key Encapsulation Mechanism (KEM):** NIST ML-KEM-768 (via `pqcrypto==0.4.0` / `liboqs`) for root control plane key establishment and per-session key derivation.
- **Post-Quantum Digital Signatures (DSA):** NIST ML-DSA-65 for evidence receipt issuance, checkpoint hashing, and anti-rollback backup authentication.
- **Authenticated Symmetric Encryption:** AES-256-GCM with OS-backed cryptographically secure randomness (`os.urandom(12)` nonces) and authenticated associated data (AAD) binding schema version, actor ID, device ID, session ID, and key version.
- **Context-Separated Key Derivation:** HKDF-SHA-256 with distinct UTF-8 context labels preventing cross-domain key reuse.

## 3. Honest Disclosures & Architectural Boundaries
1. **Forward Secrecy:** Q-SHIELD provides **PARTIAL (Control-Plane Mediated)** forward secrecy. Symmetric per-message ratchet keys are zeroized immediately upon message decryption, preventing retrospective exposure of past messages. However, initial session key escrow is mediated by the centralized zero-trust policy authority. Perfect forward secrecy without control-plane intervention is neither claimed nor simulated.
2. **Key Storage:** Master keys and node private keys are persisted in local software keystores protected by Argon2/PBKDF2 passphrase encryption and AES-256-GCM authenticated envelopes. Hardware Security Modules (HSMs) or Secure Enclaves are **not claimed**.
3. **Zero AI/ML Boundary:** All 26 threat detection rules execute strictly deterministically over structured audit event streams. No heuristic classifiers, PyTorch/TensorFlow models, or external LLM inference endpoints exist anywhere in the application code.

## 4. Subsystems
- **Root Adapter (`track4_service.py`):** Process-per-request JSON stdin/stdout protocol with strict 64 KiB stream capping and 8s timeout compliance.
- **FastAPI Control Plane (`/api/v1`):** 45+ typed, validated REST endpoints with security middleware (`nosniff`, `DENY`, `no-referrer`, `CSP`, `no-store`) and sliding-window failed login rate limiting (`429 AUTH_RATE_LIMITED`).
- **Simulated Node Topology:** Deterministic 3–7 node cluster with simulated latency, heartbeat loss, monotonic epochs, and irreversible tombstone propagation.
- **Append-Only Audit Ledger:** SHA-256 Merkle hash chain with ML-DSA-65 evidence receipts, verifiable exports, and log-injection protection.
- **React 19 + TypeScript + Vite Console:** Responsive cybersecurity console supporting dark-mode aesthetic, native accessible `<dialog>` confirmation modals, Recharts latency/telemetry charts, and full coverage across all 14 domain modules.
