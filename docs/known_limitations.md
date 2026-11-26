# Q-SHIELD Known Limitations & Architectural Boundaries

In compliance with the Master Build Prompt, all known architectural constraints and honest limitations are explicitly cataloged below:

## 1. Control-Plane Mediated Forward Secrecy
- **Classification:** `PARTIAL (Control-Plane Mediated)`
- **Mechanism:** Q-SHIELD provides immediate post-compromise security through symmetric ratchet key zeroization per decrypted message. Once a session key is erased, past messages cannot be retrospectively decrypted.
- **Limitation:** Initial session establishment is mediated by the centralized control plane policy authority using ML-KEM-768. Q-SHIELD does not implement full asynchronous Double-Ratchet or Signal-protocol ratcheting independent of the control-plane authority.

## 2. Software Keystore Storage Model
- **Classification:** `Passphrase-Encrypted Software Keystore`
- **Mechanism:** Master root keys and node private keys are encrypted on disk using PBKDF2/Argon2 passphrase derivation with AES-256-GCM authenticated envelopes.
- **Limitation:** Hardware Security Modules (HSMs), TPMs, and Secure Enclaves (e.g. AWS KMS, Nitro Enclaves) are **not simulated or claimed**. Compromise of the root host system operating memory or master passphrase allows key extraction.

## 3. Simulated Multi-Node Architecture
- **Classification:** `In-Memory Deterministic Process Simulation`
- **Mechanism:** The 3–7 node cluster is executed within single-host SQLite transactions and memory models, allowing repeatable fault injection, latency emulation, and tombstone verification.
- **Limitation:** Q-SHIELD does not deploy a real distributed consensus protocol (e.g. Raft or Paxos) across live distinct network interfaces. Network partitions are simulated via software flags rather than true physical packet drops.

## 4. Deterministic Non-ML Threat Detection
- **Classification:** `Rule-Based Telemetry Pattern Matcher`
- **Mechanism:** 26 deterministic rules inspect structured audit events, watermark windows, and service graphs for explicit indicators of compromise.
- **Limitation:** The detector does not employ generative AI, clustering, deep neural networks, or predictive forecasting. Attack patterns that fall outside the 26 defined rule thresholds will not trigger an alert.
