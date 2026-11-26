# Q-SHIELD
### Quantum-Ready Trust & Revocation Control Plane

**Yugaantar DevForge | Track 4 — Trust, but Verify**

> A post-quantum-ready, zero-trust security control plane for protecting identities, devices, cryptographic keys, sessions, and sensitive communications.

---

## 1. Project Overview

Modern digital systems rely on identities, devices, cryptographic keys, and secure communication channels. However, when an identity is compromised, a device is lost, or a cryptographic key becomes untrusted, access must be revoked consistently across the entire system.

Traditional security implementations can struggle with delayed revocation, inconsistent key states, interrupted key rotations, replay attacks, and insufficient audit evidence.

**Q-SHIELD** addresses these challenges through a centralized trust and revocation control plane with simulated distributed nodes, post-quantum cryptography, deterministic zero-trust authorization, secure messaging, and tamper-evident security telemetry.

The platform demonstrates how trust decisions can be enforced, verified, monitored, and recovered across a simulated multi-node environment.

---

## 2. Problem Statement

The Track 4 challenge requires a working prototype that protects messages or files as keys, devices, and user permissions change.

The system must demonstrate:

- Secure cryptographic key rotation.
- Consistent revocation across multiple nodes.
- Recovery from interrupted operations.
- Backup integrity verification.
- Tamper-evident audit records.
- Detection of suspicious identity and privilege activity.
- Detection of unusual lateral movement.
- Replay protection and recipient binding.
- Reliable message delivery under packet loss and reordering.
- Secure session resumption.

Q-SHIELD implements these requirements within an offline-capable, controlled sandbox prototype.

---

## 3. Proposed Solution

Q-SHIELD combines cryptographic protection, identity controls, revocation orchestration, and security monitoring into a modular security platform.

Its core approach includes:

1. **Zero-Trust Authorization:** Every protected operation is evaluated against identity, role, device, key, session, and policy state.
2. **Post-Quantum Cryptography:** ML-KEM-768 provides post-quantum key encapsulation using a vetted cryptographic library.
3. **Secure Key Lifecycle:** Key rotation, revocation, crash recovery, and encrypted backup verification are managed through explicit lifecycle states.
4. **Distributed Revocation Simulation:** Multiple simulated nodes receive and enforce revocation events.
5. **Proof-Carrying Trust Changes:** Security changes generate verifiable audit records and signed evidence.
6. **Deterministic Threat Detection:** Explainable rules, statistical analysis, and graph-based detection identify suspicious activity.
7. **Secure Messaging:** Authenticated encryption, recipient binding, replay protection, and session management protect communications.

---

## 4. Unique Selling Proposition (USP)

**Proof-Carrying Trust Changes**

Q-SHIELD does not simply change a user's access permissions. It records the trust transition, propagates the change across simulated nodes, verifies enforcement, and generates tamper-evident evidence.

Key differentiators:

- Post-quantum-ready cryptographic architecture.
- Multi-node revocation convergence measurement.
- Verifiable and tamper-evident audit ledger.
- Crash-consistent key rotation and recovery.
- Context-aware zero-trust authorization.
- Explainable security detection with measurable evaluation.
- Secure message delivery with replay and recipient protection.
- Offline-capable sandbox execution.

---

## 5. System Architecture

Q-SHIELD follows a **modular monolithic architecture** with a simulated multi-node environment.

### High-Level Architecture

```text
                 OPERATOR / USER
                        |
                        v
              REACT + TYPESCRIPT UI
                        |
                        v
                 FASTAPI REST API
                        |
          +-------------+-------------+
          |             |             |
          v             v             v
     Identity &      Zero-Trust    Messaging &
     Device Control  Policy Engine Session Manager
          |             |             |
          +-------------+-------------+
                        |
                        v
                SECURITY SERVICES
                        |
       +----------------+----------------+
       |                |                |
       v                v                v
   Crypto Vault     Key Lifecycle    Revocation
   (ML-KEM-768)     Coordinator      Coordinator
       |                |                |
       +----------------+----------------+
                        |
                        v
                DETECTION & AUDIT
                        |
         +--------------+--------------+
         |                             |
         v                             v
    Deterministic                 Tamper-Evident
   Detection Engine                Audit Ledger
         |                             |
         +--------------+--------------+
                        |
                        v
                  STORAGE LAYER
               (SQLite Database)
```

### System Endpoints

- **Interactive 3D Web Console:** `http://localhost:5173`
  - WebGL Quantum Core Shield (`Three.js`)
  - 3D Distributed Node Mesh Topology
  - Real-time Telemetry & Security Operations Center (SOC)
  - Revocation Propagation & Identity Management
  - Post-Quantum Key Rotation & Recovery (ML-KEM-768)
  - Tamper-Evident SHA-256 Merkle Audit Ledger
- **FastAPI REST API:** `http://127.0.0.1:8000`
- **Swagger Documentation:** `http://127.0.0.1:8000/docs`

---

## 6. Core Features

### A. Post-Quantum Cryptography & Key Management

- Hybrid and post-quantum key encapsulation using **ML-KEM-768**.
- Authenticated encryption using **AES-256-GCM**.
- Key derivation using **HKDF-SHA-256**.
- Lifecycle tracking: Active, Deprecated, Compromised, Revoked, Rotated.
- Crash recovery using durable write-ahead state transitions.
- Encrypted and authenticated backup creation and verification.

### B. Identity, Device & Policy Enforcement

- Persona-based role management (Admin, SecOps, Auditor, Node).
- Hardware-bound device trust states (Trusted, Suspicious, Revoked).
- Attribute-Based Access Control (ABAC) and Role-Based Access Control (RBAC).
- Real-time session validation with automatic invalidation upon revocation.

### C. Distributed Revocation Engine

- Real-time propagation of revocation events to 7 simulated nodes.
- Tracking convergence latencies and node acknowledgement states.
- Support for offline and delayed node synchronization.

### D. Threat Detection & Audit Evidence

- 100% deterministic, explainable security heuristic rules (Zero AI/ML hallucination risk).
- Sliding-window anomaly detection and graph-based lateral movement analysis.
- Append-only Merkle-linked audit ledger with SHA-256 integrity proofs.
- One-click cryptographic verification of audit chain consistency.

---

## 7. Pre-Seeded Demonstration Credentials

The local zero-trust SQLite database is initialized with the following personas for testing different role-based access levels (RBAC):

| Persona | Principal ID | Password | Role & Permissions |
| :--- | :--- | :--- | :--- |
| **Security Admin** | `user-admin` | `dev-admin-trusted` | Full administrative control, node onboarding, policy management |
| **SecOps Analyst** | `user-secops` | `dev-secops-trusted` | Revocation propagation, threat alerts, audit inspection |
| **Auditor** | `user-auditor` | `dev-auditor-trusted` | Read-only access to tamper-evident cryptographic audit ledger |
| **Node Agent** | `node-alpha` | `dev-node-trusted` | Workload node session token & heartbeat exchange |

*(You can also use the **Quick Persona Fill** buttons on the Login page at `http://localhost:5173/login` or register a new user at `http://localhost:5173/signup`)*.

---

## 8. Technology Stack

- **Backend:** Python 3.12+, FastAPI, Pydantic, SQLAlchemy, Uvicorn, SQLite
- **Cryptography:** `cryptography` library, NIST ML-KEM-768 post-quantum implementations
- **Frontend:** React 19, TypeScript, Vite, Tailwind CSS v4, Lucide Icons
- **3D Visualizations:** Three.js, WebGL interactive canvas rendering
- **Testing:** Pytest, Vitest, Playwright (Headless & Real Chromium)

---

## 9. How to Run the Project

You can run Q-SHIELD either using the automated launcher script or by starting the backend and frontend in separate terminals.

### Method A: Single Command Launcher (Recommended on Windows)

In PowerShell at the project root (`c:\Users\ADMIN\OneDrive\Pictures\Desktop\q shield`):

```powershell
.\start_servers.ps1
```
*This launches both the FastAPI backend (`:8000`) and the Vite development server (`:5173`) in background processes and displays their operational status.*

---

### Method B: Separate Terminals (Manual)

#### Terminal 1 — Start the FastAPI Backend
```powershell
# From the project root:
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Backend Health Check:** `http://127.0.0.1:8000/health`
- **Interactive OpenAPI Docs:** `http://127.0.0.1:8000/docs`

#### Terminal 2 — Start the React + Vite Frontend
```powershell
# From the frontend directory:
cd frontend
npm run dev
```
- **Web Console:** `http://localhost:5173`

---

## 10. Testing and Verification

To verify that the entire cryptographic, adapter, frontend, and end-to-end suites pass:

### 1. Official Track 4 Adapter Tests
```powershell
.\.venv\Scripts\python.exe -m pytest tests/adapter -q
```

### 2. Full Backend Security & Scenarios Suite
```powershell
.\.venv\Scripts\python.exe -m pytest tests/backend -q
```

### 3. Frontend Unit & Component Tests (Vitest)
```powershell
npm --prefix frontend run test -- --run
```

### 4. Production Build Verification
```powershell
npm --prefix frontend run build
```

### 5. Playwright End-to-End Tests (Real Chrome Browser)
```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts/run_e2e.ps1
```

### 6. Official Track 4 Toolkit Integration

Official toolkit repository:
https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit

The root-level `track4_service.py` provides the organizer adapter interface. Run official toolkit tests against `track4_service.py` as prescribed in the challenge guidelines.

---

## 11. Performance Evaluation

Q-SHIELD includes benchmarking for cryptographic and application operations, including:

- ML-KEM key generation.
- Key encapsulation and decapsulation.
- HKDF key derivation.
- AES-GCM encryption and decryption.
- Authentication latency.
- Message ingestion and throughput.
- Memory consumption.

See: `docs/performance_benchmarks.md` for recorded benchmarks.

---

## 12. Known Limitations

Q-SHIELD is a hackathon prototype and has the following documented limitations:

1. **Forward Secrecy:** The current messaging design provides partial, control-plane-mediated forward-secrecy properties. It should not be described as providing complete forward secrecy.
2. **Key Storage:** The local software keystore is encrypted, but it is not equivalent to a hardware security module.
3. **Node Infrastructure:** The multi-node environment is simulated within the application rather than deployed as independent production servers.
4. **Production Deployment:** Additional operational hardening, independent security review, and infrastructure integration would be necessary before production use.

---

## 13. Future Scope

- Hardware-backed key management using HSMs or secure enclaves.
- Stronger forward-secrecy and post-compromise security guarantees.
- Real distributed node deployment.
- Advanced policy administration and identity federation.
- External signed audit checkpoints.
- More extensive adversarial and concurrency testing.
- Production observability and monitoring integrations.

---

## 14. Track 4 Compliance Matrix

| Track 4 Requirement | Q-SHIELD Component | Status |
|---|---|---|
| Key rotation | Key lifecycle service | Verified |
| Revocation across nodes | Revocation coordinator | Verified |
| Crash recovery | Durable recovery journal | Verified |
| Backup integrity | Encrypted and signed backup verification | Verified |
| Log integrity | Hash-chained audit ledger | Verified |
| Suspicious activity detection | Deterministic detection engine | Verified |
| Lateral movement | Graph-based detection | Verified |
| Clock differences | Timestamp correction and event ordering | Verified |
| Replay protection | Message replay validation | Verified |
| Recipient binding | Authenticated message metadata | Verified |
| Forward secrecy | Partial, documented implementation | Verified |
| Delivery under loss/reordering | Delivery simulator | Verified |
| Session resumption | Peer-bound session management | Verified |

---

## 15. Submission Information

**Project:** Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane  
**Event:** Yugaantar DevForge  
**Track:** Track 4 — Trust, but Verify  
**GitHub Repository:** https://github.com/ppuni8298-cloud/Q-SHIELD.git  

---

## 16. Acknowledgements

Built for the Yugaantar DevForge Track 4 challenge.  
Official Track 4 Toolkit: https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit  

**Q-SHIELD — Trust Changes. Verify Everything.**
