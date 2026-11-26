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
  ML-KEM-768       Rotation         Coordinator
  AES-256-GCM      Recovery         Node Simulator
  HKDF / HMAC      Backup           3–7 Nodes
       |                |                |
       +----------------+----------------+
                        |
                        v
              AUDIT & DETECTION LAYER
                        |
          +-------------+-------------+
          |                           |
          v                           v
     Audit Ledger               Threat Detector
     SHA-256 Chain              Rule-Based Analysis
     Signed Evidence            Graph Detection
          |                           |
          +-------------+-------------+
                        |
                        v
                  SQLITE DATABASE
```

### Architecture Components

| Component | Responsibility |
|---|---|
| Frontend | Security dashboard and operator controls |
| API Layer | REST endpoints and request validation |
| Identity Service | User, role, and device management |
| Policy Engine | Zero-trust access decisions |
| Crypto Vault | Cryptographic key and protected-data operations |
| Key Lifecycle | Rotation, revocation, backup, and recovery |
| Node Simulator | Multi-node revocation enforcement |
| Messaging Service | Secure communication and delivery |
| Audit Ledger | Tamper-evident event records |
| Detection Engine | Suspicious activity and lateral movement detection |
| Database | Persistent application and security state |

## 6. Core Features

### 6.1 Identity and Zero-Trust Access Control
- Role-based access control.
- Identity and device validation.
- Context-aware authorization.
- Policy-based allow and deny decisions.
- Security decision logging.

### 6.2 Post-Quantum Cryptography
- ML-KEM-768 key encapsulation.
- AES-256-GCM authenticated encryption.
- HKDF-SHA256 key derivation.
- HMAC-SHA256 verification.
- SHA-256 integrity verification.
- ML-DSA-based signed evidence where implemented.

### 6.3 Key Management
- Cryptographic key lifecycle management.
- Controlled key rotation.
- Revocation and cutoff enforcement.
- Crash recovery using a durable rotation journal.
- Encrypted backup and integrity verification.
- Anti-rollback protection.

### 6.4 Distributed Revocation
- Simulated multi-node environment.
- Revocation event propagation.
- Duplicate and stale event handling.
- Offline-node catch-up.
- Revocation convergence measurement.
- Fail-closed access enforcement.

### 6.5 Tamper-Evident Audit
- Append-only audit ledger.
- Hash-chained security events.
- Signed checkpoints and evidence receipts.
- Canonical event serialization.
- Independent audit verification.
- Sensitive-data redaction.

### 6.6 Threat Detection
- Deterministic, explainable detection rules.
- Suspicious privilege-change detection.
- Lateral movement analysis.
- Out-of-order event handling.
- Clock-skew awareness.
- Alert lifecycle and recommendations.
- Measured precision, recall, F1, and false-alert rates.

### 6.7 Secure Messaging
- Authenticated encrypted messages.
- Recipient and sender binding.
- Replay protection.
- Message sequence validation.
- Session lifecycle management.
- Peer-bound session resumption.
- Delivery simulation under loss and reordering.

### 6.8 Operator Dashboard
- Security overview.
- Identity and device management.
- Key and vault management.
- Node and revocation monitoring.
- Audit evidence inspection.
- Threat alerts.
- Messaging and session management.
- Scenario simulation and benchmarks.

## 7. Technology Stack

| Layer | Technologies |
|---|---|
| Frontend | React, TypeScript, Vite |
| Styling | Tailwind CSS |
| Backend | Python, FastAPI |
| API Validation | Pydantic |
| ORM | SQLAlchemy |
| Database | SQLite |
| Migrations | Alembic |
| Post-Quantum KEM | ML-KEM-768 |
| Digital Signatures | ML-DSA-65 where implemented |
| Symmetric Encryption | AES-256-GCM |
| Key Derivation | HKDF-SHA256 |
| Message Authentication | HMAC-SHA256 |
| Integrity | SHA-256 |
| Testing | Pytest, HTTPX, Vitest, Playwright |
| Benchmarking | Python performance and memory profiling |

Cryptographic algorithms are provided through vetted libraries rather than custom cryptographic implementations.

## 8. Security Design

Q-SHIELD follows these security principles:

- **Least Privilege:** Users receive only the permissions required for their roles.
- **Fail Closed:** Invalid, revoked, or unverifiable security states do not grant access.
- **Cryptographic Integrity:** Protected data and audit evidence are verified.
- **Replay Resistance:** Duplicate messages and reused session tokens are rejected.
- **Revocation Enforcement:** Revoked identities, devices, keys, and sessions are prevented from continuing unauthorized operations.
- **Secure Recovery:** Interrupted operations recover to a consistent authorized state.
- **Offline Operation:** Runtime security functionality does not depend on external AI services or internet access.
- **Auditability:** Security decisions and trust transitions generate verifiable evidence.

### Threat Model

**Protected Assets**
- User identities and permissions.
- Device trust state.
- Cryptographic keys.
- Protected messages and files.
- Session credentials.
- Audit records and security evidence.

**Potential Threats**
- Identity compromise.
- Lost or compromised devices.
- Key compromise.
- Unauthorized privilege escalation.
- Replay and message tampering.
- Lateral movement.
- Audit log manipulation.
- Backup corruption.
- Interrupted key rotation.

**Assumptions and Limitations**

The prototype uses synthetic identities, simulated nodes, and a local demonstration environment. It is not a certified production HSM-backed distributed security infrastructure.

## 9. Project Structure

The repository is organized into the following logical areas. Exact paths should reflect the committed implementation.

```text
Q-SHIELD/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── models/
│   │   ├── services/
│   │   ├── crypto/
│   │   ├── messaging/
│   │   └── main.py
│   │
│   └── tests/
│
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── context/
│   └── package.json
│
├── scripts/
│   ├── security_checks.py
│   ├── benchmark.py
│   └── run_e2e.ps1
│
├── tests/
│   ├── adapter/
│   └── security/
│
├── docs/
│   ├── architecture.md
│   ├── threat_model.md
│   ├── requirement_traceability.csv
│   ├── performance_benchmarks.md
│   ├── known_limitations.md
│   └── final_security_assessment.md
│
├── track4_service.py
├── README.md
├── requirements.txt
└── .gitignore
```

*Note: This is the intended logical layout. Update it to match the actual repository after the final file-organization audit.*

## 10. Installation and Setup

### Prerequisites

- Python 3.12
- Node.js and npm
- Git
- Windows, Linux, or macOS

### Clone the Repository

```bash
git clone YOUR_PUBLIC_GITHUB_REPOSITORY_URL
cd Q-SHIELD
```

### Backend Setup

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install the backend dependencies using the repository's dependency file:

```bash
pip install -r requirements.txt
```

If dependencies are maintained in a backend-specific file, use that file instead.

Apply database migrations:

```bash
alembic upgrade head
```

Start the backend using the project's configured FastAPI application:

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

The API documentation is available at:

```text
http://127.0.0.1:8000/docs
```

### Frontend Setup

Open a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open the local frontend URL displayed by Vite.

Ensure the frontend API configuration points to the running backend.

## 11. Testing and Verification

Q-SHIELD includes backend, adapter, security, frontend, and end-to-end verification.

### Backend Tests

```bash
python -m pytest backend/tests tests/adapter -q
```

### Adapter Tests

```bash
python -m pytest tests/adapter -v
```

### Offline Network Isolation Tests

```bash
python -m pytest tests/security/test_offline_network_isolation.py -v
```

### Security Checks

```bash
python scripts/security_checks.py
```

### Frontend Tests

```bash
cd frontend
npx vitest run
npm run build
```

### End-to-End Tests

Run the repository's configured Playwright test script:

```powershell
powershell.exe -ExecutionPolicy Bypass -File scripts/run_e2e.ps1
```

### Official Track 4 Toolkit

Official toolkit:

https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit

The root-level `track4_service.py` provides the organizer adapter interface.

Run the official validator and toolkit tests using the commands supplied by the official toolkit.

**Important:** Actual test results should be recorded from the final clean-machine verification. Do not treat previously reported test results as proof that a later commit passes.

## 12. Performance Evaluation

Q-SHIELD includes benchmarking for cryptographic and application operations, including:

- ML-KEM key generation.
- Key encapsulation and decapsulation.
- HKDF key derivation.
- AES-GCM encryption and decryption.
- Authentication.
- Message ingestion.
- Memory consumption.

The benchmark report should include measured mean, median, p95, p99, and peak memory usage where applicable.

See:

`docs/performance_benchmarks.md`

Performance values must come from actual executions, not estimates.

## 13. Known Limitations

Q-SHIELD is a hackathon prototype and has the following documented limitations:

1. **Forward Secrecy:** The current messaging design provides partial, control-plane-mediated forward-secrecy properties. It should not be described as providing complete forward secrecy.
2. **Key Storage:** The local software keystore is encrypted, but it is not equivalent to a hardware security module.
3. **Node Infrastructure:** The multi-node environment is simulated within the application rather than deployed as independent production servers.
4. **Production Deployment:** Additional operational hardening, independent security review, and infrastructure integration would be necessary before production use.

## 14. Future Scope

- Hardware-backed key management using HSMs or secure enclaves.
- Stronger forward-secrecy and post-compromise security guarantees.
- Real distributed node deployment.
- Advanced policy administration and identity federation.
- External signed audit checkpoints.
- More extensive adversarial and concurrency testing.
- Production observability and monitoring integrations.
- Integration with enterprise identity and access management systems.

## 15. Track 4 Compliance

| Track 4 Requirement | Q-SHIELD Component |
|---|---|
| Key rotation | Key lifecycle service |
| Revocation across nodes | Revocation coordinator |
| Crash recovery | Durable recovery journal |
| Backup integrity | Encrypted and signed backup verification |
| Log integrity | Hash-chained audit ledger |
| Suspicious activity detection | Deterministic detection engine |
| Lateral movement | Graph-based detection |
| Clock differences | Timestamp correction and event ordering |
| Replay protection | Message replay validation |
| Recipient binding | Authenticated message metadata |
| Forward secrecy | Partial, documented implementation |
| Delivery under loss/reordering | Delivery simulator |
| Session resumption | Peer-bound session management |

## 16. Submission Information

**Project:** Q-SHIELD — Quantum-Ready Trust & Revocation Control Plane

**Event:** Yugaantar DevForge

**Track:** Track 4 — Trust, but Verify

**GitHub Repository:** 
**Project Brief:** Add the final two-page PDF to the repository or provide its submission link.

**Demo Video:** 

---

## 17. Acknowledgements

Built for the Yugaantar DevForge Track 4 challenge.

Official Track 4 Toolkit:

https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit

**Q-SHIELD — Trust Changes. Verify Everything.**
