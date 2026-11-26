import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Cpu, KeyRound, Lock, Radio, ShieldCheck, Terminal } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';

interface HealthStatus {
  status: string;
  service: string;
  demo_mode: boolean;
  offline_mode: boolean;
}

interface ReadyStatus {
  ready: boolean;
  database: boolean;
  crypto: boolean;
}

export function LandingPage() {
  const { user } = useAuth();
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [readyStatus, setReadyStatus] = useState<ReadyStatus | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([api.get<HealthStatus>('/health', false), api.get<ReadyStatus>('/ready', false)])
      .then(([h, rd]) => {
        if (!active) return;
        setHealth(h);
        setReadyStatus(rd);
      })
      .catch((err) => {
        if (!active) return;
        setBackendError(err instanceof Error ? err.message : 'Backend unavailable');
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <div style={{ minHeight: '100vh', background: 'radial-gradient(circle at top right, #0f213d 0%, var(--bg-canvas) 55%)', padding: '32px 24px 64px' }}>
      <div style={{ maxWidth: 1180, margin: '0 auto', display: 'flex', flexDirection: 'column', gap: 28 }}>
        <header style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <Cpu size={28} color="var(--accent-cyan)" />
            <div>
              <div style={{ fontWeight: 800, fontSize: '1.15rem', letterSpacing: '0.04em' }}>Q-SHIELD</div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Scaler Open Source Labs Track 4 · Trust, but Verify</div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 10 }}>
            <Link to={user ? '/dashboard' : '/login'} className="btn btn-primary">
              <span>{user ? 'Open Security Console' : 'Sign In to Demo Console'}</span>
              <ArrowRight size={15} />
            </Link>
          </div>
        </header>

        <section className="card" style={{ padding: '32px 28px', borderColor: 'var(--border-strong)' }}>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14 }}>
            <span className="badge badge-info">ML-KEM-768 + ML-DSA-65 + AES-256-GCM</span>
            <span className="badge badge-ok">100% Offline Deterministic Runtime</span>
            <span className="badge badge-warn">Zero Runtime AI/ML/LLM</span>
          </div>
          <h1 style={{ margin: '0 0 12px', fontSize: 'clamp(1.7rem, 3.2vw, 2.5rem)', lineHeight: 1.2 }}>
            Post-Quantum Zero-Trust Control Plane &amp; Verifiable Security Workbench
          </h1>
          <p style={{ margin: '0 0 22px', color: 'var(--text-secondary)', maxWidth: 780, fontSize: '1rem' }}>
            Q-SHIELD combines NIST ML-KEM-768 key encapsulation, ML-DSA-65 evidence signatures, AES-256-GCM AAD envelope
            encryption, irreversible revocation tombstones across simulated nodes, phased crash-safe key rotation, an
            append-only hash-chained audit ledger, an explainable 26-rule threat detector, and end-to-end encrypted messaging.
          </p>

          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <Link to="/login" className="btn btn-primary">
              <Terminal size={15} />
              <span>Launch Interactive Demo Login</span>
            </Link>
            {user && (
              <Link to="/scenarios" className="btn btn-emerald">
                <span>Run 14 Verification Scenarios</span>
              </Link>
            )}
          </div>
        </section>

        <section className="grid-cards">
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <ShieldCheck size={18} color="var(--accent-cyan)" />
              <strong>10-Step Zero-Trust Policy</strong>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
              Fail-closed evaluation of actor, session, trusted device ownership, RBAC, resource state, active key version, and tombstones.
            </p>
          </div>
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <KeyRound size={18} color="var(--accent-emerald)" />
              <strong>Crash-Safe Key Lifecycle</strong>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
              Durable rotation journal, deterministic crash injection, zero-grace cutoff enforcement, and signed anti-rollback backups.
            </p>
          </div>
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Radio size={18} color="var(--accent-amber)" />
              <strong>Revocation &amp; Convergence</strong>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
              Deterministic simulated multi-node propagation, fault injection, and convergence tracking without distributed fabric illusions.
            </p>
          </div>
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Lock size={18} color="var(--accent-violet)" />
              <strong>Honest Security Boundaries</strong>
            </div>
            <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
              Documents local passphrase-encrypted keystore and PARTIAL control-plane-mediated forward secrecy rather than claiming hardware HSM isolation.
            </p>
          </div>
        </section>

        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1.05rem' }}>Live Backend &amp; Cryptographic Primitives Status</h2>
            {health && (
              <span className="badge badge-ok">
                <CheckCircle2 size={13} /> {health.status.toUpperCase()}
              </span>
            )}
          </div>
          {backendError ? (
            <div className="alert-banner alert-error">
              <span>Live API probe unreachable ({backendError}). Start FastAPI backend (`uvicorn backend.app.main:app --port 8000`).</span>
            </div>
          ) : !health || !readyStatus ? (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>Probing live readiness endpoint...</div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, fontSize: '0.85rem' }}>
              <div>
                <div style={{ color: 'var(--text-muted)' }}>Service Mode</div>
                <div className="mono">demo={String(health.demo_mode)} · offline={String(health.offline_mode)}</div>
              </div>
              <div>
                <div style={{ color: 'var(--text-muted)' }}>Database &amp; Crypto Readiness</div>
                <div className="mono">ready={String(readyStatus.ready)} · db={String(readyStatus.database)} · pqc={String(readyStatus.crypto)}</div>
              </div>
              <div>
                <div style={{ color: 'var(--text-muted)' }}>Post-Quantum Suite</div>
                <div className="mono">ML-KEM-768 · ML-DSA-65 · AES-256-GCM · HKDF-SHA-256</div>
              </div>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}

export default LandingPage;

