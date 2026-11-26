import { FormEvent, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { KeyRound, Shield, UserCheck } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner } from '../components/StatusViews';

const SEEDED_PROFILES = [
  { actorId: 'user-admin', deviceId: 'dev-admin-trusted', role: 'admin', label: 'Platform Admin (Full Control & Users)' },
  { actorId: 'user-secops', deviceId: 'dev-secops-trusted', role: 'security_operator', label: 'Security Operator (Revocations, Keys, Alerts)' },
  { actorId: 'user-auditor', deviceId: 'dev-auditor-trusted', role: 'auditor', label: 'Auditor (Read-Only Ledger, Evidence, Metrics)' },
  { actorId: 'user-alex', deviceId: 'dev-alex-trusted', role: 'owner', label: 'Resource Owner — Alex (Vault & E2E Messaging)' },
  { actorId: 'user-blair', deviceId: 'dev-blair-trusted', role: 'owner', label: 'Resource Owner — Blair (Cross-User & Peer Recipient)' },
];

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [actorId, setActorId] = useState('user-secops');
  const [deviceId, setDeviceId] = useState('dev-secops-trusted');
  const [peerId, setPeerId] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const performLogin = async (aId: string, dId: string, pId?: string) => {
    setSubmitting(true);
    setError(null);
    try {
      await login(aId.trim(), dId.trim(), pId?.trim() || undefined);
      navigate('/dashboard');
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void performLogin(actorId, deviceId, peerId);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24, background: 'var(--bg-canvas)' }}>
      <div style={{ maxWidth: 880, width: '100%', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: 20 }}>
        <section className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <Shield size={22} color="var(--accent-cyan)" />
            <h1 style={{ margin: 0, fontSize: '1.25rem' }}>Q-SHIELD Synthetic Demo Sign-In</h1>
          </div>
          <p style={{ margin: '0 0 16px', fontSize: '0.86rem', color: 'var(--text-secondary)' }}>
            Authenticates against the live FastAPI backend (`/api/v1/auth/demo-login`). Failed attempts trigger sliding-window rate limiting (`429 AUTH_RATE_LIMITED`).
          </p>

          <ErrorBanner error={error} onDismiss={() => setError(null)} />

          <form onSubmit={onSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14, marginTop: 14 }}>
            <div>
              <label htmlFor="login-actor-id" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
                Actor ID
              </label>
              <input
                id="login-actor-id"
                className="input"
                value={actorId}
                onChange={(e) => setActorId(e.target.value)}
                required
                placeholder="e.g. user-secops"
              />
            </div>

            <div>
              <label htmlFor="login-device-id" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
                Trusted Device ID
              </label>
              <input
                id="login-device-id"
                className="input"
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
                required
                placeholder="e.g. dev-secops-trusted"
              />
            </div>

            <div>
              <label htmlFor="login-peer-id" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
                Optional Peer Binding ID
              </label>
              <input
                id="login-peer-id"
                className="input"
                value={peerId}
                onChange={(e) => setPeerId(e.target.value)}
                placeholder="Optional bound peer identity"
              />
            </div>

            <button type="submit" className="btn btn-primary" disabled={submitting}>
              <KeyRound size={15} />
              <span>{submitting ? 'Authenticating...' : 'Authenticate Session'}</span>
            </button>
          </form>

          <div style={{ marginTop: 16, fontSize: '0.82rem' }}>
            <Link to="/">Back to Overview Landing Page</Link>
          </div>
        </section>

        <section className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <UserCheck size={18} color="var(--accent-emerald)" />
            <h2 style={{ margin: 0, fontSize: '1rem' }}>Seeded Demo Identities</h2>
          </div>
          <p style={{ margin: '0 0 12px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Select a synthetic persona to fill credentials or sign in immediately for role testing:
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 9 }}>
            {SEEDED_PROFILES.map((p) => (
              <div
                key={p.actorId}
                style={{
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 10,
                  padding: '10px 12px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 10,
                  background: 'var(--bg-elevated)',
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>{p.label}</div>
                  <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    {p.actorId} · {p.deviceId}
                  </div>
                </div>
                <button
                  type="button"
                  className="btn"
                  disabled={submitting}
                  onClick={() => {
                    setActorId(p.actorId);
                    setDeviceId(p.deviceId);
                    void performLogin(p.actorId, p.deviceId);
                  }}
                >
                  Use
                </button>
              </div>
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}
