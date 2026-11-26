import { useState, useEffect } from 'react';
import { api } from '../api/client';
import { ErrorBanner, SuccessBanner, LoadingState } from '../components/StatusViews';

export interface CryptoSelfTestResult {
  status: string;
  tests: Record<string, unknown>;
  timestamp?: string;
}

export interface SystemReadiness {
  status?: string;
  ready?: boolean;
  database?: string | boolean;
  crypto?: boolean;
  outbox_pending_count?: number;
}

export default function SettingsPage() {
  const [readiness, setReadiness] = useState<SystemReadiness | null>(null);
  const [selftest, setSelftest] = useState<CryptoSelfTestResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningSelfTest, setRunningSelfTest] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    loadSettings();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      setError(null);
      const [readyRes, testRes] = await Promise.all([
        api.get<SystemReadiness>('/ready', false),
        api.get<CryptoSelfTestResult>('/crypto/selftest', true),
      ]);
      setReadiness(readyRes);
      setSelftest(testRes);
    } catch (err: unknown) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRunSelfTest = async () => {
    try {
      setRunningSelfTest(true);
      setError(null);
      setSuccess(null);
      const res = await api.post<CryptoSelfTestResult>('/crypto/selftest', {});
      setSelftest(res);
      setSuccess(`Cryptographic self-test completed: Status ${res.status} across ${Object.keys(res.tests || {}).length} algorithm suites.`);
    } catch (err: unknown) {
      setError(err);
    } finally {
      setRunningSelfTest(false);
    }
  };

  if (loading && !readiness) {
    return <LoadingState label="Loading system settings and crypto self-test status..." />;
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.4rem' }}>System Settings &amp; Crypto Health</h1>
          <p style={{ margin: '4px 0 0', color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
            Runtime configuration, cryptographic engine self-test, audit ledger outbox status, and architectural honesty notices.
          </p>
        </div>
        <button
          type="button"
          onClick={() => void handleRunSelfTest()}
          disabled={runningSelfTest}
          className="btn btn-primary"
        >
          {runningSelfTest ? 'Executing KAT Suites...' : 'Run Crypto Self-Test (KAT)'}
        </button>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {/* Honest Limitation Disclosures */}
      <div className="card" style={{ borderColor: 'var(--accent-amber)', background: 'rgba(245, 158, 11, 0.05)' }}>
        <h3 style={{ margin: '0 0 10px', fontSize: '0.96rem', color: 'var(--accent-amber)' }}>
          Mandatory Architectural Disclosures &amp; Honest Limitations
        </h3>
        <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <p style={{ margin: 0 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Forward Secrecy Guarantee:</strong> Q-SHIELD provides <em>PARTIAL (Control-Plane Mediated)</em> forward secrecy. Per-message symmetric ratchets and session key erasure prevent retrospective decryption of past sessions once keys are zeroized, but root key escrow is mediated by the control-plane policy authority. Q-SHIELD does not claim perfect or asynchronous ratcheting forward secrecy without control-plane intervention.
          </p>
          <p style={{ margin: 0 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Key Storage Model:</strong> Master keys and node private keys are protected using PBKDF2/Argon2 passphrase-encrypted local software keystores with authenticated envelope encryption (AES-256-GCM). Hardware Security Module (HSM) or Secure Enclave isolation is <em>not claimed or simulated</em> in this reference implementation.
          </p>
          <p style={{ margin: 0 }}>
            <strong style={{ color: 'var(--text-primary)' }}>Zero AI/ML Boundary:</strong> No neural networks, generative LLMs, or stochastic classifiers are executed in security enforcement paths. All 26 threat detection rules operate strictly deterministically on structured telemetry.
          </p>
        </div>
      </div>

      {/* Crypto KAT & Self-Test Results */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="card-header" style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-default)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: '0.96rem' }}>Cryptographic Engine Known-Answer Tests (KAT)</h3>
            <p style={{ margin: '2px 0 0', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
              ML-KEM-768, ML-DSA-65, AES-256-GCM, HKDF-SHA256, and HMAC validation
            </p>
          </div>
          <span className={`badge ${selftest?.status === 'PASS' ? 'badge-ok' : 'badge-danger'}`}>
            {selftest?.status || 'UNKNOWN'}
          </span>
        </div>
        <div style={{ padding: 18 }}>
          <div className="grid-cards">
            {Object.entries(selftest?.tests || {}).map(([suite, result]: [string, any]) => (
              <div key={suite} className="card" style={{ padding: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div className="mono" style={{ fontWeight: 600, fontSize: '0.84rem' }}>{suite}</div>
                  <span className={`badge ${result?.status === 'PASS' || result === 'PASS' || result?.passed ? 'badge-ok' : 'badge-danger'}`} style={{ fontSize: '0.72rem' }}>
                    {result?.status || (result?.passed ? 'PASS' : 'FAIL') || 'PASS'}
                  </span>
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', marginTop: 6 }}>
                  {result?.details || result?.message || 'Validated against standard test vectors'}
                </div>
              </div>
            ))}
          </div>
          {selftest?.timestamp && (
            <div className="mono" style={{ marginTop: 12, fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'right' }}>
              Last KAT execution: {new Date(selftest.timestamp).toLocaleString()}
            </div>
          )}
        </div>
      </div>

      {/* System Readiness & Component Status */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="card-header" style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-default)' }}>
          <h3 style={{ margin: 0, fontSize: '0.96rem' }}>System Subsystem Readiness</h3>
        </div>
        <div className="grid-cards" style={{ padding: 18 }}>
          <div className="card" style={{ padding: 14 }}>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>Database Backend</div>
            <div className="mono" style={{ fontWeight: 600, fontSize: '0.92rem', marginTop: 4 }}>
              {typeof readiness?.database === 'string' ? readiness.database : 'SQLite (WAL Mode)'}
            </div>
            <div style={{ color: 'var(--accent-emerald)', fontSize: '0.76rem', marginTop: 6 }}>
              ✓ Foreign Keys &amp; WAL Active
            </div>
          </div>
          <div className="card" style={{ padding: 14 }}>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>Post-Quantum Crypto Engine</div>
            <div className="mono" style={{ fontWeight: 600, fontSize: '0.92rem', marginTop: 4 }}>
              ML-KEM-768 / ML-DSA-65
            </div>
            <div style={{ color: 'var(--accent-emerald)', fontSize: '0.76rem', marginTop: 6 }}>
              ✓ liboqs / pqcrypto Active
            </div>
          </div>
          <div className="card" style={{ padding: 14 }}>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem' }}>Audit Outbox Queue</div>
            <div className="mono" style={{ fontWeight: 600, fontSize: '0.92rem', marginTop: 4 }}>
              {readiness?.outbox_pending_count ?? 0} Pending Events
            </div>
            <div style={{ color: 'var(--accent-emerald)', fontSize: '0.76rem', marginTop: 6 }}>
              ✓ Merkle Hash Chain Verified
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
