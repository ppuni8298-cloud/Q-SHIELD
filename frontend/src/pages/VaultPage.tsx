import { FormEvent, useCallback, useEffect, useState } from 'react';
import { KeyRound, Lock, Plus, RefreshCw, Shield, Unlock } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface ResourceRecord {
  id: string;
  owner_id: string;
  type: string;
  metadata: Record<string, unknown>;
  key_version: number;
  state: 'ACTIVE' | 'DISABLED';
  created_at: string;
  updated_at: string;
}

interface PolicyDecision {
  decision: 'ALLOW' | 'DENY';
  reason_code: string;
  rule: string;
  correlation_id: string;
}

export function VaultPage() {
  const { user } = useAuth();
  const [resources, setResources] = useState<ResourceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // New resource form
  const [showCreate, setShowCreate] = useState(false);
  const [newResId, setNewResId] = useState('');
  const [newType, setNewType] = useState('document');
  const [initialSecret, setInitialSecret] = useState('');

  // Policy eval interactive test
  const [evalActor, setEvalActor] = useState(user?.actor_id || 'user-alex');
  const [evalSession, setEvalSession] = useState(user?.session?.id || 'sess-alex-valid');
  const [evalDevice, setEvalDevice] = useState(user?.session?.device_id || 'dev-alex-trusted');
  const [evalResId, setEvalResId] = useState('res-alex-brief');
  const [evalAction, setEvalAction] = useState('read');
  const [policyResult, setPolicyResult] = useState<PolicyDecision | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  // Decryption interactive test
  const [decryptResId, setDecryptResId] = useState('res-alex-brief');
  const [decryptedPlaintext, setDecryptedPlaintext] = useState<string | null>(null);
  const [decrypting, setDecrypting] = useState(false);

  // Encrypt interactive test
  const [encryptResId, setEncryptResId] = useState('res-alex-brief');
  const [encryptPlaintext, setEncryptPlaintext] = useState('');
  const [encrypting, setEncrypting] = useState(false);

  const loadResources = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: ResourceRecord[] }>('/resources');
      setResources(res.items);
      if (res.items.length > 0) {
        setEvalResId(res.items[0].id);
        setDecryptResId(res.items[0].id);
        setEncryptResId(res.items[0].id);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadResources();
  }, [loadResources]);

  const handleCreateResource = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    try {
      await api.post('/resources', {
        id: newResId.trim(),
        type: newType.trim(),
        metadata: { description: 'Interactive user vault asset' },
        initial_plaintext: initialSecret ? initialSecret : undefined,
      });
      setSuccess(`Resource '${newResId}' created successfully.`);
      setShowCreate(false);
      setNewResId('');
      setInitialSecret('');
      await loadResources();
    } catch (err) {
      setError(err);
    }
  };

  const handleEvaluatePolicy = async (e: FormEvent) => {
    e.preventDefault();
    setEvaluating(true);
    setError(null);
    try {
      const res = await api.post<PolicyDecision>('/policy/evaluate', {
        actor_id: evalActor.trim(),
        session_id: evalSession.trim(),
        device_id: evalDevice.trim(),
        resource_id: evalResId.trim(),
        action: evalAction.trim(),
      });
      setPolicyResult(res);
    } catch (err) {
      setError(err);
    } finally {
      setEvaluating(false);
    }
  };

  const handleDecrypt = async () => {
    setDecrypting(true);
    setError(null);
    setDecryptedPlaintext(null);
    try {
      const res = await api.post<{ plaintext: string }>(`/resources/${decryptResId}/decrypt`, {});
      setDecryptedPlaintext(res.plaintext);
      setSuccess(`Successfully authenticated & decrypted resource '${decryptResId}'.`);
    } catch (err) {
      setError(err);
    } finally {
      setDecrypting(false);
    }
  };

  const handleEncrypt = async (e: FormEvent) => {
    e.preventDefault();
    setEncrypting(true);
    setError(null);
    try {
      await api.post(`/resources/${encryptResId}/encrypt`, {
        plaintext: encryptPlaintext,
      });
      setSuccess(`Encrypted new content under AES-256-GCM + wrapped DEK for '${encryptResId}'.`);
      setEncryptPlaintext('');
      await loadResources();
    } catch (err) {
      setError(err);
    } finally {
      setEncrypting(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Protected Vault &amp; Zero-Trust Policy Engine</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Envelope encryption (AES-256-GCM) · Wrapped DEK per resource · 10-step fail-closed policy evaluation
          </div>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => setShowCreate(!showCreate)}>
          <Plus size={15} />
          <span>{showCreate ? 'Close Form' : 'Register Resource'}</span>
        </button>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {showCreate && (
        <form onSubmit={handleCreateResource} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Register Protected Resource</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <label htmlFor="create-res-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Resource ID</label>
              <input id="create-res-id" className="input" value={newResId} onChange={(e) => setNewResId(e.target.value)} required placeholder="res-financial-report" />
            </div>
            <div>
              <label htmlFor="create-res-type" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Resource Type</label>
              <input id="create-res-type" className="input" value={newType} onChange={(e) => setNewType(e.target.value)} required placeholder="document" />
            </div>
            <div>
              <label htmlFor="create-res-secret" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Initial Plaintext (Optional)</label>
              <input id="create-res-secret" className="input" value={initialSecret} onChange={(e) => setInitialSecret(e.target.value)} placeholder="Secret payload encrypted immediately" />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowCreate(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary">Create Resource</button>
          </div>
        </form>
      )}

      {loading && resources.length === 0 ? (
        <LoadingState label="Loading vault resources..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Lock size={16} /> Vault Assets ({resources.length})
            </h2>
            <button type="button" className="btn" onClick={() => void loadResources()}>
              <RefreshCw size={13} />
              <span>Refresh</span>
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Resource ID</th>
                  <th>Owner</th>
                  <th>Type</th>
                  <th>KEK Version</th>
                  <th>Status</th>
                  <th>Registered</th>
                </tr>
              </thead>
              <tbody>
                {resources.map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.id}</td>
                    <td className="mono">{r.owner_id}</td>
                    <td>{r.type}</td>
                    <td><span className="badge badge-info">v{r.key_version}</span></td>
                    <td><StatusBadge value={r.state} /></td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{r.created_at.slice(0, 19).replace('T', ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Interactive 10-Step Policy Engine Workbench */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Shield size={16} color="var(--accent-cyan)" /> 10-Step Zero-Trust Policy Simulator
            </h2>
          </div>
          <p style={{ margin: '0 0 14px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Evaluates identity status, session validity, device trust, role permissions, resource state, key version, and tombstones in strict order.
          </p>

          <form onSubmit={handleEvaluatePolicy} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label htmlFor="eval-actor" style={{ display: 'block', fontSize: '0.76rem', color: 'var(--text-muted)' }}>Actor ID</label>
                <input id="eval-actor" className="input" value={evalActor} onChange={(e) => setEvalActor(e.target.value)} required />
              </div>
              <div>
                <label htmlFor="eval-session" style={{ display: 'block', fontSize: '0.76rem', color: 'var(--text-muted)' }}>Session ID</label>
                <input id="eval-session" className="input" value={evalSession} onChange={(e) => setEvalSession(e.target.value)} required />
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label htmlFor="eval-device" style={{ display: 'block', fontSize: '0.76rem', color: 'var(--text-muted)' }}>Device ID</label>
                <input id="eval-device" className="input" value={evalDevice} onChange={(e) => setEvalDevice(e.target.value)} required />
              </div>
              <div>
                <label htmlFor="eval-resource" style={{ display: 'block', fontSize: '0.76rem', color: 'var(--text-muted)' }}>Resource ID</label>
                <input id="eval-resource" className="input" value={evalResId} onChange={(e) => setEvalResId(e.target.value)} required />
              </div>
            </div>
            <div>
              <label htmlFor="eval-action" style={{ display: 'block', fontSize: '0.76rem', color: 'var(--text-muted)' }}>Action</label>
              <select id="eval-action" className="select" value={evalAction} onChange={(e) => setEvalAction(e.target.value)}>
                <option value="read">read</option>
                <option value="encrypt">encrypt</option>
                <option value="write">write</option>
                <option value="admin">admin</option>
              </select>
            </div>
            <button type="submit" className="btn btn-primary" disabled={evaluating}>
              <span>{evaluating ? 'Evaluating...' : 'Run 10-Step Policy Evaluation'}</span>
            </button>
          </form>

          {policyResult && (
            <div style={{ marginTop: 14, background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <strong>Decision Outcome:</strong>
                <StatusBadge value={policyResult.decision} />
              </div>
              <div style={{ fontSize: '0.82rem' }}>
                <div><span style={{ color: 'var(--text-muted)' }}>Reason Code:</span> <span className="mono">{policyResult.reason_code}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>Triggered Rule:</span> <span className="mono">{policyResult.rule}</span></div>
                <div><span style={{ color: 'var(--text-muted)' }}>Correlation ID:</span> <span className="mono" style={{ fontSize: '0.74rem' }}>{policyResult.correlation_id}</span></div>
              </div>
            </div>
          )}
        </section>

        {/* Interactive Encrypt / Decrypt Laboratory */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={16} color="var(--accent-emerald)" /> Authenticated Decryption Lab
            </h2>
          </div>
          <p style={{ margin: '0 0 12px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Requires authenticated session matching resource owner or admin permissions. Authenticates AES-256-GCM AEAD tag and unwrap DEK.
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <select className="select" value={decryptResId} onChange={(e) => setDecryptResId(e.target.value)} style={{ flex: 1 }}>
              {resources.map((r) => (
                <option key={r.id} value={r.id}>{r.id} ({r.owner_id})</option>
              ))}
            </select>
            <button type="button" className="btn btn-emerald" onClick={() => void handleDecrypt()} disabled={decrypting}>
              <Unlock size={14} />
              <span>{decrypting ? 'Decrypting...' : 'Decrypt'}</span>
            </button>
          </div>

          {decryptedPlaintext !== null && (
            <div style={{ background: '#050a14', border: '1px solid var(--accent-emerald)', borderRadius: 8, padding: 12, marginBottom: 14 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', fontWeight: 600, marginBottom: 4 }}>
                AUTHENTICATED PLAINTEXT (AEAD VALID):
              </div>
              <pre style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.88rem', whiteSpace: 'pre-wrap' }}>
                {decryptedPlaintext}
              </pre>
            </div>
          )}

          <hr style={{ border: 'none', borderTop: '1px solid var(--border-subtle)', margin: '14px 0' }} />

          <form onSubmit={handleEncrypt} style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>Re-encrypt Resource Plaintext</div>
            <textarea
              className="textarea"
              rows={2}
              value={encryptPlaintext}
              onChange={(e) => setEncryptPlaintext(e.target.value)}
              required
              placeholder="Enter new secret content to envelope-encrypt under wrapped DEK..."
            />
            <button type="submit" className="btn btn-primary" disabled={encrypting || !encryptPlaintext.trim()}>
              <Lock size={14} />
              <span>{encrypting ? 'Encrypting...' : 'Encrypt & Persist'}</span>
            </button>
          </form>
        </section>
      </div>
    </div>
  );
}
