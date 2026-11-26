import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, Download, Eye, FileCheck, FileText, RefreshCw, ShieldAlert, XCircle } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface AuditEventItem {
  sequence: number;
  event_id: string;
  event_type: string;
  event_category: string;
  timestamp_utc: string;
  actor_id: string;
  action: string;
  outcome: string;
  reason_code: string;
  event_hash: string;
  prev_hash: string;
  source_component: string;
}

interface VerificationReport {
  valid: boolean;
  ledger_id: string;
  verified_event_count: number;
  total_events_inspected: number;
  head_hash: string | null;
  detail: string;
}

interface EvidenceReceipt {
  receipt_id: string;
  receipt_type: string;
  sequence: number;
  event_hash: string;
  chain_head_hash: string;
  signature_algorithm: string;
  signature_b64: string;
}

export function AuditPage() {
  const { hasPermission } = useAuth();
  const [events, setEvents] = useState<AuditEventItem[]>([]);
  const [verification, setVerification] = useState<VerificationReport | null>(null);
  const [receipt, setReceipt] = useState<EvidenceReceipt | null>(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [evRes, verRes] = await Promise.all([
        api.get<{ items: AuditEventItem[] }>('/audit/events?limit=30'),
        api.post<VerificationReport>('/audit/verify', {}),
      ]);
      setEvents(evRes.items);
      setVerification(verRes);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleRunVerify = async () => {
    setVerifying(true);
    setError(null);
    try {
      const res = await api.post<VerificationReport>('/audit/verify', {});
      setVerification(res);
      if (res.valid) {
        setSuccess(`Full audit hash chain VERIFIED across ${res.verified_event_count} events.`);
      } else {
        setError(`Audit chain verification detected TAMPERING: ${res.detail}`);
      }
    } catch (err) {
      setError(err);
    } finally {
      setVerifying(false);
    }
  };

  const handleIssueReceipt = async (eventId: string) => {
    setError(null);
    setReceipt(null);
    try {
      const res = await api.post<EvidenceReceipt>(`/audit/events/${eventId}/receipt`, {});
      setReceipt(res);
      setSuccess(`Issued ML-DSA-65 signed evidence receipt for '${eventId}'.`);
    } catch (err) {
      setError(err);
    }
  };

  const handleExportPackage = async () => {
    setError(null);
    try {
      const res = await api.post<{ package_id: string; total_events: number; signed_receipt: unknown }>('/audit/export', {
        first_sequence: 1,
      });
      setSuccess(`Exported verifiable evidence package '${res.package_id}' (${res.total_events} events, signed with ML-DSA-65).`);
    } catch (err) {
      setError(err);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Tamper-Evident Audit Ledger &amp; Evidence Engine</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Cryptographically linked append-only ledger · SHA-256 hash chains · ML-DSA-65 verifiable receipts &amp; export
          </div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button type="button" className="btn btn-emerald" onClick={() => void handleExportPackage()}>
            <Download size={14} />
            <span>Export Evidence</span>
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void handleRunVerify()} disabled={verifying}>
            <CheckCircle2 size={14} />
            <span>{verifying ? 'Verifying Chain...' : 'Verify Hash Chain'}</span>
          </button>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {verification && (
        <div className="card" style={{ borderColor: verification.valid ? 'var(--accent-emerald)' : 'var(--accent-rose)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                {verification.valid ? <CheckCircle2 size={18} color="var(--accent-emerald)" /> : <XCircle size={18} color="var(--accent-rose)" />}
                <strong style={{ fontSize: '1.05rem' }}>
                  {verification.valid ? 'Audit Hash Chain Valid & Intact' : 'TAMPER DETECTED ON AUDIT CHAIN'}
                </strong>
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
                {verification.detail}
              </p>
            </div>
            <div style={{ textAlign: 'right' }}>
              <div className="mono" style={{ fontSize: '0.8rem' }}>Events Inspected: {verification.total_events_inspected}</div>
              <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                head={verification.head_hash ? `${verification.head_hash.slice(0, 20)}...` : 'none'}
              </div>
            </div>
          </div>
        </div>
      )}

      {receipt && (
        <div className="card" style={{ background: '#050a14', borderColor: 'var(--accent-cyan)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <strong style={{ color: 'var(--accent-cyan)' }}>ML-DSA-65 Evidence Receipt ({receipt.receipt_id})</strong>
            <span className="badge badge-info">{receipt.signature_algorithm}</span>
          </div>
          <div className="mono" style={{ fontSize: '0.76rem', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 6 }}>
            <div>sequence={receipt.sequence}</div>
            <div>event_hash={receipt.event_hash.slice(0, 20)}...</div>
            <div>chain_head={receipt.chain_head_hash.slice(0, 20)}...</div>
            <div>sig={receipt.signature_b64.slice(0, 32)}...</div>
          </div>
        </div>
      )}

      {loading && events.length === 0 ? (
        <LoadingState label="Inspecting cryptographically linked audit ledger..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <FileText size={16} /> Audit Event Stream (Recent {events.length})
            </h2>
            <button type="button" className="btn" onClick={() => void loadData()}>
              <RefreshCw size={13} />
              <span>Refresh</span>
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Seq</th>
                  <th>Event ID</th>
                  <th>Type</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Outcome</th>
                  <th>Reason</th>
                  <th>Event Hash</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.event_id}>
                    <td className="mono" style={{ color: 'var(--accent-cyan)' }}>#{e.sequence}</td>
                    <td className="mono" style={{ fontSize: '0.74rem' }}>{e.event_id.slice(0, 14)}...</td>
                    <td><span className="mono" style={{ fontSize: '0.78rem' }}>{e.event_type}</span></td>
                    <td className="mono">{e.actor_id}</td>
                    <td>{e.action}</td>
                    <td><StatusBadge value={e.outcome} /></td>
                    <td style={{ fontSize: '0.78rem' }}>{e.reason_code}</td>
                    <td className="mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{e.event_hash.slice(0, 12)}...</td>
                    <td>
                      <button
                        type="button"
                        className="btn"
                        style={{ padding: '2px 8px', fontSize: '0.72rem' }}
                        onClick={() => void handleIssueReceipt(e.event_id)}
                      >
                        Receipt
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
