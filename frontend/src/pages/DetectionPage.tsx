import { FormEvent, useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Check, CheckCircle2, Filter, Play, RefreshCw, ShieldAlert, X } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ConfirmModal } from '../components/ConfirmModal';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface RuleItem {
  rule_id: string;
  category: string;
  title: string;
  severity: string;
  base_weight: number;
  recommended_response: string;
  description: string;
}

interface AlertItem {
  id: string;
  rule_id: string;
  severity: string;
  confidence: number;
  explanation: string;
  actor_id: string;
  device_id: string | null;
  status: 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';
  recommended_response: string;
  alert_time: string;
}

interface DetectionRunResult {
  run_id: string;
  events_inspected: number;
  alerts_created: number;
  alerts_deduplicated: number;
  audit_chain_verified: boolean;
  status: string;
  summary_detail: string;
}

export function DetectionPage() {
  const { hasPermission } = useAuth();
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [latestRun, setLatestRun] = useState<DetectionRunResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [evaluating, setEvaluating] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Triage confirm modal
  const [pendingTriage, setPendingTriage] = useState<{
    alertId: string;
    action: 'acknowledge' | 'resolve' | 'false-positive';
  } | null>(null);
  const [modalBusy, setModalBusy] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rRes, aRes, runRes] = await Promise.all([
        api.get<{ rules: RuleItem[] }>('/detector/rules'),
        api.get<{ items: AlertItem[] }>('/detector/alerts'),
        api.get<{ items: DetectionRunResult[] }>('/detector/runs').catch(() => ({ items: [] })),
      ]);
      setRules(rRes.rules);
      setAlerts(aRes.items);
      if (runRes.items.length > 0) {
        setLatestRun(runRes.items[0]);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleEvaluate = async (source = 'audit_ledger') => {
    setEvaluating(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<{ run: DetectionRunResult; alerts: AlertItem[] }>('/detector/evaluate', {
        source,
      });
      setLatestRun(res.run);
      setSuccess(`Evaluation completed: inspected ${res.run.events_inspected} events, created ${res.run.alerts_created} alerts (deduped ${res.run.alerts_deduplicated}). Audit chain verified=${String(res.run.audit_chain_verified)}.`);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setEvaluating(false);
    }
  };

  const handleTriageAction = async (reason: string) => {
    if (!pendingTriage) return;
    setModalBusy(true);
    setError(null);
    try {
      const { alertId, action } = pendingTriage;
      await api.post(`/detector/alerts/${alertId}/${action}`, {
        reason,
        confirmation: true,
      });
      setSuccess(`Alert '${alertId}' transitioned to '${action.toUpperCase()}'.`);
      setPendingTriage(null);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setModalBusy(false);
    }
  };

  const canTriage = hasPermission('detector:triage');
  const canRun = hasPermission('detector:run');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Explainable Deterministic Threat Detector</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            26 deterministic rules across 6 threat categories · Zero AI/ML/LLM · Precondition audit-chain verification · Non-destructive triage
          </div>
        </div>
        {canRun && (
          <div style={{ display: 'flex', gap: 10 }}>
            <button type="button" className="btn btn-primary" onClick={() => void handleEvaluate('audit_ledger')} disabled={evaluating}>
              <Play size={14} />
              <span>{evaluating ? 'Evaluating...' : 'Evaluate Live Ledger'}</span>
            </button>
          </div>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {latestRun && (
        <div className="card" style={{ borderColor: 'var(--border-strong)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
            <div>
              <div style={{ fontWeight: 600, fontSize: '0.94rem' }}>
                Latest Detection Run: <span className="mono">{latestRun.run_id}</span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: 2 }}>
                {latestRun.summary_detail}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span className="badge badge-info">{latestRun.events_inspected} events inspected</span>
              <span className="badge badge-warn">{latestRun.alerts_created} alerts</span>
              <span className="badge badge-ok">Chain Verified: {String(latestRun.audit_chain_verified)}</span>
            </div>
          </div>
        </div>
      )}

      {/* Active Alerts Table */}
      <div className="card">
        <div className="card-header">
          <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldAlert size={16} color="var(--accent-rose)" /> Detected Security Alerts ({alerts.length})
          </h2>
          <button type="button" className="btn" onClick={() => void loadData()}>
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
        </div>
        {loading && alerts.length === 0 ? (
          <LoadingState label="Loading security alerts..." />
        ) : alerts.length === 0 ? (
          <div style={{ color: 'var(--text-secondary)', fontSize: '0.86rem', padding: '12px 0' }}>
            No security alerts currently active. Evaluate the live ledger or run the 14-scenario lab to trigger detection rules.
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule ID</th>
                  <th>Severity</th>
                  <th>Actor</th>
                  <th>Status</th>
                  <th>Explanation &amp; Recommended Action</th>
                  {canTriage && <th>Triage Controls</th>}
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <tr key={a.id}>
                    <td className="mono" style={{ color: 'var(--accent-cyan)' }}>{a.rule_id}</td>
                    <td><StatusBadge value={a.severity} /></td>
                    <td className="mono">{a.actor_id}</td>
                    <td><StatusBadge value={a.status} /></td>
                    <td style={{ fontSize: '0.82rem' }}>
                      <div>{a.explanation}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.74rem', marginTop: 2 }}>
                        Rec: {a.recommended_response}
                      </div>
                    </td>
                    {canTriage && (
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {a.status === 'OPEN' && (
                            <button
                              type="button"
                              className="btn btn-amber"
                              style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                              onClick={() => setPendingTriage({ alertId: a.id, action: 'acknowledge' })}
                            >
                              Ack
                            </button>
                          )}
                          {['OPEN', 'ACKNOWLEDGED'].includes(a.status) && (
                            <>
                              <button
                                type="button"
                                className="btn btn-emerald"
                                style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                                onClick={() => setPendingTriage({ alertId: a.id, action: 'resolve' })}
                              >
                                Resolve
                              </button>
                              <button
                                type="button"
                                className="btn"
                                style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                                onClick={() => setPendingTriage({ alertId: a.id, action: 'false-positive' })}
                              >
                                False +
                              </button>
                            </>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* 26-Rule Catalog Accordion/Grid */}
      <div className="card">
        <div className="card-header">
          <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
            <Filter size={16} /> 26 Deterministic Detection Rules Catalog
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
          {rules.map((r) => (
            <div key={r.rule_id} style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                <span className="mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600, fontSize: '0.85rem' }}>{r.rule_id}</span>
                <StatusBadge value={r.severity} />
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.84rem', marginBottom: 4 }}>{r.title}</div>
              <p style={{ margin: '0 0 6px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{r.description}</p>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Rec: <span className="mono">{r.recommended_response}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      <ConfirmModal
        open={Boolean(pendingTriage)}
        title={`Triage Alert ${pendingTriage?.alertId} (${pendingTriage?.action})`}
        description={`Record triage action '${pendingTriage?.action}' into the append-only audit ledger with operator reason.`}
        danger={pendingTriage?.action === 'false-positive'}
        confirmLabel="Record Triage"
        busy={modalBusy}
        onCancel={() => setPendingTriage(null)}
        onConfirm={handleTriageAction}
      />
    </div>
  );
}
