import { useState, useEffect } from 'react';
import { api } from '../api/client';
import { ErrorBanner, SuccessBanner, LoadingState, StatusBadge } from '../components/StatusViews';
import ConfirmModal from '../components/ConfirmModal';

export interface ScenarioResult {
  scenario_id: string;
  name: string;
  category: string;
  description: string;
  status: string;
  duration_ms?: number;
  audit_event_ids?: string[];
  details?: Record<string, unknown>;
  executed_at?: string;
}

interface ScenarioListResponse {
  total: number;
  items?: ScenarioResult[];
  data?: ScenarioResult[];
}

interface ScenarioRunAllResponse {
  total_executed: number;
  total_passed: number;
  total_failed: number;
  total_duration_ms: number;
  results: ScenarioResult[];
}

export default function ScenariosPage() {
  const [scenarios, setScenarios] = useState<ScenarioResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningAll, setRunningAll] = useState(false);
  const [runningId, setRunningId] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioResult | null>(null);
  const [confirmRunAll, setConfirmRunAll] = useState(false);

  useEffect(() => {
    loadScenarios();
  }, []);

  const loadScenarios = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.get<ScenarioListResponse>('/simulation/scenarios');
      const raw = res.items || res.data || [];
      const normalized: ScenarioResult[] = raw.map((item: any) => ({
        scenario_id: String(item.scenario_id || item.id || 'scenario'),
        name: String(item.name || item.title || item.id || 'Scenario'),
        category: String(item.category || 'General'),
        description: String(item.description || item.title || 'Deterministic test scenario'),
        status: String(item.status || 'NOT_RUN'),
        duration_ms: item.duration_ms,
        audit_event_ids: item.audit_event_ids || [],
        details: item.details,
        executed_at: item.executed_at,
      }));
      setScenarios(normalized);
    } catch (err: unknown) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRunSingle = async (id: string) => {
    try {
      setRunningId(id);
      setError(null);
      setSuccess(null);
      const res = await api.post<any>(`/simulation/scenarios/${id}/run`, {});
      const rawRes = res.data || res;
      const updated: ScenarioResult = {
        scenario_id: rawRes.scenario_id || id,
        name: rawRes.title || rawRes.name || id,
        category: rawRes.category || 'Scenario',
        description: rawRes.detail || rawRes.description || 'Execution completed',
        status: rawRes.status || (rawRes.passed ? 'PASSED' : 'FAILED'),
        duration_ms: Math.round(rawRes.duration_ms || 0),
        audit_event_ids: rawRes.audit_event_ids || [],
        details: rawRes.detail ? { detail: rawRes.detail } : rawRes.details,
        executed_at: new Date().toISOString(),
      };
      setScenarios((prev) => prev.map((s) => (s.scenario_id === id ? updated : s)));
      setSuccess(`Scenario "${updated.name}" completed successfully (${updated.duration_ms}ms).`);
      if (selectedScenario && selectedScenario.scenario_id === id) {
        setSelectedScenario(updated);
      }
    } catch (err: unknown) {
      setError(err);
    } finally {
      setRunningId(null);
    }
  };

  const handleRunAll = async () => {
    setConfirmRunAll(false);
    try {
      setRunningAll(true);
      setError(null);
      setSuccess(null);
      const res = await api.post<{ scenario_id: string; data: ScenarioRunAllResponse }>('/simulation/scenarios/run-all', {});
      const allRes = res.data;
      setScenarios(allRes.results);
      setSuccess(`All ${allRes.total_executed} scenarios executed (${allRes.total_passed} passed, ${allRes.total_failed} failed) in ${allRes.total_duration_ms}ms.`);
    } catch (err: unknown) {
      setError(err);
    } finally {
      setRunningAll(false);
    }
  };

  if (loading && scenarios.length === 0) {
    return <LoadingState label="Loading deterministic security verification scenarios..." />;
  }

  const passedCount = scenarios.filter((s) => s.status === 'PASSED').length;
  const failedCount = scenarios.filter((s) => s.status === 'FAILED').length;
  const pendingCount = scenarios.filter((s) => s.status === 'NOT_RUN' || s.status === 'PENDING').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.4rem' }}>Deterministic Security Scenarios</h1>
          <p style={{ margin: '4px 0 0', color: 'var(--text-secondary)', fontSize: '0.86rem' }}>
            14 production test scenarios verifying crypto, revocation, tampering, audit, and recovery against actual backend logic.
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <button
            type="button"
            onClick={loadScenarios}
            disabled={loading || runningAll || runningId !== null}
            className="btn"
          >
            Refresh Status
          </button>
          <button
            type="button"
            onClick={() => setConfirmRunAll(true)}
            disabled={runningAll || runningId !== null}
            className="btn btn-primary"
          >
            {runningAll ? 'Executing All 14 Scenarios...' : 'Run All 14 Scenarios'}
          </button>
        </div>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {/* Summary counters */}
      <div className="grid-cards">
        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', textTransform: 'uppercase' }}>Total Scenarios</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, marginTop: 4 }}>{scenarios.length}</div>
        </div>
        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', textTransform: 'uppercase' }}>Passed</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, marginTop: 4, color: 'var(--accent-emerald)' }}>{passedCount}</div>
        </div>
        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', textTransform: 'uppercase' }}>Failed</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, marginTop: 4, color: 'var(--accent-rose)' }}>{failedCount}</div>
        </div>
        <div className="card">
          <div style={{ color: 'var(--text-muted)', fontSize: '0.78rem', textTransform: 'uppercase' }}>Not Run</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 800, marginTop: 4, color: 'var(--text-secondary)' }}>{pendingCount}</div>
        </div>
      </div>

      {/* Scenario Table */}
      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="card-header" style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-default)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ margin: 0, fontSize: '0.96rem' }}>Security &amp; Reliability Scenarios</h3>
          <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>resettable in-memory isolated runs</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="table">
            <thead>
              <tr>
                <th>ID &amp; Category</th>
                <th>Name &amp; Description</th>
                <th>Status</th>
                <th>Duration</th>
                <th>Audit Events</th>
                <th style={{ textAlign: 'right' }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {scenarios.map((sc) => (
                <tr key={sc.scenario_id}>
                  <td className="mono" style={{ fontWeight: 600 }}>
                    <div>{sc.scenario_id}</div>
                    <span className="badge badge-neutral" style={{ fontSize: '0.7rem', marginTop: 4 }}>
                      {sc.category}
                    </span>
                  </td>
                  <td style={{ maxWidth: 360 }}>
                    <div style={{ fontWeight: 600 }}>{sc.name}</div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', marginTop: 3 }}>{sc.description}</div>
                  </td>
                  <td>
                    <StatusBadge value={sc.status} />
                  </td>
                  <td className="mono" style={{ fontSize: '0.84rem' }}>
                    {sc.duration_ms !== undefined && sc.duration_ms !== null ? `${sc.duration_ms} ms` : '—'}
                  </td>
                  <td className="mono" style={{ fontSize: '0.84rem' }}>
                    {sc.audit_event_ids && sc.audit_event_ids.length > 0 ? (
                      <button
                        type="button"
                        onClick={() => setSelectedScenario(sc)}
                        className="btn"
                        style={{ padding: '2px 8px', fontSize: '0.75rem' }}
                      >
                        {sc.audit_event_ids.length} event(s)
                      </button>
                    ) : (
                      'None'
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      type="button"
                      onClick={() => void handleRunSingle(sc.scenario_id)}
                      disabled={runningAll || runningId !== null}
                      className="btn btn-primary"
                      style={{ padding: '4px 10px', fontSize: '0.78rem' }}
                    >
                      {runningId === sc.scenario_id ? 'Running...' : 'Run Scenario'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scenario Detail Modal */}
      {selectedScenario && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 60, display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: 'rgba(0,0,0,0.6)', padding: 16 }}>
          <div className="card" style={{ maxWidth: 640, width: '100%', maxHeight: '85vh', overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--border-default)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1rem' }}>{selectedScenario.name}</h3>
                <div className="mono" style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>{selectedScenario.scenario_id}</div>
              </div>
              <button type="button" onClick={() => setSelectedScenario(null)} className="btn" style={{ padding: '2px 8px' }}>
                ✕
              </button>
            </div>
            <div style={{ padding: 20, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <StatusBadge value={selectedScenario.status} />
                <span style={{ fontSize: '0.84rem' }}>Duration: <strong className="mono">{selectedScenario.duration_ms}ms</strong></span>
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: '0.86rem', marginBottom: 6 }}>Execution Details</div>
                <pre className="mono" style={{ background: '#0a101d', padding: 12, borderRadius: 6, fontSize: '0.75rem', overflowX: 'auto' }}>
                  {JSON.stringify(selectedScenario.details || {}, null, 2)}
                </pre>
              </div>
              {selectedScenario.audit_event_ids && selectedScenario.audit_event_ids.length > 0 && (
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.86rem', marginBottom: 6 }}>Audit Ledger References</div>
                  <ul className="mono" style={{ margin: 0, paddingLeft: 18, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    {selectedScenario.audit_event_ids.map((id: string) => (
                      <li key={id}>{id}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border-default)', display: 'flex', justifyContent: 'flex-end' }}>
              <button type="button" onClick={() => setSelectedScenario(null)} className="btn">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Confirm Run All Modal */}
      <ConfirmModal
        open={confirmRunAll}
        title="Execute All 14 Verification Scenarios?"
        description="This will sequentially execute all 14 deterministic security scenarios against the live backend engine. All cryptographic encryptions, tampering checks, and audit ledgers will run and verify in real time."
        confirmLabel="Execute Scenarios"
        requireReason={false}
        danger={false}
        onConfirm={() => void handleRunAll()}
        onCancel={() => setConfirmRunAll(false)}
      />
    </div>
  );
}
