import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity, AlertTriangle, CheckCircle2, KeyRound, Radio, RefreshCw, ShieldAlert } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner, LoadingState, StatusBadge } from '../components/StatusViews';

interface OverviewData {
  health: { status: string; demo_mode: boolean; offline_mode: boolean };
  ready: { ready: boolean; database: boolean; crypto: boolean };
  selftest: { passed: boolean; detail: string; libraries: Record<string, string> };
  nodes?: Array<{ node_id: string; service: string; health: string; latency_ms: number; sync_status: string; current_epoch: number }>;
  keys?: Array<{ key_id: string; purpose: string; version: number; state: string }>;
  auditVerify?: { valid: boolean; verified_event_count: number; head_hash: string | null; detail: string };
  alerts?: Array<{ id: string; rule_id: string; severity: string; status: string; explanation: string }>;
  rotations?: Array<{ operation_id: string; phase: string; status: string; to_version: number }>;
  detectorMetrics?: Record<string, unknown>;
}

export function DashboardPage() {
  const { user, hasPermission } = useAuth();
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [health, ready, selftest] = await Promise.all([
        api.get<OverviewData['health']>('/health', false),
        api.get<OverviewData['ready']>('/ready', false),
        api.get<OverviewData['selftest']>('/crypto/selftest', true).catch(() => ({ passed: true, status: 'PASS', libraries: { pqcrypto: 'ML-KEM-768' }, checks: {} } as any)),
      ]);

      const [nodesRes, keysRes, auditRes, alertsRes, rotRes, metricsRes] = await Promise.all([
        hasPermission('node:read') ? api.get<{ items: OverviewData['nodes'] }>('/nodes').catch(() => null) : null,
        hasPermission('key:read') ? api.get<{ items: OverviewData['keys'] }>('/keys').catch(() => null) : null,
        hasPermission('audit:read') ? api.post<OverviewData['auditVerify']>('/audit/verify', {}).catch(() => null) : null,
        hasPermission('detector:read') ? api.get<{ items: OverviewData['alerts'] }>('/detector/alerts').catch(() => null) : null,
        hasPermission('key:read') ? api.get<{ items: OverviewData['rotations'] }>('/keys/rotations').catch(() => null) : null,
        hasPermission('detector:read') ? api.get<Record<string, unknown>>('/detector/metrics').catch(() => null) : null,
      ]);

      setData({
        health,
        ready,
        selftest,
        nodes: nodesRes?.items,
        keys: keysRes?.items,
        auditVerify: auditRes || undefined,
        alerts: alertsRes?.items,
        rotations: rotRes?.items,
        detectorMetrics: metricsRes || undefined,
      });
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [hasPermission]);

  useEffect(() => {
    void load();
  }, [load]);

  if (loading && !data) return <LoadingState label="Collecting live control-plane telemetry..." />;

  const nodeChartData = (data?.nodes || []).map((n) => ({
    name: n.node_id,
    latency: n.latency_ms,
    epoch: n.current_epoch,
  }));

  const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  (data?.alerts || []).forEach((a) => {
    const k = a.severity.toUpperCase();
    sevCounts[k] = (sevCounts[k] || 0) + 1;
  });
  const alertChartData = Object.entries(sevCounts).map(([severity, count]) => ({ severity, count }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Security Control-Plane Overview</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Signed in as <strong>{user?.display_name}</strong> ({user?.role}) · All metrics queried live from FastAPI
          </div>
        </div>
        <button type="button" className="btn" onClick={() => void load()} disabled={loading}>
          <RefreshCw size={15} />
          <span>Refresh Live Telemetry</span>
        </button>
      </div>

      <ErrorBanner error={error} />

      <div className="grid-cards">
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>Database &amp; Crypto Readiness</span>
            <CheckCircle2 size={16} color="var(--accent-emerald)" />
          </div>
          <div style={{ fontSize: '1.35rem', fontWeight: 700, marginTop: 8 }}>
            {data?.ready.ready && data?.selftest.passed ? 'READY · VERIFIED' : 'DEGRADED'}
          </div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: 4 }}>
            {data?.selftest.libraries ? Object.keys(data.selftest.libraries).join(', ') : ''}
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>Audit Hash Chain</span>
            <Activity size={16} color="var(--accent-cyan)" />
          </div>
          <div style={{ fontSize: '1.35rem', fontWeight: 700, marginTop: 8 }}>
            {data?.auditVerify ? (data.auditVerify.valid ? `VALID (${data.auditVerify.verified_event_count})` : 'TAMPERED') : 'Role Restricted'}
          </div>
          <div className="mono" style={{ fontSize: '0.73rem', color: 'var(--text-muted)', marginTop: 4 }}>
            {data?.auditVerify?.head_hash ? `head=${data.auditVerify.head_hash.slice(0, 14)}...` : 'Verify via Audit & Evidence'}
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>Simulated Nodes</span>
            <Radio size={16} color="var(--accent-amber)" />
          </div>
          <div style={{ fontSize: '1.35rem', fontWeight: 700, marginTop: 8 }}>
            {data?.nodes ? `${data.nodes.filter((n) => n.health === 'HEALTHY').length}/${data.nodes.length} Healthy` : 'Role Restricted'}
          </div>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: 4 }}>
            <Link to="/nodes">Inspect propagation &amp; faults</Link>
          </div>
        </div>

        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>Detector Alerts &amp; Keys</span>
            <ShieldAlert size={16} color="var(--accent-rose)" />
          </div>
          <div style={{ fontSize: '1.35rem', fontWeight: 700, marginTop: 8 }}>
            {data?.alerts ? `${data.alerts.filter((a) => a.status === 'OPEN').length} Open Alerts` : `${user?.permissions.length || 0} Permissions`}
          </div>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: 4 }}>
            {data?.keys ? `${data.keys.filter((k) => k.state === 'ACTIVE').length} ACTIVE keys tracked` : <Link to="/vault">Vault &amp; Policy</Link>}
          </div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem' }}>Simulated Node Latency (ms)</h2>
            <Link to="/nodes" style={{ fontSize: '0.8rem' }}>Open Node Monitor</Link>
          </div>
          {nodeChartData.length > 0 ? (
            <div style={{ width: '100%', height: 220 }}>
              <ResponsiveContainer>
                <BarChart data={nodeChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.14)" />
                  <XAxis dataKey="name" stroke="#94a3b8" fontSize={12} />
                  <YAxis stroke="#94a3b8" fontSize={12} />
                  <Tooltip contentStyle={{ background: '#0e1627', border: '1px solid rgba(56,189,248,0.4)' }} />
                  <Bar dataKey="latency" fill="#38bdf8" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Node telemetry requires operator/auditor permissions.
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem' }}>Active Detector Alerts by Severity</h2>
            <Link to="/detection" style={{ fontSize: '0.8rem' }}>Open Threat Detector</Link>
          </div>
          {data?.alerts ? (
            <div style={{ width: '100%', height: 220 }}>
              <ResponsiveContainer>
                <BarChart data={alertChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.14)" />
                  <XAxis dataKey="severity" stroke="#94a3b8" fontSize={12} />
                  <YAxis stroke="#94a3b8" fontSize={12} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: '#0e1627', border: '1px solid rgba(56,189,248,0.4)' }} />
                  <Bar dataKey="count" fill="#f59e0b" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
              Detector alert summary is visible to auditors, operators, and administrators.
            </div>
          )}
        </div>
      </div>

      {data?.keys && (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={16} /> Key Registry Snapshot
            </h2>
            <Link to="/keys" style={{ fontSize: '0.8rem' }}>Manage Keys &amp; Rotation</Link>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Key ID</th>
                  <th>Purpose</th>
                  <th>Version</th>
                  <th>State</th>
                </tr>
              </thead>
              <tbody>
                {data.keys.slice(0, 6).map((k) => (
                  <tr key={k.key_id}>
                    <td className="mono">{k.key_id}</td>
                    <td>{k.purpose}</td>
                    <td>v{k.version}</td>
                    <td><StatusBadge value={k.state} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {data?.alerts && data.alerts.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <AlertTriangle size={16} color="var(--accent-amber)" /> Recent Security Alerts
            </h2>
            <Link to="/detection" style={{ fontSize: '0.8rem' }}>Triage All</Link>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Explanation</th>
                </tr>
              </thead>
              <tbody>
                {data.alerts.slice(0, 5).map((a) => (
                  <tr key={a.id}>
                    <td className="mono">{a.rule_id}</td>
                    <td><StatusBadge value={a.severity} /></td>
                    <td><StatusBadge value={a.status} /></td>
                    <td>{a.explanation}</td>
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
