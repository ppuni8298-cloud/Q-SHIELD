import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Activity, AlertTriangle, ArrowRight, CheckCircle2, Radio, RefreshCw, Send } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ConfirmModal } from '../components/ConfirmModal';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface NodeState {
  node_id: string;
  service: string;
  health: 'HEALTHY' | 'DEGRADED' | 'OFFLINE' | 'PARTITIONED';
  available: boolean;
  current_epoch: number;
  latency_profile: string;
  latency_ms: number;
  last_event_seq: number;
  last_applied_event_id: string | null;
  sync_status: 'SYNCHRONIZED' | 'LAGGING' | 'DESYNCHRONIZED';
  fault_mode: string;
  local_revocations: Record<string, string[]>;
  last_heartbeat: string;
}

interface RevocationEventRecord {
  event_id: string;
  sequence_number: number;
  event_type: string;
  subject_type: 'actor' | 'device' | 'key' | 'session';
  subject_id: string;
  reason: string;
  issued_by: string;
  revocation_epoch: number;
  created_at: string;
}

interface ConvergenceResult {
  event_id: string;
  converged: boolean;
  total_nodes: number;
  converged_nodes: number;
  node_status: Record<string, { applied: boolean; local_epoch: number; sync_status: string }>;
}

export function NodesPage() {
  const { hasPermission } = useAuth();
  const [nodes, setNodes] = useState<NodeState[]>([]);
  const [events, setEvents] = useState<RevocationEventRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Cluster configure
  const [showConfig, setShowConfig] = useState(false);
  const [nodeCount, setNodeCount] = useState(3);

  // Issue revocation form
  const [subjectType, setSubjectType] = useState<'device' | 'actor' | 'key' | 'session'>('device');
  const [subjectId, setSubjectId] = useState('dev-alex-trusted');
  const [revReason, setRevReason] = useState('Reported lost or compromised hardware unit');
  const [autoPropagate, setAutoPropagate] = useState(true);
  const [issuing, setIssuing] = useState(false);
  const [convergenceData, setConvergenceData] = useState<ConvergenceResult | null>(null);

  // Node fault modal
  const [pendingFault, setPendingFault] = useState<{
    nodeId: string;
    available: boolean;
    faultMode: string;
  } | null>(null);
  const [modalBusy, setModalBusy] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [nodesRes, eventsRes] = await Promise.all([
        api.get<any>('/nodes'),
        api.get<any>('/revocations/events'),
      ]);
      const nodeList = Array.isArray(nodesRes) ? nodesRes : (nodesRes?.items || []);
      const eventList = Array.isArray(eventsRes) ? eventsRes : (eventsRes?.items || []);
      setNodes(nodeList);
      setEvents(eventList);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleConfigureCluster = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    try {
      await api.post('/nodes/configure', {
        node_count: Number(nodeCount),
        reason: 'Adjusting simulated cluster topology',
      });
      setSuccess(`Cluster reconfigured with ${nodeCount} simulated nodes.`);
      setShowConfig(false);
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const handleIssueRevocation = async (e: FormEvent) => {
    e.preventDefault();
    setIssuing(true);
    setError(null);
    setSuccess(null);
    setConvergenceData(null);
    try {
      const res = await api.post<{ event: RevocationEventRecord; convergence: ConvergenceResult }>('/revocations', {
        subject_type: subjectType,
        subject_id: subjectId.trim(),
        reason: revReason.trim(),
        confirmation: true,
        auto_propagate: autoPropagate,
      });
      setConvergenceData(res.convergence);
      setSuccess(`Issued revocation tombstone '${res.event.event_id}'. Convergence: ${res.convergence.converged_nodes}/${res.convergence.total_nodes} nodes applied.`);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setIssuing(false);
    }
  };

  const handleExecuteFault = async (reason: string) => {
    if (!pendingFault) return;
    setModalBusy(true);
    setError(null);
    try {
      const { nodeId, available, faultMode } = pendingFault;
      await api.post(`/nodes/${nodeId}/availability`, {
        available,
        fault_mode: faultMode,
        reason,
      });
      setSuccess(`Node '${nodeId}' updated: available=${String(available)}, fault_mode=${faultMode}.`);
      setPendingFault(null);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setModalBusy(false);
    }
  };

  const handleRestartNode = async (nodeId: string) => {
    setError(null);
    try {
      await api.post(`/nodes/${nodeId}/restart`, {});
      setSuccess(`Node '${nodeId}' restarted and synchronized.`);
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const canManage = hasPermission('node:manage');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Simulated Node Registry &amp; Revocation Propagation</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Deterministic simulated network · Latency profiles · Fault injection · Monotonic epoch convergence tracking
          </div>
        </div>
        {canManage && (
          <button type="button" className="btn btn-primary" onClick={() => setShowConfig(!showConfig)}>
            <span>{showConfig ? 'Close Configure' : 'Configure Cluster (3–7 Nodes)'}</span>
          </button>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {showConfig && canManage && (
        <form onSubmit={handleConfigureCluster} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Configure Cluster Size</h2>
          <div>
            <label htmlFor="config-nodes" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>
              Node Count (3 to 7)
            </label>
            <input
              id="config-nodes"
              type="number"
              min={3}
              max={7}
              className="input"
              value={nodeCount}
              onChange={(e) => setNodeCount(Number(e.target.value))}
              style={{ maxWidth: 160 }}
              required
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowConfig(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary">Apply Topology</button>
          </div>
        </form>
      )}

      {loading && nodes.length === 0 ? (
        <LoadingState label="Loading simulated node cluster..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Radio size={16} /> Simulated Node Cluster ({nodes.length} Nodes)
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
                  <th>Node ID</th>
                  <th>Service</th>
                  <th>Health</th>
                  <th>Current Epoch</th>
                  <th>Latency</th>
                  <th>Sync Status</th>
                  <th>Fault Mode</th>
                  {canManage && <th>Fault Injection Controls</th>}
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => (
                  <tr key={n.node_id}>
                    <td className="mono">{n.node_id}</td>
                    <td>{n.service}</td>
                    <td><StatusBadge value={n.health} /></td>
                    <td><span className="badge badge-info">epoch={n.current_epoch}</span></td>
                    <td className="mono">{n.latency_ms} ms</td>
                    <td><StatusBadge value={n.sync_status} /></td>
                    <td><span className="mono" style={{ fontSize: '0.78rem' }}>{n.fault_mode}</span></td>
                    {canManage && (
                      <td>
                        <div style={{ display: 'flex', gap: 6 }}>
                          {n.available ? (
                            <button
                              type="button"
                              className="btn btn-danger"
                              style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                              onClick={() => setPendingFault({ nodeId: n.node_id, available: false, faultMode: 'PARTITIONED' })}
                            >
                              Partition
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="btn btn-emerald"
                              style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                              onClick={() => void handleRestartNode(n.node_id)}
                            >
                              Restart &amp; Heal
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Issue Revocation Form */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Send size={16} color="var(--accent-rose)" /> Issue Revocation Tombstone
            </h2>
          </div>
          <p style={{ margin: '0 0 14px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Emits an immutable cryptographic tombstone signed with ML-DSA-65 and broadcasts it across all available simulated nodes.
          </p>

          <form onSubmit={handleIssueRevocation} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 10 }}>
              <div>
                <label htmlFor="rev-subject-type" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)' }}>Subject Type</label>
                <select id="rev-subject-type" className="select" value={subjectType} onChange={(e) => setSubjectType(e.target.value as any)}>
                  <option value="device">device</option>
                  <option value="actor">actor</option>
                  <option value="key">key</option>
                  <option value="session">session</option>
                </select>
              </div>
              <div>
                <label htmlFor="rev-subject-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)' }}>Subject ID</label>
                <input id="rev-subject-id" className="input" value={subjectId} onChange={(e) => setSubjectId(e.target.value)} required />
              </div>
            </div>

            <div>
              <label htmlFor="rev-reason" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)' }}>Reason (Logged to Ledger)</label>
              <input id="rev-reason" className="input" value={revReason} onChange={(e) => setRevReason(e.target.value)} required />
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input
                type="checkbox"
                id="rev-propagate"
                checked={autoPropagate}
                onChange={(e) => setAutoPropagate(e.target.checked)}
              />
              <label htmlFor="rev-propagate" style={{ fontSize: '0.82rem' }}>
                Auto-propagate immediately to all simulated node inboxes
              </label>
            </div>

            <button type="submit" className="btn btn-danger" disabled={issuing}>
              <span>{issuing ? 'Broadcasting Tombstone...' : 'Issue Irreversible Revocation'}</span>
            </button>
          </form>

          {convergenceData && (
            <div style={{ marginTop: 14, background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                <strong>Cluster Convergence:</strong>
                <StatusBadge value={convergenceData.converged ? 'CONVERGED' : 'LAGGING'} />
              </div>
              <div style={{ fontSize: '0.82rem', marginBottom: 6 }}>
                Applied across <strong>{convergenceData.converged_nodes}</strong> of <strong>{convergenceData.total_nodes}</strong> nodes.
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {Object.entries(convergenceData.node_status).map(([nodeId, stat]) => (
                  <span key={nodeId} className="mono" style={{ fontSize: '0.72rem', background: '#070b14', padding: '3px 7px', borderRadius: 5, border: '1px solid var(--border-subtle)' }}>
                    {nodeId}: {stat.applied ? 'APPLIED' : 'PENDING'}
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>

        {/* Recent Revocations Feed */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Activity size={16} /> Recent Revocation Tombstones ({events.length})
            </h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Target</th>
                  <th>Epoch</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {events.slice(0, 6).map((ev) => (
                  <tr key={ev.event_id}>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{ev.event_id}</td>
                    <td className="mono">{ev.subject_type}:{ev.subject_id}</td>
                    <td><span className="badge badge-neutral">ep={ev.revocation_epoch}</span></td>
                    <td style={{ fontSize: '0.8rem' }}>{ev.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <ConfirmModal
        open={Boolean(pendingFault)}
        title={`Inject Fault into Node ${pendingFault?.nodeId}`}
        description={`Set node availability to '${String(pendingFault?.available)}' with fault mode '${pendingFault?.faultMode}'. This tests convergence under network partition.`}
        danger={true}
        confirmLabel="Apply Fault"
        busy={modalBusy}
        onCancel={() => setPendingFault(null)}
        onConfirm={handleExecuteFault}
      />
    </div>
  );
}
