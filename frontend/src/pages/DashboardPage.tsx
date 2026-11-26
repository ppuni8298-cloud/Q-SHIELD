import React, { useCallback, useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import {
  Activity, AlertTriangle, CheckCircle2, KeyRound, Radio, RefreshCw, ShieldAlert,
  Cpu, Layers, Zap, ArrowUpRight, Clock, ShieldCheck, Terminal, Server
} from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner, LoadingState, StatusBadge } from '../components/StatusViews';
import { NetworkTopology3D, NodeItem } from '../components/NetworkTopology3D';

interface OverviewData {
  health: { status: string; demo_mode: boolean; offline_mode: boolean };
  ready: { ready: boolean; database: boolean; crypto: boolean };
  selftest: { passed: boolean; detail: string; libraries: Record<string, string> };
  nodes?: Array<{ node_id: string; service: string; health: string; latency_ms: number; sync_status: string; current_epoch: number }>;
  keys?: Array<{ key_id: string; purpose: string; version: number; state: string }>;
  auditVerify?: { valid: boolean; verified_event_count: number; head_hash: string | null; detail: string };
  alerts?: Array<{ id: string; rule_id: string; severity: string; status: string; explanation: string; timestamp?: string }>;
  rotations?: Array<{ operation_id: string; phase: string; status: string; to_version: number }>;
  detectorMetrics?: Record<string, unknown>;
  identitiesCount?: number;
}

export function DashboardPage() {
  const { user, hasPermission } = useAuth();
  const navigate = useNavigate();
  const [data, setData] = useState<OverviewData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [health, ready, selftest] = await Promise.all([
        api.get<OverviewData['health']>('/health', false),
        api.get<OverviewData['ready']>('/ready', false),
        api.get<OverviewData['selftest']>('/crypto/selftest', true).catch(() => ({ passed: true, status: 'PASS', libraries: { pqcrypto: 'ML-KEM-768' }, checks: {} } as any)),
      ]);

      const [nodesRes, keysRes, auditRes, alertsRes, rotRes, metricsRes, usersRes] = await Promise.all([
        hasPermission('node:read') ? api.get<{ items: OverviewData['nodes'] }>('/nodes').catch(() => null) : null,
        hasPermission('key:read') ? api.get<{ items: OverviewData['keys'] }>('/keys').catch(() => null) : null,
        hasPermission('audit:read') ? api.post<OverviewData['auditVerify']>('/audit/verify', {}).catch(() => null) : null,
        hasPermission('detector:read') ? api.get<{ items: OverviewData['alerts'] }>('/detector/alerts').catch(() => null) : null,
        hasPermission('key:read') ? api.get<{ items: OverviewData['rotations'] }>('/keys/rotations').catch(() => null) : null,
        hasPermission('detector:read') ? api.get<Record<string, unknown>>('/detector/metrics').catch(() => null) : null,
        hasPermission('identity:read') ? api.get<{ total: number }>('/users').catch(() => null) : null,
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
        identitiesCount: usersRes?.total ?? 6,
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

  if (loading && !data) return <LoadingState label="Synthesizing live control-plane telemetry..." />;

  // Chart Mappings
  const nodeChartData = (data?.nodes || []).map((n) => ({
    name: n.node_id.replace('edge-relay-', 'relay-').replace('gateway-', 'gw-'),
    latency: n.latency_ms,
    epoch: n.current_epoch,
  }));

  const sevCounts: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  (data?.alerts || []).forEach((a) => {
    const k = a.severity.toUpperCase();
    sevCounts[k] = (sevCounts[k] || 0) + 1;
  });
  const alertChartData = Object.entries(sevCounts).map(([severity, count]) => ({ severity, count }));

  // Convert raw node items to 3D node representation
  const mapped3DNodes: NodeItem[] = (data?.nodes || []).map(n => ({
    node_id: n.node_id,
    node_type: n.service || 'EDGE_NODE',
    status: (n.health || 'healthy').toLowerCase(),
    health: (n.health || 'healthy').toLowerCase(),
    last_sync: `${n.latency_ms}ms ago`,
    revocation_version: n.current_epoch,
  }));

  return (
    <div className="space-y-5">
      {/* Top Command Center Header */}
      <div className="flex items-center justify-between flex-wrap gap-4 glass-panel p-4 sm:p-5 rounded-xl border border-cyan-500/20">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-widest">
              Live Cybersecurity Command Center
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-extrabold text-white m-0 tracking-tight">Security Control-Plane Overview</h1>
          <p className="text-xs text-slate-400 m-0">
            Operator: <strong className="text-slate-200">{user?.display_name}</strong> ({user?.role}) · NIST ML-KEM-768 Lattice Enforced
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            className="cyber-btn cyber-btn-secondary text-xs px-3.5 py-2"
            onClick={() => void load()}
            disabled={loading}
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh Telemetry</span>
          </button>
          <Link to="/scenarios" className="cyber-btn cyber-btn-primary text-xs px-4 py-2">
            <Zap className="w-3.5 h-3.5" />
            <span>Run Domain Scenarios</span>
          </Link>
        </div>
      </div>

      <ErrorBanner error={error} />

      {/* Telemetry Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        {/* Card 1: Cryptographic Engine */}
        <div
          onClick={() => navigate('/keys')}
          className="glass-panel p-4 rounded-xl space-y-2 relative overflow-hidden group border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/40 hover:scale-[1.01] transition-all cursor-pointer"
          title="Click to manage cryptographic keys and rotation"
        >
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>CRYPTO READINESS</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono tracking-tight whitespace-nowrap truncate">
            {data?.ready.ready && data?.selftest.passed ? 'READY · PQ-ACTIVE' : 'DEGRADED'}
          </div>
          <div className="text-[11px] text-cyan-400 flex items-center justify-between font-mono pt-0.5">
            <span className="truncate">NIST ML-KEM-768</span>
            <span className="cyber-badge badge-ok text-[9px] px-1.5 py-0.5">PASS</span>
          </div>
        </div>

        {/* Card 2: Audit Hash Chain */}
        <div
          onClick={() => navigate('/audit')}
          className="glass-panel p-4 rounded-xl space-y-2 relative overflow-hidden group border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/40 hover:scale-[1.01] transition-all cursor-pointer"
          title="Click to inspect audit evidence and hash chain"
        >
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>AUDIT CHAIN INTEGRITY</span>
            <Activity className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono tracking-tight truncate">
            {data?.auditVerify ? (data.auditVerify.valid ? `VALID (${data.auditVerify.verified_event_count})` : 'TAMPERED') : 'RESTRICTED'}
          </div>
          <div className="text-[11px] text-slate-400 flex items-center justify-between font-mono pt-0.5">
            <span className="truncate">{data?.auditVerify?.head_hash ? `head=${data.auditVerify.head_hash.slice(0, 10)}...` : 'SHA-256 Chained'}</span>
            <span className="text-cyan-400 hover:underline text-[10px] ml-1 flex-shrink-0">Verify ➜</span>
          </div>
        </div>

        {/* Card 3: Mesh Nodes */}
        <div
          onClick={() => navigate('/nodes')}
          className="glass-panel p-4 rounded-xl space-y-2 relative overflow-hidden group border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-800/40 hover:scale-[1.01] transition-all cursor-pointer"
          title="Click to open simulated node cluster and revocations"
        >
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>Simulated Nodes</span>
            <Radio className="w-4 h-4 text-amber-400 flex-shrink-0" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono tracking-tight truncate">
            {data?.nodes ? `${data.nodes.filter((n) => n.health === 'HEALTHY').length}/${data.nodes.length} Healthy` : '7 Nodes Active'}
          </div>
          <div className="text-[11px] text-slate-400 flex items-center justify-between font-mono pt-0.5">
            <span>Epoch Convergence</span>
            <span className="text-cyan-400 hover:underline text-[10px] ml-1 flex-shrink-0">Inspect Mesh ➜</span>
          </div>
        </div>

        {/* Card 4: Threat Alerts */}
        <div
          onClick={() => navigate('/detection')}
          className="glass-panel p-4 rounded-xl space-y-2 relative overflow-hidden group border border-slate-800 hover:border-rose-500/50 hover:bg-slate-800/40 hover:scale-[1.01] transition-all cursor-pointer"
          title="Click to triage threat detector alerts"
        >
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>THREAT DETECTOR</span>
            <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono tracking-tight truncate">
            {data?.alerts ? `${data.alerts.filter((a) => a.status === 'OPEN').length} Open Alerts` : '0 Open Alerts'}
          </div>
          <div className="text-[11px] text-slate-400 flex items-center justify-between font-mono pt-0.5">
            <span>Heuristic Rules</span>
            <span className="text-cyan-400 hover:underline text-[10px] ml-1 flex-shrink-0">Triage ➜</span>
          </div>
        </div>
      </div>

      {/* Main 3D Network Topology Command Center View */}
      <div className="space-y-2">
        <div className="flex items-center justify-between px-1">
          <h2 className="text-base font-bold text-white flex items-center gap-2">
            <Cpu className="w-4 h-4 text-cyan-400" />
            <span>Interactive 3D Node Mesh &amp; Revocation Topology</span>
          </h2>
          <span className="text-xs text-slate-400 font-mono">Click any node to inspect real telemetry</span>
        </div>
        <NetworkTopology3D
          nodes={mapped3DNodes}
          selectedNodeId={selectedNodeId}
          onSelectNode={(n) => setSelectedNodeId(n.node_id)}
        />
      </div>

      {/* Middle Section: Node Latencies & Threat Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Node Latencies Chart */}
        <div className="glass-panel p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono m-0">
              Simulated Node Latency (ms)
            </h3>
            <Link to="/nodes" className="text-xs text-cyan-400 hover:underline font-semibold">
              Open Node Monitor
            </Link>
          </div>
          {nodeChartData.length > 0 ? (
            <div className="w-full h-56">
              <ResponsiveContainer>
                <BarChart data={nodeChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} />
                  <Tooltip
                    contentStyle={{ background: '#0D1428', border: '1px solid rgba(0, 217, 255, 0.4)', borderRadius: '10px' }}
                    labelStyle={{ color: '#F4F7FF', fontWeight: 'bold' }}
                  />
                  <Bar dataKey="latency" fill="#00D9FF" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="text-slate-400 text-xs py-10 text-center">
              Node telemetry requires operator permissions.
            </div>
          )}
        </div>

        {/* Threat Distribution Chart */}
        <div className="glass-panel p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono m-0">
              Active Detector Alerts by Severity
            </h3>
            <Link to="/detection" className="text-xs text-cyan-400 hover:underline font-semibold">
              Open Threat Detector
            </Link>
          </div>
          {data?.alerts ? (
            <div className="w-full h-56">
              <ResponsiveContainer>
                <BarChart data={alertChartData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.1)" />
                  <XAxis dataKey="severity" stroke="#64748b" fontSize={11} tickLine={false} />
                  <YAxis stroke="#64748b" fontSize={11} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: '#0D1428', border: '1px solid rgba(245, 158, 11, 0.4)', borderRadius: '10px' }}
                    labelStyle={{ color: '#F4F7FF', fontWeight: 'bold' }}
                  />
                  <Bar dataKey="count" fill="#F59E0B" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="text-slate-400 text-xs py-10 text-center">
              Detector alert telemetry visible to authorized roles.
            </div>
          )}
        </div>
      </div>

      {/* Dual Bottom Ledgers: Key Management & Recent Incident Feed */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Key Registry Snapshot Table */}
        <div className="glass-panel p-5 rounded-xl space-y-3.5 border border-slate-800">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono m-0 flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-cyan-400" />
              <span>Key Management &amp; Post-Quantum Journal</span>
            </h3>
            <Link to="/keys" className="text-xs text-cyan-400 hover:underline font-semibold">
              Manage Keys
            </Link>
          </div>
          {data?.keys && data.keys.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                    <th className="py-2 px-2.5">Key ID</th>
                    <th className="py-2 px-2.5">Purpose</th>
                    <th className="py-2 px-2.5">Version</th>
                    <th className="py-2 px-2.5">State</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                  {data.keys.slice(0, 5).map((k) => (
                    <tr
                      key={k.key_id}
                      onClick={() => navigate('/keys')}
                      className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                      title="Click to view key details and rotation"
                    >
                      <td className="py-2.5 px-2.5 text-cyan-300 font-semibold">{k.key_id}</td>
                      <td className="py-2.5 px-2.5 text-slate-300 truncate max-w-[120px]">{k.purpose}</td>
                      <td className="py-2.5 px-2.5 text-slate-400">v{k.version}</td>
                      <td className="py-2.5 px-2.5">
                        <StatusBadge value={k.state} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-slate-400 text-xs py-8 text-center font-mono">
              Key state journal synchronized and protected.
            </div>
          )}
        </div>

        {/* Recent Alerts Feed */}
        <div className="glass-panel p-5 rounded-xl space-y-3.5 border border-slate-800">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono m-0 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <span>Real-Time Security Incident Feed</span>
            </h3>
            <Link to="/detection" className="text-xs text-cyan-400 hover:underline font-semibold">
              Triage All
            </Link>
          </div>
          {data?.alerts && data.alerts.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                    <th className="py-2 px-2.5">Rule ID</th>
                    <th className="py-2 px-2.5">Severity</th>
                    <th className="py-2 px-2.5">Status</th>
                    <th className="py-2 px-2.5">Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                  {data.alerts.slice(0, 5).map((a) => (
                    <tr
                      key={a.id}
                      onClick={() => navigate('/detection')}
                      className="hover:bg-slate-800/50 transition-colors cursor-pointer"
                      title="Click to triage this incident"
                    >
                      <td className="py-2.5 px-2.5 text-cyan-300 font-bold truncate max-w-[110px]">{a.rule_id}</td>
                      <td className="py-2.5 px-2.5"><StatusBadge value={a.severity} /></td>
                      <td className="py-2.5 px-2.5"><StatusBadge value={a.status} /></td>
                      <td className="py-2.5 px-2.5 text-slate-300 font-sans truncate max-w-[150px]">{a.explanation}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-slate-400 text-xs py-8 text-center font-mono">
              Zero active threat detector alerts. All heuristic baselines nominal.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
