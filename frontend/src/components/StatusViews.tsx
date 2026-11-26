import React from 'react';
import { AlertCircle, CheckCircle2, Info, Loader2 } from 'lucide-react';
import { extractErrorMessage } from '../api/client';

export function ErrorBanner({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  const parsed = typeof error === 'string' ? { code: 'ERROR', message: error } : extractErrorMessage(error);
  return (
    <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-start gap-3 shadow-lg" role="alert">
      <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5 text-rose-400" />
      <div className="flex-1">
        <strong className="font-mono text-rose-200">{parsed.code}</strong>: {parsed.message}
        {parsed.correlationId && (
          <div className="font-mono text-[11px] text-rose-400/80 mt-1">
            correlation_id: {parsed.correlationId}
          </div>
        )}
      </div>
      {onDismiss && (
        <button
          type="button"
          className="cyber-btn cyber-btn-secondary text-[11px] px-2.5 py-1"
          onClick={onDismiss}
        >
          Dismiss
        </button>
      )}
    </div>
  );
}

export function SuccessBanner({ message, onDismiss }: { message: string | null; onDismiss?: () => void }) {
  if (!message) return null;
  return (
    <div className="p-4 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs flex items-center justify-between gap-3 shadow-lg" role="status">
      <div className="flex items-center gap-2.5">
        <CheckCircle2 className="w-4 h-4 flex-shrink-0 text-emerald-400" />
        <span>{message}</span>
      </div>
      {onDismiss && (
        <button
          type="button"
          className="cyber-btn cyber-btn-secondary text-[11px] px-2.5 py-1"
          onClick={onDismiss}
        >
          Dismiss
        </button>
      )}
    </div>
  );
}

export function LoadingState({ label = 'Loading live control-plane state...' }: { label?: string }) {
  return (
    <div className="glass-panel p-8 rounded-2xl flex items-center justify-center gap-3 text-slate-300 text-xs font-mono">
      <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="glass-panel p-8 rounded-2xl text-center space-y-2">
      <Info className="w-6 h-6 text-cyan-400 mx-auto mb-1" />
      <div className="font-bold text-sm text-white">{title}</div>
      <div className="text-xs text-slate-400 max-w-sm mx-auto">{detail}</div>
    </div>
  );
}

export function StatusBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="cyber-badge badge-neutral">UNKNOWN</span>;
  const up = String(value).toUpperCase();
  if (['ACTIVE', 'TRUSTED', 'HEALTHY', 'CONVERGED', 'VERIFIED', 'COMPLETED', 'ALLOW', 'PASS', 'ESTABLISHED', 'DELIVERED', 'ACKED', 'RESOLVED', 'FALSE_POSITIVE', 'OPEN_OK'].includes(up)) {
    return <span className="cyber-badge badge-ok">{value}</span>;
  }
  if (['PENDING', 'SUSPENDED', 'ROTATING', 'PREPARED', 'IN_PROGRESS', 'ACKNOWLEDGED', 'OPEN', 'DELAYED', 'DEGRADED', 'LAGGING'].includes(up)) {
    return <span className="cyber-badge badge-warn">{value}</span>;
  }
  if (['REVOKED', 'COMPROMISED', 'DENY', 'FAIL', 'FAILED', 'FAILED_CLOSED', 'OFFLINE', 'PARTITIONED', 'INVALID', 'CRITICAL', 'HIGH', 'REPLAY_REJECTED', 'TAMPERED'].includes(up)) {
    return <span className="cyber-badge badge-danger">{value}</span>;
  }
  return <span className="cyber-badge badge-neutral">{value}</span>;
}
