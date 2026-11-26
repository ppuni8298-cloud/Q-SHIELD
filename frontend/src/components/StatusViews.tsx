import { AlertCircle, CheckCircle2, Info, Loader2 } from 'lucide-react';
import { extractErrorMessage } from '../api/client';

export function ErrorBanner({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  const parsed = typeof error === 'string' ? { code: 'ERROR', message: error } : extractErrorMessage(error);
  return (
    <div className="alert-banner alert-error" role="alert">
      <AlertCircle size={18} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ flex: 1 }}>
        <strong className="mono">{parsed.code}</strong>: {parsed.message}
        {parsed.correlationId && (
          <div className="mono" style={{ fontSize: '0.74rem', marginTop: 4, opacity: 0.85 }}>
            correlation_id: {parsed.correlationId}
          </div>
        )}
      </div>
      {onDismiss && (
        <button type="button" className="btn" onClick={onDismiss} style={{ padding: '3px 8px', fontSize: '0.75rem' }}>
          Dismiss
        </button>
      )}
    </div>
  );
}

export function SuccessBanner({ message, onDismiss }: { message: string | null; onDismiss?: () => void }) {
  if (!message) return null;
  return (
    <div className="alert-banner alert-success" role="status">
      <CheckCircle2 size={18} style={{ flexShrink: 0, marginTop: 2 }} />
      <div style={{ flex: 1 }}>{message}</div>
      {onDismiss && (
        <button type="button" className="btn" onClick={onDismiss} style={{ padding: '3px 8px', fontSize: '0.75rem' }}>
          Dismiss
        </button>
      )}
    </div>
  );
}

export function LoadingState({ label = 'Loading live control-plane state...' }: { label?: string }) {
  return (
    <div className="card" style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-secondary)' }}>
      <Loader2 size={18} />
      <span>{label}</span>
    </div>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="card" style={{ textAlign: 'center', padding: '28px 18px', color: 'var(--text-secondary)' }}>
      <Info size={22} style={{ marginBottom: 6, color: 'var(--accent-cyan)' }} />
      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{title}</div>
      <div style={{ fontSize: '0.84rem', marginTop: 4 }}>{detail}</div>
    </div>
  );
}

export function StatusBadge({ value }: { value?: string | null }) {
  if (!value) return <span className="badge badge-neutral">UNKNOWN</span>;
  const up = String(value).toUpperCase();
  if (['ACTIVE', 'TRUSTED', 'HEALTHY', 'CONVERGED', 'VERIFIED', 'COMPLETED', 'ALLOW', 'PASS', 'ESTABLISHED', 'DELIVERED', 'ACKED', 'RESOLVED', 'FALSE_POSITIVE', 'OPEN_OK'].includes(up)) {
    return <span className="badge badge-ok">{value}</span>;
  }
  if (['PENDING', 'SUSPENDED', 'ROTATING', 'PREPARED', 'IN_PROGRESS', 'ACKNOWLEDGED', 'OPEN', 'DELAYED', 'DEGRADED', 'LAGGING'].includes(up)) {
    return <span className="badge badge-warn">{value}</span>;
  }
  if (['REVOKED', 'COMPROMISED', 'DENY', 'FAIL', 'FAILED', 'FAILED_CLOSED', 'OFFLINE', 'PARTITIONED', 'INVALID', 'CRITICAL', 'HIGH', 'REPLAY_REJECTED', 'TAMPERED'].includes(up)) {
    return <span className="badge badge-danger">{value}</span>;
  }
  return <span className="badge badge-neutral">{value}</span>;
}
