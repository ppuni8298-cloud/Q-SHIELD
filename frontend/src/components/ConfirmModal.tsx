import { useEffect, useId, useRef, useState } from 'react';
import { AlertTriangle } from 'lucide-react';

interface ConfirmModalProps {
  open: boolean;
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
  requireReason?: boolean;
  defaultReason?: string;
  busy?: boolean;
  onCancel: () => void;
  onConfirm: (reason: string) => Promise<void> | void;
}

export function ConfirmModal({
  open,
  title,
  description,
  confirmLabel = 'Confirm Action',
  danger = true,
  requireReason = true,
  defaultReason = 'Verified operator security action',
  busy = false,
  onCancel,
  onConfirm,
}: ConfirmModalProps) {
  const dialogRef = useRef<HTMLDialogElement | null>(null);
  const titleId = useId();
  const [reason, setReason] = useState(defaultReason);
  const [validationError, setValidationError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setReason(defaultReason);
      setValidationError(null);
    }
  }, [open, defaultReason]);

  useEffect(() => {
    const el = dialogRef.current;
    if (!el) return;
    if (open) {
      if (!el.open && typeof el.showModal === 'function') {
        el.showModal();
      }
    } else if (el.open && typeof el.close === 'function') {
      el.close();
    }
  }, [open]);

  if (!open && typeof window !== 'undefined' && typeof HTMLDialogElement === 'undefined') {
    return null;
  }

  const handleClose = () => {
    if (dialogRef.current) {
      dialogRef.current.returnValue = '';
    }
    onCancel();
  };

  const handleSubmit = async () => {
    const trimmed = reason.trim();
    if (requireReason && trimmed.length < 3) {
      setValidationError('Reason must be at least 3 characters.');
      return;
    }
    setValidationError(null);
    await onConfirm(trimmed);
  };

  return (
    <dialog
      ref={dialogRef}
      aria-labelledby={titleId}
      onClose={handleClose}
      onCancel={(e) => {
        e.preventDefault();
        handleClose();
      }}
    >
      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', marginBottom: 14 }}>
        <AlertTriangle size={22} color={danger ? '#fb7185' : '#fbbf24'} style={{ flexShrink: 0, marginTop: 2 }} />
        <div>
          <h2 id={titleId} style={{ margin: 0, fontSize: '1.1rem' }}>
            {title}
          </h2>
          <p style={{ margin: '6px 0 0', color: 'var(--text-secondary)', fontSize: '0.88rem' }}>{description}</p>
        </div>
      </div>

      {requireReason && (
        <div style={{ marginBottom: 14 }}>
          <label htmlFor={`${titleId}-reason`} style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: 6 }}>
            Audit Reason (required)
          </label>
          <input
            id={`${titleId}-reason`}
            className="input"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Enter justification recorded to audit ledger"
            disabled={busy}
          />
        </div>
      )}

      {validationError && (
        <div className="alert-banner alert-error" style={{ marginBottom: 12 }}>
          <span>{validationError}</span>
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
        <button type="button" className="btn" autoFocus={danger} onClick={handleClose} disabled={busy}>
          Cancel
        </button>
        <button
          type="button"
          className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`}
          onClick={() => void handleSubmit()}
          disabled={busy}
        >
          {busy ? 'Executing...' : confirmLabel}
        </button>
      </div>
    </dialog>
  );
}

export default ConfirmModal;

