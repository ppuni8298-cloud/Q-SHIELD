import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Archive, CheckCircle2, FileCheck, KeyRound, Play, RefreshCw, RotateCcw, ShieldCheck, XCircle } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ConfirmModal } from '../components/ConfirmModal';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface KeyMetadata {
  key_id: string;
  purpose: string;
  algorithm: string;
  version: number;
  state: string;
  created_at: string;
  activated_at: string | null;
  revoked_at: string | null;
}

interface RotationOperation {
  operation_id: string;
  purpose: string;
  from_key_id: string;
  to_key_id: string;
  from_version: number;
  to_version: number;
  phase: string;
  status: string;
  grace_policy: string;
  actor_id: string;
  reason: string;
  committed: boolean;
  journal_hash: string;
  created_at: string;
  updated_at: string;
}

interface BackupManifest {
  backup_id: string;
  schema_version: string;
  version: number;
  active_epoch: number;
  max_revocation_epoch: number;
  tombstone_count: number;
  manifest_sha256: string;
  verification_status: string;
  created_by: string;
  created_at: string;
}

export function KeysPage() {
  const { hasPermission } = useAuth();
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [rotations, setRotations] = useState<RotationOperation[]>([]);
  const [backups, setBackups] = useState<BackupManifest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Rotation start form
  const [showRotateForm, setShowRotateForm] = useState(false);
  const [rotatePurpose, setRotatePurpose] = useState('vault_kek');
  const [gracePolicy, setGracePolicy] = useState('ZERO_GRACE');
  const [crashAt, setCrashAt] = useState<string>('NONE');
  const [autoAdvance, setAutoAdvance] = useState(true);
  const [rotating, setRotating] = useState(false);

  // Backup create
  const [backupReason, setBackupReason] = useState('Routine operator signed backup');
  const [creatingBackup, setCreatingBackup] = useState(false);

  // Confirm modal for restore
  const [pendingRestore, setPendingRestore] = useState<BackupManifest | null>(null);
  const [modalBusy, setModalBusy] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [kRes, rRes, bRes] = await Promise.all([
        api.get<any>('/keys'),
        api.get<any>('/keys/rotations'),
        api.get<any>('/keys/backups'),
      ]);
      const keyList = Array.isArray(kRes) ? kRes : (kRes?.items || []);
      const rotationList = Array.isArray(rRes) ? rRes : (rRes?.items || []);
      const backupList = Array.isArray(bRes) ? bRes : (bRes?.items || []);
      setKeys(keyList);
      setRotations(rotationList);
      setBackups(backupList);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleStartRotation = async (e: FormEvent) => {
    e.preventDefault();
    setRotating(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<{ operation: RotationOperation }>('/keys/rotate', {
        purpose: rotatePurpose,
        grace_policy: gracePolicy,
        reason: 'Authorized scheduled key rotation',
        auto_advance: autoAdvance,
        crash_at: crashAt === 'NONE' ? null : crashAt,
      });
      setSuccess(`Rotation '${res.operation.operation_id}' initiated: phase=${res.operation.phase}, status=${res.operation.status}.`);
      setShowRotateForm(false);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setRotating(false);
    }
  };

  const handleRecoverCrashed = async () => {
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<{ outcomes: Array<{ operation_id: string; final_status: string; action_taken: string }> }>('/keys/recovery/run', {});
      if (res.outcomes.length === 0) {
        setSuccess('No interrupted or crashed rotations found to recover.');
      } else {
        const details = res.outcomes.map((o) => `${o.operation_id}: ${o.action_taken} -> ${o.final_status}`).join('; ');
        setSuccess(`Recovered rotations: ${details}`);
      }
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const handleCreateBackup = async (e: FormEvent) => {
    e.preventDefault();
    setCreatingBackup(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<BackupManifest>('/keys/backups/create', {
        reason: backupReason,
      });
      setSuccess(`Signed backup created: '${res.backup_id}' (sha=${res.manifest_sha256.slice(0, 16)}...).`);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setCreatingBackup(false);
    }
  };

  const handleVerifyBackup = async (backupId: string) => {
    setError(null);
    try {
      const res = await api.post<{ valid: boolean; status: string; reason: string }>(`/keys/backups/${backupId}/verify`, {});
      if (res.valid) {
        setSuccess(`Backup '${backupId}' VERIFIED: ML-DSA-65 signature and AEAD payload valid.`);
      } else {
        setError(`Backup '${backupId}' TAMPERED/INVALID: ${res.reason}`);
      }
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const handleRestoreBackup = async (reason: string) => {
    if (!pendingRestore) return;
    setModalBusy(true);
    setError(null);
    try {
      await api.post(`/keys/backups/${pendingRestore.backup_id}/restore`, {
        confirmation: true,
      });
      setSuccess(`Restored keystore snapshot from backup '${pendingRestore.backup_id}'.`);
      setPendingRestore(null);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setModalBusy(false);
    }
  };

  const canManage = hasPermission('key:manage');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Cryptographic Keys, Phased Rotation &amp; Signed Backups</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Durable rotation journal · Deterministic crash recovery · ML-DSA-65 signed anti-rollback backups
          </div>
        </div>
        {canManage && (
          <div style={{ display: 'flex', gap: 10 }}>
            <button type="button" className="btn" onClick={() => void handleRecoverCrashed()}>
              <RotateCcw size={14} />
              <span>Run Crash Recovery</span>
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setShowRotateForm(!showRotateForm)}>
              <RotateCcw size={14} />
              <span>{showRotateForm ? 'Close Form' : 'Start Key Rotation'}</span>
            </button>
          </div>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {showRotateForm && canManage && (
        <form onSubmit={handleStartRotation} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Initiate Phased Key Rotation</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <label htmlFor="rot-purpose" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Key Purpose</label>
              <select id="rot-purpose" className="select" value={rotatePurpose} onChange={(e) => setRotatePurpose(e.target.value)}>
                <option value="vault_kek">vault_kek (AES-256-GCM / DEK wrapping)</option>
                <option value="messaging">messaging (ML-KEM-768 / session ratchet)</option>
              </select>
            </div>
            <div>
              <label htmlFor="rot-grace" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Cutoff Policy</label>
              <select id="rot-grace" className="select" value={gracePolicy} onChange={(e) => setGracePolicy(e.target.value)}>
                <option value="ZERO_GRACE">ZERO_GRACE (Immediate Cutoff)</option>
                <option value="BOUNDED_GRACE">BOUNDED_GRACE (Permit In-Flight)</option>
              </select>
            </div>
            <div>
              <label htmlFor="rot-crash" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Crash Injection Test</label>
              <select id="rot-crash" className="select" value={crashAt} onChange={(e) => setCrashAt(e.target.value)}>
                <option value="NONE">NONE (Normal Full Rotation)</option>
                <option value="BEFORE_COMMIT">BEFORE_COMMIT (Rollback Test)</option>
                <option value="AFTER_COMMIT">AFTER_COMMIT (Rollforward Test)</option>
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input type="checkbox" id="rot-advance" checked={autoAdvance} onChange={(e) => setAutoAdvance(e.target.checked)} />
            <label htmlFor="rot-advance" style={{ fontSize: '0.82rem' }}>Auto-advance through PREPARE, DISTRIBUTE, COMMIT, RETIRE</label>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowRotateForm(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={rotating}>{rotating ? 'Executing...' : 'Start Rotation'}</button>
          </div>
        </form>
      )}

      {loading && keys.length === 0 ? (
        <LoadingState label="Loading key registry..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <KeyRound size={16} /> Key Registry ({keys.length})
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
                  <th>Key ID</th>
                  <th>Purpose</th>
                  <th>Algorithm</th>
                  <th>Version</th>
                  <th>State</th>
                  <th>Created At</th>
                </tr>
              </thead>
              <tbody>
                {keys.map((k) => (
                  <tr key={k.key_id}>
                    <td className="mono">{k.key_id}</td>
                    <td>{k.purpose}</td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>{k.algorithm}</td>
                    <td><span className="badge badge-info">v{k.version}</span></td>
                    <td><StatusBadge value={k.state} /></td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{k.created_at.slice(0, 19).replace('T', ' ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Rotation History & Journal */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <RotateCcw size={16} /> Phased Rotation Journal ({rotations.length})
            </h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Operation ID</th>
                  <th>Transition</th>
                  <th>Phase</th>
                  <th>Status</th>
                  <th>Committed</th>
                </tr>
              </thead>
              <tbody>
                {rotations.slice(0, 6).map((r) => (
                  <tr key={r.operation_id}>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{r.operation_id}</td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>v{r.from_version} &rarr; v{r.to_version}</td>
                    <td><span className="badge badge-neutral">{r.phase}</span></td>
                    <td><StatusBadge value={r.status} /></td>
                    <td><StatusBadge value={r.committed ? 'YES' : 'NO'} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Backups & Restorations */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Archive size={16} /> Signed Anti-Rollback Backups ({backups.length})
            </h2>
          </div>

          {canManage && (
            <form onSubmit={handleCreateBackup} style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
              <input
                className="input"
                value={backupReason}
                onChange={(e) => setBackupReason(e.target.value)}
                placeholder="Backup justification"
                style={{ flex: 1 }}
                required
              />
              <button type="submit" className="btn btn-emerald" disabled={creatingBackup}>
                <span>{creatingBackup ? 'Signing...' : 'Create Backup'}</span>
              </button>
            </form>
          )}

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Backup ID</th>
                  <th>Status</th>
                  <th>Epochs</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {backups.slice(0, 5).map((b) => (
                  <tr key={b.backup_id}>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{b.backup_id}</td>
                    <td><StatusBadge value={b.verification_status} /></td>
                    <td className="mono" style={{ fontSize: '0.74rem' }}>act={b.active_epoch} / tomb={b.max_revocation_epoch}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button
                          type="button"
                          className="btn"
                          style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                          onClick={() => void handleVerifyBackup(b.backup_id)}
                        >
                          Verify Sig
                        </button>
                        {canManage && (
                          <button
                            type="button"
                            className="btn btn-danger"
                            style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                            onClick={() => setPendingRestore(b)}
                          >
                            Restore
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <ConfirmModal
        open={Boolean(pendingRestore)}
        title={`Restore Backup ${pendingRestore?.backup_id}`}
        description="WARNING: Restoring a backup checks anti-rollback rules (cannot undo newer revocation tombstones). Un-revoked keys will be restored to their previous snapshot state."
        danger={true}
        confirmLabel="Confirm Keystore Restore"
        busy={modalBusy}
        onCancel={() => setPendingRestore(null)}
        onConfirm={handleRestoreBackup}
      />
    </div>
  );
}
