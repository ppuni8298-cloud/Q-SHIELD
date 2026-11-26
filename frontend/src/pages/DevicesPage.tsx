import { FormEvent, useCallback, useEffect, useState } from 'react';
import { AlertCircle, Check, Laptop, Plus, RefreshCw, XCircle } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ConfirmModal } from '../components/ConfirmModal';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface DeviceRecord {
  id: string;
  owner_id: string;
  credential_fingerprint: string;
  trust_state: 'PENDING' | 'TRUSTED' | 'SUSPENDED' | 'REVOKED';
  enrolled_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
}

export function DevicesPage() {
  const { hasPermission } = useAuth();
  const [devices, setDevices] = useState<DeviceRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Enroll form
  const [showEnroll, setShowEnroll] = useState(false);
  const [newDevId, setNewDevId] = useState('');
  const [newOwnerId, setNewOwnerId] = useState('');
  const [newFingerprint, setNewFingerprint] = useState('');

  // Re-enroll form
  const [showReEnroll, setShowReEnroll] = useState(false);
  const [oldDevId, setOldDevId] = useState('');
  const [replacementDevId, setReplacementDevId] = useState('');
  const [replacementFp, setReplacementFp] = useState('');

  // Confirm modal
  const [pendingAction, setPendingAction] = useState<{
    device: DeviceRecord;
    action: 'approve' | 'suspend' | 'restore' | 'revoke';
  } | null>(null);
  const [modalBusy, setModalBusy] = useState(false);

  const loadDevices = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.get<{ items: DeviceRecord[] }>('/devices');
      setDevices(res.items);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDevices();
  }, [loadDevices]);

  const handleEnroll = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    try {
      await api.post('/devices/enroll', {
        id: newDevId.trim(),
        owner_id: newOwnerId.trim(),
        credential_fingerprint: newFingerprint.trim(),
      });
      setSuccess(`Device '${newDevId}' enrolled in PENDING state.`);
      setShowEnroll(false);
      setNewDevId('');
      setNewOwnerId('');
      setNewFingerprint('');
      await loadDevices();
    } catch (err) {
      setError(err);
    }
  };

  const handleReEnroll = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    try {
      await api.post('/devices/re-enroll', {
        old_device_id: oldDevId.trim(),
        new_device_id: replacementDevId.trim(),
        new_credential_fingerprint: replacementFp.trim(),
        reason: 'Authorized hardware replacement following lost/compromised unit',
        confirmation: true,
      });
      setSuccess(`Re-enrolled replacement device '${replacementDevId}' for revoked unit '${oldDevId}'.`);
      setShowReEnroll(false);
      setOldDevId('');
      setReplacementDevId('');
      setReplacementFp('');
      await loadDevices();
    } catch (err) {
      setError(err);
    }
  };

  const handleDeviceAction = async (reason: string) => {
    if (!pendingAction) return;
    setModalBusy(true);
    setError(null);
    setSuccess(null);
    try {
      const { device, action } = pendingAction;
      await api.post(`/devices/${device.id}/${action}`, {
        reason,
        confirmation: true,
      });
      setSuccess(`Device '${device.id}' transition '${action}' completed.`);
      setPendingAction(null);
      await loadDevices();
    } catch (err) {
      setError(err);
    } finally {
      setModalBusy(false);
    }
  };

  const canManage = hasPermission('device:manage');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Device Enrollment &amp; Trust Lifecycle</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Hardware credentials bound to actor · Irreversible revocation tombstones · Re-enrollment replacement workflow
          </div>
        </div>
        {canManage && (
          <div style={{ display: 'flex', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowReEnroll(!showReEnroll)}>
              <span>{showReEnroll ? 'Close Re-enroll' : 'Re-enroll Replacement'}</span>
            </button>
            <button type="button" className="btn btn-primary" onClick={() => setShowEnroll(!showEnroll)}>
              <Plus size={15} />
              <span>{showEnroll ? 'Close Enroll' : 'Enroll Device'}</span>
            </button>
          </div>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {showEnroll && canManage && (
        <form onSubmit={handleEnroll} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Enroll New Device (Pending Approval)</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <label htmlFor="enroll-dev-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Device ID</label>
              <input id="enroll-dev-id" className="input" value={newDevId} onChange={(e) => setNewDevId(e.target.value)} required placeholder="dev-alex-workstation" />
            </div>
            <div>
              <label htmlFor="enroll-owner-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Owner Actor ID</label>
              <input id="enroll-owner-id" className="input" value={newOwnerId} onChange={(e) => setNewOwnerId(e.target.value)} required placeholder="user-alex" />
            </div>
            <div>
              <label htmlFor="enroll-fp" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Credential Fingerprint</label>
              <input id="enroll-fp" className="input" value={newFingerprint} onChange={(e) => setNewFingerprint(e.target.value)} required placeholder="fp-sha256-abc123..." />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowEnroll(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary">Enroll Device</button>
          </div>
        </form>
      )}

      {showReEnroll && canManage && (
        <form onSubmit={handleReEnroll} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12, borderColor: 'var(--accent-amber)' }}>
          <h2 style={{ margin: 0, fontSize: '1rem', color: 'var(--accent-amber)' }}>Re-enroll Replacement for Revoked Hardware</h2>
          <p style={{ margin: 0, fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Revoked devices cannot be un-revoked due to immutable tombstones. Re-enrollment creates a clean replacement unit bound to the original owner.
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <label htmlFor="reenroll-old-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Revoked Device ID</label>
              <input id="reenroll-old-id" className="input" value={oldDevId} onChange={(e) => setOldDevId(e.target.value)} required placeholder="dev-alex-trusted" />
            </div>
            <div>
              <label htmlFor="reenroll-new-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>New Replacement Device ID</label>
              <input id="reenroll-new-id" className="input" value={replacementDevId} onChange={(e) => setReplacementDevId(e.target.value)} required placeholder="dev-alex-replacement-01" />
            </div>
            <div>
              <label htmlFor="reenroll-fp" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>New Credential Fingerprint</label>
              <input id="reenroll-fp" className="input" value={replacementFp} onChange={(e) => setReplacementFp(e.target.value)} required placeholder="fp-replacement-xyz789" />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowReEnroll(false)}>Cancel</button>
            <button type="submit" className="btn btn-amber">Re-enroll Replacement</button>
          </div>
        </form>
      )}

      {loading && devices.length === 0 ? (
        <LoadingState label="Loading device registry..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Laptop size={16} /> Device Inventory ({devices.length})
            </h2>
            <button type="button" className="btn" onClick={() => void loadDevices()}>
              <RefreshCw size={13} />
              <span>Refresh</span>
            </button>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device ID</th>
                  <th>Owner</th>
                  <th>Fingerprint</th>
                  <th>State</th>
                  <th>Enrolled At</th>
                  {canManage && <th>Lifecycle Controls</th>}
                </tr>
              </thead>
              <tbody>
                {devices.map((d) => (
                  <tr key={d.id}>
                    <td className="mono">{d.id}</td>
                    <td className="mono">{d.owner_id}</td>
                    <td className="mono" style={{ fontSize: '0.74rem' }}>{d.credential_fingerprint.slice(0, 24)}...</td>
                    <td><StatusBadge value={d.trust_state} /></td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>{d.enrolled_at.slice(0, 19).replace('T', ' ')}</td>
                    {canManage && (
                      <td>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {d.trust_state === 'PENDING' && (
                            <button
                              type="button"
                              className="btn btn-emerald"
                              style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                              onClick={() => setPendingAction({ device: d, action: 'approve' })}
                            >
                              <Check size={12} /> Approve
                            </button>
                          )}
                          {d.trust_state === 'TRUSTED' && (
                            <button
                              type="button"
                              className="btn btn-amber"
                              style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                              onClick={() => setPendingAction({ device: d, action: 'suspend' })}
                            >
                              Suspend
                            </button>
                          )}
                          {d.trust_state === 'SUSPENDED' && (
                            <button
                              type="button"
                              className="btn btn-emerald"
                              style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                              onClick={() => setPendingAction({ device: d, action: 'restore' })}
                            >
                              Restore
                            </button>
                          )}
                          {d.trust_state !== 'REVOKED' && (
                            <button
                              type="button"
                              className="btn btn-danger"
                              style={{ padding: '3px 8px', fontSize: '0.74rem' }}
                              onClick={() => setPendingAction({ device: d, action: 'revoke' })}
                            >
                              <XCircle size={12} /> Revoke (Permanent)
                            </button>
                          )}
                          {d.trust_state === 'REVOKED' && (
                            <span style={{ fontSize: '0.72rem', color: 'var(--accent-rose)' }}>Tombstoned</span>
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

      <ConfirmModal
        open={Boolean(pendingAction)}
        title={pendingAction?.action === 'revoke' ? `PERMANENT REVOCATION: ${pendingAction?.device.id}` : `${pendingAction?.action.toUpperCase()} Device ${pendingAction?.device.id}`}
        description={
          pendingAction?.action === 'revoke'
            ? 'WARNING: Revocation is IRREVERSIBLE. An immutable tombstone will be recorded into the ledger and propagated to all nodes. The device can NEVER be restored.'
            : `Transition device '${pendingAction?.device.id}' to ${pendingAction?.action} status.`
        }
        danger={pendingAction?.action === 'revoke' || pendingAction?.action === 'suspend'}
        confirmLabel={pendingAction?.action === 'revoke' ? 'Confirm Permanent Revocation' : 'Execute Action'}
        busy={modalBusy}
        onCancel={() => setPendingAction(null)}
        onConfirm={handleDeviceAction}
      />
    </div>
  );
}
