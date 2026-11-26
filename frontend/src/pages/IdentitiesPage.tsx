import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Check, Plus, ShieldCheck, UserX, Users } from 'lucide-react';
import { api, extractErrorMessage } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ConfirmModal } from '../components/ConfirmModal';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface UserRecord {
  id: string;
  display_name: string;
  role: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

interface RoleDefinition {
  role: string;
  description: string;
  permissions: Array<{ action: string; scope: string; description: string }>;
}

export function IdentitiesPage() {
  const { user: currentUser, hasPermission } = useAuth();
  const [users, setUsers] = useState<UserRecord[]>([]);
  const [roles, setRoles] = useState<RoleDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // New user form state
  const [showCreate, setShowCreate] = useState(false);
  const [newId, setNewId] = useState('');
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState('viewer');

  // Confirmation modal state
  const [pendingAction, setPendingAction] = useState<{
    type: 'toggle_enabled' | 'change_role';
    targetUser: UserRecord;
    nextRole?: string;
    nextEnabled?: boolean;
  } | null>(null);
  const [modalBusy, setModalBusy] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [uRes, rRes] = await Promise.all([
        api.get<any>('/users'),
        api.get<any>('/roles'),
      ]);
      const userList = Array.isArray(uRes) ? uRes : (uRes?.items || []);
      const roleList = Array.isArray(rRes) ? rRes : (rRes?.roles || rRes?.items || []);
      setUsers(userList);
      setRoles(roleList);
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleCreateUser = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    try {
      await api.post('/users', {
        id: newId.trim(),
        display_name: newName.trim(),
        role: newRole,
        enabled: true,
      });
      setSuccess(`User '${newId}' created successfully.`);
      setShowCreate(false);
      setNewId('');
      setNewName('');
      await loadData();
    } catch (err) {
      setError(err);
    }
  };

  const handleExecuteModalAction = async (reason: string) => {
    if (!pendingAction) return;
    setModalBusy(true);
    setError(null);
    setSuccess(null);
    try {
      const { targetUser, nextRole, nextEnabled, type } = pendingAction;
      if (type === 'toggle_enabled') {
        await api.patch(`/users/${targetUser.id}`, {
          enabled: nextEnabled,
          reason,
          confirmation: true,
        });
        setSuccess(`User '${targetUser.id}' is now ${nextEnabled ? 'enabled' : 'disabled'}.`);
      } else if (type === 'change_role') {
        await api.patch(`/users/${targetUser.id}`, {
          role: nextRole,
          reason,
          confirmation: true,
        });
        setSuccess(`User '${targetUser.id}' role updated to '${nextRole}'.`);
      }
      setPendingAction(null);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setModalBusy(false);
    }
  };

  const canManage = hasPermission('user:manage');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Identities &amp; Role-Based Access Control</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            Strict RBAC enforcement · Self-escalation blocked fail-closed · All changes audited
          </div>
        </div>
        {canManage && (
          <button type="button" className="btn btn-primary" onClick={() => setShowCreate(!showCreate)}>
            <Plus size={15} />
            <span>{showCreate ? 'Close Form' : 'Enroll Identity'}</span>
          </button>
        )}
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {showCreate && canManage && (
        <form onSubmit={handleCreateUser} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Enroll New Synthetic Identity</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
            <div>
              <label htmlFor="create-user-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>User ID</label>
              <input id="create-user-id" className="input" value={newId} onChange={(e) => setNewId(e.target.value)} required placeholder="user-charlie" />
            </div>
            <div>
              <label htmlFor="create-user-name" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Display Name</label>
              <input id="create-user-name" className="input" value={newName} onChange={(e) => setNewName(e.target.value)} required placeholder="Charlie Dev" />
            </div>
            <div>
              <label htmlFor="create-user-role" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Role</label>
              <select id="create-user-role" className="select" value={newRole} onChange={(e) => setNewRole(e.target.value)}>
                {roles.map((r) => (
                  <option key={r.role} value={r.role}>{r.role}</option>
                ))}
              </select>
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowCreate(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary">Enroll User</button>
          </div>
        </form>
      )}

      {loading && users.length === 0 ? (
        <LoadingState label="Loading users and role catalog..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Users size={16} /> Seeded Users ({users.length})
            </h2>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Actor ID</th>
                  <th>Display Name</th>
                  <th>Assigned Role</th>
                  <th>Status</th>
                  {canManage && <th>Administrative Actions</th>}
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const isSelf = currentUser?.actor_id === u.id;
                  return (
                    <tr key={u.id}>
                      <td className="mono">
                        {u.id} {isSelf && <span className="badge badge-info">YOU</span>}
                      </td>
                      <td>{u.display_name}</td>
                      <td>
                        {canManage && !isSelf ? (
                          <select
                            className="select"
                            value={u.role}
                            style={{ padding: '4px 8px', width: 'auto', minWidth: 130 }}
                            onChange={(e) => {
                              const targetRole = e.target.value;
                              if (targetRole !== u.role) {
                                setPendingAction({
                                  type: 'change_role',
                                  targetUser: u,
                                  nextRole: targetRole,
                                });
                              }
                            }}
                          >
                            {roles.map((r) => (
                              <option key={r.role} value={r.role}>{r.role}</option>
                            ))}
                          </select>
                        ) : (
                          <span className="badge badge-neutral">{u.role}</span>
                        )}
                      </td>
                      <td><StatusBadge value={u.enabled ? 'ACTIVE' : 'REVOKED'} /></td>
                      {canManage && (
                        <td>
                          {isSelf ? (
                            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Self-mutation prevented</span>
                          ) : (
                            <button
                              type="button"
                              className={`btn ${u.enabled ? 'btn-danger' : 'btn-emerald'}`}
                              style={{ padding: '4px 10px', fontSize: '0.78rem' }}
                              onClick={() => {
                                setPendingAction({
                                  type: 'toggle_enabled',
                                  targetUser: u,
                                  nextEnabled: !u.enabled,
                                });
                              }}
                            >
                              {u.enabled ? <UserX size={13} /> : <Check size={13} />}
                              <span>{u.enabled ? 'Disable' : 'Enable'}</span>
                            </button>
                          )}
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} /> Canonical Role Definitions &amp; Permission Matrix
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 14 }}>
          {roles.map((r) => (
            <div key={r.role} style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)', borderRadius: 10, padding: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                <strong className="mono" style={{ color: 'var(--accent-cyan)' }}>{r.role}</strong>
                <span className="badge badge-neutral">{r.permissions.length} perms</span>
              </div>
              <p style={{ margin: '0 0 10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{r.description}</p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {r.permissions.map((p) => (
                  <span key={p.action} className="mono" style={{ fontSize: '0.7rem', background: '#070b14', padding: '2px 6px', borderRadius: 4, border: '1px solid var(--border-subtle)' }}>
                    {p.action}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      <ConfirmModal
        open={Boolean(pendingAction)}
        title={pendingAction?.type === 'change_role' ? `Change Role for ${pendingAction?.targetUser.id}` : `${pendingAction?.nextEnabled ? 'Enable' : 'Disable'} User ${pendingAction?.targetUser.id}`}
        description={
          pendingAction?.type === 'change_role'
            ? `Change role from '${pendingAction?.targetUser.role}' to '${pendingAction?.nextRole}'. This will be recorded into the append-only audit ledger.`
            : `Are you sure you want to ${pendingAction?.nextEnabled ? 're-enable' : 'disable'} this account? Inactive accounts cannot authenticate.`
        }
        danger={pendingAction?.type === 'toggle_enabled' && !pendingAction?.nextEnabled}
        busy={modalBusy}
        onCancel={() => setPendingAction(null)}
        onConfirm={handleExecuteModalAction}
      />
    </div>
  );
}
