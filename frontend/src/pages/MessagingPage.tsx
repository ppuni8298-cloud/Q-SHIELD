import { FormEvent, useCallback, useEffect, useState } from 'react';
import { ArrowRight, Lock, MessageSquare, MessageSquareLock, Pause, Play, RefreshCw, Send, ShieldAlert, XCircle } from 'lucide-react';
import { api } from '../api/client';
import { useAuth } from '../context/AuthContext';
import { ConfirmModal } from '../components/ConfirmModal';
import { ErrorBanner, LoadingState, StatusBadge, SuccessBanner } from '../components/StatusViews';

interface CryptoSessionRecord {
  id: string;
  initiator_id: string;
  recipient_id: string;
  initiator_device_id: string;
  recipient_device_id: string;
  peer_binding: string;
  state: 'NEW' | 'NEGOTIATING' | 'ESTABLISHED' | 'SUSPENDED' | 'RESUMING' | 'EXPIRED' | 'REVOKED' | 'COMPROMISED';
  key_version: number;
  generation: number;
  send_sequence: number;
  recv_expected_sequence: number;
  resumption_counter: number;
  forward_secrecy_status: string;
  expires_at: string;
  created_at: string;
}

interface MessageRecord {
  message_id: string;
  sender_id: string;
  recipient_id: string;
  session_id: string;
  sequence: number;
  session_generation: number;
  key_version: number;
  status: string;
  ack_count: number;
  expires_at: string;
  created_at: string;
}

export function MessagingPage() {
  const { user } = useAuth();
  const [sessions, setSessions] = useState<CryptoSessionRecord[]>([]);
  const [messages, setMessages] = useState<MessageRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Establish session form
  const [showEstablish, setShowEstablish] = useState(false);
  const [recipientId, setRecipientId] = useState('user-blair');
  const [recipientDeviceId, setRecipientDeviceId] = useState('dev-blair-trusted');
  const [establishing, setEstablishing] = useState(false);

  // Send message form
  const [sendSessionId, setSendSessionId] = useState('');
  const [plaintext, setPlaintext] = useState('');
  const [sending, setSending] = useState(false);

  // Receive/decrypt interactive test
  const [decryptMsgId, setDecryptMsgId] = useState('');
  const [receivedPlaintext, setReceivedPlaintext] = useState<string | null>(null);
  const [receiving, setReceiving] = useState(false);

  // Confirm modal for session suspend/revoke
  const [pendingAction, setPendingAction] = useState<{
    session: CryptoSessionRecord;
    action: 'suspend' | 'revoke';
  } | null>(null);
  const [modalBusy, setModalBusy] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [sRes, mRes] = await Promise.all([
        api.get<{ items: CryptoSessionRecord[] }>('/messages/sessions'),
        api.get<{ items: MessageRecord[] }>('/messages?limit=20'),
      ]);
      setSessions(sRes.items);
      setMessages(mRes.items);
      if (sRes.items.length > 0 && !sendSessionId) {
        setSendSessionId(sRes.items[0].id);
      }
      if (mRes.items.length > 0 && !decryptMsgId) {
        setDecryptMsgId(mRes.items[0].message_id);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [sendSessionId, decryptMsgId]);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const handleEstablishSession = async (e: FormEvent) => {
    e.preventDefault();
    setEstablishing(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<{ session: CryptoSessionRecord; resumption_token: string; forward_secrecy_note: string }>('/messages/sessions', {
        recipient_id: recipientId.trim(),
        recipient_device_id: recipientDeviceId.trim(),
        ttl_seconds: 7200,
      });
      setSuccess(`Established post-quantum session '${res.session.id}' with ${res.session.recipient_id}. Note: ${res.forward_secrecy_note}`);
      setShowEstablish(false);
      setSendSessionId(res.session.id);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setEstablishing(false);
    }
  };

  const handleSendMessage = async (e: FormEvent) => {
    e.preventDefault();
    setSending(true);
    setError(null);
    setSuccess(null);
    try {
      const res = await api.post<{ message: MessageRecord }>('/messages/send', {
        session_id: sendSessionId,
        plaintext: plaintext.trim(),
      });
      setSuccess(`Encrypted & queued message '${res.message.message_id}' (seq=${res.message.sequence}, gen=${res.message.session_generation}) with AES-256-GCM + AAD.`);
      setPlaintext('');
      setDecryptMsgId(res.message.message_id);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setSending(false);
    }
  };

  const handleReceiveMessage = async () => {
    setReceiving(true);
    setError(null);
    setReceivedPlaintext(null);
    try {
      const res = await api.post<{ plaintext: string; message: MessageRecord }>(`/messages/receive`, {
        message_id: decryptMsgId,
      });
      setReceivedPlaintext(res.plaintext);
      setSuccess(`Decrypted message '${decryptMsgId}': per-message key erased cleanly.`);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setReceiving(false);
    }
  };

  const handleSessionAction = async (reason: string) => {
    if (!pendingAction) return;
    setModalBusy(true);
    setError(null);
    try {
      const { session, action } = pendingAction;
      await api.post(`/messages/sessions/${session.id}/${action}`, {
        reason,
        confirmation: true,
      });
      setSuccess(`Session '${session.id}' transitioned to '${action.toUpperCase()}'.`);
      setPendingAction(null);
      await loadData();
    } catch (err) {
      setError(err);
    } finally {
      setModalBusy(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '1.35rem' }}>Secure End-to-End Messaging &amp; Session Resumption</h1>
          <div style={{ fontSize: '0.84rem', color: 'var(--text-secondary)' }}>
            ML-KEM-768 key establishment · HKDF-SHA-256 ratchet · AES-256-GCM AAD binding · Partial control-plane-mediated forward secrecy
          </div>
        </div>
        <button type="button" className="btn btn-primary" onClick={() => setShowEstablish(!showEstablish)}>
          <MessageSquareLock size={15} />
          <span>{showEstablish ? 'Close Form' : 'Establish E2E Session'}</span>
        </button>
      </div>

      <ErrorBanner error={error} onDismiss={() => setError(null)} />
      <SuccessBanner message={success} onDismiss={() => setSuccess(null)} />

      {showEstablish && (
        <form onSubmit={handleEstablishSession} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <h2 style={{ margin: 0, fontSize: '1rem' }}>Establish Post-Quantum Messaging Session (ML-KEM-768)</h2>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
            <div>
              <label htmlFor="msg-recip" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Recipient Actor ID</label>
              <input id="msg-recip" className="input" value={recipientId} onChange={(e) => setRecipientId(e.target.value)} required placeholder="user-blair" />
            </div>
            <div>
              <label htmlFor="msg-recip-dev" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: 4 }}>Recipient Trusted Device ID</label>
              <input id="msg-recip-dev" className="input" value={recipientDeviceId} onChange={(e) => setRecipientDeviceId(e.target.value)} required placeholder="dev-blair-trusted" />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
            <button type="button" className="btn" onClick={() => setShowEstablish(false)}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={establishing}>{establishing ? 'Establishing...' : 'Establish Session'}</button>
          </div>
        </form>
      )}

      {loading && sessions.length === 0 ? (
        <LoadingState label="Loading secure sessions..." />
      ) : (
        <div className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <MessageSquareLock size={16} /> Active &amp; Historical Messaging Sessions ({sessions.length})
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
                  <th>Session ID</th>
                  <th>Peers</th>
                  <th>State</th>
                  <th>Gen / Seq</th>
                  <th>Resumption Counter</th>
                  <th>Forward Secrecy</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((s) => (
                  <tr key={s.id}>
                    <td className="mono">{s.id}</td>
                    <td className="mono">{s.initiator_id} &harr; {s.recipient_id}</td>
                    <td><StatusBadge value={s.state} /></td>
                    <td className="mono">g{s.generation} / seq={s.send_sequence}</td>
                    <td>{s.resumption_counter}</td>
                    <td><span className="badge badge-warn" style={{ fontSize: '0.72rem' }}>{s.forward_secrecy_status}</span></td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {s.state === 'ESTABLISHED' && (
                          <button
                            type="button"
                            className="btn btn-amber"
                            style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                            onClick={() => setPendingAction({ session: s, action: 'suspend' })}
                          >
                            <Pause size={11} /> Suspend
                          </button>
                        )}
                        {!['REVOKED', 'COMPROMISED'].includes(s.state) && (
                          <button
                            type="button"
                            className="btn btn-danger"
                            style={{ padding: '2px 7px', fontSize: '0.72rem' }}
                            onClick={() => setPendingAction({ session: s, action: 'revoke' })}
                          >
                            <XCircle size={11} /> Revoke
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="grid-2">
        {/* Send Encrypted Message Form */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Send size={16} color="var(--accent-cyan)" /> Send Encrypted E2E Message
            </h2>
          </div>
          <p style={{ margin: '0 0 12px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Each message derives a unique per-message AES-256-GCM key from the ratchet. The key is erased immediately upon decryption.
          </p>

          <form onSubmit={handleSendMessage} style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div>
              <label htmlFor="send-session-id" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)' }}>Target Established Session</label>
              <select id="send-session-id" className="select" value={sendSessionId} onChange={(e) => setSendSessionId(e.target.value)} required>
                {sessions.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.id} ({s.initiator_id} &rarr; {s.recipient_id}) [{s.state}]
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="send-plaintext" style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-muted)' }}>Plaintext Message</label>
              <textarea
                id="send-plaintext"
                className="textarea"
                rows={3}
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
                required
                placeholder="Enter secret message payload bound to sender, recipient, and session AAD..."
              />
            </div>
            <button type="submit" className="btn btn-primary" disabled={sending || !sendSessionId || !plaintext.trim()}>
              <span>{sending ? 'Encrypting & Sending...' : 'Send Encrypted Message'}</span>
            </button>
          </form>
        </section>

        {/* Receive & Decrypt Lab */}
        <section className="card">
          <div className="card-header">
            <h2 style={{ margin: 0, fontSize: '1rem', display: 'flex', alignItems: 'center', gap: 8 }}>
              <Lock size={16} color="var(--accent-emerald)" /> Receive &amp; Decrypt Message
            </h2>
          </div>
          <p style={{ margin: '0 0 12px', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            Verifies AAD metadata (sender, recipient, session ID, sequence, nonce, key version). Replay attempts are rejected fail-closed.
          </p>

          <div style={{ display: 'flex', gap: 8, marginBottom: 14 }}>
            <select className="select" value={decryptMsgId} onChange={(e) => setDecryptMsgId(e.target.value)} style={{ flex: 1 }}>
              {messages.map((m) => (
                <option key={m.message_id} value={m.message_id}>
                  {m.message_id} (to: {m.recipient_id}) [{m.status}]
                </option>
              ))}
            </select>
            <button type="button" className="btn btn-emerald" onClick={() => void handleReceiveMessage()} disabled={receiving || !decryptMsgId}>
              <span>{receiving ? 'Decrypting...' : 'Receive & Decrypt'}</span>
            </button>
          </div>

          {receivedPlaintext !== null && (
            <div style={{ background: '#050a14', border: '1px solid var(--accent-emerald)', borderRadius: 8, padding: 12 }}>
              <div style={{ fontSize: '0.74rem', color: 'var(--accent-emerald)', fontWeight: 600, marginBottom: 4 }}>
                DECRYPTED PLAINTEXT (AUTHENTICATED &amp; KEY ERASED):
              </div>
              <pre style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: '0.86rem', whiteSpace: 'pre-wrap' }}>
                {receivedPlaintext}
              </pre>
            </div>
          )}
        </section>
      </div>

      <ConfirmModal
        open={Boolean(pendingAction)}
        title={`${pendingAction?.action.toUpperCase()} Messaging Session ${pendingAction?.session.id}`}
        description={
          pendingAction?.action === 'revoke'
            ? 'WARNING: Revoking a session permanently erases ratchet secrets and resumption keys. Any future message or resumption using this session will be rejected.'
            : `Suspend session '${pendingAction?.session.id}'. A suspended session can be resumed by the authorized peer with a valid resumption token.`
        }
        danger={pendingAction?.action === 'revoke'}
        confirmLabel="Confirm Action"
        busy={modalBusy}
        onCancel={() => setPendingAction(null)}
        onConfirm={handleSessionAction}
      />
    </div>
  );
}
