import React, { FormEvent, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, KeyRound, UserCheck, Eye, EyeOff, Lock, ArrowRight, Sparkles, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { ErrorBanner } from '../components/StatusViews';

const SEEDED_PROFILES = [
  { actorId: 'user-admin', deviceId: 'dev-admin-trusted', role: 'admin', label: 'Platform Admin (Full Control & Users)', desc: 'Full control plane & identities' },
  { actorId: 'user-secops', deviceId: 'dev-secops-trusted', role: 'security_operator', label: 'Security Operator (Revocations, Keys, Alerts)', desc: 'Revocation, keys, alerts' },
  { actorId: 'user-auditor', deviceId: 'dev-auditor-trusted', role: 'auditor', label: 'Auditor (Read-Only Ledger, Evidence, Metrics)', desc: 'Read-only ledger & receipts' },
  { actorId: 'user-alex', deviceId: 'dev-alex-trusted', role: 'owner', label: 'Resource Owner — Alex (Vault & E2E Messaging)', desc: 'Vault secrets & E2E messaging' },
  { actorId: 'user-blair', deviceId: 'dev-blair-trusted', role: 'owner', label: 'Resource Owner — Blair (Cross-User & Peer Recipient)', desc: 'Peer messaging recipient' },
];

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [actorId, setActorId] = useState('user-secops');
  const [deviceId, setDeviceId] = useState('dev-secops-trusted');
  const [peerId, setPeerId] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const performLogin = async (aId: string, dId: string, pId?: string) => {
    setSubmitting(true);
    setError(null);
    try {
      await login(aId.trim(), dId.trim(), pId?.trim() || undefined);
      navigate('/dashboard');
    } catch (err) {
      setError(err);
    } finally {
      setSubmitting(false);
    }
  };

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    void performLogin(actorId, deviceId, peerId);
  };

  return (
    <div className="min-h-screen bg-[#070B18] text-[#F4F7FF] flex items-center justify-center p-6 relative overflow-hidden">
      {/* Background Lighting Orbs */}
      <div className="cyber-glow-orb w-[500px] h-[500px] bg-blue-600/15 top-[-100px] left-[-100px]" />
      <div className="cyber-glow-orb w-[450px] h-[450px] bg-cyan-500/12 bottom-[-80px] right-[-80px]" />

      <div className="max-w-5xl w-full grid grid-cols-1 lg:grid-cols-12 gap-8 z-10 items-center">
        {/* Left Side: 3D Quantum Product Showcase */}
        <div className="lg:col-span-5 space-y-6 hidden lg:block">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-400/30 text-cyan-300 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            CONTROL PLANE GATEWAY
          </div>
          <h2 className="text-3xl font-extrabold leading-tight text-white">
            Post-Quantum <br />
            <span className="gradient-text-cyan">Zero-Trust Access</span>
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            Continuous verification enforced through NIST ML-KEM-768 lattice cryptography and SHA-256 tamper-evident evidence chaining.
          </p>

          <div className="space-y-3 pt-2">
            {[
              'Sliding-window brute force rate limiting active',
              'Sub-second distributed revocation convergence',
              'Dual-key window zero-downtime key rotation',
            ].map((text, i) => (
              <div key={i} className="flex items-center gap-2.5 text-xs text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-cyan-400 flex-shrink-0" />
                <span>{text}</span>
              </div>
            ))}
          </div>

          <div className="glass-panel p-4 rounded-xl border border-slate-800 text-xs text-slate-400 font-mono">
            <span className="text-cyan-400 font-bold block mb-1">// SECURITY POSTURE</span>
            STATUS: ML-KEM-768 ENFORCED<br />
            REPLAY: SINGLE-USE NONCE BOUND
          </div>
        </div>

        {/* Right Side: Authentication Panel */}
        <div className="lg:col-span-7 glass-panel-glow p-8 md:p-10 rounded-3xl space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-950/60 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
                <Shield className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white m-0">Q-SHIELD Synthetic Demo Sign-In</h1>
                <p className="text-xs text-slate-400 m-0">Authenticates against live FastAPI backend (/api/v1/auth/demo-login)</p>
              </div>
            </div>
            <Link to="/signup" className="text-xs text-cyan-400 hover:underline font-semibold">
              Create Account
            </Link>
          </div>

          <ErrorBanner error={error} onDismiss={() => setError(null)} />

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label htmlFor="login-actor-id" className="block text-xs font-mono text-slate-400 uppercase mb-1.5">
                Actor / Identity ID
              </label>
              <div className="relative">
                <input
                  id="login-actor-id"
                  className="cyber-input font-mono text-sm"
                  value={actorId}
                  onChange={(e) => setActorId(e.target.value)}
                  required
                  placeholder="e.g. user-secops"
                />
              </div>
            </div>

            <div>
              <label htmlFor="login-device-id" className="block text-xs font-mono text-slate-400 uppercase mb-1.5">
                Trusted Device ID
              </label>
              <div className="relative">
                <input
                  id="login-device-id"
                  type={showPassword ? 'text' : 'password'}
                  className="cyber-input font-mono text-sm pr-10"
                  value={deviceId}
                  onChange={(e) => setDeviceId(e.target.value)}
                  required
                  placeholder="e.g. dev-secops-trusted"
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label htmlFor="login-peer-id" className="block text-xs font-mono text-slate-400 uppercase mb-1.5">
                Optional Bound Peer ID
              </label>
              <input
                id="login-peer-id"
                className="cyber-input font-mono text-sm"
                value={peerId}
                onChange={(e) => setPeerId(e.target.value)}
                placeholder="Optional bound peer identity"
              />
            </div>

            <button
              type="submit"
              className="cyber-btn cyber-btn-primary w-full py-3 text-sm font-bold mt-2"
              disabled={submitting}
            >
              <KeyRound className="w-4 h-4" />
              <span>{submitting ? 'Verifying Credentials...' : 'Authenticate Session'}</span>
            </button>
          </form>

          {/* Seeded Persona Quick Selector */}
          <div className="pt-4 border-t border-slate-800/80 space-y-2.5">
            <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>SEEDED TEST PERSONAS (CLICK TO FILL & TEST):</span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {SEEDED_PROFILES.map((p) => (
                <div
                  key={p.actorId}
                  className="p-2.5 rounded-xl border border-slate-800 bg-slate-900/60 hover:border-cyan-400/50 flex items-center justify-between gap-2 transition-all cursor-pointer"
                  onClick={() => {
                    setActorId(p.actorId);
                    setDeviceId(p.deviceId);
                  }}
                >
                  <div className="min-w-0">
                    <div className="text-xs font-bold text-white truncate">{p.label}</div>
                    <div className="text-[10px] font-mono text-cyan-400 truncate">{p.actorId}</div>
                  </div>
                  <button
                    type="button"
                    className="cyber-btn cyber-btn-secondary text-[11px] px-2.5 py-1"
                    disabled={submitting}
                    onClick={(e) => {
                      e.stopPropagation();
                      setActorId(p.actorId);
                      setDeviceId(p.deviceId);
                      void performLogin(p.actorId, p.deviceId);
                    }}
                  >
                    Use
                  </button>
                </div>
              ))}
            </div>
          </div>

          <div className="flex items-center justify-between text-xs text-slate-500 pt-2">
            <Link to="/" className="text-slate-400 hover:text-cyan-400">← Back to Overview</Link>
            <span className="font-mono">API: /api/v1/auth/demo-login</span>
          </div>
        </div>
      </div>
    </div>
  );
}
