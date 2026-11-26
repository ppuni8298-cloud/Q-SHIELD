import React, { useState, FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Lock, Eye, EyeOff, UserPlus, CheckCircle2, AlertCircle, ArrowRight } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export const SignupPage: React.FC = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState(false);

  // Password Strength Calculation
  const calculateStrength = (pass: string) => {
    let score = 0;
    if (pass.length >= 8) score++;
    if (/[A-Z]/.test(pass)) score++;
    if (/[0-9]/.test(pass)) score++;
    if (/[^A-Za-z0-9]/.test(pass)) score++;
    return score;
  };

  const strength = calculateStrength(password);
  const getStrengthLabel = (s: number) => {
    if (s <= 1) return { label: 'Weak', color: 'bg-rose-500', text: 'text-rose-400' };
    if (s === 2) return { label: 'Moderate', color: 'bg-amber-500', text: 'text-amber-400' };
    if (s === 3) return { label: 'Strong', color: 'bg-cyan-500', text: 'text-cyan-400' };
    return { label: 'Very Strong', color: 'bg-emerald-500', text: 'text-emerald-400' };
  };

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setLoading(true);
    try {
      // In zero-trust architecture, public registration enrolls standard non-privileged identities
      // Synthesizing principal actor and device ID for seamless verification
      const derivedActorId = `user-${email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '') || 'new'}`;
      const derivedDeviceId = `dev-${derivedActorId}-enrolled`;

      // Simulating immediate local enrollment with login
      await login(derivedActorId, derivedDeviceId);
      setSuccess(true);
      setTimeout(() => {
        navigate('/dashboard');
      }, 1200);
    } catch (err: any) {
      setError(err?.message || 'Identity enrollment failed. Please check backend status.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#070B18] text-[#F4F7FF] flex items-center justify-center p-6 relative overflow-hidden">
      {/* Background Lighting Orbs */}
      <div className="cyber-glow-orb w-[500px] h-[500px] bg-purple-600/15 top-[-100px] right-[-100px]" />
      <div className="cyber-glow-orb w-[450px] h-[450px] bg-cyan-500/12 bottom-[-80px] left-[-80px]" />

      <div className="max-w-4xl w-full grid grid-cols-1 lg:grid-cols-12 gap-8 z-10 items-center">
        {/* Left Side: Security Policy Guidance */}
        <div className="lg:col-span-5 space-y-6 hidden lg:block">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-400/30 text-cyan-300 text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            ZERO-TRUST ENROLLMENT
          </div>
          <h2 className="text-3xl font-extrabold leading-tight text-white">
            Register New <br />
            <span className="gradient-text-cyan">Principal Identity</span>
          </h2>
          <p className="text-sm text-slate-300 leading-relaxed">
            Every enrolled identity is provisioned with non-privileged standard permissions. Cryptographic certificates and device posture are bound at first handshake.
          </p>

          <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 text-xs text-slate-400">
            <div className="text-amber-400 font-bold flex items-center gap-1.5">
              <Shield className="w-4 h-4" />
              <span>SECURITY NOTICE:</span>
            </div>
            <p className="m-0 leading-relaxed">
              Public registration never grants administrative or operator privileges. Elevated roles require out-of-band credentialing by a designated Security Officer.
            </p>
          </div>
        </div>

        {/* Right Side: Signup Form */}
        <div className="lg:col-span-7 glass-panel-glow p-8 md:p-10 rounded-3xl space-y-6">
          <div className="flex items-center justify-between border-b border-slate-800 pb-5">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-950/60 border border-cyan-400/40 flex items-center justify-center text-cyan-400">
                <UserPlus className="w-5 h-5" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-white m-0">Create Identity</h1>
                <p className="text-xs text-slate-400 m-0">Enroll as a verified identity in the Q-SHIELD mesh</p>
              </div>
            </div>
            <Link to="/login" className="text-xs text-cyan-400 hover:underline font-semibold">
              Sign In Instead
            </Link>
          </div>

          {error && (
            <div className="p-3.5 rounded-xl bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="p-3.5 rounded-xl bg-emerald-950/40 border border-emerald-500/40 text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              <span>Identity provisioned successfully! Redirecting to command center...</span>
            </div>
          )}

          <form onSubmit={onSubmit} className="space-y-4">
            <div>
              <label className="block text-xs font-mono text-slate-400 uppercase mb-1.5">Full Name</label>
              <input
                className="cyber-input text-sm"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                required
                placeholder="e.g. Alex Vance"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 uppercase mb-1.5">Corporate Email</label>
              <input
                type="email"
                className="cyber-input text-sm"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="e.g. alex@qshield.security"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 uppercase mb-1.5">Passphrase</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="cyber-input text-sm pr-10 font-mono"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  placeholder="At least 8 characters"
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-cyan-400"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              {/* Password Strength Indicator */}
              {password && (
                <div className="mt-2 space-y-1">
                  <div className="flex justify-between items-center text-[11px] font-mono">
                    <span className="text-slate-400">Strength:</span>
                    <span className={getStrengthLabel(strength).text}>{getStrengthLabel(strength).label}</span>
                  </div>
                  <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden flex gap-1">
                    <div className={`h-full flex-1 rounded-full ${strength >= 1 ? getStrengthLabel(strength).color : 'bg-slate-800'}`} />
                    <div className={`h-full flex-1 rounded-full ${strength >= 2 ? getStrengthLabel(strength).color : 'bg-slate-800'}`} />
                    <div className={`h-full flex-1 rounded-full ${strength >= 3 ? getStrengthLabel(strength).color : 'bg-slate-800'}`} />
                    <div className={`h-full flex-1 rounded-full ${strength >= 4 ? getStrengthLabel(strength).color : 'bg-slate-800'}`} />
                  </div>
                </div>
              )}
            </div>

            <div>
              <label className="block text-xs font-mono text-slate-400 uppercase mb-1.5">Confirm Passphrase</label>
              <input
                type={showPassword ? 'text' : 'password'}
                className="cyber-input text-sm font-mono"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                placeholder="Re-type passphrase"
              />
            </div>

            <button
              type="submit"
              className="cyber-btn cyber-btn-primary w-full py-3 text-sm font-bold mt-2"
              disabled={loading}
            >
              <UserPlus className="w-4 h-4" />
              <span>{loading ? 'Enrolling Identity...' : 'Complete Enrollment'}</span>
            </button>
          </form>

          <div className="text-xs text-center text-slate-500 pt-2">
            Already enrolled?{' '}
            <Link to="/login" className="text-cyan-400 hover:underline">
              Access existing session
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};
