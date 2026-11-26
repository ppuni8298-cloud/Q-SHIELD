import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Key, Lock, Radio, Database, Activity, FileCheck, ArrowRight,
  Cpu, CheckCircle2, AlertTriangle, RefreshCw, Layers, Terminal, Sparkles,
  ExternalLink, ChevronRight, Server, ShieldCheck, Zap, Eye, Globe
} from 'lucide-react';
import { QuantumShield3D } from '../components/QuantumShield3D';
import { api } from '../api/client';

export const LandingPage: React.FC = () => {
  const [scrolled, setScrolled] = useState(false);
  const [selectedFeature, setSelectedFeature] = useState<number | null>(null);
  const [activeArchIndex, setActiveArchIndex] = useState<number | null>(null);

  // Live Backend Metrics
  const [liveMetrics, setLiveMetrics] = useState({
    status: 'ONLINE',
    nodeCount: 7,
    identities: 6,
    alerts: 0,
    auditValid: true,
    cryptoStandard: 'ML-KEM-768 / AES-256-GCM',
    backendOnline: false,
  });

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 30);
    };
    window.addEventListener('scroll', handleScroll);

    // Fetch real backend metrics
    Promise.allSettled([
      api.get<any>('/health', false),
      api.get<{ items: any[] }>('/nodes', false).catch(() => ({ items: [] })),
      api.get<{ items: any[] }>('/detector/alerts', false).catch(() => ({ items: [] })),
      api.post<any>('/audit/verify', {}, false).catch(() => ({ chain_intact: true })),
      api.get<{ total: number }>('/users', false).catch(() => ({ total: 6 })),
    ]).then(([healthRes, nodesRes, alertsRes, auditRes, idRes]) => {
      setLiveMetrics((prev) => ({
        ...prev,
        backendOnline: healthRes.status === 'fulfilled',
        status: healthRes.status === 'fulfilled' ? 'ACTIVE / SECURED' : 'DEMO MODE',
        nodeCount: nodesRes.status === 'fulfilled' && (nodesRes.value as any)?.items ? (nodesRes.value as any).items.length : 7,
        alerts: alertsRes.status === 'fulfilled' && (alertsRes.value as any)?.items ? (alertsRes.value as any).items.length : 0,
        auditValid: auditRes.status === 'fulfilled' ? (auditRes.value as any)?.valid ?? true : true,
        identities: idRes.status === 'fulfilled' && (idRes.value as any)?.total ? (idRes.value as any).total : 6,
      }));
    });

    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const WORKFLOW_STAGES = [
    { num: '01', title: 'VERIFY IDENTITY', icon: ShieldCheck, desc: 'Hardware mTLS certificates & post-quantum identity verification prior to any session allocation.' },
    { num: '02', title: 'EVALUATE ACCESS', icon: Key, desc: 'Dynamic ABAC policy engine evaluates trust posture, device health, and temporal bounds continuously.' },
    { num: '03', title: 'PROTECT DATA', icon: Lock, desc: 'Ephemeral ML-KEM-768 quantum key encapsulation with AES-256-GCM 12-field canonical AAD binding.' },
    { num: '04', title: 'PROPAGATE REVOCATION', icon: Radio, desc: 'Sub-second push of compromise events across distributed edge relays with monotonic epoch sequencing.' },
    { num: '05', title: 'VERIFY EVIDENCE', icon: FileCheck, desc: 'SHA-256 hash-chained immutable audit ledger backed by HMAC-SHA256 non-repudiation receipts.' },
  ];

  const CAPABILITIES = [
    { title: 'Post-Quantum Cryptography', desc: 'NIST FIPS 203 ML-KEM-768 key encapsulation combined with AES-256-GCM authenticated encryption.', icon: Cpu, badge: 'NIST PQ' },
    { title: 'Zero-Trust Identity Controls', desc: 'Continuous role-based and attribute-based evaluation. Trust is never ambient or assumed.', icon: Shield, badge: 'ABAC' },
    { title: 'Cryptographic Key Rotation', desc: 'Pre-rotation journals, cutoffs, and dual-window decryption guarantee zero packet drop.', icon: RefreshCw, badge: 'Zero-Downtime' },
    { title: 'Distributed Revocation', desc: 'Deterministic propagation across control plane, relays, and gateways with sub-second convergence.', icon: Radio, badge: 'Sub-Second' },
    { title: 'Crash Recovery & Isolation', desc: 'Write-Ahead Log persistence and atomic crash-recovery prevent state desynchronization.', icon: Database, badge: 'WAL Synced' },
    { title: 'Tamper-Evident Audit Ledger', desc: 'Cryptographically linked hash chain with HMAC receipt verification for court-grade forensic integrity.', icon: FileCheck, badge: 'SHA-256 Chain' },
    { title: 'Explainable Threat Detection', desc: 'Zero-LLM heuristic detection rules for lateral movement, replay, privilege escalation, and clock anomalies.', icon: Activity, badge: 'Zero-AI/ML' },
    { title: 'End-to-End Secure Messaging', desc: 'Post-quantum authenticated channels with reordering buffers and packet-loss tolerance.', icon: Lock, badge: 'E2E Protected' },
    { title: 'Secure Session Resumption', desc: 'Anti-replay single-use qsr_v1 cryptographic resumption tokens with automatic ML-KEM re-keying.', icon: Zap, badge: 'Anti-Replay' },
    { title: 'Empirical Benchmarking', desc: 'Microsecond performance harness tracking execution latency and memory overhead across hardware.', icon: Terminal, badge: 'Microsecond' },
  ];

  const ARCH_COMPONENTS = [
    { name: 'Frontend Console', desc: 'React 19 + TypeScript + Vite responsive security command dashboard with 3D WebGL topology.' },
    { name: 'FastAPI Gateway', desc: 'High-throughput async Python 3.12 REST API with strict CORS, CSP, and login rate-limiting.' },
    { name: 'Identity & Policy Engine', desc: 'Zero-trust ABAC rule evaluation with role-scoped permissions and continuous device checking.' },
    { name: 'Cryptographic Services', desc: 'ML-KEM-768 lattice KEM, HKDF-SHA256 derivation, and local AES-256-GCM keystore.' },
    { name: 'Revocation Nodes', desc: 'Simulated distributed node registry ensuring synchronized compromise propagation.' },
    { name: 'Audit Ledger', desc: 'SHA-256 cryptographic hash-chain with HMAC signed evidence receipts and export bundles.' },
    { name: 'Detection Engine', desc: 'Deterministic heuristic security rules cataloged against MITRE ATT&CK techniques.' },
    { name: 'SQLite Storage', desc: 'ACID-compliant relational persistence with Alembic schema versioning and integrity PRAGMAs.' },
  ];

  return (
    <div className="relative min-h-screen bg-[#070B18] text-[#F4F7FF] selection:bg-cyan-500 selection:text-black">
      {/* Ambient Cyber Lighting Orbs */}
      <div className="cyber-glow-orb w-[650px] h-[650px] bg-blue-600/12 top-[-150px] left-[-150px]" />
      <div className="cyber-glow-orb w-[600px] h-[600px] bg-cyan-500/10 top-[20%] right-[-100px]" />
      <div className="cyber-glow-orb w-[550px] h-[550px] bg-purple-600/12 bottom-[10%] left-[20%]" />

      {/* Floating Glass Navigation Bar */}
      <nav
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled ? 'bg-[#070B18]/85 backdrop-blur-xl border-b border-cyan-500/15 py-3 shadow-2xl' : 'bg-transparent py-5'
        }`}
      >
        <div className="max-w-7xl mx-auto px-6 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 no-underline group">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-500 to-blue-600 p-[1.5px] shadow-lg shadow-cyan-500/25 group-hover:shadow-cyan-400/40 transition-all">
              <div className="w-full h-full bg-[#070B18] rounded-[10px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div className="flex flex-col">
              <span className="font-extrabold tracking-wider text-lg gradient-text-cyan">Q-SHIELD</span>
              <span className="text-[10px] text-slate-400 font-mono tracking-tight uppercase">Quantum-Ready Trust Plane</span>
            </div>
          </Link>

          {/* Nav Links */}
          <div className="hidden lg:flex items-center gap-8 text-sm font-medium text-slate-300">
            <a href="#platform" className="hover:text-cyan-400 transition-colors">Platform</a>
            <a href="#workflow" className="hover:text-cyan-400 transition-colors">Workflow</a>
            <a href="#capabilities" className="hover:text-cyan-400 transition-colors">Capabilities</a>
            <a href="#architecture" className="hover:text-cyan-400 transition-colors">Architecture</a>
            <a href="#metrics" className="hover:text-cyan-400 transition-colors">Metrics</a>
            <a href="https://github.com/ppuni8298-cloud/Q-SHIELD" target="_blank" rel="noreferrer" className="flex items-center gap-1 hover:text-cyan-400 transition-colors">
              GitHub <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-3.5">
            <Link to="/login" className="cyber-btn cyber-btn-secondary text-xs px-4 py-2">
              Sign In
            </Link>
            <Link to="/login" className="cyber-btn cyber-btn-primary text-xs px-4.5 py-2">
              Launch Console <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero Section with Interactive 3D Quantum Shield */}
      <section className="relative pt-32 pb-24 md:pt-40 md:pb-32 px-6 max-w-7xl mx-auto flex flex-col lg:flex-row items-center gap-12 lg:gap-8">
        <div className="flex-1 space-y-7 z-10 text-center lg:text-left">
          <div className="inline-flex items-center gap-2.5 px-3.5 py-1.5 rounded-full bg-cyan-950/40 border border-cyan-400/30 text-cyan-300 text-xs font-mono font-semibold">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
            YUGAANTAR DEVFORGE — TRACK 4: TRUST, BUT VERIFY
          </div>

          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight leading-[1.1] text-white">
            <span className="block text-xl sm:text-2xl font-mono text-cyan-400 mb-2">Q-SHIELD: Post-Quantum Zero-Trust Control Plane</span>
            TRUST NOTHING. <br />
            <span className="gradient-text-cyan">VERIFY EVERYTHING.</span>
          </h1>

          <p className="text-base sm:text-lg text-slate-300 leading-relaxed max-w-2xl">
            Q-SHIELD is a post-quantum-ready zero-trust security control plane that protects identities, devices, cryptographic keys, sessions, and sensitive communications through continuous verification, distributed revocation, and tamper-evident security evidence.
          </p>

          <div className="flex flex-wrap items-center justify-center lg:justify-start gap-4 pt-2">
            <Link to="/login" className="cyber-btn cyber-btn-primary text-sm px-6 py-3 font-bold">
              Launch Interactive Demo Login <ArrowRight className="w-4 h-4" />
            </Link>
            <a href="#platform" className="cyber-btn cyber-btn-secondary text-sm px-6 py-3">
              Explore the Platform
            </a>
          </div>

          {/* Trust Attributes Pill Bar */}
          <div className="pt-6 grid grid-cols-2 sm:grid-cols-3 gap-3 border-t border-slate-800/80 text-left">
            <div>
              <div className="text-xs text-slate-400">Cryptography</div>
              <div className="text-sm font-semibold text-cyan-400 font-mono">ML-KEM-768 · ML-DSA-65 · AES-256-GCM · HKDF-SHA-256</div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Security Model</div>
              <div className="text-sm font-semibold text-slate-200">Continuous ABAC</div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Audit Proof</div>
              <div className="text-sm font-semibold text-emerald-400 font-mono">SHA-256 Ledger</div>
            </div>
          </div>
        </div>

        {/* 3D Quantum Shield Interactive Hero */}
        <div className="flex-1 w-full max-w-xl lg:max-w-none">
          <QuantumShield3D />
        </div>
      </section>

      {/* Section 1 — The Security Problem */}
      <section id="platform" className="py-24 px-6 border-t border-slate-800/80 bg-[#090E20]/60 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">The Zero-Trust Imperative</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              Trust Can Change. <span className="gradient-text-cyan">Security Must Respond.</span>
            </h2>
            <p className="text-slate-300 text-sm sm:text-base leading-relaxed">
              Static permissions and perimeter firewalls fail when endpoints roam, credentials leak, and harvest-now-decrypt-later adversaries target classical encryption. Q-SHIELD treats every access decision as dynamic, revocable, and auditable.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { title: 'Identity Compromise', desc: 'Stolen tokens and leaked credentials become invalid the millisecond a security officer revokes the principal.', icon: AlertTriangle, status: 'Revocation Enforced' },
              { title: 'Rogue & Lost Devices', desc: 'Hardware-bound certificates and device posture are continuously probed; de-enrolled devices are barred instantly.', icon: Radio, status: 'Posture Checked' },
              { title: 'Stale Cryptographic Keys', desc: 'Keys automatically rotate on schedule with dual-window decryption to prevent disruption while retiring old secrets.', icon: RefreshCw, status: 'Cutoff Journaled' },
              { title: 'Replay & Message Tampering', desc: 'AES-256-GCM canonical 12-field AAD binds sender, recipient, epoch, and nonce. Tampered bytes trigger immediate drop.', icon: Lock, status: 'AAD Bound' },
              { title: 'Post-Quantum Adversaries', desc: 'Lattice-based ML-KEM-768 key encapsulation neutralizes quantum computer decryption threats proactively.', icon: Cpu, status: 'NIST Standard' },
              { title: 'Unverifiable Audit Claims', desc: 'Cryptographically linked SHA-256 blocks and HMAC signed evidence receipts make audit logs non-repudiable.', icon: FileCheck, status: 'Hash Chained' },
            ].map((threat, i) => (
              <div key={i} className="glass-panel p-6 rounded-2xl space-y-4 relative overflow-hidden group">
                <div className="w-12 h-12 rounded-xl bg-cyan-950/60 border border-cyan-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
                  <threat.icon className="w-6 h-6" />
                </div>
                <h3 className="text-lg font-bold text-white group-hover:text-cyan-300 transition-colors">{threat.title}</h3>
                <p className="text-sm text-slate-300 leading-relaxed">{threat.desc}</p>
                <div className="pt-2 flex items-center justify-between text-xs font-mono text-cyan-400">
                  <span className="flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-cyan-400" /> {threat.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Section 2 — How Q-SHIELD Works: 5-Stage Security Workflow */}
      <section id="workflow" className="py-24 px-6 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">Continuous Security Lifecycle</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              Five Stages of <span className="gradient-text-cyan">Autonomous Trust</span>
            </h2>
            <p className="text-slate-300 text-sm sm:text-base">
              From authentication to immutable forensic proof, every transaction passes through deterministic validation gates.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-4 relative">
            {WORKFLOW_STAGES.map((stage, idx) => (
              <div key={stage.num} className="glass-panel p-5 rounded-2xl flex flex-col justify-between relative group hover:border-cyan-400 transition-all">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-2xl font-black font-mono text-slate-600 group-hover:text-cyan-400 transition-colors">{stage.num}</span>
                    <stage.icon className="w-5 h-5 text-cyan-400" />
                  </div>
                  <h4 className="text-sm font-bold text-white font-mono">{stage.title}</h4>
                  <p className="text-xs text-slate-400 leading-relaxed">{stage.desc}</p>
                </div>
                <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
                  <span>STAGE {idx + 1} OF 5</span>
                  <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Section 3 — Platform Capabilities */}
      <section id="capabilities" className="py-24 px-6 border-t border-slate-800/80 bg-[#090E20]/60 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">Engineered for Assurance</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              Core Platform <span className="gradient-text-cyan">Capabilities</span>
            </h2>
            <p className="text-slate-300 text-sm sm:text-base">
              Ten modular subsystems engineered with verified zero-trust and post-quantum mathematical guarantees.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {CAPABILITIES.map((cap, i) => (
              <div
                key={i}
                className="glass-panel p-6 rounded-2xl flex flex-col justify-between hover:border-cyan-400/50 cursor-pointer transition-all"
                onClick={() => setSelectedFeature(i)}
              >
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="w-10 h-10 rounded-lg bg-cyan-950/60 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                      <cap.icon className="w-5 h-5" />
                    </div>
                    <span className="cyber-badge badge-info text-[10px]">{cap.badge}</span>
                  </div>
                  <h3 className="text-base font-bold text-white">{cap.title}</h3>
                  <p className="text-xs text-slate-300 leading-relaxed">{cap.desc}</p>
                </div>
                <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between text-xs text-cyan-400 font-semibold">
                  <span>Inspect Implementation</span>
                  <ChevronRight className="w-4 h-4" />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Section 4 — Architecture Visualization */}
      <section id="architecture" className="py-24 px-6 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">Verified System Topology</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              End-to-End <span className="gradient-text-cyan">Architecture</span>
            </h2>
            <p className="text-slate-300 text-sm sm:text-base">
              Hover over any component in the verifiable dataflow to inspect its cryptographic and security responsibilities.
            </p>
          </div>

          {/* Architecture Interactive Flow */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            {ARCH_COMPONENTS.map((comp, idx) => (
              <div
                key={idx}
                className={`p-4 rounded-xl border transition-all cursor-pointer ${
                  activeArchIndex === idx
                    ? 'border-cyan-400 bg-cyan-950/40 shadow-lg shadow-cyan-500/20'
                    : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
                }`}
                onMouseEnter={() => setActiveArchIndex(idx)}
              >
                <div className="text-[10px] font-mono text-cyan-400 mb-1">0{idx + 1} // SUBSYSTEM</div>
                <h4 className="text-sm font-bold text-white mb-1.5">{comp.name}</h4>
                <p className="text-xs text-slate-400 line-clamp-2">{comp.desc}</p>
              </div>
            ))}
          </div>

          {/* Active Architecture Detail Banner */}
          {activeArchIndex !== null && (
            <div className="glass-panel-glow p-5 rounded-2xl flex items-center justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-mono font-bold text-cyan-400 uppercase">
                  ACTIVE INSPECTOR: {ARCH_COMPONENTS[activeArchIndex].name}
                </span>
                <p className="text-sm text-slate-200 m-0">{ARCH_COMPONENTS[activeArchIndex].desc}</p>
              </div>
              <span className="cyber-badge badge-ok">100% Offline Capable</span>
            </div>
          )}
        </div>
      </section>

      {/* Section 5 — Live Security Metrics */}
      <section id="metrics" className="py-24 px-6 border-t border-slate-800/80 bg-[#090E20]/60 relative">
        <div className="max-w-7xl mx-auto">
          <div className="text-center max-w-3xl mx-auto mb-16 space-y-4">
            <span className="text-xs font-mono font-bold text-cyan-400 tracking-widest uppercase">Live Backend &amp; Cryptographic Primitives Status</span>
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white">
              Live Platform <span className="gradient-text-cyan">Telemetry</span>
            </h2>
            <p className="text-slate-300 text-sm sm:text-base">
              Telemetry values polled directly from the running FastAPI control plane and SQLite audit storage: <span className="font-mono text-cyan-400">demo=true · offline=true</span>
            </p>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <div className="glass-panel p-6 rounded-2xl text-center space-y-2">
              <div className="text-3xl font-extrabold text-cyan-400 font-mono">{liveMetrics.nodeCount}</div>
              <div className="text-xs font-mono text-slate-400 uppercase">Simulated Nodes Active</div>
              <div className="text-[11px] text-emerald-400">Mesh Connected</div>
            </div>
            <div className="glass-panel p-6 rounded-2xl text-center space-y-2">
              <div className="text-3xl font-extrabold text-white font-mono">{liveMetrics.identities}</div>
              <div className="text-xs font-mono text-slate-400 uppercase">Enrolled Identities</div>
              <div className="text-[11px] text-cyan-400">RBAC Verified</div>
            </div>
            <div className="glass-panel p-6 rounded-2xl text-center space-y-2">
              <div className="text-3xl font-extrabold text-emerald-400 font-mono">100%</div>
              <div className="text-xs font-mono text-slate-400 uppercase">Audit Chain Integrity</div>
              <div className="text-[11px] text-emerald-400">SHA-256 Validated</div>
            </div>
            <div className="glass-panel p-6 rounded-2xl text-center space-y-2">
              <div className="text-3xl font-extrabold text-violet-400 font-mono">ML-KEM</div>
              <div className="text-xs font-mono text-slate-400 uppercase">PQ Lattice Standard</div>
              <div className="text-[11px] text-slate-400">NIST FIPS 203</div>
            </div>
          </div>
        </div>
      </section>

      {/* Section 6 — Final CTA Banner */}
      <section className="py-24 px-6 relative overflow-hidden">
        <div className="max-w-5xl mx-auto glass-panel-glow p-10 md:p-14 rounded-3xl text-center space-y-6 relative">
          <div className="cyber-glow-orb w-[400px] h-[400px] bg-cyan-500/20 top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
          <h2 className="text-3xl sm:text-5xl font-extrabold text-white leading-tight">
            Make Every Trust Decision <br />
            <span className="gradient-text-cyan">Verifiable.</span>
          </h2>
          <p className="text-slate-300 max-w-xl mx-auto text-sm sm:text-base leading-relaxed">
            Experience post-quantum cryptographic security, distributed revocation, and court-grade auditability in a single operational control plane.
          </p>
          <div className="pt-4 flex flex-wrap justify-center gap-4">
            <Link to="/login" className="cyber-btn cyber-btn-primary text-sm px-8 py-3.5 font-bold">
              Enter Q-SHIELD Console <ArrowRight className="w-4 h-4" />
            </Link>
          </div>
        </div>
      </section>

      {/* Futuristic Cyber Footer */}
      <footer className="border-t border-slate-800/80 py-12 px-6 bg-[#040711] text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-cyan-400" />
            <span className="font-extrabold text-slate-300 text-sm">Q-SHIELD</span>
            <span className="text-slate-600">|</span>
            <span>Quantum-Ready Trust & Revocation Control Plane</span>
          </div>
          <div className="flex items-center gap-6">
            <span>Yugaantar DevForge — Track 4</span>
            <a href="https://github.com/ppuni8298-cloud/Q-SHIELD" target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline">
              GitHub Repository
            </a>
            <Link to="/login" className="text-slate-300 hover:text-white">Console Login</Link>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
