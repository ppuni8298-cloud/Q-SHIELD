import React, { useState } from 'react';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import {
  Activity,
  BookOpen,
  Cpu,
  FileCheck2,
  Gauge,
  KeyRound,
  Laptop,
  LayoutDashboard,
  Lock,
  LogOut,
  Menu,
  MessageSquareLock,
  PlayCircle,
  Radio,
  ShieldAlert,
  Users,
  X,
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';

export interface NavItem {
  to: string;
  label: string;
  icon: any;
  requiredPerm?: string;
}

export const CONSOLE_NAV_ITEMS: NavItem[] = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard },
  { to: '/identities', label: 'Identities & RBAC', icon: Users, requiredPerm: 'identity:read' },
  { to: '/devices', label: 'Devices', icon: Laptop, requiredPerm: 'device:read' },
  { to: '/vault', label: 'Vault & Policy', icon: Lock },
  { to: '/nodes', label: 'Nodes & Revocation', icon: Radio, requiredPerm: 'node:read' },
  { to: '/keys', label: 'Keys & Backups', icon: KeyRound, requiredPerm: 'key:read' },
  { to: '/audit', label: 'Audit & Evidence', icon: FileCheck2, requiredPerm: 'audit:read' },
  { to: '/detection', label: 'Threat Detector', icon: ShieldAlert, requiredPerm: 'detector:read' },
  { to: '/messaging', label: 'Secure Messaging', icon: MessageSquareLock },
  { to: '/scenarios', label: '14-Scenario Lab', icon: PlayCircle, requiredPerm: 'audit:read' },
  { to: '/benchmarks', label: 'Benchmarks', icon: Gauge, requiredPerm: 'bench:read' },
  { to: '/settings', label: 'System & Docs', icon: BookOpen },
];

export function Layout({ children }: { children?: React.ReactNode }) {
  const { user, logout, hasPermission } = useAuth();
  const navigate = useNavigate();
  const [drawerOpen, setDrawerOpen] = useState(false);

  const visibleItems = CONSOLE_NAV_ITEMS.filter((item) => !item.requiredPerm || hasPermission(item.requiredPerm));

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      <aside className={`sidebar ${drawerOpen ? 'open' : ''}`} aria-label="Primary Navigation">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 6px' }}>
          <NavLink to="/" style={{ display: 'flex', alignItems: 'center', gap: 10, color: 'var(--text-primary)', textDecoration: 'none' }}>
            <Cpu size={22} color="var(--accent-cyan)" />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.96rem', letterSpacing: '0.03em' }}>Q-SHIELD</div>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)' }}>Trust &amp; Revocation Plane</div>
            </div>
          </NavLink>
          <button
            type="button"
            className="btn mobile-menu-btn"
            aria-label="Close navigation menu"
            onClick={() => setDrawerOpen(false)}
            style={{ padding: 6 }}
          >
            <X size={16} />
          </button>
        </div>

        <nav className="sidebar-nav">
          {visibleItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                onClick={() => setDrawerOpen(false)}
              >
                <Icon size={16} />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </nav>

        <div style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: 12, fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
            <Activity size={13} color="var(--accent-emerald)" />
            <span>Offline Mode · Zero AI/ML</span>
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            Track 4 · ML-KEM-768 + ML-DSA-65 + AES-256-GCM
          </div>
        </div>
      </aside>

      <div className="main-area">
        <header className="topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              type="button"
              className="btn mobile-menu-btn"
              aria-label="Open navigation menu"
              onClick={() => setDrawerOpen(true)}
            >
              <Menu size={16} />
            </button>
            <span className="badge badge-info">SYNTHETIC DEMO MODE</span>
            <span className="badge badge-warn">PARTIAL FS (Control-Plane Mediated)</span>
          </div>

          {user && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ textAlign: 'right', fontSize: '0.8rem' }}>
                <div style={{ fontWeight: 600 }}>
                  {user.display_name} <span className="badge badge-neutral">{user.role}</span>
                </div>
                <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>
                  {user.actor_id} · {user.session.device_id}
                </div>
              </div>
              <button type="button" className="btn" onClick={() => void handleLogout()}>
                <LogOut size={15} />
                <span>Sign out</span>
              </button>
            </div>
          )}
        </header>

        <main className="page-content">
          {children || <Outlet />}
        </main>
      </div>
    </div>
  );
}
