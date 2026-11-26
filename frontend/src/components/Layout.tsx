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
  ChevronLeft,
  ChevronRight,
  Shield
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
  const [collapsed, setCollapsed] = useState(false);

  const visibleItems = CONSOLE_NAV_ITEMS.filter((item) => !item.requiredPerm || hasPermission(item.requiredPerm));

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="app-shell">
      {/* Sidebar Navigation */}
      <aside className={`sidebar ${drawerOpen ? 'open' : ''} ${collapsed ? 'collapsed' : ''}`} aria-label="Primary Navigation">
        <div className="flex items-center justify-between pb-2 border-b border-slate-800">
          <NavLink to="/" className="flex items-center gap-2.5 text-white no-underline group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-500 to-blue-600 flex items-center justify-center shadow-md shadow-cyan-500/20">
              <Shield className="w-4 h-4 text-black font-extrabold" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-extrabold text-sm tracking-wider gradient-text-cyan">Q-SHIELD</span>
                <span className="text-[10px] text-slate-400 font-mono tracking-tight">TRUST CONTROL PLANE</span>
              </div>
            )}
          </NavLink>
          <div className="flex items-center gap-1">
            <button
              type="button"
              className="text-slate-400 hover:text-white p-1 rounded-md hidden lg:block"
              onClick={() => setCollapsed(!collapsed)}
              title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            >
              {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
            </button>
            <button
              type="button"
              className="mobile-menu-btn text-slate-400 hover:text-white p-1"
              aria-label="Close navigation menu"
              onClick={() => setDrawerOpen(false)}
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="sidebar-nav">
          {visibleItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `nav-link ${isActive ? 'active' : ''} ${collapsed ? 'justify-center px-0' : ''}`
                }
                onClick={() => setDrawerOpen(false)}
                title={collapsed ? item.label : undefined}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                {!collapsed && <span>{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>

        {/* Bottom System Status Badge */}
        {!collapsed && (
          <div className="pt-2.5 pb-1 border-t border-slate-800/80 text-[11px] font-mono text-slate-400 space-y-1 flex-shrink-0">
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
              <Activity className="w-3.5 h-3.5" />
              <span>Offline Ready · Zero AI/ML</span>
            </div>
            <div className="text-[10px] text-slate-500 truncate">
              NIST FIPS 203 ML-KEM-768
            </div>
          </div>
        )}
      </aside>

      {/* Main Command Center Stage */}
      <div className="main-area">
        {/* Topbar Header */}
        <header className="topbar">
          <div className="flex items-center gap-2.5">
            <button
              type="button"
              className="mobile-menu-btn cyber-btn cyber-btn-secondary p-2"
              aria-label="Open navigation menu"
              onClick={() => setDrawerOpen(true)}
            >
              <Menu className="w-4 h-4" />
            </button>
            <span className="cyber-badge badge-info text-[10px]">SYNTHETIC DEMO MODE</span>
            <span className="cyber-badge badge-warn text-[10px] hidden sm:inline-flex">
              PARTIAL FS (Control-Plane Mediated)
            </span>
          </div>

          {user && (
            <div className="flex items-center gap-3">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-bold text-white flex items-center justify-end gap-1.5">
                  <span>{user.display_name}</span>
                  <span className="cyber-badge badge-ok text-[10px]">{user.role}</span>
                </div>
                <div className="text-[10px] font-mono text-slate-400">
                  {user.actor_id} · {user.session?.device_id}
                </div>
              </div>
              <button
                type="button"
                className="cyber-btn cyber-btn-secondary text-xs px-3 py-1.5"
                onClick={() => void handleLogout()}
              >
                <LogOut className="w-3.5 h-3.5 text-rose-400" />
                <span className="hidden sm:inline">Sign out</span>
              </button>
            </div>
          )}
        </header>

        {/* Dynamic Page Content */}
        <main className="page-content">
          {children || <Outlet />}
        </main>
      </div>
    </div>
  );
}
