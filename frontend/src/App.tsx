import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { Layout } from './components/Layout';

import LandingPage from './pages/LandingPage';
import { LoginPage } from './pages/LoginPage';
import { DashboardPage } from './pages/DashboardPage';
import { IdentitiesPage } from './pages/IdentitiesPage';
import { DevicesPage } from './pages/DevicesPage';
import { VaultPage } from './pages/VaultPage';
import { NodesPage } from './pages/NodesPage';
import { KeysPage } from './pages/KeysPage';
import { AuditPage } from './pages/AuditPage';
import { DetectionPage } from './pages/DetectionPage';
import { MessagingPage } from './pages/MessagingPage';
import ScenariosPage from './pages/ScenariosPage';
import BenchmarksPage from './pages/BenchmarksPage';
import SettingsPage from './pages/SettingsPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-900 text-slate-100">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="text-xs text-slate-400 font-mono">Authenticating secure session...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}


export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          {/* Public routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />

          {/* Protected Console layout */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Layout>
                  <DashboardPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/identities"
            element={
              <ProtectedRoute>
                <Layout>
                  <IdentitiesPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/devices"
            element={
              <ProtectedRoute>
                <Layout>
                  <DevicesPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/vault"
            element={
              <ProtectedRoute>
                <Layout>
                  <VaultPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/nodes"
            element={
              <ProtectedRoute>
                <Layout>
                  <NodesPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/keys"
            element={
              <ProtectedRoute>
                <Layout>
                  <KeysPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/audit"
            element={
              <ProtectedRoute>
                <Layout>
                  <AuditPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/detection"
            element={
              <ProtectedRoute>
                <Layout>
                  <DetectionPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/messaging"
            element={
              <ProtectedRoute>
                <Layout>
                  <MessagingPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/scenarios"
            element={
              <ProtectedRoute>
                <Layout>
                  <ScenariosPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/benchmarks"
            element={
              <ProtectedRoute>
                <Layout>
                  <BenchmarksPage />
                </Layout>
              </ProtectedRoute>
            }
          />
          <Route
            path="/settings"
            element={
              <ProtectedRoute>
                <Layout>
                  <SettingsPage />
                </Layout>
              </ProtectedRoute>
            }
          />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
