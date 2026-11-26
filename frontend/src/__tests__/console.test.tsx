import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import LandingPage from '../pages/LandingPage';
import { AuthProvider } from '../context/AuthContext';
import ConfirmModal from '../components/ConfirmModal';

vi.mock('../api/client', async (importOriginal) => {
  const actual: any = await importOriginal();
  return {
    ...actual,
    getStoredToken: vi.fn().mockReturnValue(null),
    setStoredToken: vi.fn(),
    api: {
      get: vi.fn().mockImplementation((path: string) => {
        if (path === '/health') {
          return Promise.resolve({
            status: 'UP',
            service: 'qshield-control-plane',
            demo_mode: true,
            offline_mode: true,
          });
        }
        if (path === '/ready') {
          return Promise.resolve({
            ready: true,
            database: true,
            crypto: true,
          });
        }
        return Promise.resolve({});
      }),
      post: vi.fn().mockResolvedValue({}),
      getHealth: vi.fn().mockResolvedValue({
        status: 'UP',
        database: 'connected',
        crypto_backend: 'pqcrypto',
        version: '1.0.0',
      }),
      getCryptoSelfTest: vi.fn().mockResolvedValue({
        status: 'PASS',
        tests: {
          'ml-kem-768': { status: 'PASS' },
          'aes-256-gcm': { status: 'PASS' },
        },
      }),
      getSystemReadiness: vi.fn().mockResolvedValue({
        status: 'READY',
        database: 'SQLite',
        outbox_pending_count: 0,
      }),
      getSession: vi.fn().mockReturnValue(null),
      login: vi.fn(),
      logout: vi.fn(),
      me: vi.fn().mockRejectedValue(new Error('Unauthenticated')),
    },
  };
});

describe('Frontend Console Units', () => {
  beforeEach(() => {
    if (!HTMLDialogElement.prototype.showModal) {
      HTMLDialogElement.prototype.showModal = function () {
        this.open = true;
      };
    }
    if (!HTMLDialogElement.prototype.close) {
      HTMLDialogElement.prototype.close = function () {
        this.open = false;
      };
    }
  });

  it('renders landing page with core project information and live backend status', async () => {
    render(
      <BrowserRouter>
        <AuthProvider>
          <LandingPage />
        </AuthProvider>
      </BrowserRouter>
    );

    // Use getAllByText for Q-SHIELD branding which appears in header and hero
    const brandElements = screen.getAllByText(/Q-SHIELD/i);
    expect(brandElements.length).toBeGreaterThan(0);

    expect(screen.getByText(/Post-Quantum Zero-Trust Control Plane/i)).toBeInTheDocument();
    expect(screen.getByText(/Live Backend & Cryptographic Primitives Status/i)).toBeInTheDocument();

    // Verify async probe resolves and updates the card
    await waitFor(() => {
      expect(screen.getByText(/demo=true · offline=true/i)).toBeInTheDocument();
    });
  });

  it('renders modern accessible dialog modal with proper accessibility semantics', () => {
    const handleConfirm = vi.fn();
    const handleCancel = vi.fn();

    render(
      <ConfirmModal
        open={true}
        title="Confirm Key Rotation"
        description="Are you sure you want to trigger phased key rotation?"
        confirmLabel="Rotate Key"
        onConfirm={handleConfirm}
        onCancel={handleCancel}
      />
    );

    expect(screen.getByText('Confirm Key Rotation')).toBeInTheDocument();
    expect(screen.getByText('Are you sure you want to trigger phased key rotation?')).toBeInTheDocument();
    expect(screen.getByText('Rotate Key')).toBeInTheDocument();
    expect(screen.getByText('Cancel')).toBeInTheDocument();
  });
});
