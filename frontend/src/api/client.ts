/**
 * Typed HTTP API client for Q-SHIELD FastAPI Control Plane (/api/v1).
 * Never caches secrets in localStorage; uses in-session bearer tokens cleanly.
 */

export class ApiError extends Error {
  status: number;
  code: string;
  correlationId?: string;

  constructor(status: number, code: string, message: string, correlationId?: string) {
    super(message);
    this.status = status;
    this.code = code;
    this.correlationId = correlationId;
  }
}

const TOKEN_STORAGE_KEY = 'qshield_session_token_v1';

export function getStoredToken(): string | null {
  try {
    return window.sessionStorage.getItem(TOKEN_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function setStoredToken(token: string | null): void {
  try {
    if (token) {
      window.sessionStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
      window.sessionStorage.removeItem(TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage unavailability cleanly
  }
}

export function extractErrorMessage(err: unknown): { code: string; message: string; correlationId?: string } {
  if (err instanceof ApiError) {
    return { code: err.code, message: err.message, correlationId: err.correlationId };
  }
  if (err instanceof Error) {
    return { code: 'CLIENT_ERROR', message: err.message };
  }
  return { code: 'UNKNOWN_ERROR', message: 'Request failed unexpectedly.' };
}

async function requestJson<T>(path: string, init: RequestInit = {}, auth = true): Promise<T> {
  const headers = new Headers(init.headers || {});
  if (!headers.has('Content-Type') && init.body) {
    headers.set('Content-Type', 'application/json');
  }
  if (auth) {
    const token = getStoredToken();
    if (token) {
      headers.set('Authorization', `Bearer ${token}`);
    }
  }

  let res: Response;
  try {
    res = await fetch(path.startsWith('/api') ? path : `/api/v1${path}`, {
      ...init,
      headers,
    });
  } catch {
    throw new ApiError(0, 'BACKEND_UNREACHABLE', 'Cannot reach Q-SHIELD backend API (/api/v1). Confirm FastAPI is running on port 8000.');
  }

  let body: any = null;
  const text = await res.text();
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = null;
    }
  }

  if (!res.ok) {
    const errObj = body?.error || body?.detail || {};
    const code = typeof errObj.code === 'string' ? errObj.code : `HTTP_${res.status}`;
    const message =
      typeof errObj.message === 'string'
        ? errObj.message
        : typeof body?.detail === 'string'
        ? body.detail
        : `HTTP ${res.status} error`;
    const corr = typeof errObj.correlation_id === 'string' ? errObj.correlation_id : undefined;
    throw new ApiError(res.status, code, message, corr);
  }

  return body as T;
}

export const api = {
  get: <T>(path: string, auth = true) => requestJson<T>(path, { method: 'GET' }, auth),
  post: <T>(path: string, data?: unknown, auth = true) =>
    requestJson<T>(path, { method: 'POST', body: data !== undefined ? JSON.stringify(data) : undefined }, auth),
  patch: <T>(path: string, data: unknown, auth = true) =>
    requestJson<T>(path, { method: 'PATCH', body: JSON.stringify(data) }, auth),
};
