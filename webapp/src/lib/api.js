// Client for the MerkleTrust REST API (/api/v1, proxied to the FastAPI backend by Vite).
// The session token is kept in sessionStorage (this tab only) and sent solely in the
// Authorization header — never as a cookie.

const BASE = (import.meta.env.VITE_API_BASE || '') + '/api/v1';
const KEY = 'merkletrust.session';

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const session = {
  get() {
    try { return JSON.parse(sessionStorage.getItem(KEY)); } catch { return null; }
  },
  set(value) {
    try { sessionStorage.setItem(KEY, JSON.stringify(value)); } catch { /* storage unavailable */ }
  },
  clear() {
    try { sessionStorage.removeItem(KEY); } catch { /* storage unavailable */ }
  },
};

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

function authHeaders(extra = {}) {
  const token = session.get()?.token;
  return token ? { Authorization: `Bearer ${token}`, ...extra } : extra;
}

function toError(status, body) {
  const err = body?.error || {};
  return new ApiError(status, err.code || 'error', err.message || `Request failed (${status})`);
}

async function request(method, path, { params, json } = {}) {
  const qs = params
    ? `?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''))}`
    : '';
  let res;
  try {
    res = await fetch(`${BASE}${path}${qs}`, {
      method,
      headers: authHeaders(json === undefined ? {} : { 'Content-Type': 'application/json' }),
      body: json === undefined ? undefined : JSON.stringify(json),
    });
  } catch {
    throw new ApiError(0, 'network', 'Cannot reach the MerkleTrust server. Is the backend running on port 8000?');
  }
  if (res.status === 204) return null;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    // Only an expired or revoked session bounces to sign-in — not a failed sign-in attempt.
    if (res.status === 401 && session.get()?.token) onUnauthorized();
    throw toError(res.status, body);
  }
  return body;
}

export const api = {
  get: (path, params) => request('GET', path, { params }),
  post: (path, json) => request('POST', path, { json }),

  // Multipart upload with progress events (fetch has no upload progress).
  upload(path, file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open('POST', `${BASE}${path}`);
      const token = session.get()?.token;
      if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) onProgress?.(e.loaded / e.total);
      });
      xhr.addEventListener('load', () => {
        let body = null;
        try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
        if (xhr.status >= 200 && xhr.status < 300) return resolve(body);
        if (xhr.status === 401 && session.get()?.token) onUnauthorized();
        reject(toError(xhr.status, body));
      });
      xhr.addEventListener('error', () =>
        reject(new ApiError(0, 'network', 'Upload failed: cannot reach the MerkleTrust server.')));
      const form = new FormData();
      form.append('file', file);
      xhr.send(form);
    });
  },
};
