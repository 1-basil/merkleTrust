// api.js — small client for the MerkleTrust REST API (/api/v1).
// The session token lives in sessionStorage: it is scoped to this tab and sent
// only in the Authorization header (never as a cookie).

const BASE = '/api/v1';
const KEY = 'merkletrust.session';

export class ApiError extends Error {
  constructor(status, code, message, requestId) {
    super(message);
    this.status = status;
    this.code = code;
    this.requestId = requestId;
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

async function parse(res) {
  if (res.status === 204) return null;
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = body?.error || {};
    // Only an expired/revoked session should bounce to the login page — not a failed sign-in.
    if (res.status === 401 && session.get()?.token) onUnauthorized();
    throw new ApiError(res.status, err.code || 'error', err.message || `Request failed (${res.status})`,
      err.request_id || res.headers.get('X-Request-ID'));
  }
  return body;
}

function headers(extra = {}) {
  const s = session.get();
  return s?.token ? { Authorization: `Bearer ${s.token}`, ...extra } : extra;
}

export async function get(path, params) {
  const qs = params ? `?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== ''))}` : '';
  return parse(await fetch(`${BASE}${path}${qs}`, { headers: headers() }));
}

export async function post(path, body) {
  return parse(await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: headers(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    body: body === undefined ? undefined : JSON.stringify(body),
  }));
}

// Multipart upload with progress (fetch has no upload progress events).
export function upload(path, file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE}${path}`);
    const s = session.get();
    if (s?.token) xhr.setRequestHeader('Authorization', `Bearer ${s.token}`);
    xhr.upload.addEventListener('progress', (e) => { if (e.lengthComputable) onProgress?.(e.loaded / e.total); });
    xhr.addEventListener('load', () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(body);
      if (xhr.status === 401 && session.get()?.token) onUnauthorized();
      const err = body?.error || {};
      reject(new ApiError(xhr.status, err.code || 'error', err.message || `Upload failed (${xhr.status})`, err.request_id));
    });
    xhr.addEventListener('error', () => reject(new ApiError(0, 'network', 'Network error — is the server running?')));
    const form = new FormData();
    form.append('file', file);
    xhr.send(form);
  });
}

export async function login(username, password) {
  const data = await post('/auth/login', { username, password });
  session.set({ token: data.access_token, user: data.user, expires: data.expires_at });
  return data.user;
}

export async function logout() {
  try { await post('/auth/logout'); } catch { /* already invalid */ }
  session.clear();
}
