// HTTP client and session handling.
//
// The access token lives only in this module's memory: never in localStorage
// or a readable cookie, so an XSS payload cannot simply copy it out of
// storage. The long-lived refresh token sits in an httpOnly cookie the page
// cannot read at all.

let accessToken = null;
let refreshTimer = null;
let refreshInFlight = null;
const tokenListeners = new Set();
let sessionLostHandler = () => {};

export class ApiError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export const getAccessToken = () => accessToken;

/** Called when an active session can no longer be refreshed (revoked or expired). */
export function onSessionLost(handler) {
  sessionLostHandler = handler;
}

/** Called with the new token after every login/refresh, or null on logout. */
export function onTokenChange(listener) {
  tokenListeners.add(listener);
  return () => tokenListeners.delete(listener);
}

function decodeExpiry(token) {
  try {
    const payload = JSON.parse(atob(token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp * 1000 : null;
  } catch {
    return null;
  }
}

export function setAccessToken(token) {
  accessToken = token;
  clearTimeout(refreshTimer);
  if (token) {
    // Refresh one minute before expiry so requests never see an expired token.
    const expiresAt = decodeExpiry(token);
    if (expiresAt) {
      const delay = Math.max(5_000, expiresAt - Date.now() - 60_000);
      refreshTimer = setTimeout(() => refreshSession().catch(() => {}), delay);
    }
  }
  tokenListeners.forEach((listener) => listener(token));
}

function readCookie(name) {
  const match = document.cookie.split('; ').find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : '';
}

/** True if this browser holds a session cookie worth trying to refresh. */
export const hasSessionCookie = () => readCookie('lnc_csrf') !== '';

async function parseResponse(res) {
  if (res.status === 204) return null;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new ApiError(res.status, body.error?.code ?? 'error', body.error?.message ?? 'Request failed');
  }
  return body;
}

async function doRefresh() {
  const hadSession = accessToken !== null;
  const res = await fetch('/api/auth/refresh', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'X-CSRF-Token': readCookie('lnc_csrf') },
  });
  try {
    const body = await parseResponse(res);
    setAccessToken(body.accessToken);
    return body;
  } catch (err) {
    setAccessToken(null);
    if (hadSession) sessionLostHandler();
    throw err;
  }
}

/**
 * Exchange the refresh cookie for a new access token. Refresh tokens are
 * single-use (a reused one revokes the session), so refreshes must never
 * overlap: one in-flight request per tab, and a Web Lock across tabs so a
 * second tab waits and then sends the already-rotated cookie.
 */
export function refreshSession() {
  if (!refreshInFlight) {
    const run = navigator.locks
      ? navigator.locks.request('locknchat-refresh', doRefresh)
      : doRefresh();
    refreshInFlight = run.finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

/**
 * JSON request helper. Authenticated calls retry once after refreshing if the
 * access token turned out to be expired.
 */
export async function api(path, { method = 'GET', body, auth = true, csrf = false, retry = true } = {}) {
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
  if (csrf) headers['X-CSRF-Token'] = readCookie('lnc_csrf');

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (res.status === 401 && auth && retry) {
    const { error } = await res.clone().json().catch(() => ({}));
    if (error?.code === 'token_expired' || error?.code === 'invalid_token') {
      await refreshSession();
      return api(path, { method, body, auth, csrf, retry: false });
    }
  }
  return parseResponse(res);
}

export async function logoutRequest() {
  try {
    await api('/api/auth/logout', { method: 'POST', auth: false, csrf: true });
  } finally {
    setAccessToken(null);
  }
}
