import * as e2ee from './crypto.js';
import * as keystore from './keystore.js';
import {
  api,
  ApiError,
  refreshSession,
  setAccessToken,
  getAccessToken,
  onTokenChange,
  logoutRequest,
  hasSessionCookie,
  onSessionLost,
} from './api.js';

// ------------------------------------------------------------------ elements

const $ = (id) => document.getElementById(id);
const els = {
  navUser: $('nav-user'),
  navUsername: $('nav-username'),
  connection: $('connection'),
  logoutBtn: $('logout-btn'),
  authView: $('auth-view'),
  authForm: $('auth-form'),
  username: $('username'),
  password: $('password'),
  passwordRules: $('password-rules'),
  authStatus: $('auth-status'),
  chatView: $('chat-view'),
  search: $('search'),
  searchResults: $('search-results'),
  conversationList: $('conversation-list'),
  emptyState: $('empty-state'),
  conversationPane: $('conversation-pane'),
  backBtn: $('back-btn'),
  peerName: $('peer-name'),
  keyWarning: $('key-warning'),
  trustKeyBtn: $('trust-key-btn'),
  messages: $('messages'),
  composer: $('composer'),
  messageInput: $('message-input'),
  safety: $('safety'),
  safetyNumber: $('safety-number'),
  lastCiphertext: $('last-ciphertext'),
  toast: $('toast'),
};

// --------------------------------------------------------------------- state

const state = {
  me: null,
  privateKey: null,
  socket: null,
  conversations: new Map(),
  conversationKeys: new Map(),
  unread: new Set(),
  activeId: null,
  keyChanged: false,
};

function resetState() {
  Object.assign(state, {
    me: null,
    privateKey: null,
    socket: null,
    conversations: new Map(),
    conversationKeys: new Map(),
    unread: new Set(),
    activeId: null,
    keyChanged: false,
  });
}

// ------------------------------------------------------------------- helpers

/** Create an element. Text is always set via textContent, never as HTML. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

let toastTimer;
function showToast(message) {
  els.toast.textContent = message;
  els.toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.hidden = true;
  }, 5000);
}

function errorMessage(err) {
  if (err instanceof ApiError) return err.message;
  console.error(err);
  return 'Something went wrong. Please try again.';
}

const formatTime = (iso) => new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

// ---------------------------------------------------------------------- auth

const USERNAME_PATTERN = /^[a-z0-9_]{3,32}$/;

// The server only ever sees a key derived from the password, so password
// strength has to be enforced here, before registration.
const PASSWORD_RULES = [
  [/.{10,}/, 'At least 10 characters'],
  [/[a-z]/, 'A lowercase letter'],
  [/[A-Z]/, 'An uppercase letter'],
  [/\d/, 'A number'],
  [/[^A-Za-z0-9]/, 'A symbol'],
];

function setAuthStatus(message, isError = false) {
  els.authStatus.textContent = message;
  els.authStatus.classList.toggle('error', isError);
}

function setAuthBusy(busy) {
  for (const button of els.authForm.querySelectorAll('button')) button.disabled = busy;
}

function showPasswordRules(failed) {
  els.passwordRules.replaceChildren(...failed.map(([, label]) => el('li', null, label)));
  els.passwordRules.hidden = failed.length === 0;
}

async function startSession(user, accessToken, privateKey) {
  state.me = user;
  state.privateKey = privateKey;
  setAccessToken(accessToken);
  try {
    await keystore.saveIdentity(user.id, privateKey);
  } catch {
    // Storage can be unavailable (e.g. some private browsing modes). The
    // session still works; the user will just need to log in after a reload.
  }
}

async function register(username, password) {
  setAuthStatus('Generating your encryption keys…');
  const { payload, privateKey } = await e2ee.createRegistration(username, password);
  setAuthStatus('Creating your account…');
  const { user, accessToken } = await api('/api/auth/register', { method: 'POST', body: payload, auth: false });
  await startSession(user, accessToken, privateKey);
}

async function login(username, password) {
  setAuthStatus('Deriving your keys…');
  const { authKey, wrapKey } = await e2ee.deriveCredentialKeys(username, password);
  setAuthStatus('Signing in…');
  const { user, keys, accessToken } = await api('/api/auth/login', {
    method: 'POST',
    body: { username, authKey },
    auth: false,
  });
  const privateKey = await e2ee.unwrapPrivateKey(keys, wrapKey);
  await startSession(user, accessToken, privateKey);
}

els.authForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  const action = event.submitter?.dataset.action === 'register' ? 'register' : 'login';
  const username = e2ee.normalizeUsername(els.username.value);
  const password = els.password.value;

  showPasswordRules([]);
  if (!USERNAME_PATTERN.test(username)) {
    return setAuthStatus('Username must be 3-32 characters: letters, numbers or underscores.', true);
  }
  if (!password) return setAuthStatus('Enter your password.', true);
  if (action === 'register') {
    const failed = PASSWORD_RULES.filter(([pattern]) => !pattern.test(password));
    if (failed.length) {
      showPasswordRules(failed);
      return setAuthStatus('Please choose a stronger password:', true);
    }
  }

  setAuthBusy(true);
  try {
    if (action === 'register') await register(username, password);
    else await login(username, password);
    els.password.value = '';
    setAuthStatus('');
    await enterChat();
  } catch (err) {
    setAuthStatus(errorMessage(err), true);
  } finally {
    setAuthBusy(false);
  }
});

async function logout(message = '') {
  const { socket } = state;
  resetState();
  socket?.disconnect();
  await logoutRequest().catch(() => {});
  await keystore.clearIdentity().catch(() => {});
  showAuth(message);
}

let sessionLost = false;
function handleSessionLost() {
  if (sessionLost) return;
  sessionLost = true;
  logout('Your session has ended. Please log in again.').finally(() => {
    sessionLost = false;
  });
}

els.logoutBtn.addEventListener('click', () => logout());
onSessionLost(handleSessionLost);

// --------------------------------------------------------------------- views

function showAuth(message = '') {
  els.chatView.hidden = true;
  els.navUser.hidden = true;
  els.authView.hidden = false;
  setAuthStatus(message, Boolean(message));
  els.username.focus();
}

async function enterChat() {
  els.authView.hidden = true;
  els.chatView.hidden = false;
  els.navUser.hidden = false;
  els.navUsername.textContent = state.me.username;
  closeConversation();
  connectSocket();
  await loadConversations();
}

function setConnection(online) {
  els.connection.textContent = online ? 'Online' : 'Offline';
  els.connection.classList.toggle('online', online);
  els.connection.classList.toggle('offline', !online);
}

// -------------------------------------------------------------------- socket

function connectSocket() {
  // window.io is provided by /socket.io/socket.io.min.js. The auth callback
  // runs on every (re)connect, so it always presents the current token.
  const socket = window.io({
    auth: (cb) => cb({ token: getAccessToken() }),
    transports: ['websocket'],
    autoConnect: false,
  });
  state.socket = socket;

  let connectedBefore = false;
  let authRetries = 0;

  async function reconnectWithFreshToken() {
    if (state.socket !== socket) return;
    if (authRetries++ >= 3) return handleSessionLost();
    try {
      await refreshSession();
      if (state.socket === socket) socket.connect();
    } catch {
      handleSessionLost();
    }
  }

  socket.on('connect', () => {
    authRetries = 0;
    setConnection(true);
    // Catch up on anything sent while we were disconnected.
    if (connectedBefore) resync();
    connectedBefore = true;
  });

  socket.on('disconnect', (reason) => {
    setConnection(false);
    // The server disconnects us when the access token expires.
    if (reason === 'io server disconnect') reconnectWithFreshToken();
  });

  socket.on('connect_error', (err) => {
    setConnection(false);
    if (err.message === 'invalid_token' || err.message === 'unauthenticated') reconnectWithFreshToken();
  });

  socket.on('message:new', (message) => enqueueIncoming(message));

  socket.connect();
}

// After a proactive token refresh, reconnect so the socket uses the new token.
onTokenChange((token) => {
  const { socket } = state;
  if (token && socket?.connected) {
    socket.disconnect();
    socket.connect();
  }
});

async function resync() {
  try {
    await loadConversations();
    const active = state.conversations.get(state.activeId);
    if (active) await loadMessages(active);
  } catch (err) {
    showToast(errorMessage(err));
  }
}

// ------------------------------------------------------------- conversations

async function loadConversations() {
  const { conversations } = await api('/api/conversations');
  state.conversations = new Map(conversations.map((c) => [c.id, c]));
  renderConversationList();
}

function chatHead(username, { active = false, unread = false } = {}) {
  const button = el('button', `chat-head${active ? ' active' : ''}`);
  button.type = 'button';
  button.append(el('span', 'avatar', username.charAt(0)), el('span', 'chat-head-name', username));
  if (unread) button.append(el('span', 'unread-dot'));
  return button;
}

function renderConversationList() {
  const items = [...state.conversations.values()].map((conversation) => {
    const li = el('li');
    const button = chatHead(conversation.peer.username, {
      active: conversation.id === state.activeId,
      unread: state.unread.has(conversation.id),
    });
    button.addEventListener('click', () => openConversation(conversation.id));
    li.append(button);
    return li;
  });
  if (items.length === 0) items.push(el('li', 'list-empty', 'No chats yet. Search for a user above.'));
  els.conversationList.replaceChildren(...items);
}

function conversationKey(conversation) {
  // Memoize the promise so concurrent callers share one derivation.
  if (!state.conversationKeys.has(conversation.id)) {
    state.conversationKeys.set(
      conversation.id,
      e2ee.deriveConversationKey(state.privateKey, conversation.peer.publicKey, conversation.id)
    );
  }
  return state.conversationKeys.get(conversation.id);
}

function closeConversation() {
  state.activeId = null;
  els.conversationPane.hidden = true;
  els.emptyState.hidden = false;
  els.safety.hidden = true;
  els.chatView.classList.remove('has-active');
  els.messages.replaceChildren();
}

async function openConversation(id) {
  const conversation = state.conversations.get(id);
  if (!conversation) return;

  state.activeId = id;
  state.unread.delete(id);
  renderConversationList();

  els.emptyState.hidden = true;
  els.conversationPane.hidden = false;
  els.chatView.classList.add('has-active');
  els.peerName.textContent = conversation.peer.username;
  els.messages.replaceChildren();
  els.lastCiphertext.textContent = 'Send or receive a message to see its encrypted form.';

  await Promise.all([checkPeerKey(conversation), showSafetyNumber(conversation)]);
  try {
    await loadMessages(conversation);
  } catch (err) {
    showToast(errorMessage(err));
  }
  if (!state.keyChanged) els.messageInput.focus();
}

els.backBtn.addEventListener('click', () => {
  closeConversation();
  renderConversationList();
});

async function showSafetyNumber(conversation) {
  els.safetyNumber.textContent = await e2ee.safetyNumber(state.me.publicKey, conversation.peer.publicKey);
  els.safety.hidden = false;
}

/** Warn (and pause sending) if a contact's public key differs from last time. */
async function checkPeerKey(conversation) {
  let result = { changed: false };
  try {
    result = await keystore.checkPeerKey(state.me.id, conversation.peer.id, conversation.peer.publicKey);
  } catch {
    // Without storage we cannot compare; the safety number is still shown.
  }
  if (state.activeId !== conversation.id) return;
  state.keyChanged = result.changed;
  els.keyWarning.hidden = !result.changed;
  setComposerEnabled(!result.changed);
}

els.trustKeyBtn.addEventListener('click', async () => {
  const conversation = state.conversations.get(state.activeId);
  if (!conversation) return;
  await keystore.trustPeerKey(state.me.id, conversation.peer.id, conversation.peer.publicKey).catch(() => {});
  state.keyChanged = false;
  els.keyWarning.hidden = true;
  setComposerEnabled(true);
  els.messageInput.focus();
});

function setComposerEnabled(enabled) {
  els.messageInput.disabled = !enabled;
  els.composer.querySelector('button').disabled = !enabled;
}

// ------------------------------------------------------------------ messages

async function renderMessage(message, key) {
  let text;
  let failed = false;
  try {
    text = await e2ee.decryptMessage(key, message, {
      conversationId: message.conversationId,
      senderId: message.senderId,
    });
  } catch {
    // Wrong key or tampered ciphertext: AES-GCM authentication failed.
    text = '🔒 This message could not be decrypted';
    failed = true;
  }

  const mine = message.senderId === state.me.id;
  const li = el('li', `message ${mine ? 'self' : 'other'}${failed ? ' failed' : ''}`);
  li.dataset.id = message.id;
  li.append(el('div', 'bubble', text), el('time', 'message-time', formatTime(message.createdAt)));
  return li;
}

function scrollToBottom() {
  els.messages.scrollTop = els.messages.scrollHeight;
}

async function loadMessages(conversation) {
  const { messages } = await api(`/api/conversations/${conversation.id}/messages?limit=100`);
  if (state.activeId !== conversation.id) return;
  const key = await conversationKey(conversation);
  const nodes = await Promise.all(messages.map((m) => renderMessage(m, key)));
  if (state.activeId !== conversation.id) return;
  els.messages.replaceChildren(...nodes);
  scrollToBottom();
}

function showServerView(message) {
  const preview = {
    conversationId: message.conversationId,
    senderId: message.senderId,
    iv: message.iv,
    ciphertext: message.ciphertext.length > 120 ? `${message.ciphertext.slice(0, 120)}…` : message.ciphertext,
  };
  els.lastCiphertext.textContent = JSON.stringify(preview, null, 2);
}

// Process incoming messages strictly in order, even though decryption is async.
let incomingQueue = Promise.resolve();
function enqueueIncoming(message) {
  incomingQueue = incomingQueue.then(() => handleIncoming(message)).catch((err) => console.error(err));
}

async function handleIncoming(message) {
  if (!state.me) return;
  if (!state.conversations.has(message.conversationId)) await loadConversations();
  const conversation = state.conversations.get(message.conversationId);
  if (!conversation) return;

  // Move the conversation to the top of the list.
  conversation.lastMessageAt = message.createdAt;
  state.conversations.delete(conversation.id);
  state.conversations = new Map([[conversation.id, conversation], ...state.conversations]);

  if (message.conversationId === state.activeId) {
    showServerView(message);
    if (!els.messages.querySelector(`[data-id="${CSS.escape(message.id)}"]`)) {
      els.messages.append(await renderMessage(message, await conversationKey(conversation)));
      scrollToBottom();
    }
  } else if (message.senderId !== state.me.id) {
    state.unread.add(message.conversationId);
  }
  renderConversationList();
}

els.composer.addEventListener('submit', async (event) => {
  event.preventDefault();
  const conversation = state.conversations.get(state.activeId);
  const text = els.messageInput.value.trim();
  if (!conversation || !text || state.keyChanged) return;
  if (text.length > e2ee.MAX_MESSAGE_LENGTH) {
    return showToast(`Messages can be at most ${e2ee.MAX_MESSAGE_LENGTH} characters.`);
  }

  setComposerEnabled(false);
  try {
    const key = await conversationKey(conversation);
    const sealed = await e2ee.encryptMessage(key, text, { conversationId: conversation.id, senderId: state.me.id });
    // Only ciphertext and IV leave the browser.
    const ack = await state.socket.timeout(8000).emitWithAck('message:send', { conversationId: conversation.id, ...sealed });
    if (!ack.ok) {
      showToast(ack.error?.message ?? 'Message could not be sent');
      return;
    }
    els.messageInput.value = '';
  } catch {
    showToast('Message could not be sent. Check your connection.');
  } finally {
    setComposerEnabled(!state.keyChanged);
    els.messageInput.focus();
  }
});

// -------------------------------------------------------------------- search

let searchTimer;
let searchSeq = 0;

els.search.addEventListener('input', () => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(runSearch, 250);
});

async function runSearch() {
  const query = els.search.value.trim();
  const seq = ++searchSeq;
  if (!query) return els.searchResults.replaceChildren();

  try {
    const { users } = await api(`/api/users/search?q=${encodeURIComponent(query)}`);
    if (seq !== searchSeq) return; // a newer search has started
    const items = users.map((user) => {
      const li = el('li');
      const button = chatHead(user.username);
      button.addEventListener('click', () => startConversation(user.id));
      li.append(button);
      return li;
    });
    if (items.length === 0) items.push(el('li', 'list-empty', 'No users found'));
    els.searchResults.replaceChildren(...items);
  } catch (err) {
    if (err instanceof ApiError && err.code === 'validation_error') return;
    showToast(errorMessage(err));
  }
}

async function startConversation(userId) {
  try {
    const { conversation } = await api('/api/conversations', { method: 'POST', body: { userId } });
    if (!state.conversations.has(conversation.id)) {
      state.conversations = new Map([[conversation.id, conversation], ...state.conversations]);
    }
    els.search.value = '';
    els.searchResults.replaceChildren();
    await openConversation(conversation.id);
  } catch (err) {
    showToast(errorMessage(err));
  }
}

// ---------------------------------------------------------------------- boot

/** Restore a session after a reload: refresh cookie + key stored on device. */
async function boot() {
  if (!hasSessionCookie()) return showAuth();
  try {
    const { user } = await refreshSession();
    const privateKey = await keystore.loadIdentity(user.id).catch(() => null);
    if (!privateKey) {
      await logoutRequest().catch(() => {});
      return showAuth('Please log in to unlock your encryption keys on this device.');
    }
    state.me = user;
    state.privateKey = privateKey;
    await enterChat();
  } catch {
    showAuth();
  }
}

boot();
