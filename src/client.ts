// Клиент: регистрация и вход по passkey через navigator.credentials, список ключей аккаунта.

const app = document.getElementById('app')!;
const toastEl = document.getElementById('toast')!;

type Attrs = Record<string, string | boolean | ((e: Event) => void)>;
function h(tag: string, attrs: Attrs = {}, ...kids: Array<Node | string | null>): HTMLElement {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (typeof v === 'function') el.addEventListener(k.replace(/^on/, ''), v);
    else if (typeof v === 'boolean') {
      if (v) el.setAttribute(k, '');
    } else el.setAttribute(k, v);
  }
  for (const kid of kids) if (kid !== null) el.append(kid);
  return el;
}

function toast(msg: string): void {
  toastEl.textContent = msg;
  toastEl.classList.add('on');
  setTimeout(() => toastEl.classList.remove('on'), 3000);
}

const b64uToBuf = (s: string): ArrayBuffer => {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};
const bufToB64u = (b: ArrayBuffer): string => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

class ApiError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, { method, headers: body === undefined ? {} : { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body), credentials: 'same-origin' });
  const data = (await res.json().catch(() => ({}))) as { error?: string; message?: string };
  if (!res.ok) throw new ApiError(data.error ?? 'error', data.message ?? `Ошибка ${res.status}`);
  return data as T;
}

interface CredInfo {
  id: string;
  createdAt: number;
  lastUsedAt: number | null;
  backedUp: boolean;
  backupEligible: boolean;
  locked: boolean;
  signCount: number;
}
interface Me {
  username: string;
  credentials: CredInfo[];
}

function friendly(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof DOMException) {
    if (e.name === 'NotAllowedError') return 'Операция отменена или время вышло.';
    if (e.name === 'InvalidStateError') return 'Этот ключ уже зарегистрирован на устройстве.';
    if (e.name === 'SecurityError') return 'Браузер отклонил запрос: адрес страницы не подходит для passkey.';
    return `${e.name}: ${e.message}`;
  }
  return e instanceof Error ? e.message : String(e);
}

async function createPasskey(username: string): Promise<void> {
  const { challengeId, options } = await api<{ challengeId: string; options: any }>('POST', '/api/register/options', { username });
  const publicKey: PublicKeyCredentialCreationOptions = {
    ...options,
    challenge: b64uToBuf(options.challenge),
    user: { ...options.user, id: b64uToBuf(options.user.id) },
    excludeCredentials: options.excludeCredentials.map((c: { id: string }) => ({ type: 'public-key', id: b64uToBuf(c.id) })),
  };
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Ключ не создан.');
  const r = cred.response as AuthenticatorAttestationResponse;
  await api('POST', '/api/register/verify', {
    challengeId,
    credential: { id: cred.id, rawId: bufToB64u(cred.rawId), type: cred.type, response: { clientDataJSON: bufToB64u(r.clientDataJSON), attestationObject: bufToB64u(r.attestationObject), transports: r.getTransports?.() ?? [] } },
  });
}

async function signIn(): Promise<void> {
  const { challengeId, options } = await api<{ challengeId: string; options: any }>('POST', '/api/login/options', {});
  const publicKey: PublicKeyCredentialRequestOptions = { ...options, challenge: b64uToBuf(options.challenge), allowCredentials: [] };
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('Вход отменён.');
  const r = cred.response as AuthenticatorAssertionResponse;
  await api('POST', '/api/login/verify', {
    challengeId,
    credential: {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: { clientDataJSON: bufToB64u(r.clientDataJSON), authenticatorData: bufToB64u(r.authenticatorData), signature: bufToB64u(r.signature), userHandle: r.userHandle ? bufToB64u(r.userHandle) : null },
    },
  });
}

function show(...nodes: Node[]): void {
  app.replaceChildren(...nodes);
}

const fmt = (t: number | null): string => (t === null ? 'ещё не использовался' : new Date(t).toLocaleString('ru-RU'));

function viewLogin(message = ''): void {
  const name = h('input', { id: 'username', autocomplete: 'username webauthn', maxlength: '32', placeholder: 'alice' }) as HTMLInputElement;
  const problems = h('div', { class: 'banner', role: 'alert', hidden: message === '' }, message);
  const setProblem = (m: string): void => {
    problems.textContent = m;
    problems.toggleAttribute('hidden', m === '');
  };
  const busy = (b: boolean): void => document.querySelectorAll('button').forEach((x) => ((x as HTMLButtonElement).disabled = b));
  show(
    h('section', { class: 'card' },
      h('h2', {}, 'Вход без пароля'),
      problems,
      h('p', { class: 'hint' }, 'Passkey хранится на вашем устройстве или в менеджере паролей. Сервер знает только открытый ключ.'),
      h('div', { class: 'actions' }, h('button', { class: 'primary', id: 'signin', type: 'button', onclick: async () => {
        busy(true);
        try {
          await signIn();
          await viewAccount();
        } catch (e) {
          setProblem(friendly(e));
          busy(false);
        }
      } }, 'Войти по passkey')),
    ),
    h('section', { class: 'card' },
      h('h2', {}, 'Новый аккаунт'),
      h('label', { for: 'username' }, 'Имя пользователя'),
      name,
      h('div', { class: 'actions' }, h('button', { id: 'signup', type: 'button', onclick: async () => {
        busy(true);
        try {
          await createPasskey(name.value);
          await viewAccount();
        } catch (e) {
          setProblem(friendly(e));
          busy(false);
        }
      } }, 'Создать passkey')),
    ),
  );
}

async function viewAccount(): Promise<void> {
  let me: Me;
  try {
    me = await api<Me>('GET', '/api/me');
  } catch {
    return viewLogin();
  }
  const rows = me.credentials.map((c, i) =>
    h('li', { 'data-testid': 'credential' },
      h('div', {}, h('strong', {}, `Ключ ${i + 1}`), c.locked ? h('span', { class: 'pill bad' }, ' заблокирован') : null, c.backedUp ? h('span', { class: 'pill' }, ' синхронизирован') : null),
      h('div', { class: 'hint' }, `добавлен ${fmt(c.createdAt)}, последний вход: ${fmt(c.lastUsedAt)}, подписей: ${c.signCount}`),
      h('button', { type: 'button', 'aria-label': `Удалить ключ ${i + 1}`, onclick: async () => {
        try {
          await api('DELETE', '/api/credentials/' + c.id);
          await viewAccount();
        } catch (e) {
          toast(friendly(e));
        }
      } }, 'Удалить'),
    ),
  );
  show(
    h('section', { class: 'card' },
      h('h2', {}, 'Вы вошли'),
      h('p', { 'data-testid': 'whoami' }, 'Аккаунт: ', h('strong', {}, me.username)),
      h('div', { class: 'actions' },
        h('button', { type: 'button', id: 'logout', onclick: async () => {
          await api('POST', '/api/logout', {});
          viewLogin();
        } }, 'Выйти'),
      ),
    ),
    h('section', { class: 'card' },
      h('h2', {}, 'Ваши ключи'),
      h('ul', { class: 'keys' }, ...rows),
      h('div', { class: 'actions' }, h('button', { id: 'addkey', type: 'button', onclick: async () => {
        try {
          await createPasskey(me.username);
          await viewAccount();
          toast('Ключ добавлен');
        } catch (e) {
          toast(friendly(e));
        }
      } }, 'Добавить ещё один ключ')),
    ),
  );
}

if (!window.PublicKeyCredential) {
  show(h('section', { class: 'card', role: 'alert' }, h('h2', {}, 'Passkey не поддерживается'), h('p', {}, 'Этот браузер не поддерживает WebAuthn. Откройте страницу в современном Chrome, Safari, Firefox или Edge.')));
} else {
  void viewAccount();
}
