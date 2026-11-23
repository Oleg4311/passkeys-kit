// Настоящий собранный Worker в Miniflare: HTTP-слой, куки, защита от CSRF, ограничение частоты, заголовки безопасности.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { after, before, test } from 'node:test';
import { fromBase64Url } from '../src/bytes.ts';
import { buildWorker, makeMiniflare } from '../scripts/mf.mjs';
import { SoftAuthenticator } from './softauth.ts';

let mf: ReturnType<typeof makeMiniflare>;
let base: string;
let host: string;

before(async () => {
  execFileSync(process.execPath, ['scripts/build.mjs'], { stdio: 'ignore' });
  buildWorker();
  mf = makeMiniflare();
  base = (await mf.ready).toString().replace(/\/$/, '');
  host = new URL(base).hostname;
});
after(async () => {
  await mf.dispose();
});

interface Reply {
  status: number;
  json: any;
  headers: { get(name: string): string | null };
  text: string;
}

/** Клиент с «банкой куки»: хранит только __Host-sid, как браузер. */
class Browser {
  cookie = '';
  ip: string;
  constructor(ip = '203.0.113.' + Math.floor(Math.random() * 200)) {
    this.ip = ip;
  }
  async call(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<Reply> {
    const headers: Record<string, string> = { 'cf-connecting-ip': this.ip, ...extra };
    if (this.cookie) headers['cookie'] = this.cookie;
    if (method !== 'GET' && !('origin' in extra)) headers['origin'] = base;
    if (body !== undefined && !('content-type' in extra)) headers['content-type'] = 'application/json';
    const res = await mf.dispatchFetch(base + path, { method, headers, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
    const text = await res.text();
    const sc = res.headers.get('set-cookie');
    if (sc) this.cookie = sc.startsWith('__Host-sid=;') || /Max-Age=0/.test(sc) ? '' : sc.split(';')[0]!;
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* не JSON */
    }
    return { status: res.status, json, headers: res.headers, text };
  }
}

const ORIGIN = (): string => base;

async function signUp(b: Browser, name: string, a?: SoftAuthenticator) {
  const auth = a ?? (await SoftAuthenticator.make('es256', host));
  const opts = await b.call('POST', '/api/register/options', { username: name });
  assert.equal(opts.status, 200, opts.text);
  const cred = await auth.create({ challenge: opts.json.options.challenge, origin: ORIGIN() });
  const ver = await b.call('POST', '/api/register/verify', { challengeId: opts.json.challengeId, credential: cred });
  return { auth, opts, ver, userId: opts.json.options.user.id as string };
}

async function signIn(b: Browser, a: SoftAuthenticator, userId: string, tweak: Record<string, unknown> = {}) {
  const opts = await b.call('POST', '/api/login/options', {});
  assert.equal(opts.status, 200, opts.text);
  const cred = await a.get({ challenge: opts.json.options.challenge, origin: ORIGIN(), userHandle: fromBase64Url(userId), ...tweak });
  return b.call('POST', '/api/login/verify', { challengeId: opts.json.challengeId, credential: cred });
}

test('здоровье и заголовки безопасности страницы', async () => {
  const h = await mf.dispatchFetch(base + '/api/health');
  assert.equal(h.status, 200);
  assert.equal(h.headers.get('cache-control'), 'no-store');
  const page = await mf.dispatchFetch(base + '/');
  assert.equal(page.status, 200);
  const csp = page.headers.get('content-security-policy') ?? '';
  assert.match(csp, /default-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /script-src 'self'/);
  assert.ok(!/unsafe-eval|script-src[^;]*unsafe-inline/.test(csp), 'скрипты только со своего адреса');
  assert.equal(page.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
  assert.match(page.headers.get('permissions-policy') ?? '', /publickey-credentials-create=\(self\)/);
});

test('полный цикл по HTTP: регистрация, кука сессии, /api/me, выход, вход по passkey, удаление ключа', async () => {
  const b = new Browser();
  const { auth, ver, userId, opts } = await signUp(b, 'Alice');
  assert.equal(ver.status, 200, ver.text);
  assert.equal(ver.json.username, 'alice');
  assert.ok(!('sessionToken' in ver.json), 'токен сессии не попадает в тело ответа');
  const sc = ver.headers.get('set-cookie') ?? '';
  assert.match(sc, /^__Host-sid=[A-Za-z0-9_-]{40,}/);
  for (const attr of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) assert.ok(sc.includes(attr), `в куке нет ${attr}`);
  assert.ok(!sc.includes('Domain='), '__Host- не допускает Domain');
  assert.equal(opts.json.options.rp.id, host, 'rpId берётся из адреса запроса');
  assert.equal(opts.json.options.attestation, 'none');

  const me = await b.call('GET', '/api/me');
  assert.equal(me.status, 200);
  assert.equal(me.json.username, 'alice');
  assert.equal(me.json.credentials.length, 1);
  assert.ok(!/publicKey|public_key/i.test(me.text), 'открытый ключ наружу не отдаётся');

  assert.equal((await b.call('POST', '/api/logout', {})).status, 200);
  assert.equal(b.cookie, '');
  assert.equal((await b.call('GET', '/api/me')).status, 401);

  const login = await signIn(b, auth, userId);
  assert.equal(login.status, 200, login.text);
  assert.equal((await b.call('GET', '/api/me')).json.credentials[0].signCount, 1);

  // второй ключ и удаление первого
  const opts2 = await b.call('POST', '/api/register/options', { username: 'alice' });
  assert.equal(opts2.json.options.excludeCredentials.length, 1);
  const second = await SoftAuthenticator.make('ed25519', host);
  const v2 = await b.call('POST', '/api/register/verify', { challengeId: opts2.json.challengeId, credential: await second.create({ challenge: opts2.json.options.challenge, origin: ORIGIN() }) });
  assert.equal(v2.status, 200, v2.text);
  const del = await b.call('DELETE', '/api/credentials/' + auth.id);
  assert.equal(del.status, 200);
  assert.equal((await b.call('GET', '/api/me')).json.credentials.length, 1);
  assert.equal((await b.call('DELETE', '/api/credentials/' + second.id)).status, 409);
});

test('CSRF: запросы без Origin, с чужим Origin или не JSON отклоняются; GET без Origin работает', async () => {
  const b = new Browser();
  const noOrigin = await mf.dispatchFetch(base + '/api/login/options', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(noOrigin.status, 403);
  assert.equal((await b.call('POST', '/api/login/options', {}, { origin: 'https://evil.test' })).status, 403);
  assert.equal((await b.call('POST', '/api/login/options', {}, { origin: base + ':1' })).status, 403);
  assert.equal((await b.call('POST', '/api/login/options', 'x=1', { 'content-type': 'application/x-www-form-urlencoded' })).status, 415);
  assert.equal((await b.call('POST', '/api/login/options', 'x', { 'content-type': 'text/plain' })).status, 415);
  assert.equal((await b.call('DELETE', '/api/credentials/abc', undefined, { origin: 'https://evil.test' })).status, 403);
  assert.equal((await b.call('GET', '/api/health')).status, 200);
});

test('разбор запроса: мусорный JSON, большой запрос, неизвестные маршруты и методы', async () => {
  const b = new Browser();
  assert.equal((await b.call('POST', '/api/register/options', '{не json')).status, 400);
  assert.equal((await b.call('POST', '/api/register/options', { username: 'x'.repeat(20000) })).status, 413);
  assert.equal((await b.call('GET', '/api/nope')).status, 404);
  assert.equal((await b.call('GET', '/api/register/options')).status, 404);
  assert.equal((await b.call('POST', '/api/me', {})).status, 404);
  assert.equal((await b.call('POST', '/api/register/options', { username: 5 })).status, 400);
  assert.equal((await b.call('POST', '/api/register/options', { username: 'a b' })).json.error, 'bad_username');
});

test('ответ об ошибке не раскрывает внутренностей', async () => {
  const b = new Browser();
  const r = await b.call('POST', '/api/login/verify', { challengeId: 'AAAAAAAAAAAAAAAAAAAAAA', credential: { id: 5 } });
  assert.ok(r.status >= 400 && r.status < 500);
  assert.ok(!/at |stack|\.ts|\.mjs/.test(r.text));
});

test('чужая сессия и подделанная кука не дают доступа', async () => {
  const alice = new Browser();
  await signUp(alice, 'session-owner');
  const mallory = new Browser();
  mallory.cookie = '__Host-sid=' + 'A'.repeat(43);
  assert.equal((await mallory.call('GET', '/api/me')).status, 401);
  mallory.cookie = alice.cookie.slice(0, -2) + 'xx'; // испорченный токен
  assert.equal((await mallory.call('GET', '/api/me')).status, 401);
  mallory.cookie = 'sid=' + alice.cookie.split('=')[1]; // без префикса __Host-
  assert.equal((await mallory.call('GET', '/api/me')).status, 401);
});

test('ограничение частоты: после 120 попыток в минуту с одного адреса отказ с Retry-After; другой адрес не затронут', async () => {
  const b = new Browser('198.51.100.7');
  let limited: Reply | null = null;
  for (let i = 0; i < 130 && !limited; i++) {
    const r = await b.call('POST', '/api/login/options', {});
    if (r.status === 429) limited = r;
  }
  assert.ok(limited, 'ограничение не сработало');
  assert.equal(limited.headers.get('retry-after'), '60');
  assert.equal(limited.json.error, 'rate_limited');
  assert.equal((await new Browser('198.51.100.8').call('POST', '/api/login/options', {})).status, 200);
  assert.equal((await b.call('GET', '/api/me')).status, 401, 'GET не ограничивается этим счётчиком');
});

test('клон по HTTP: счётчик не вырос → 403 и блокировка ключа', async () => {
  const b = new Browser();
  const { auth, userId } = await signUp(b, 'clonetest');
  assert.equal((await signIn(b, auth, userId)).status, 200);
  assert.equal((await signIn(b, auth, userId)).status, 200);
  const stale = Object.assign(Object.create(Object.getPrototypeOf(auth)), auth) as SoftAuthenticator;
  stale.counter = 0;
  const bad = await signIn(new Browser(), stale, userId);
  assert.equal(bad.status, 403);
  assert.equal(bad.json.error, 'counter_regression');
  assert.equal((await signIn(new Browser(), auth, userId)).json.error, 'credential_locked');
  assert.equal((await b.call('GET', '/api/me')).json.credentials[0].locked, true);
});
