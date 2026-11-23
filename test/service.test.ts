import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fromBase64Url } from '../src/bytes.ts';
import { AuthService, HttpError, LIMITS, normalizeUsername } from '../src/service.ts';
import type { Context, Store } from '../src/service.ts';
import { SoftAuthenticator } from './softauth.ts';

const RP = 'example.test';
const ORIGIN = 'https://example.test';
const T0 = 1_800_000_000_000;

class MapStore implements Store {
  m = new Map<string, unknown>();
  async get<T>(k: string): Promise<T | undefined> {
    const v = this.m.get(k);
    return v === undefined ? undefined : (structuredClone(v) as T);
  }
  async put(k: string, v: unknown): Promise<void> {
    this.m.set(k, structuredClone(v));
  }
  async delete(k: string): Promise<void> {
    this.m.delete(k);
  }
}

const ctx = (now = T0): Context => ({ rpId: RP, origin: ORIGIN, now });

async function rejects(p: Promise<unknown>, status: number, code: string): Promise<void> {
  try {
    await p;
  } catch (e) {
    assert.ok(e instanceof HttpError, String(e));
    assert.equal(e.status, status, `${e.code}: ${e.message}`);
    assert.equal(e.code, code, e.message);
    return;
  }
  assert.fail(`ожидалась ошибка ${status} ${code}`);
}

/** Полная регистрация нового пользователя настоящим (программным) аутентификатором. */
async function signUp(svc: AuthService, username: string, a?: SoftAuthenticator, now = T0, session?: string) {
  const auth = a ?? (await SoftAuthenticator.make('es256', RP));
  const { challengeId, options } = await svc.registerOptions(ctx(now), { username }, session);
  const cred = await auth.create({ challenge: options.challenge, origin: ORIGIN });
  const out = await svc.registerVerify(ctx(now), { challengeId, credential: cred }, session);
  return { auth, options, out, userId: options.user.id };
}

async function signIn(svc: AuthService, a: SoftAuthenticator, userId: string, now = T0, tweak: Record<string, unknown> = {}) {
  const { challengeId, options } = await svc.loginOptions(ctx(now));
  const cred = await a.get({ challenge: options.challenge, origin: ORIGIN, userHandle: fromBase64Url(userId), ...tweak });
  return svc.loginVerify(ctx(now), { challengeId, credential: cred });
}

test('имя пользователя: нормализация и отказы', () => {
  assert.equal(normalizeUsername('  Alice.Smith-1_ '), 'alice.smith-1_');
  for (const bad of [5, null, '', 'ab', 'a'.repeat(33), '.dot', '-dash', 'with space', 'кириллица', 'a<b>', 'a\u0000b', 'a@b']) assert.throws(() => normalizeUsername(bad), HttpError, String(bad));
});

test('регистрация и вход целиком: сессия выдаётся, ключи видны, счётчик растёт', async () => {
  const svc = new AuthService(new MapStore());
  const { auth, options, out, userId } = await signUp(svc, 'Alice');
  assert.equal(out.username, 'alice');
  assert.ok(out.sessionToken && out.sessionToken.length >= 40);
  assert.equal(options.rp.id, RP);
  assert.equal(options.attestation, 'none');
  assert.deepEqual(options.authenticatorSelection, { residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
  assert.deepEqual(options.pubKeyCredParams.map((p) => p.alg), [-7, -8, -257]);
  const me = await svc.me(out.sessionToken, T0);
  assert.equal(me.credentials.length, 1);
  assert.equal(me.credentials[0]!.id, auth.id);
  const login = await signIn(svc, auth, userId, T0 + 1000);
  assert.equal(login.username, 'alice');
  assert.notEqual(login.sessionToken, out.sessionToken);
  assert.equal((await svc.me(login.sessionToken, T0 + 2000)).credentials[0]!.signCount, 1);
  assert.equal((await svc.me(login.sessionToken, T0 + 2000)).credentials[0]!.lastUsedAt, T0 + 1000);
  await signIn(svc, auth, userId, T0 + 3000);
  assert.equal((await svc.me(login.sessionToken, T0 + 4000)).credentials[0]!.signCount, 2);
});

test('в хранилище нет открытых токенов сессии и challenge после использования', async () => {
  const store = new MapStore();
  const svc = new AuthService(store);
  const { out } = await signUp(svc, 'alice');
  const dump = JSON.stringify([...store.m]);
  assert.ok(!dump.includes(out.sessionToken!), 'токен сессии хранится только хешем');
  assert.ok(![...store.m.keys()].some((k) => k.startsWith('chal:')), 'использованный challenge удалён');
});

test('challenge одноразовый, ограничен по времени и привязан к виду операции', async () => {
  const svc = new AuthService(new MapStore());
  const a = await SoftAuthenticator.make('es256', RP);
  const { challengeId, options } = await svc.registerOptions(ctx(), { username: 'alice' }, undefined);
  const cred = await a.create({ challenge: options.challenge, origin: ORIGIN });
  await svc.registerVerify(ctx(), { challengeId, credential: cred }, undefined);
  await rejects(svc.registerVerify(ctx(), { challengeId, credential: cred }, undefined), 400, 'challenge_unknown'); // повтор того же ответа

  const b = await SoftAuthenticator.make('es256', RP);
  const late = await svc.registerOptions(ctx(), { username: 'bob' }, undefined);
  const lateCred = await b.create({ challenge: late.options.challenge, origin: ORIGIN });
  await rejects(svc.registerVerify(ctx(T0 + LIMITS.challengeTtlMs + 1), { challengeId: late.challengeId, credential: lateCred }, undefined), 400, 'challenge_expired');
  // тип операции: challenge входа нельзя использовать для регистрации
  const login = await svc.loginOptions(ctx());
  await rejects(svc.registerVerify(ctx(), { challengeId: login.challengeId, credential: lateCred }, undefined), 400, 'challenge_unknown');
  for (const bad of [undefined, null, 5, '', 'x', 'нет такого', '!'.repeat(22)]) await rejects(svc.registerVerify(ctx(), { challengeId: bad, credential: {} }, undefined), 400, 'bad_challenge').catch(() => {});
});

test('неудачная попытка тоже сжигает challenge', async () => {
  const svc = new AuthService(new MapStore());
  const a = await SoftAuthenticator.make('es256', RP);
  const { challengeId, options } = await svc.registerOptions(ctx(), { username: 'alice' }, undefined);
  const wrong = await a.create({ challenge: options.challenge, origin: 'https://evil.test' });
  await rejects(svc.registerVerify(ctx(), { challengeId, credential: wrong }, undefined), 400, 'origin_mismatch');
  const right = await a.create({ challenge: options.challenge, origin: ORIGIN });
  await rejects(svc.registerVerify(ctx(), { challengeId, credential: right }, undefined), 400, 'challenge_unknown');
});

test('имя занято: чужой не может ни зарегистрироваться, ни добавить ключ без входа', async () => {
  const svc = new AuthService(new MapStore());
  await signUp(svc, 'alice');
  await rejects(svc.registerOptions(ctx(), { username: 'ALICE' }, undefined), 409, 'username_taken');
  const mallory = await signUp(svc, 'mallory');
  await rejects(svc.registerOptions(ctx(), { username: 'alice' }, mallory.out.sessionToken), 409, 'username_taken'); // вошёл под другим именем
});

test('гонка: два одновременных запроса на одно имя, место получает ровно один', async () => {
  for (let round = 0; round < 20; round++) {
    const svc = new AuthService(new MapStore());
    const [a, b] = await Promise.all([SoftAuthenticator.make('es256', RP), SoftAuthenticator.make('es256', RP)]);
    const [oa, ob] = await Promise.all([svc.registerOptions(ctx(), { username: 'racer' }, undefined), svc.registerOptions(ctx(), { username: 'racer' }, undefined)]);
    const [ca, cb] = await Promise.all([a.create({ challenge: oa.options.challenge, origin: ORIGIN }), b.create({ challenge: ob.options.challenge, origin: ORIGIN })]);
    const results = await Promise.allSettled([svc.registerVerify(ctx(), { challengeId: oa.challengeId, credential: ca }, undefined), svc.registerVerify(ctx(), { challengeId: ob.challengeId, credential: cb }, undefined)]);
    const ok = results.filter((r) => r.status === 'fulfilled').length;
    assert.equal(ok, 1, `раунд ${round}: успешных ${ok}`);
  }
});

test('второй ключ добавляется только из сессии; excludeCredentials защищает от повторной регистрации того же устройства', async () => {
  const svc = new AuthService(new MapStore());
  const first = await signUp(svc, 'alice');
  const opts = await svc.registerOptions(ctx(), { username: 'alice' }, first.out.sessionToken);
  assert.deepEqual(opts.options.excludeCredentials, [{ type: 'public-key', id: first.auth.id }]);
  assert.equal(opts.options.user.id, first.userId, 'идентификатор пользователя тот же');
  const second = await SoftAuthenticator.make('ed25519', RP);
  const cred = await second.create({ challenge: opts.options.challenge, origin: ORIGIN });
  const out = await svc.registerVerify(ctx(), { challengeId: opts.challengeId, credential: cred }, first.out.sessionToken);
  assert.equal(out.sessionToken, undefined);
  assert.equal((await svc.me(first.out.sessionToken, T0)).credentials.length, 2);
  // тот же ключ второй раз: отклонён
  const again = await svc.registerOptions(ctx(), { username: 'alice' }, first.out.sessionToken);
  const dup = await second.create({ challenge: again.options.challenge, origin: ORIGIN });
  await rejects(svc.registerVerify(ctx(), { challengeId: again.challengeId, credential: dup }, first.out.sessionToken), 409, 'credential_exists');
  // оба ключа входят
  await signIn(svc, first.auth, first.userId, T0 + 1);
  await signIn(svc, second, first.userId, T0 + 2);
});

test('предел числа ключей', async () => {
  const svc = new AuthService(new MapStore());
  const first = await signUp(svc, 'alice');
  for (let i = 1; i < LIMITS.maxCredentials; i++) await signUp(svc, 'alice', undefined, T0, first.out.sessionToken);
  await rejects(svc.registerOptions(ctx(), { username: 'alice' }, first.out.sessionToken), 409, 'too_many_credentials');
});

test('вход: неизвестный ключ, чужой userHandle и отсутствие userHandle дают один и тот же отказ без подсказок', async () => {
  const svc = new AuthService(new MapStore());
  const { auth, userId } = await signUp(svc, 'alice');
  const bob = await signUp(svc, 'bob');
  const stranger = await SoftAuthenticator.make('es256', RP);
  const messages = new Set<string>();
  const attempts: Array<[string, () => Promise<unknown>]> = [
    ['неизвестный ключ', () => signIn(svc, stranger, userId, T0 + 1)],
    ['userHandle другого пользователя', () => signIn(svc, auth, bob.userId, T0 + 2)],
    ['userHandle отсутствует', async () => {
      const { challengeId, options } = await svc.loginOptions(ctx(T0 + 3));
      return svc.loginVerify(ctx(T0 + 3), { challengeId, credential: await auth.get({ challenge: options.challenge, origin: ORIGIN }) });
    }],
  ];
  for (const [name, fn] of attempts) {
    try {
      await fn();
      assert.fail(`${name}: вход не должен был пройти`);
    } catch (e) {
      assert.ok(e instanceof HttpError, `${name}: ${String(e)}`);
      assert.equal(e.status, 401, name);
      assert.equal(e.code, 'login_failed', name);
      messages.add(e.message);
    }
  }
  assert.equal(messages.size, 1, 'тексты отказов одинаковы: по ним нельзя отличить случаи');
  // после неудач настоящий вход всё ещё работает: счётчик не пострадал
  assert.equal((await signIn(svc, auth, userId, T0 + 4)).username, 'alice');
});

test('вход: чужой origin и порча подписи отклоняются', async () => {
  const svc = new AuthService(new MapStore());
  const { auth, userId } = await signUp(svc, 'alice');
  await rejects(signIn(svc, auth, userId, T0 + 1, { origin: 'https://evil.test' }), 401, 'login_failed');
  await rejects(signIn(svc, auth, userId, T0 + 2, { rpId: 'evil.test' }), 401, 'login_failed');
});

test('клон: счётчик не вырос → отказ, ключ блокируется, дальше вход этим ключом закрыт, другой ключ работает', async () => {
  const svc = new AuthService(new MapStore());
  const first = await signUp(svc, 'alice');
  await signIn(svc, first.auth, first.userId, T0 + 1);
  await signIn(svc, first.auth, first.userId, T0 + 2); // сервер помнит 2
  const clone = Object.assign(Object.create(Object.getPrototypeOf(first.auth)), first.auth) as SoftAuthenticator;
  clone.counter = 0; // копия ключа с устаревшим счётчиком
  await rejects(signIn(svc, clone, first.userId, T0 + 3), 403, 'counter_regression');
  await rejects(signIn(svc, first.auth, first.userId, T0 + 4), 403, 'credential_locked'); // блокировка касается ключа, а не только копии
  const me = await svc.me(first.out.sessionToken, T0 + 5);
  assert.equal(me.credentials[0]!.locked, true);
  // второй ключ пользователя продолжает работать
  const opts = await svc.registerOptions(ctx(T0 + 6), { username: 'alice' }, first.out.sessionToken);
  const second = await SoftAuthenticator.make('es256', RP);
  await svc.registerVerify(ctx(T0 + 6), { challengeId: opts.challengeId, credential: await second.create({ challenge: opts.options.challenge, origin: ORIGIN }) }, first.out.sessionToken);
  assert.equal((await signIn(svc, second, first.userId, T0 + 7)).username, 'alice');
});

test('блокировка ставится только после проверки подписи: чужой ответ с известным id ключ не блокирует', async () => {
  const svc = new AuthService(new MapStore());
  const first = await signUp(svc, 'alice');
  await signIn(svc, first.auth, first.userId, T0 + 1);
  const attacker = await SoftAuthenticator.make('es256', RP);
  attacker.credentialId = first.auth.credentialId; // знает идентификатор, но не закрытый ключ
  attacker.counter = 0;
  await rejects(signIn(svc, attacker, first.userId, T0 + 2, { signCount: 0 }), 401, 'login_failed');
  assert.equal((await signIn(svc, first.auth, first.userId, T0 + 3)).username, 'alice');
});

test('сессии: срок жизни, выход, неверные токены', async () => {
  const svc = new AuthService(new MapStore());
  const { out } = await signUp(svc, 'alice');
  const token = out.sessionToken!;
  assert.equal((await svc.me(token, T0 + LIMITS.sessionTtlMs - 1)).username, 'alice');
  await rejects(svc.me(token, T0 + LIMITS.sessionTtlMs + 1), 401, 'unauthenticated');
  const fresh = await signUp(svc, 'bob');
  await svc.logout(fresh.out.sessionToken, T0);
  await rejects(svc.me(fresh.out.sessionToken, T0), 401, 'unauthenticated');
  for (const bad of [undefined, '', 'x', 'a'.repeat(44), '!'.repeat(43)]) await rejects(svc.me(bad as string, T0), 401, 'unauthenticated');
  await svc.logout(undefined, T0); // выход без сессии не падает
});

test('удаление ключей: чужой ключ и последний ключ удалить нельзя', async () => {
  const svc = new AuthService(new MapStore());
  const first = await signUp(svc, 'alice');
  const bob = await signUp(svc, 'bob');
  await rejects(svc.deleteCredential(first.out.sessionToken, first.auth.id, T0), 409, 'last_credential');
  await rejects(svc.deleteCredential(first.out.sessionToken, bob.auth.id, T0), 404, 'not_found');
  await rejects(svc.deleteCredential(undefined, first.auth.id, T0), 401, 'unauthenticated');
  const opts = await svc.registerOptions(ctx(), { username: 'alice' }, first.out.sessionToken);
  const second = await SoftAuthenticator.make('es256', RP);
  await svc.registerVerify(ctx(), { challengeId: opts.challengeId, credential: await second.create({ challenge: opts.options.challenge, origin: ORIGIN }) }, first.out.sessionToken);
  await svc.deleteCredential(first.out.sessionToken, first.auth.id, T0);
  assert.equal((await svc.me(first.out.sessionToken, T0)).credentials.length, 1);
  await rejects(signIn(svc, first.auth, first.userId, T0 + 1), 401, 'login_failed'); // удалённым ключом войти нельзя
});
