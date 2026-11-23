// Сервис входа по passkey: одноразовые challenge, пользователи, ключи, сессии. Чистая логика над абстрактным хранилищем:
// в Worker под ней Durable Object, в тестах обычный Map.

import { WebAuthnError, sha256, toBase64Url } from './bytes.ts';
import { verifyAuthentication, verifyRegistration } from './webauthn.ts';
import type { AuthenticationResponse, RegistrationResponse } from './webauthn.ts';

export const LIMITS = { challengeTtlMs: 5 * 60_000, sessionTtlMs: 7 * 24 * 3600_000, maxCredentials: 10, usernameMin: 3, usernameMax: 32 } as const;

export class HttpError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

export interface Store {
  get<T>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
}

export interface Context {
  rpId: string;
  origin: string;
  now: number;
}

interface Credential {
  id: string;
  publicKey: string;
  signCount: number;
  backupEligible: boolean;
  backedUp: boolean;
  transports: string[];
  aaguid: string;
  createdAt: number;
  lastUsedAt: number | null;
  /** Ставится при подозрении на клон: вход этим ключом закрыт, пока пользователь его не удалит. */
  lockedAt: number | null;
}
interface User {
  id: string;
  username: string;
  createdAt: number;
  credentials: Credential[];
}
interface Challenge {
  challenge: string;
  kind: 'reg' | 'auth';
  username?: string;
  userId?: string;
  expiresAt: number;
}
interface Session {
  username: string;
  expiresAt: number;
}

const rand = (n: number): string => toBase64Url(crypto.getRandomValues(new Uint8Array(n)));
const sessionKey = async (token: string): Promise<string> => 'sess:' + toBase64Url(await sha256(new TextEncoder().encode(token)));

export function normalizeUsername(v: unknown): string {
  if (typeof v !== 'string') throw new HttpError(400, 'bad_username', 'Имя пользователя должно быть строкой.');
  const s = v.trim().toLowerCase();
  if (s.length < LIMITS.usernameMin || s.length > LIMITS.usernameMax || !/^[a-z0-9][a-z0-9._-]*$/.test(s)) {
    throw new HttpError(400, 'bad_username', `Имя: от ${LIMITS.usernameMin} до ${LIMITS.usernameMax} знаков, латиница, цифры, точка, дефис и подчёркивание, начинается с буквы или цифры.`);
  }
  return s;
}

export class AuthService {
  private readonly store: Store;
  constructor(store: Store) {
    this.store = store;
  }

  private async takeChallenge(id: unknown, kind: Challenge['kind'], now: number): Promise<Challenge> {
    if (typeof id !== 'string' || !/^[A-Za-z0-9_-]{20,24}$/.test(id)) throw new HttpError(400, 'bad_challenge', 'Неверный идентификатор запроса.');
    const key = 'chal:' + id;
    const c = await this.store.get<Challenge>(key);
    await this.store.delete(key); // одноразовый: удаляется при любой попытке, успешной или нет
    if (!c || c.kind !== kind) throw new HttpError(400, 'challenge_unknown', 'Запрос не найден или уже использован. Начните заново.');
    if (c.expiresAt < now) throw new HttpError(400, 'challenge_expired', 'Время запроса вышло. Начните заново.');
    return c;
  }

  private async session(token: string | undefined, now: number): Promise<{ user: User; key: string } | null> {
    if (!token || !/^[A-Za-z0-9_-]{40,50}$/.test(token)) return null;
    const key = await sessionKey(token);
    const s = await this.store.get<Session>(key);
    if (!s) return null;
    if (s.expiresAt < now) {
      await this.store.delete(key);
      return null;
    }
    const user = await this.store.get<User>('user:' + s.username);
    return user ? { user, key } : null;
  }

  private async newSession(username: string, now: number): Promise<string> {
    const token = rand(32);
    await this.store.put(await sessionKey(token), { username, expiresAt: now + LIMITS.sessionTtlMs } satisfies Session);
    return token;
  }

  async registerOptions(ctx: Context, body: unknown, sessionToken: string | undefined) {
    const username = normalizeUsername((body as { username?: unknown } | null)?.username);
    const sess = await this.session(sessionToken, ctx.now);
    const existing = await this.store.get<User>('user:' + username);
    let userId: string;
    let exclude: Array<{ type: 'public-key'; id: string }> = [];
    if (existing) {
      if (sess?.user.username !== username) throw new HttpError(409, 'username_taken', 'Это имя уже занято. Если оно ваше, войдите и добавьте ключ из аккаунта.');
      if (existing.credentials.length >= LIMITS.maxCredentials) throw new HttpError(409, 'too_many_credentials', `Можно хранить не больше ${LIMITS.maxCredentials} ключей.`);
      userId = existing.id;
      exclude = existing.credentials.map((c) => ({ type: 'public-key', id: c.id }));
    } else {
      userId = rand(16);
    }
    const challenge = rand(32);
    const challengeId = rand(16);
    await this.store.put('chal:' + challengeId, { challenge, kind: 'reg', username, userId, expiresAt: ctx.now + LIMITS.challengeTtlMs } satisfies Challenge);
    return {
      challengeId,
      options: {
        rp: { id: ctx.rpId, name: 'passkeys-kit' },
        user: { id: userId, name: username, displayName: username },
        challenge,
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }, { type: 'public-key', alg: -257 }],
        timeout: LIMITS.challengeTtlMs,
        attestation: 'none',
        excludeCredentials: exclude,
        authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
      },
    };
  }

  async registerVerify(ctx: Context, body: unknown, sessionToken: string | undefined) {
    const b = (body ?? {}) as { challengeId?: unknown; credential?: unknown };
    const chal = await this.takeChallenge(b.challengeId, 'reg', ctx.now);
    const sess = await this.session(sessionToken, ctx.now);
    let cred;
    try {
      cred = await verifyRegistration(b.credential as RegistrationResponse, { challenge: chal.challenge, origins: [ctx.origin], rpId: ctx.rpId, requireUV: true });
    } catch (e) {
      if (e instanceof WebAuthnError) throw new HttpError(400, e.code, e.message);
      throw e;
    }
    // Токен готовим заранее: между чтением пользователя и его записью не должно быть пауз на не-хранилищные операции,
    // иначе два параллельных запроса оба увидят «имя свободно».
    const token = rand(32);
    const sessKey = await sessionKey(token);
    if (await this.store.get('cred:' + cred.id)) throw new HttpError(409, 'credential_exists', 'Этот ключ уже зарегистрирован.');
    const username = chal.username!;
    let user = await this.store.get<User>('user:' + username);
    const record: Credential = { id: cred.id, publicKey: cred.publicKey, signCount: cred.signCount, backupEligible: cred.backupEligible, backedUp: cred.backedUp, transports: cred.transports, aaguid: cred.aaguid, createdAt: ctx.now, lastUsedAt: null, lockedAt: null };
    let created = false;
    if (user) {
      if (sess?.user.username !== username || user.id !== chal.userId) throw new HttpError(409, 'username_taken', 'Это имя уже занято.');
      if (user.credentials.length >= LIMITS.maxCredentials) throw new HttpError(409, 'too_many_credentials', `Можно хранить не больше ${LIMITS.maxCredentials} ключей.`);
      user.credentials.push(record);
    } else {
      user = { id: chal.userId!, username, createdAt: ctx.now, credentials: [record] };
      created = true;
    }
    await this.store.put('user:' + username, user);
    await this.store.put('cred:' + cred.id, { username });
    if (created) await this.store.put(sessKey, { username, expiresAt: ctx.now + LIMITS.sessionTtlMs } satisfies Session);
    return { username, credentialId: cred.id, ...(created ? { sessionToken: token } : {}) };
  }

  async loginOptions(ctx: Context) {
    const challenge = rand(32);
    const challengeId = rand(16);
    await this.store.put('chal:' + challengeId, { challenge, kind: 'auth', expiresAt: ctx.now + LIMITS.challengeTtlMs } satisfies Challenge);
    // без списка допустимых ключей: устройство само предложит нужный (discoverable credentials), поэтому по запросу нельзя узнать, есть ли такой пользователь
    return { challengeId, options: { challenge, rpId: ctx.rpId, timeout: LIMITS.challengeTtlMs, userVerification: 'required', allowCredentials: [] } };
  }

  async loginVerify(ctx: Context, body: unknown) {
    const b = (body ?? {}) as { challengeId?: unknown; credential?: unknown };
    const chal = await this.takeChallenge(b.challengeId, 'auth', ctx.now);
    const resp = b.credential as AuthenticationResponse;
    const id = (resp as { id?: unknown } | null)?.id;
    const generic = new HttpError(401, 'login_failed', 'Вход не удался: ключ не найден или проверка не пройдена.');
    if (typeof id !== 'string') throw generic;
    const ref = await this.store.get<{ username: string }>('cred:' + id);
    const user = ref ? await this.store.get<User>('user:' + ref.username) : undefined;
    const cred = user?.credentials.find((c) => c.id === id);
    if (!user || !cred) throw generic;
    if (cred.lockedAt !== null) throw new HttpError(403, 'credential_locked', 'Этот ключ заблокирован: ранее счётчик подписей вёл себя как у копии. Удалите ключ и добавьте заново.');
    let result;
    try {
      result = await verifyAuthentication(resp, { challenge: chal.challenge, origins: [ctx.origin], rpId: ctx.rpId, requireUV: true, credential: { id: cred.id, publicKey: cred.publicKey, signCount: cred.signCount, backupEligible: cred.backupEligible } });
    } catch (e) {
      if (e instanceof WebAuthnError) {
        if (e.code === 'counter_regression') {
          const fresh = await this.store.get<User>('user:' + user.username);
          const target = fresh?.credentials.find((c) => c.id === id);
          if (fresh && target) {
            target.lockedAt = ctx.now;
            await this.store.put('user:' + user.username, fresh);
          }
          throw new HttpError(403, 'counter_regression', 'Счётчик подписей не вырос: возможно, ключ скопирован. Ключ заблокирован.');
        }
        throw new HttpError(401, 'login_failed', `Вход не удался: ${e.message}`);
      }
      throw e;
    }
    // найденный ключ должен принадлежать пользователю, чей идентификатор вернуло устройство (защита от подмены userHandle)
    if (result.userHandle === null || result.userHandle !== user.id) throw generic;
    const fresh = (await this.store.get<User>('user:' + user.username)) ?? user;
    const target = fresh.credentials.find((c) => c.id === id);
    if (!target) throw generic;
    if (result.signCount <= target.signCount && (result.signCount !== 0 || target.signCount !== 0)) throw new HttpError(409, 'race', 'Параллельный вход этим же ключом, повторите.');
    target.signCount = result.signCount;
    target.backedUp = result.backedUp;
    target.lastUsedAt = ctx.now;
    await this.store.put('user:' + fresh.username, fresh);
    return { username: fresh.username, sessionToken: await this.newSession(fresh.username, ctx.now) };
  }

  async me(token: string | undefined, now: number) {
    const s = await this.session(token, now);
    if (!s) throw new HttpError(401, 'unauthenticated', 'Нужно войти.');
    return {
      username: s.user.username,
      credentials: s.user.credentials.map((c) => ({ id: c.id, createdAt: c.createdAt, lastUsedAt: c.lastUsedAt, backedUp: c.backedUp, backupEligible: c.backupEligible, transports: c.transports, locked: c.lockedAt !== null, signCount: c.signCount })),
    };
  }

  async logout(token: string | undefined, now: number): Promise<void> {
    const s = await this.session(token, now);
    if (s) await this.store.delete(s.key);
  }

  async deleteCredential(token: string | undefined, id: string, now: number): Promise<void> {
    const s = await this.session(token, now);
    if (!s) throw new HttpError(401, 'unauthenticated', 'Нужно войти.');
    const user = await this.store.get<User>('user:' + s.user.username);
    const idx = user?.credentials.findIndex((c) => c.id === id) ?? -1;
    if (!user || idx < 0) throw new HttpError(404, 'not_found', 'Такого ключа у вас нет.');
    if (user.credentials.length === 1) throw new HttpError(409, 'last_credential', 'Нельзя удалить последний ключ: вы потеряете доступ. Сначала добавьте другой.');
    user.credentials.splice(idx, 1);
    await this.store.put('user:' + user.username, user);
    await this.store.delete('cred:' + id);
  }
}
