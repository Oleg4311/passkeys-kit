// Worker: маршруты API входа по passkey, защита от CSRF, куки сессии, заголовки безопасности. Состояние хранит Durable Object.

import { AuthService, HttpError } from '../src/service.ts';
import type { Context, Store } from '../src/service.ts';

export interface Env {
  AUTH: DurableObjectNamespace;
  ASSETS: Fetcher;
  /** Попыток регистрации и входа в минуту с одного адреса (по умолчанию 120; повышается для e2e-прогонов). */
  RATE_PER_MINUTE?: string;
}

const MAX_BODY = 16 * 1024;
const COOKIE = '__Host-sid';
const DEFAULT_RATE = 120;
const API_HEADERS = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const PAGE_HEADERS: Record<string, string> = {
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'publickey-credentials-get=(self), publickey-credentials-create=(self), camera=(), microphone=(), geolocation=()',
  'cross-origin-opener-policy': 'same-origin',
};

const json = (data: unknown, status = 200, headers: Record<string, string> = {}): Response => new Response(JSON.stringify(data), { status, headers: { ...API_HEADERS, ...headers } });
const fail = (e: HttpError, headers: Record<string, string> = {}): Response => json({ error: e.code, message: e.message }, e.status, headers);

function cookieOf(req: Request): string | undefined {
  for (const part of (req.headers.get('cookie') ?? '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === COOKIE) return v.join('=');
  }
  return undefined;
}

const setCookie = (token: string, maxAgeSec: number): string => `${COOKIE}=${token}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; Secure; SameSite=Strict`;

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    const url = new URL(req.url);
    if (!url.pathname.startsWith('/api/')) {
      const res = await env.ASSETS.fetch(req);
      const out = new Response(res.body, res);
      for (const [k, v] of Object.entries(PAGE_HEADERS)) out.headers.set(k, v);
      return out;
    }
    try {
      if (url.pathname === '/api/health') return json({ ok: true });
      if (req.method !== 'GET') {
        // CSRF: запросы, меняющие состояние, принимаются только со своей страницы и только как JSON
        if (req.headers.get('origin') !== url.origin) return json({ error: 'forbidden_origin', message: 'Запрос не со страницы сервиса.' }, 403);
        if (req.method === 'POST' && !(req.headers.get('content-type') ?? '').startsWith('application/json')) return json({ error: 'bad_content_type', message: 'Нужен application/json.' }, 415);
        if (Number(req.headers.get('content-length') ?? '0') > MAX_BODY) return json({ error: 'too_large', message: 'Слишком большой запрос.' }, 413);
      }
      const res = await env.AUTH.get(env.AUTH.idFromName('main')).fetch(req);
      return new Response(res.body, { status: res.status, headers: res.headers });
    } catch {
      return json({ error: 'internal', message: 'Внутренняя ошибка.' }, 500);
    }
  },
};

/** Один объект на всё приложение: простая модель, последовательная обработка. Для большой нагрузки данные нужно делить по пользователям. */
export class AuthDO {
  private readonly ctx: DurableObjectState;
  private readonly svc: AuthService;
  private readonly hits = new Map<string, number[]>();
  private readonly rate: number;

  constructor(ctx: DurableObjectState, env: Env) {
    this.ctx = ctx;
    const r = Number(env.RATE_PER_MINUTE);
    this.rate = Number.isFinite(r) && r > 0 ? r : DEFAULT_RATE;
    const storage = ctx.storage;
    const store: Store = {
      get: (k) => storage.get(k) as Promise<never>,
      put: async (k, v) => {
        await storage.put(k, v);
        if ((await storage.getAlarm()) === null) await storage.setAlarm(Date.now() + 3600_000);
      },
      delete: async (k) => {
        await storage.delete(k);
      },
    };
    this.svc = new AuthService(store);
  }

  private limited(ip: string, now: number): boolean {
    const recent = (this.hits.get(ip) ?? []).filter((t) => now - t < 60_000);
    recent.push(now);
    this.hits.set(ip, recent);
    if (this.hits.size > 5000) for (const [k, v] of this.hits) if (v.every((t) => now - t >= 60_000)) this.hits.delete(k);
    return recent.length > this.rate;
  }

  async fetch(req: Request): Promise<Response> {
    const url = new URL(req.url);
    const now = Date.now();
    const c: Context = { rpId: url.hostname, origin: url.origin, now };
    const token = cookieOf(req);
    const path = url.pathname;
    try {
      let body: unknown;
      if (req.method === 'POST') {
        const text = await req.text();
        if (text.length > MAX_BODY) throw new HttpError(413, 'too_large', 'Слишком большой запрос.');
        try {
          body = text === '' ? {} : JSON.parse(text);
        } catch {
          throw new HttpError(400, 'bad_request', 'Неверный JSON.');
        }
      }
      if (req.method === 'POST' && /^\/api\/(register|login)\//.test(path) && this.limited(req.headers.get('cf-connecting-ip') ?? 'local', now)) {
        return json({ error: 'rate_limited', message: 'Слишком много попыток, подождите минуту.' }, 429, { 'retry-after': '60' });
      }
      if (req.method === 'POST' && path === '/api/register/options') return json(await this.svc.registerOptions(c, body, token));
      if (req.method === 'POST' && path === '/api/register/verify') {
        const r = await this.svc.registerVerify(c, body, token);
        const { sessionToken, ...rest } = r as typeof r & { sessionToken?: string };
        return json(rest, 200, sessionToken ? { 'set-cookie': setCookie(sessionToken, 7 * 24 * 3600) } : {});
      }
      if (req.method === 'POST' && path === '/api/login/options') return json(await this.svc.loginOptions(c));
      if (req.method === 'POST' && path === '/api/login/verify') {
        const { sessionToken, ...rest } = await this.svc.loginVerify(c, body);
        return json(rest, 200, { 'set-cookie': setCookie(sessionToken, 7 * 24 * 3600) });
      }
      if (req.method === 'GET' && path === '/api/me') return json(await this.svc.me(token, now));
      if (req.method === 'POST' && path === '/api/logout') {
        await this.svc.logout(token, now);
        return json({ ok: true }, 200, { 'set-cookie': setCookie('', 0) });
      }
      const m = /^\/api\/credentials\/([A-Za-z0-9_-]{1,1400})$/.exec(path);
      if (req.method === 'DELETE' && m) {
        await this.svc.deleteCredential(token, m[1]!, now);
        return json({ ok: true });
      }
      return json({ error: 'not_found', message: 'Не найдено.' }, 404);
    } catch (e) {
      if (e instanceof HttpError) return fail(e);
      return json({ error: 'internal', message: 'Внутренняя ошибка.' }, 500);
    }
  }

  /** Раз в час убирает просроченные challenge и сессии. */
  async alarm(): Promise<void> {
    const now = Date.now();
    let remaining = 0;
    for (const prefix of ['chal:', 'sess:']) {
      const all = await this.ctx.storage.list<{ expiresAt: number }>({ prefix });
      for (const [k, v] of all) {
        if (v.expiresAt < now) await this.ctx.storage.delete(k);
        else remaining++;
      }
    }
    if (remaining > 0) await this.ctx.storage.setAlarm(now + 3600_000);
  }
}
