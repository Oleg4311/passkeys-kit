// Дифференциальная проверка: независимая реализация @simplewebauthn/server и наша получают одни и те же ответы (корректные и испорченные)
// и должны выносить одинаковый вердикт. Расхождения допустимы только из явного списка с объяснением.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateAuthenticationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import { fromBase64Url, toBase64Url } from '../src/bytes.ts';
import { verifyAuthentication, verifyRegistration } from '../src/webauthn.ts';
import type { AuthenticationResponse, RegistrationResponse } from '../src/webauthn.ts';
import { SoftAuthenticator } from './softauth.ts';
import type { Kind, Options } from './softauth.ts';

void generateAuthenticationOptions;

const RP = 'example.test';
const ORIGIN = 'https://example.test';
const CH = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));

interface Verdict {
  ours: boolean;
  theirs: boolean;
}

async function ours<T>(p: Promise<T>): Promise<boolean> {
  try {
    await p;
    return true;
  } catch (e) {
    if ((e as { code?: string }).code === undefined) throw e; // неожиданное исключение — это уже наша ошибка
    return false;
  }
}
async function theirs(p: Promise<{ verified: boolean }>): Promise<boolean> {
  try {
    return (await p).verified;
  } catch {
    return false;
  }
}

const disagreements: string[] = [];
let compared = 0;
let acceptedBoth = 0;
let rejectedBoth = 0;
const KNOWN: Record<string, string> = {
  'registration: вложенный фрейм (crossOrigin)': 'SimpleWebAuthn проверяет crossOrigin только вместе с expectedTopOrigin; мы отклоняем любой crossOrigin: true',
  'authentication: вложенный фрейм (crossOrigin)': 'то же',
  'authentication: BE изменился': 'мы требуем неизменности признака BE (W3C 7.2, шаг 18+); SimpleWebAuthn этого не требует',
  'registration: BS без BE': 'мы отклоняем невозможное сочетание флагов; SimpleWebAuthn принимает',
  'authentication: BS без BE': 'то же',
};

let envelopeStricter = 0;

function record(name: string, v: Verdict, envelope = false): void {
  compared++;
  if (v.ours === v.theirs) {
    if (v.ours) acceptedBoth++;
    else rejectedBoth++;
    return;
  }
  if (KNOWN[name] && v.ours === false) return; // мы строже: это осознанное расхождение
  if (envelope && v.ours === false) {
    envelopeStricter++; // порча только DER-оболочки подписи (тег, длина): SimpleWebAuthn её не замечает, мы отклоняем
    return;
  }
  disagreements.push(`${name}: наша=${v.ours ? 'принято' : 'отклонено'}, SimpleWebAuthn=${v.theirs ? 'принято' : 'отклонено'}`);
}

const kinds: Kind[] = ['es256', 'ed25519', 'rs256'];
const keyCache = new Map<Kind, SoftAuthenticator>();
async function auth(kind: Kind, o: { be?: boolean; bs?: boolean } = {}): Promise<SoftAuthenticator> {
  if (o.be !== undefined || o.bs !== undefined) return SoftAuthenticator.make(kind, RP, o);
  if (!keyCache.has(kind)) keyCache.set(kind, await SoftAuthenticator.make(kind, RP));
  const a = keyCache.get(kind)!;
  a.counter = 0;
  return a;
}

async function compareRegistration(name: string, resp: RegistrationResponse, o: { challenge?: string; origin?: string; rpId?: string; requireUV?: boolean; envelope?: boolean } = {}): Promise<void> {
  const challenge = o.challenge ?? CH;
  const origin = o.origin ?? ORIGIN;
  const rpId = o.rpId ?? RP;
  const requireUV = o.requireUV ?? true;
  const a = await ours(verifyRegistration(resp, { challenge, origins: [origin], rpId, requireUV }));
  const b = await theirs(verifyRegistrationResponse({ response: resp as never, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpId, requireUserVerification: requireUV }));
  record(`registration: ${name}`, { ours: a, theirs: b }, o.envelope);
}

async function compareAuthentication(name: string, a: SoftAuthenticator, resp: AuthenticationResponse, o: { challenge?: string; origin?: string; rpId?: string; requireUV?: boolean; counter?: number; be?: boolean; envelope?: boolean } = {}): Promise<void> {
  const challenge = o.challenge ?? CH;
  const origin = o.origin ?? ORIGIN;
  const rpId = o.rpId ?? RP;
  const requireUV = o.requireUV ?? true;
  const counter = o.counter ?? 0;
  const publicKey = toBase64Url(a.coseKey);
  const mine = await ours(verifyAuthentication(resp, { challenge, origins: [origin], rpId, requireUV, credential: { id: a.id, publicKey, signCount: counter, backupEligible: o.be ?? a.be } }));
  const other = await theirs(verifyAuthenticationResponse({ response: resp as never, expectedChallenge: challenge, expectedOrigin: origin, expectedRPID: rpId, requireUserVerification: requireUV, credential: { id: a.id, publicKey: a.coseKey as never, counter } }));
  record(`authentication: ${name}`, { ours: mine, theirs: other }, o.envelope);
}

/** Попадает ли байт `i` подписи DER в «оболочку»: тег и длина всей последовательности, тег и длина r, тег и длина s. */
function inEnvelope(i: number, sig: Uint8Array): boolean {
  if (sig[0] !== 0x30) return false;
  const rLen = sig[3] ?? 0;
  return [0, 1, 2, 3, 4 + rLen, 5 + rLen].includes(i);
}

/** То же для подписи внутри attestationObject формата packed (ключ «sig», затем 0x58 и длина). */
function envelopeAt(att: Uint8Array, at: number): boolean {
  for (let k = 0; k + 6 < att.length; k++) {
    if (att[k] === 0x63 && att[k + 1] === 0x73 && att[k + 2] === 0x69 && att[k + 3] === 0x67 && att[k + 4] === 0x58) {
      const start = k + 6;
      return at >= start && inEnvelope(at - start, att.slice(start, start + att[k + 5]!));
    }
  }
  return false;
}

const flip = (b64: string, byte: number, bit: number): string => {
  const bytes = fromBase64Url(b64);
  bytes[byte % bytes.length]! ^= 1 << bit;
  return toBase64Url(bytes);
};

const regMutations: Array<[string, Partial<Options>]> = [
  ['чужой challenge', { challenge: toBase64Url(new Uint8Array(32)) }],
  ['чужой origin', { origin: 'https://evil.test' }],
  ['другой порт', { origin: 'https://example.test:8443' }],
  ['http вместо https', { origin: 'http://example.test' }],
  ['вложенный фрейм (crossOrigin)', { crossOrigin: true }],
  ['тип get', { type: 'webauthn.get' }],
  ['чужой rpId', { rpId: 'evil.test' }],
  ['нет присутствия', { flags: 0x44 }],
  ['нет проверки пользователя', { flags: 0x41 }],
  ['нет AT', { flags: 0x05 }],
  ['BS без BE', { flags: 0x01 | 0x04 | 0x40 | 0x10 }],
  ['неподдерживаемая аттестация', { fmt: 'other' }],
];

test('регистрация: вердикты совпадают на корректных ответах и на 12 видах порчи, для трёх алгоритмов и двух форматов', async () => {
  for (const kind of kinds) {
    for (const fmt of ['none', 'packed'] as const) {
      const a = await auth(kind);
      await compareRegistration(`${kind}/${fmt} корректный`, await a.create({ challenge: CH, origin: ORIGIN, fmt }));
      for (const [name, m] of regMutations) await compareRegistration(`${name}`, await a.create({ challenge: CH, origin: ORIGIN, fmt, ...m }));
      await compareRegistration('requireUV: UV есть', await a.create({ challenge: CH, origin: ORIGIN, fmt }), { requireUV: true });
      await compareRegistration('ожидается другой rpId', await a.create({ challenge: CH, origin: ORIGIN, fmt }), { rpId: 'evil.test' });
      await compareRegistration('ожидается другой origin', await a.create({ challenge: CH, origin: ORIGIN, fmt }), { origin: 'https://evil.test' });
      await compareRegistration('ожидается другой challenge', await a.create({ challenge: CH, origin: ORIGIN, fmt }), { challenge: toBase64Url(new Uint8Array(32)) });
    }
  }
  const noUV = await SoftAuthenticator.make('es256', RP, { uv: false });
  await compareRegistration('аутентификатор без UV, UV требуется', await noUV.create({ challenge: CH, origin: ORIGIN }), { requireUV: true });
  await compareRegistration('аутентификатор без UV, UV не требуется', await noUV.create({ challenge: CH, origin: ORIGIN }), { requireUV: false });
  const synced = await auth('es256', { be: true, bs: true });
  await compareRegistration('синхронизируемый ключ', await synced.create({ challenge: CH, origin: ORIGIN }));
});

test('регистрация: побитовая порча каждого поля ответа (по 60 случаев на поле) даёт одинаковый вердикт', async () => {
  const a = await auth('es256');
  const good = await a.create({ challenge: CH, origin: ORIGIN, fmt: 'packed' });
  for (const field of ['clientDataJSON', 'attestationObject'] as const) {
    const len = fromBase64Url(good.response[field]).length;
    for (let i = 0; i < 60; i++) {
      const at = Math.floor((i * len) / 60);
      const resp = { ...good, response: { ...good.response, [field]: flip(good.response[field], at, i % 8) } };
      const envelope = field === 'attestationObject' && envelopeAt(fromBase64Url(good.response.attestationObject), at);
      await compareRegistration(`порча ${field} #${i}`, resp, { envelope });
    }
  }
});

const authMutations: Array<[string, Partial<Options>]> = [
  ['чужой challenge', { challenge: toBase64Url(new Uint8Array(32)) }],
  ['чужой origin', { origin: 'https://evil.test' }],
  ['тип create', { type: 'webauthn.create' }],
  ['чужой rpId', { rpId: 'evil.test' }],
  ['нет присутствия', { flags: 0x04 }],
  ['нет проверки пользователя', { flags: 0x01 }],
  ['вложенный фрейм (crossOrigin)', { crossOrigin: true }],
  ['BE изменился', { flags: 0x05 | 0x08 }],
  ['BS без BE', { flags: 0x05 | 0x10 }],
];

test('вход: вердикты совпадают на корректных ответах и на видах порчи, для трёх алгоритмов', async () => {
  for (const kind of kinds) {
    const a = await auth(kind);
    await compareAuthentication(`${kind} корректный`, a, await a.get({ challenge: CH, origin: ORIGIN }));
    for (const [name, m] of authMutations) {
      a.counter = 0;
      await compareAuthentication(name, a, await a.get({ challenge: CH, origin: ORIGIN, ...m }));
    }
    for (const stored of [0, 5, 10]) {
      for (const sent of [0, 4, 5, 6, 11]) {
        a.counter = 0;
        await compareAuthentication(`счётчик хранится ${stored}, пришёл ${sent}`, a, await a.get({ challenge: CH, origin: ORIGIN, signCount: sent }), { counter: stored });
      }
    }
    a.counter = 0;
    await compareAuthentication('ожидается другой rpId', a, await a.get({ challenge: CH, origin: ORIGIN }), { rpId: 'evil.test' });
    await compareAuthentication('ожидается другой challenge', a, await a.get({ challenge: CH, origin: ORIGIN }), { challenge: toBase64Url(new Uint8Array(32)) });
  }
  const noUV = await SoftAuthenticator.make('es256', RP, { uv: false });
  await compareAuthentication('без UV, UV требуется', noUV, await noUV.get({ challenge: CH, origin: ORIGIN }), { requireUV: true });
  await compareAuthentication('без UV, UV не требуется', noUV, await noUV.get({ challenge: CH, origin: ORIGIN }), { requireUV: false });
});

test('вход: побитовая порча подписи, authenticatorData и clientDataJSON даёт одинаковый вердикт', async () => {
  for (const kind of kinds) {
    const a = await auth(kind);
    const good = await a.get({ challenge: CH, origin: ORIGIN });
    for (const field of ['signature', 'authenticatorData', 'clientDataJSON'] as const) {
      const len = fromBase64Url(good.response[field]).length;
      for (let i = 0; i < 40; i++) {
        a.counter = 0;
        const at = Math.floor((i * len) / 40);
        const resp = { ...good, response: { ...good.response, [field]: flip(good.response[field], at, i % 8) } };
        const envelope = field === 'signature' && kind === 'es256' && inEnvelope(at, fromBase64Url(good.response.signature));
        await compareAuthentication(`${kind}: порча ${field} #${i}`, a, resp, { envelope });
      }
    }
  }
});

test('находка сверки: SimpleWebAuthn принимает подпись с испорченной DER-оболочкой, мы отклоняем', async () => {
  const a = await auth('es256');
  const good = await a.get({ challenge: CH, origin: ORIGIN });
  const sig = fromBase64Url(good.response.signature);
  const variants: Array<[string, Uint8Array]> = [
    ['лишние байты после подписи', Uint8Array.from([...sig, 0, 0, 0])],
    ['неверный тег последовательности', Uint8Array.from([0xb0, ...sig.slice(1)])],
  ];
  const seen: string[] = [];
  for (const [name, bad] of variants) {
    const resp = { ...good, response: { ...good.response, signature: toBase64Url(bad) } };
    a.counter = 0;
    const mine = await ours(verifyAuthentication(resp, { challenge: CH, origins: [ORIGIN], rpId: RP, credential: { id: a.id, publicKey: toBase64Url(a.coseKey), signCount: 0, backupEligible: false } }));
    assert.equal(mine, false, `${name}: мы обязаны отклонить`);
    const other = await theirs(verifyAuthenticationResponse({ response: resp as never, expectedChallenge: CH, expectedOrigin: ORIGIN, expectedRPID: RP, credential: { id: a.id, publicKey: a.coseKey as never, counter: 0 } }));
    seen.push(`${name}: SimpleWebAuthn ${other ? 'принимает' : 'отклоняет'}`);
  }
  console.log(seen.join('; '));
});

test('итог сверки: расхождений вне списка нет, оба варианта принимают и отклоняют достаточно часто', () => {
  console.log(`сравнено ${compared} случаев: принято обеими ${acceptedBoth}, отклонено обеими ${rejectedBoth}, строже у нас осознанно ${compared - acceptedBoth - rejectedBoth - disagreements.length} (из них порча только DER-оболочки подписи: ${envelopeStricter})`);
  assert.deepEqual(disagreements, []);
  assert.ok(compared > 600, `сравнено только ${compared}`);
  assert.ok(acceptedBoth >= 20, 'мало случаев, где обе приняли (проверка могла выродиться в «всё отклонять»)');
  assert.ok(rejectedBoth > 400);
});
