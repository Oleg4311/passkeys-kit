import assert from 'node:assert/strict';
import { test } from 'node:test';
import { toBase64Url } from '../src/bytes.ts';
import { importCoseKey } from '../src/cose.ts';
import { parseAuthData, verifyAuthentication, verifyRegistration } from '../src/webauthn.ts';
import type { AuthenticationExpect, RegistrationExpect, RegistrationResponse, StoredCredential } from '../src/webauthn.ts';
import { SoftAuthenticator, encodeCbor } from './softauth.ts';
import type { Kind, Options } from './softauth.ts';

const RP = 'example.test';
const ORIGIN = 'https://example.test';
const CH = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
const regExpect = (o: Partial<RegistrationExpect> = {}): RegistrationExpect => ({ challenge: CH, origins: [ORIGIN], rpId: RP, ...o });

const cache = new Map<Kind, Promise<SoftAuthenticator>>();
const auth = (kind: Kind, opts: { uv?: boolean; be?: boolean; bs?: boolean } = {}): Promise<SoftAuthenticator> => {
  if (opts.uv === undefined && opts.be === undefined && opts.bs === undefined) {
    // ключи RSA дорогие: переиспользуем один и тот же, но счётчик сбрасываем
    if (!cache.has(kind)) cache.set(kind, SoftAuthenticator.make(kind, RP));
    return cache.get(kind)!.then((a) => {
      a.counter = 0;
      return a;
    });
  }
  return SoftAuthenticator.make(kind, RP, opts);
};

async function registered(a: SoftAuthenticator, o: Partial<Options> = {}) {
  return verifyRegistration(await a.create({ challenge: CH, origin: ORIGIN, ...o }), regExpect());
}

const stored = (c: Awaited<ReturnType<typeof registered>>): StoredCredential => ({ id: c.id, publicKey: c.publicKey, signCount: c.signCount, backupEligible: c.backupEligible });
const authExpect = (cred: StoredCredential, o: Partial<AuthenticationExpect> = {}): AuthenticationExpect => ({ challenge: CH, origins: [ORIGIN], rpId: RP, credential: cred, ...o });

async function rejects(p: Promise<unknown>, code: string): Promise<void> {
  try {
    await p;
  } catch (e) {
    assert.equal((e as { code?: string }).code, code, e instanceof Error ? e.message : String(e));
    return;
  }
  assert.fail(`ожидалась ошибка ${code}`);
}

for (const kind of ['es256', 'ed25519', 'rs256'] as const) {
  for (const fmt of ['none', 'packed'] as const) {
    test(`${kind}, аттестация ${fmt}: регистрация и вход проходят`, async () => {
      const a = await auth(kind);
      const c = await registered(a, { fmt });
      assert.equal(c.id, a.id);
      assert.equal(c.alg, a.alg);
      assert.equal(c.attestationFormat, fmt === 'none' ? 'none' : 'packed-self');
      assert.equal(c.userVerified, true);
      assert.equal(c.signCount, 0);
      const ok = await verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN }), authExpect(stored(c), { requireUV: true }));
      assert.equal(ok.signCount, 1);
      assert.equal(ok.userHandle, null);
    });
  }
}

test('флаги резервного копирования и имя транспорта сохраняются; недопустимое сочетание BS без BE отклоняется', async () => {
  const synced = await SoftAuthenticator.make('es256', RP, { be: true, bs: true });
  const c = await registered(synced);
  assert.deepEqual([c.backupEligible, c.backedUp, c.transports], [true, true, ['internal']]);
  const weird = await SoftAuthenticator.make('es256', RP, { be: false, bs: true });
  await rejects(registered(weird), 'invalid_backup_flags');
});

test('регистрация: каждый вид порчи отклоняется со своим кодом', async () => {
  const a = await auth('es256');
  const cases: Array<[string, Partial<Options>, Partial<RegistrationExpect>, string]> = [
    ['чужой challenge', { challenge: toBase64Url(new Uint8Array(32)) }, {}, 'challenge_mismatch'],
    ['чужой origin', { origin: 'https://evil.test' }, {}, 'origin_mismatch'],
    ['origin с другим портом', { origin: 'https://example.test:8443' }, {}, 'origin_mismatch'],
    ['тот же домен по http', { origin: 'http://example.test' }, {}, 'origin_mismatch'],
    ['вложенный фрейм', { crossOrigin: true }, {}, 'cross_origin'],
    ['тип get вместо create', { type: 'webauthn.get' }, {}, 'wrong_type'],
    ['чужой rpId', { rpId: 'evil.test' }, {}, 'rpid_mismatch'],
    ['нет флага присутствия', { flags: 0x40 | 0x04 }, {}, 'user_not_present'],
    ['нет проверки пользователя при requireUV', { flags: 0x40 | 0x01 }, { requireUV: true }, 'user_not_verified'],
    ['нет данных ключа (AT)', { flags: 0x01 | 0x04 }, {}, 'bad_auth_data'],
    ['неподдерживаемая аттестация', { fmt: 'other' }, {}, 'unsupported_attestation_format'],
  ];
  for (const [name, o, e, code] of cases) {
    const resp = await a.create({ challenge: CH, origin: ORIGIN, ...o });
    await rejects(verifyRegistration(resp, regExpect(e)), code).catch((err) => {
      throw new Error(`${name}: ${err.message}`);
    });
  }
});

test('регистрация: подмена в ответе (id, rawId, packed-подпись, мусор) отвергается', async () => {
  const a = await auth('es256');
  const good = await a.create({ challenge: CH, origin: ORIGIN, fmt: 'packed' });
  const b64 = (o: object): string => JSON.stringify(o);
  void b64;
  await rejects(verifyRegistration({ ...good, id: toBase64Url(crypto.getRandomValues(new Uint8Array(32))) }, regExpect()), 'id_mismatch');
  const other = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  await rejects(verifyRegistration({ ...good, id: other, rawId: other }, regExpect()), 'id_mismatch'); // идентификатор в authData другой
  await rejects(verifyRegistration({ ...good, type: 'password' as never }, regExpect()), 'bad_response');
  await rejects(verifyRegistration(null as never, regExpect()), 'bad_response');
  await rejects(verifyRegistration({ ...good, response: { ...good.response, clientDataJSON: '!!!' } }, regExpect()), 'bad_base64url');
  await rejects(verifyRegistration({ ...good, response: { ...good.response, clientDataJSON: toBase64Url(new TextEncoder().encode('[]')) } }, regExpect()), 'bad_client_data');
  await rejects(verifyRegistration({ ...good, response: { ...good.response, clientDataJSON: toBase64Url(new TextEncoder().encode('не json')) } }, regExpect()), 'bad_client_data');
  await rejects(verifyRegistration({ ...good, response: { ...good.response, attestationObject: toBase64Url(new Uint8Array([0xa0])) } }, regExpect()), 'bad_attestation');
  await rejects(verifyRegistration({ ...good, response: { ...good.response, attestationObject: toBase64Url(new Uint8Array([0xff, 0xff])) } }, regExpect()), 'bad_attestation');
  // packed с испорченной подписью: порча байта подписи внутри attestationObject
  const bytes = Uint8Array.from(atob(good.response.attestationObject.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
  const i = bytes.length > 200 ? 10 : 5;
  void i;
  const att = (await import('../src/cbor.ts')).decodeCbor(bytes) as Map<string, unknown>;
  const stmt = att.get('attStmt') as Map<string, Uint8Array>;
  const sig = stmt.get('sig')!.slice();
  sig[sig.length - 1] ^= 1;
  const tampered = encodeCbor(new Map<string, never>([['fmt', 'packed' as never], ['attStmt', new Map<string, never>([['alg', -7 as never], ['sig', sig as never]]) as never], ['authData', att.get('authData') as never]]));
  await rejects(verifyRegistration({ ...good, response: { ...good.response, attestationObject: toBase64Url(tampered) } }, regExpect()), 'bad_attestation');
  // packed с x5c не проверяется, поэтому отклоняется честно, а не принимается вслепую
  const withChain = encodeCbor(new Map<string, never>([['fmt', 'packed' as never], ['attStmt', new Map<string, never>([['alg', -7 as never], ['sig', sig as never], ['x5c', [new Uint8Array(3)] as never]]) as never], ['authData', att.get('authData') as never]]));
  await rejects(verifyRegistration({ ...good, response: { ...good.response, attestationObject: toBase64Url(withChain) } }, regExpect()), 'unsupported_attestation_format');
});

test('вход: каждый вид порчи отклоняется со своим кодом', async () => {
  const a = await auth('es256');
  const c = await registered(a);
  const cases: Array<[string, Partial<Options>, Partial<AuthenticationExpect>, string]> = [
    ['чужой challenge', { challenge: toBase64Url(new Uint8Array(32)) }, {}, 'challenge_mismatch'],
    ['чужой origin', { origin: 'https://evil.test' }, {}, 'origin_mismatch'],
    ['тип create вместо get', { type: 'webauthn.create' }, {}, 'wrong_type'],
    ['чужой rpId', { rpId: 'evil.test' }, {}, 'rpid_mismatch'],
    ['нет присутствия', { flags: 0x04 }, {}, 'user_not_present'],
    ['нет проверки пользователя', { flags: 0x01 }, { requireUV: true }, 'user_not_verified'],
    ['флаг AT при входе', { flags: 0x01 | 0x04 | 0x40 }, {}, 'bad_auth_data'],
    ['флаг ED без данных', { flags: 0x01 | 0x04 | 0x80 }, {}, 'bad_auth_data'],
    ['BE изменился', { flags: 0x01 | 0x04 | 0x08 }, {}, 'backup_eligibility_changed'],
  ];
  for (const [name, o, e, code] of cases) {
    a.counter = 0;
    const resp = await a.get({ challenge: CH, origin: ORIGIN, ...o });
    await rejects(verifyAuthentication(resp, authExpect(stored(c), e)), code).catch((err) => {
      throw new Error(`${name}: ${err.message}`);
    });
  }
});

test('вход: испорченная подпись, чужой ключ и подмена данных', async () => {
  const a = await auth('es256');
  const c = await registered(a);
  const resp = await a.get({ challenge: CH, origin: ORIGIN });
  // каждый бит подписи, authenticatorData и clientDataJSON: любое изменение даёт отказ
  const flip = (b64: string, bit: number): string => {
    const bytes = Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), (ch) => ch.charCodeAt(0));
    bytes[Math.floor(bit / 8) % bytes.length]! ^= 1 << bit % 8;
    return toBase64Url(bytes);
  };
  for (const field of ['signature', 'authenticatorData', 'clientDataJSON'] as const) {
    for (let bit = 0; bit < 64; bit += 7) {
      const t = { ...resp, response: { ...resp.response, [field]: flip(resp.response[field], bit * 3) } };
      await assert.rejects(verifyAuthentication(t, authExpect(stored(c))), { name: 'Error' }, `${field} бит ${bit}`);
    }
  }
  const stranger = await SoftAuthenticator.make('es256', RP);
  stranger.credentialId = a.credentialId;
  const forged = await stranger.get({ challenge: CH, origin: ORIGIN });
  await rejects(verifyAuthentication(forged, authExpect(stored(c))), 'bad_signature');
  await rejects(verifyAuthentication({ ...resp, id: toBase64Url(new Uint8Array(32)), rawId: toBase64Url(new Uint8Array(32)) }, authExpect(stored(c))), 'credential_mismatch');
  await rejects(verifyAuthentication({ ...resp, response: { ...resp.response, signature: toBase64Url(new Uint8Array(70)) } }, authExpect(stored(c))), 'bad_signature');
});

test('счётчик: растёт — верно; не растёт или падает — подозрение на клон; нули допустимы, если ключ не ведёт счёт', async () => {
  const a = await auth('es256');
  const c = await registered(a);
  const s = stored(c);
  const r1 = await verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN }), authExpect(s));
  s.signCount = r1.signCount;
  const r2 = await verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN }), authExpect(s));
  assert.equal(r2.signCount, 2);
  s.signCount = 2;
  for (const n of [2, 1, 0]) {
    await rejects(verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN, signCount: n }), authExpect(s)), 'counter_regression');
  }
  const big = await verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN, signCount: 4294967295 }), authExpect(s));
  assert.equal(big.signCount, 4294967295);
  // ключ без счётчика: всегда 0
  const zero = { ...s, signCount: 0 };
  assert.equal((await verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN, signCount: 0 }), authExpect(zero))).signCount, 0);
});

test('userHandle возвращается и проверяется как base64url', async () => {
  const a = await auth('es256');
  const c = await registered(a);
  const handle = crypto.getRandomValues(new Uint8Array(16));
  const ok = await verifyAuthentication(await a.get({ challenge: CH, origin: ORIGIN, userHandle: handle }), authExpect(stored(c)));
  assert.equal(ok.userHandle, toBase64Url(handle));
  const resp = await a.get({ challenge: CH, origin: ORIGIN });
  await rejects(verifyAuthentication({ ...resp, response: { ...resp.response, userHandle: '!!' } }, authExpect(stored(c))), 'bad_base64url');
});

test('authenticatorData: границы длин, лишние байты, расширения', async () => {
  const rp = new Uint8Array(32);
  const base = (flags: number, tail: Uint8Array = new Uint8Array()): Uint8Array => Uint8Array.from([...rp, flags, 0, 0, 0, 5, ...tail]);
  assert.equal(parseAuthData(base(0x01)).signCount, 5);
  assert.throws(() => parseAuthData(new Uint8Array(36)), { code: 'bad_auth_data' });
  assert.throws(() => parseAuthData(base(0x01, Uint8Array.of(0))), { code: 'bad_auth_data' }); // лишний байт
  assert.equal(parseAuthData(base(0x81, encodeCbor(new Map([['credProtect', 2]])))).up, true); // расширение разобрано
  assert.throws(() => parseAuthData(base(0x81, Uint8Array.of(0xa1))), { code: 'bad_auth_data' }); // расширение оборвано
  const aaguid = new Uint8Array(16);
  const withKey = (idLen: number, id: Uint8Array, key: Uint8Array): Uint8Array => base(0x41, Uint8Array.from([...aaguid, idLen >> 8, idLen & 255, ...id, ...key]));
  const key = encodeCbor(new Map<number, number>([[1, 2]]));
  assert.equal(parseAuthData(withKey(3, Uint8Array.of(1, 2, 3), key)).attested?.credentialId.length, 3);
  assert.throws(() => parseAuthData(withKey(0, new Uint8Array(), key)), { code: 'bad_auth_data' });
  assert.throws(() => parseAuthData(withKey(1024, new Uint8Array(1024), key)), { code: 'bad_auth_data' });
  assert.throws(() => parseAuthData(withKey(10, Uint8Array.of(1, 2, 3), key)), { code: 'bad_auth_data' });
  assert.equal(parseAuthData(withKey(1023, new Uint8Array(1023), key)).attested?.credentialId.length, 1023);
});

test('ключи COSE: чужие и сломанные не импортируются', async () => {
  const a = await auth('es256');
  await importCoseKey(a.coseKey);
  const x = new Uint8Array(32).fill(1);
  const y = new Uint8Array(32).fill(2);
  const bad: Array<[string, Map<number, never>]> = [
    ['точка не на кривой', new Map([[1, 2], [3, -7], [-1, 1], [-2, x], [-3, y]] as never)],
    ['кривая P-384', new Map([[1, 2], [3, -7], [-1, 2], [-2, x], [-3, y]] as never)],
    ['алгоритм ES384', new Map([[1, 2], [3, -35], [-1, 2], [-2, x], [-3, y]] as never)],
    ['короткая координата', new Map([[1, 2], [3, -7], [-1, 1], [-2, new Uint8Array(31)], [-3, y]] as never)],
    ['RSA 1024 бит', new Map([[1, 3], [3, -257], [-1, new Uint8Array(128).fill(0x81)], [-2, Uint8Array.of(1, 0, 1)]] as never)],
    ['чётный показатель RSA', new Map([[1, 3], [3, -257], [-1, new Uint8Array(256).fill(0x81)], [-2, Uint8Array.of(1, 0, 0)]] as never)],
    ['Ed25519 короткий ключ', new Map([[1, 1], [3, -8], [-1, 6], [-2, new Uint8Array(31)]] as never)],
  ];
  for (const [name, m] of bad) await assert.rejects(importCoseKey(encodeCbor(m as never)), { code: 'bad_public_key' }, name);
  for (const raw of [new Uint8Array(), Uint8Array.of(0x01), encodeCbor([1, 2])]) await assert.rejects(importCoseKey(raw), { code: 'bad_public_key' });
});

test('RegistrationResponse без лишних полей не принимается за PublicKeyCredential', async () => {
  const resp = {} as unknown as RegistrationResponse;
  await rejects(verifyRegistration(resp, regExpect()), 'bad_response');
});
