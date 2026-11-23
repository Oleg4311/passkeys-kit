// Проверка ответов WebAuthn (регистрация и вход) по спецификации W3C Level 3, разделы 7.1 и 7.2.
// Без зависимостей: Web Crypto, собственный CBOR. Любая неопределённость трактуется как отказ.

import { WebAuthnError, concat, equalBytes, fromBase64Url, sha256, toBase64Url } from './bytes.ts';
import { CborError, decodeCbor, decodeFirst } from './cbor.ts';
import { ALGS, importCoseKey, verifySignature } from './cose.ts';
import type { Alg } from './cose.ts';

const fail = (code: string, message: string): never => {
  throw new WebAuthnError(code, message);
};

export interface RegistrationResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; attestationObject: string; transports?: string[] };
}
export interface AuthenticationResponse {
  id: string;
  rawId: string;
  type: 'public-key';
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string | null };
}

// ---------- authenticatorData ----------

export interface AuthData {
  rpIdHash: Uint8Array;
  up: boolean;
  uv: boolean;
  be: boolean;
  bs: boolean;
  signCount: number;
  attested?: { aaguid: Uint8Array; credentialId: Uint8Array; publicKey: Uint8Array };
}

export function parseAuthData(data: Uint8Array): AuthData {
  if (data.length < 37) return fail('bad_auth_data', 'authenticatorData короче 37 байт.');
  const flags = data[32]!;
  const out: AuthData = {
    rpIdHash: data.slice(0, 32),
    up: (flags & 0x01) !== 0,
    uv: (flags & 0x04) !== 0,
    be: (flags & 0x08) !== 0,
    bs: (flags & 0x10) !== 0,
    signCount: new DataView(data.buffer, data.byteOffset + 33, 4).getUint32(0),
  };
  if (out.bs && !out.be) fail('invalid_backup_flags', 'Ключ помечен как синхронизированный, но не как допускающий копирование.');
  const at = (flags & 0x40) !== 0;
  const ed = (flags & 0x80) !== 0;
  let i = 37;
  if (at) {
    if (data.length < i + 18) return fail('bad_auth_data', 'Данные о ключе оборваны.');
    const aaguid = data.slice(i, i + 16);
    const len = (data[i + 16]! << 8) | data[i + 17]!;
    i += 18;
    if (len < 1 || len > 1023) return fail('bad_auth_data', 'Длина идентификатора ключа вне 1–1023.');
    if (data.length < i + len) return fail('bad_auth_data', 'Идентификатор ключа оборван.');
    const credentialId = data.slice(i, i + len);
    i += len;
    let used: number;
    try {
      used = decodeFirst(data.subarray(i)).length;
    } catch (e) {
      return fail('bad_auth_data', `Открытый ключ не разбирается: ${e instanceof Error ? e.message : String(e)}`);
    }
    out.attested = { aaguid, credentialId, publicKey: data.slice(i, i + used) };
    i += used;
  }
  if (ed) {
    try {
      const { length } = decodeFirst(data.subarray(i));
      i += length;
    } catch (e) {
      return fail('bad_auth_data', `Расширения не разбираются: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (i !== data.length) return fail('bad_auth_data', 'В authenticatorData лишние байты.');
  return out;
}

// ---------- clientDataJSON ----------

function checkClientData(raw: Uint8Array, type: 'webauthn.create' | 'webauthn.get', challenge: string, origins: string[]): void {
  let cd: unknown;
  try {
    cd = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(raw));
  } catch {
    return fail('bad_client_data', 'clientDataJSON не разбирается.');
  }
  if (typeof cd !== 'object' || cd === null || Array.isArray(cd)) return fail('bad_client_data', 'clientDataJSON должен быть объектом.');
  const o = cd as Record<string, unknown>;
  if (o['type'] !== type) fail('wrong_type', `Ожидался тип ${type}.`);
  if (typeof o['challenge'] !== 'string') return fail('bad_client_data', 'Нет challenge.');
  const enc = new TextEncoder();
  if (!equalBytes(enc.encode(o['challenge']), enc.encode(challenge))) fail('challenge_mismatch', 'Challenge не совпадает.');
  if (typeof o['origin'] !== 'string' || !origins.includes(o['origin'])) fail('origin_mismatch', 'Страница не из разрешённых источников.');
  if (o['crossOrigin'] === true) fail('cross_origin', 'Запрос из чужого фрейма отклонён.');
}

async function checkRpId(authData: AuthData, rpId: string, requireUV: boolean): Promise<void> {
  const expected = await sha256(new TextEncoder().encode(rpId));
  if (!equalBytes(authData.rpIdHash, expected)) fail('rpid_mismatch', 'Хеш rpId не совпадает.');
  if (!authData.up) fail('user_not_present', 'Не подтверждено присутствие пользователя.');
  if (requireUV && !authData.uv) fail('user_not_verified', 'Не пройдена проверка пользователя (PIN, биометрия).');
}

// ---------- регистрация ----------

export interface RegistrationExpect {
  challenge: string;
  origins: string[];
  rpId: string;
  requireUV?: boolean;
}

export interface RegisteredCredential {
  id: string;
  /** Ключ COSE (байты CBOR) в base64url. */
  publicKey: string;
  alg: Alg;
  signCount: number;
  aaguid: string;
  backupEligible: boolean;
  backedUp: boolean;
  userVerified: boolean;
  transports: string[];
  attestationFormat: 'none' | 'packed-self';
}

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

export async function verifyRegistration(resp: RegistrationResponse, expect: RegistrationExpect): Promise<RegisteredCredential> {
  if (typeof resp !== 'object' || resp === null || resp.type !== 'public-key' || typeof resp.response !== 'object' || resp.response === null) return fail('bad_response', 'Ответ не похож на PublicKeyCredential.');
  const rawId = fromBase64Url(resp.rawId);
  if (resp.id !== toBase64Url(rawId)) fail('id_mismatch', 'id не совпадает с rawId.');
  const clientData = fromBase64Url(resp.response.clientDataJSON);
  checkClientData(clientData, 'webauthn.create', expect.challenge, expect.origins);

  let att: unknown;
  try {
    att = decodeCbor(fromBase64Url(resp.response.attestationObject));
  } catch (e) {
    return fail('bad_attestation', e instanceof CborError ? `attestationObject: ${e.message}` : 'attestationObject не разбирается.');
  }
  if (!(att instanceof Map)) return fail('bad_attestation', 'attestationObject должен быть словарём.');
  const fmt = att.get('fmt');
  const attStmt = att.get('attStmt');
  const authDataBytes = att.get('authData');
  if (typeof fmt !== 'string' || !(attStmt instanceof Map) || !(authDataBytes instanceof Uint8Array)) return fail('bad_attestation', 'В attestationObject нет fmt, attStmt или authData.');

  const authData = parseAuthData(authDataBytes);
  await checkRpId(authData, expect.rpId, expect.requireUV === true);
  if (!authData.attested) return fail('no_credential_data', 'В ответе нет данных нового ключа.');
  if (!equalBytes(authData.attested.credentialId, rawId)) fail('id_mismatch', 'Идентификатор ключа в authData не совпадает с rawId.');
  const pub = await importCoseKey(authData.attested.publicKey);
  if (!ALGS.includes(pub.alg)) fail('unsupported_algorithm', 'Неподдерживаемый алгоритм.');

  let format: RegisteredCredential['attestationFormat'];
  if (fmt === 'none') {
    if (attStmt.size !== 0) return fail('bad_attestation', 'У формата none attStmt должен быть пустым.');
    format = 'none';
  } else if (fmt === 'packed') {
    if (attStmt.has('x5c') || attStmt.has('ecdaaKeyId')) return fail('unsupported_attestation_format', 'Цепочки сертификатов не проверяются: запросите attestation: "none".');
    const alg = attStmt.get('alg');
    const sig = attStmt.get('sig');
    if (alg !== pub.alg || !(sig instanceof Uint8Array)) return fail('bad_attestation', 'packed: алгоритм самоподписи не совпадает с ключом.');
    const ok = await verifySignature(pub, concat(authDataBytes, await sha256(clientData)), sig);
    if (!ok) return fail('bad_attestation', 'packed: подпись не сошлась.');
    format = 'packed-self';
  } else {
    return fail('unsupported_attestation_format', `Формат аттестации «${fmt}» не поддерживается: запросите attestation: "none".`);
  }

  const transports = Array.isArray(resp.response.transports) ? resp.response.transports.filter((t): t is string => typeof t === 'string' && /^[a-z-]{1,16}$/.test(t)).slice(0, 8) : [];
  return {
    id: resp.id,
    publicKey: toBase64Url(authData.attested.publicKey),
    alg: pub.alg,
    signCount: authData.signCount,
    aaguid: hex(authData.attested.aaguid),
    backupEligible: authData.be,
    backedUp: authData.bs,
    userVerified: authData.uv,
    transports,
    attestationFormat: format,
  };
}

// ---------- вход ----------

export interface StoredCredential {
  id: string;
  publicKey: string;
  signCount: number;
  backupEligible: boolean;
}

export interface AuthenticationExpect {
  challenge: string;
  origins: string[];
  rpId: string;
  requireUV?: boolean;
  credential: StoredCredential;
}

export interface Authenticated {
  signCount: number;
  userVerified: boolean;
  backedUp: boolean;
  userHandle: string | null;
}

export async function verifyAuthentication(resp: AuthenticationResponse, expect: AuthenticationExpect): Promise<Authenticated> {
  if (typeof resp !== 'object' || resp === null || resp.type !== 'public-key' || typeof resp.response !== 'object' || resp.response === null) return fail('bad_response', 'Ответ не похож на PublicKeyCredential.');
  const rawId = fromBase64Url(resp.rawId);
  if (resp.id !== toBase64Url(rawId)) fail('id_mismatch', 'id не совпадает с rawId.');
  if (resp.id !== expect.credential.id) fail('credential_mismatch', 'Ответ относится к другому ключу.');
  const clientData = fromBase64Url(resp.response.clientDataJSON);
  checkClientData(clientData, 'webauthn.get', expect.challenge, expect.origins);
  const authDataBytes = fromBase64Url(resp.response.authenticatorData);
  const authData = parseAuthData(authDataBytes);
  if (authData.attested) fail('bad_auth_data', 'При входе данные нового ключа не ожидаются.');
  await checkRpId(authData, expect.rpId, expect.requireUV === true);
  if (authData.be !== expect.credential.backupEligible) fail('backup_eligibility_changed', 'Признак «можно копировать» не должен меняться.');

  const pub = await importCoseKey(fromBase64Url(expect.credential.publicKey));
  const signature = fromBase64Url(resp.response.signature);
  const ok = await verifySignature(pub, concat(authDataBytes, await sha256(clientData)), signature);
  if (!ok) fail('bad_signature', 'Подпись не сошлась.');

  // подпись верна, теперь счётчик: если он не растёт, ключ мог быть скопирован
  if ((expect.credential.signCount !== 0 || authData.signCount !== 0) && authData.signCount <= expect.credential.signCount) {
    fail('counter_regression', 'Счётчик подписей не вырос: возможно, ключ скопирован.');
  }
  let userHandle: string | null = null;
  if (resp.response.userHandle !== undefined && resp.response.userHandle !== null) {
    fromBase64Url(resp.response.userHandle);
    userHandle = resp.response.userHandle;
  }
  return { signCount: authData.signCount, userVerified: authData.uv, backedUp: authData.bs, userHandle };
}
