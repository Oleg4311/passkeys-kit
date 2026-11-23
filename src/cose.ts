// Открытые ключи в формате COSE (RFC 9052) и проверка подписи через Web Crypto: ES256 (P-256), EdDSA (Ed25519), RS256.

import { WebAuthnError, toBase64Url } from './bytes.ts';
import { decodeCbor } from './cbor.ts';
import type { CborValue } from './cbor.ts';

export type Alg = -7 | -8 | -257;
export const ALGS: readonly Alg[] = [-7, -8, -257];

export interface PublicKey {
  alg: Alg;
  key: CryptoKey;
}

const bad = (m: string): WebAuthnError => new WebAuthnError('bad_public_key', m);

function bytesOf(m: Map<number | string, CborValue>, k: number, len?: { min: number; max: number }): Uint8Array {
  const v = m.get(k);
  if (!(v instanceof Uint8Array)) throw bad(`В ключе COSE нет байтового поля ${k}.`);
  if (len && (v.length < len.min || v.length > len.max)) throw bad(`Поле ${k} ключа COSE неверной длины.`);
  return v;
}

/** Разбор открытого ключа из COSE (байты CBOR или уже разобранный словарь) и импорт в Web Crypto. */
export async function importCoseKey(cose: Uint8Array | CborValue): Promise<PublicKey> {
  let m: CborValue;
  try {
    m = cose instanceof Uint8Array ? decodeCbor(cose) : cose;
  } catch (e) {
    throw bad(`Ключ COSE не разбирается: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (!(m instanceof Map)) throw bad('Ключ COSE должен быть словарём.');
  const kty = m.get(1);
  const alg = m.get(3);
  try {
    if (kty === 2 && alg === -7) {
      if (m.get(-1) !== 1) throw bad('Кривая ES256 должна быть P-256.');
      const jwk = { kty: 'EC', crv: 'P-256', x: toBase64Url(bytesOf(m, -2, { min: 32, max: 32 })), y: toBase64Url(bytesOf(m, -3, { min: 32, max: 32 })) };
      return { alg: -7, key: await crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']) };
    }
    if (kty === 1 && alg === -8) {
      if (m.get(-1) !== 6) throw bad('Кривая EdDSA должна быть Ed25519.');
      const jwk = { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(bytesOf(m, -2, { min: 32, max: 32 })) };
      return { alg: -8, key: await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify']) };
    }
    if (kty === 3 && alg === -257) {
      const n = bytesOf(m, -1, { min: 256, max: 512 });
      const e = bytesOf(m, -2, { min: 1, max: 8 });
      if (n[0] === 0) throw bad('Модуль RSA с ведущим нулём.');
      if ((e[e.length - 1]! & 1) === 0) throw bad('Показатель RSA должен быть нечётным.');
      const jwk = { kty: 'RSA', alg: 'RS256', n: toBase64Url(n), e: toBase64Url(e) };
      return { alg: -257, key: await crypto.subtle.importKey('jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']) };
    }
  } catch (e) {
    if (e instanceof WebAuthnError) throw e;
    throw bad('Ключ не принят: точка не лежит на кривой или параметры неверны.');
  }
  throw bad(`Неподдерживаемый ключ COSE (kty=${String(kty)}, alg=${String(alg)}). Поддержаны ES256, EdDSA и RS256.`);
}

/** DER-подпись ECDSA → «сырая» r||s по 32 байта. Строгий разбор: без лишних нулей, без отрицательных чисел, без хвоста. */
export function derToRaw(der: Uint8Array): Uint8Array {
  const fail = (): never => {
    throw new WebAuthnError('bad_signature', 'Подпись ECDSA не в формате DER.');
  };
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) return fail();
  let i = 2;
  const out = new Uint8Array(64);
  for (let part = 0; part < 2; part++) {
    if (der[i++] !== 0x02) return fail();
    const len = der[i++];
    if (len === undefined || len === 0 || len > 33 || i + len > der.length) return fail();
    let v = der.slice(i, i + len);
    i += len;
    if (v[0]! & 0x80) return fail(); // отрицательное
    if (v.length > 1 && v[0] === 0 && !(v[1]! & 0x80)) return fail(); // лишний ведущий ноль
    if (v[0] === 0) v = v.slice(1);
    if (v.length > 32) return fail();
    out.set(v, part * 32 + (32 - v.length));
  }
  if (i !== der.length) return fail();
  return out;
}

export async function verifySignature(pk: PublicKey, data: Uint8Array, signature: Uint8Array): Promise<boolean> {
  try {
    if (pk.alg === -7) return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pk.key, derToRaw(signature) as BufferSource, data as BufferSource);
    if (pk.alg === -8) return await crypto.subtle.verify({ name: 'Ed25519' }, pk.key, signature as BufferSource, data as BufferSource);
    return await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, pk.key, signature as BufferSource, data as BufferSource);
  } catch (e) {
    if (e instanceof WebAuthnError) return false;
    return false;
  }
}
