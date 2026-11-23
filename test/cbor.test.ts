import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fromBase64Url, toBase64Url } from '../src/bytes.ts';
import { CborError, decodeCbor, decodeFirst } from '../src/cbor.ts';
import type { CborValue } from '../src/cbor.ts';
import { derToRaw } from '../src/cose.ts';
import { encodeCbor } from './softauth.ts';
import type { Enc } from './softauth.ts';

const hex = (s: string): Uint8Array => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));

test('RFC 8949, приложение A: стандартные примеры разбираются', () => {
  const m = (...kv: Array<[number | string, CborValue]>): Map<number | string, CborValue> => new Map(kv);
  const cases: Array<[string, CborValue]> = [
    ['00', 0], ['01', 1], ['0a', 10], ['17', 23], ['1818', 24], ['1819', 25], ['1864', 100], ['1903e8', 1000], ['1a000f4240', 1000000],
    ['1b000000e8d4a51000', 1000000000000], ['1bffffffffffffffff', 18446744073709551615n],
    ['20', -1], ['29', -10], ['3863', -100], ['3903e7', -1000],
    ['f90000', 0], ['f93c00', 1], ['f93e00', 1.5], ['f97bff', 65504], ['fa47c35000', 100000], ['fa7f7fffff', 3.4028234663852886e38],
    ['fb3ff199999999999a', 1.1], ['fbc010666666666666', -4.1], ['f97c00', Infinity], ['f9fc00', -Infinity],
    ['f4', false], ['f5', true], ['f6', null], ['f7', undefined],
    ['40', new Uint8Array()], ['4401020304', Uint8Array.of(1, 2, 3, 4)],
    ['60', ''], ['6161', 'a'], ['6449455446', 'IETF'], ['62c3bc', 'ü'], ['63e6b0b4', '水'],
    ['80', []], ['83010203', [1, 2, 3]], ['8301820203820405', [1, [2, 3], [4, 5]]],
    ['a0', m()], ['a201020304', m([1, 2], [3, 4])], ['a26161016162820203', m(['a', 1], ['b', [2, 3]])],
  ];
  for (const [h, want] of cases) assert.deepEqual(decodeCbor(hex(h)), want, h);
  assert.equal(decodeCbor(hex('f93c00')), 1);
  assert.ok(Number.isNaN(decodeCbor(hex('f97e00')) as number));
});

test('отрицательные числа за границей 2^53 разбираются как bigint', () => {
  assert.equal(decodeCbor(hex('3bffffffffffffffff')), -18446744073709551616n);
  assert.equal(decodeCbor(hex('3b0000000000000000')), -1);
});

test('отказы: неопределённая длина, теги, хвост, дубликаты, ключи не числа и не текст, глубина, плохой UTF-8, простые значения', () => {
  const bad: Array<[string, string]> = [
    ['5f4101ff', 'неопределённая длина байтов'], ['9fff', 'неопределённый массив'], ['bfff', 'неопределённый словарь'], ['7f6161ff', 'неопределённый текст'],
    ['c074323031332d30332d32315432303a30343a30305a', 'тег'], ['c11a514b67b0', 'тег'],
    ['0001', 'хвост'], ['a201020102', 'дубликат ключа'], ['a16161016161', 'хвост после словаря'], ['a18101' + '01', 'ключ-массив'],
    ['62ffff', 'не UTF-8'], ['62c328', 'не UTF-8'], ['f800', 'простое значение 0'], ['f8ff', 'простое значение 255'], ['ff', 'break'],
    ['1c', 'код длины 28'], ['1d', 'код длины 29'], ['1e', 'код длины 30'],
    ['5bffffffffffffffff', 'длина-бомба'], ['9affffffff', 'массив-бомба'], ['baffffffff', 'словарь-бомба'], ['4401', 'оборвано'], ['', 'пусто'],
  ];
  for (const [h, why] of bad) assert.throws(() => decodeCbor(hex(h)), CborError, why);
  const deep = (n: number): Uint8Array => Uint8Array.from([...Array(n).fill(0x81), 0x00]);
  assert.doesNotThrow(() => decodeCbor(deep(16)));
  assert.throws(() => decodeCbor(deep(17)), CborError, 'глубина');
});

test('любой обрыв корректного документа отвергается', () => {
  const doc = encodeCbor(new Map<number | string, Enc>([[1, 2], ['k', [Uint8Array.of(1, 2, 3), 'текст', -5, true]]]));
  assert.doesNotThrow(() => decodeCbor(doc));
  for (let n = 0; n < doc.length; n++) assert.throws(() => decodeCbor(doc.slice(0, n)), CborError, `префикс ${n}`);
});

test('decodeFirst возвращает длину и оставляет хвост нетронутым', () => {
  const r = decodeFirst(hex('83010203ffee'));
  assert.deepEqual(r.value, [1, 2, 3]);
  assert.equal(r.length, 4);
});

function rnd(seed: number): () => number {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomValue(r: () => number, depth: number): Enc {
  const k = Math.floor(r() * (depth > 3 ? 4 : 6));
  if (k === 0) return Math.floor((r() - 0.5) * 2 ** (1 + Math.floor(r() * 52)));
  if (k === 1) return crypto.getRandomValues(new Uint8Array(Math.floor(r() * 40)));
  if (k === 2) return Array.from({ length: Math.floor(r() * 12) }, () => String.fromCodePoint(0x20 + Math.floor(r() * 0x2000))).join('');
  if (k === 3) return r() < 0.5;
  if (k === 4) return Array.from({ length: Math.floor(r() * 5) }, () => randomValue(r, depth + 1));
  const m = new Map<number | string, Enc>();
  for (let i = Math.floor(r() * 5); i > 0; i--) m.set(r() < 0.5 ? Math.floor(r() * 1000) - 500 : `k${Math.floor(r() * 50)}`, randomValue(r, depth + 1));
  return m;
}

test('свойство: кодирование и разбор взаимно обратны на 3000 случайных структур', () => {
  const r = rnd(42);
  for (let i = 0; i < 3000; i++) {
    const v = randomValue(r, 0);
    const bytes = encodeCbor(v);
    assert.deepEqual(decodeCbor(bytes), v, `случай ${i}`);
    assert.equal(decodeFirst(bytes).length, bytes.length);
  }
});

test('фаззинг: на случайных и мутированных байтах разбор либо успешен, либо бросает CborError, и не зависает', () => {
  const r = rnd(7);
  const seeds = Array.from({ length: 50 }, () => encodeCbor(randomValue(r, 0)));
  const t0 = Date.now();
  for (let i = 0; i < 30000; i++) {
    const b = i % 2 === 0 ? crypto.getRandomValues(new Uint8Array(Math.floor(r() * 64))) : seeds[i % seeds.length]!.slice();
    if (i % 2 === 1 && b.length) for (let k = 0; k < 1 + Math.floor(r() * 3); k++) b[Math.floor(r() * b.length)] = Math.floor(r() * 256);
    try {
      decodeCbor(b);
    } catch (e) {
      assert.ok(e instanceof CborError, `неожиданная ошибка ${String(e)} на ${[...b].map((x) => x.toString(16)).join('')}`);
    }
  }
  assert.ok(Date.now() - t0 < 15000, 'фаззинг не должен занимать больше 15 секунд');
});

test('base64url: векторы RFC 4648 без заполнения и строгие отказы', () => {
  const vectors: Array<[string, string]> = [['', ''], ['f', 'Zg'], ['fo', 'Zm8'], ['foo', 'Zm9v'], ['foob', 'Zm9vYg'], ['fooba', 'Zm9vYmE'], ['foobar', 'Zm9vYmFy']];
  for (const [plain, enc] of vectors) {
    assert.equal(toBase64Url(new TextEncoder().encode(plain)), enc);
    assert.equal(new TextDecoder().decode(fromBase64Url(enc)), plain);
  }
  assert.equal(toBase64Url(Uint8Array.of(0xfb, 0xff, 0xfe)), '-__-');
  for (const bad of ['Zg==', 'Zm9v=', 'Z', 'Zm9vY', 'Zm+v', 'Zm/v', 'Zh', 'Zm9 v', 'Zm9v\n', 'ключ', 5, null, undefined]) assert.throws(() => fromBase64Url(bad), { code: 'bad_base64url' }, String(bad));
  const r = rnd(3);
  for (let i = 0; i < 500; i++) {
    const b = crypto.getRandomValues(new Uint8Array(Math.floor(r() * 70)));
    assert.deepEqual(fromBase64Url(toBase64Url(b)), b);
  }
});

test('DER → r||s: корректные подписи и строгие отказы', () => {
  const ok = derToRaw(hex('3006020101020102'));
  assert.deepEqual([...ok.slice(30, 32), ...ok.slice(62, 64)], [0, 1, 0, 2]);
  assert.equal(ok.length, 64);
  const full = derToRaw(hex('3044' + '0220' + '11'.repeat(32) + '0220' + '22'.repeat(32)));
  assert.deepEqual([...full.slice(0, 2), ...full.slice(32, 34)], [0x11, 0x11, 0x22, 0x22]);
  const withZero = derToRaw(hex('3045' + '022100' + 'ff'.repeat(32) + '0220' + '22'.repeat(32)));
  assert.equal(withZero[0], 0xff);
  const bad = [
    '', '30', '3006020101020102ff', '3005020101020102', '3006030101020102', '3006020101030102',
    '3006020181020102', // отрицательное
    '300702020001020102', // лишний ведущий ноль
  ];
  for (const h of bad) assert.throws(() => derToRaw(hex(h)), { code: 'bad_signature' }, h);
  assert.throws(() => derToRaw(hex('3046' + '0221' + '01'.repeat(33) + '0220' + '22'.repeat(32))), { code: 'bad_signature' }, 'число длиннее 32 байт');
  assert.throws(() => derToRaw(new Uint8Array(100).fill(0x30)), { code: 'bad_signature' });
});
