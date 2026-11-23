// Строгий разбор CBOR (RFC 8949) в объёме, нужном WebAuthn: целые, байты, текст, массивы, словари, булевы, null, числа с плавающей точкой.
// Не принимает неопределённую длину, повторные ключи, хвост после значения, слишком глубокую вложенность.

export type CborValue = number | bigint | Uint8Array | string | boolean | null | undefined | CborValue[] | Map<number | string, CborValue>;

export class CborError extends Error {}

const MAX_DEPTH = 16;
const MAX_ITEMS = 4096;

interface Reader {
  b: Uint8Array;
  i: number;
  items: number;
}

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

function need(r: Reader, n: number): void {
  if (n < 0 || r.i + n > r.b.length) throw new CborError('Данные оборваны.');
}

function readUint(r: Reader, ai: number): number | bigint {
  if (ai < 24) return ai;
  if (ai === 24) {
    need(r, 1);
    return r.b[r.i++]!;
  }
  if (ai === 25) {
    need(r, 2);
    const v = (r.b[r.i]! << 8) | r.b[r.i + 1]!;
    r.i += 2;
    return v;
  }
  if (ai === 26) {
    need(r, 4);
    const v = new DataView(r.b.buffer, r.b.byteOffset + r.i, 4).getUint32(0);
    r.i += 4;
    return v;
  }
  if (ai === 27) {
    need(r, 8);
    const v = new DataView(r.b.buffer, r.b.byteOffset + r.i, 8).getBigUint64(0);
    r.i += 8;
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
  throw new CborError(ai === 31 ? 'Неопределённая длина не поддерживается.' : 'Неверный код длины.');
}

function half(h: number): number {
  const s = h & 0x8000 ? -1 : 1;
  const e = (h >> 10) & 0x1f;
  const f = h & 0x3ff;
  if (e === 0) return s * 2 ** -14 * (f / 1024);
  if (e === 31) return f ? Number.NaN : s * Infinity;
  return s * 2 ** (e - 15) * (1 + f / 1024);
}

function readItem(r: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new CborError('Слишком глубокая вложенность.');
  if (++r.items > MAX_ITEMS) throw new CborError('Слишком много элементов.');
  need(r, 1);
  const head = r.b[r.i++]!;
  const major = head >> 5;
  const ai = head & 0x1f;
  switch (major) {
    case 0:
      return readUint(r, ai);
    case 1: {
      const v = readUint(r, ai);
      return typeof v === 'bigint' ? -1n - v : -1 - v;
    }
    case 2:
    case 3: {
      const len = readUint(r, ai);
      if (typeof len === 'bigint') throw new CborError('Слишком длинная строка.');
      need(r, len);
      const bytes = r.b.slice(r.i, r.i + len);
      r.i += len;
      if (major === 2) return bytes;
      try {
        return utf8.decode(bytes);
      } catch {
        throw new CborError('Текст не в UTF-8.');
      }
    }
    case 4: {
      const len = readUint(r, ai);
      if (typeof len === 'bigint' || len > MAX_ITEMS) throw new CborError('Слишком длинный массив.');
      const out: CborValue[] = [];
      for (let k = 0; k < len; k++) out.push(readItem(r, depth + 1));
      return out;
    }
    case 5: {
      const len = readUint(r, ai);
      if (typeof len === 'bigint' || len > MAX_ITEMS) throw new CborError('Слишком большой словарь.');
      const m = new Map<number | string, CborValue>();
      for (let k = 0; k < len; k++) {
        const key = readItem(r, depth + 1);
        if (typeof key !== 'number' && typeof key !== 'string') throw new CborError('Ключ словаря должен быть числом или текстом.');
        if (m.has(key)) throw new CborError('Повторяющийся ключ словаря.');
        m.set(key, readItem(r, depth + 1));
      }
      return m;
    }
    case 6:
      throw new CborError('Теги не поддерживаются.');
    default: {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
      if (ai === 23) return undefined;
      if (ai === 25) {
        need(r, 2);
        const v = half((r.b[r.i]! << 8) | r.b[r.i + 1]!);
        r.i += 2;
        return v;
      }
      if (ai === 26) {
        need(r, 4);
        const v = new DataView(r.b.buffer, r.b.byteOffset + r.i, 4).getFloat32(0);
        r.i += 4;
        return v;
      }
      if (ai === 27) {
        need(r, 8);
        const v = new DataView(r.b.buffer, r.b.byteOffset + r.i, 8).getFloat64(0);
        r.i += 8;
        return v;
      }
      throw new CborError('Неподдерживаемое простое значение.');
    }
  }
}

/** Читает одно значение с начала и возвращает его вместе с числом прочитанных байт (после значения может идти что угодно). */
export function decodeFirst(bytes: Uint8Array): { value: CborValue; length: number } {
  const r: Reader = { b: bytes, i: 0, items: 0 };
  const value = readItem(r, 0);
  return { value, length: r.i };
}

/** Ровно одно значение, без хвоста. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const { value, length } = decodeFirst(bytes);
  if (length !== bytes.length) throw new CborError('После значения остались лишние байты.');
  return value;
}
