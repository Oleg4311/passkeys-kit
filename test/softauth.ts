// Программный аутентификатор для тестов: делает настоящие ключи Web Crypto и собирает ответы так, как их собирает устройство.
import { concat, sha256, toBase64Url } from '../src/bytes.ts';
import type { AuthenticationResponse, RegistrationResponse } from '../src/webauthn.ts';

// ---------- кодировщик CBOR (только для тестов) ----------
export type Enc = number | bigint | Uint8Array | string | boolean | null | Enc[] | Map<number | string, Enc>;

function head(major: number, n: number | bigint): Uint8Array {
  const m = major << 5;
  if (n < 24) return Uint8Array.of(m | Number(n));
  if (n < 256) return Uint8Array.of(m | 24, Number(n));
  if (n < 65536) return Uint8Array.of(m | 25, Number(n) >> 8, Number(n) & 255);
  if (n < 2 ** 32) {
    const b = new Uint8Array(5);
    b[0] = m | 26;
    new DataView(b.buffer).setUint32(1, Number(n));
    return b;
  }
  const b = new Uint8Array(9);
  b[0] = m | 27;
  new DataView(b.buffer).setBigUint64(1, BigInt(n));
  return b;
}

export function encodeCbor(v: Enc): Uint8Array {
  if (typeof v === 'number' || typeof v === 'bigint') {
    if (typeof v === 'number' && !Number.isInteger(v)) throw new Error('только целые');
    if (v >= 0) return head(0, v);
    return head(1, typeof v === 'bigint' ? -1n - v : -1 - v);
  }
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (typeof v === 'string') {
    const b = new TextEncoder().encode(v);
    return concat(head(3, b.length), b);
  }
  if (typeof v === 'boolean') return Uint8Array.of(v ? 0xf5 : 0xf4);
  if (v === null) return Uint8Array.of(0xf6);
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(encodeCbor));
  return concat(head(5, v.size), ...[...v].flatMap(([k, x]) => [encodeCbor(k), encodeCbor(x)]));
}

// ---------- ключи ----------
export type Kind = 'es256' | 'ed25519' | 'rs256';
const b64u = (s: string): Uint8Array => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

function derFromRaw(raw: Uint8Array): Uint8Array {
  const part = (v: Uint8Array): Uint8Array => {
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    let s: Uint8Array = v.slice(i);
    if (s[0]! & 0x80) s = concat(Uint8Array.of(0), s);
    return concat(Uint8Array.of(0x02, s.length), s);
  };
  const body = concat(part(raw.slice(0, 32)), part(raw.slice(32)));
  return concat(Uint8Array.of(0x30, body.length), body);
}

export interface Options {
  rpId?: string;
  origin?: string;
  challenge?: string;
  /** Полностью заменить байт флагов. */
  flags?: number;
  signCount?: number;
  type?: string;
  crossOrigin?: boolean;
  /** Для регистрации: none (по умолчанию) или packed (самоподпись). */
  fmt?: 'none' | 'packed' | 'other';
  userHandle?: Uint8Array | null;
}

export class SoftAuthenticator {
  readonly kind: Kind;
  readonly rpId: string;
  readonly uv: boolean;
  readonly be: boolean;
  readonly bs: boolean;
  credentialId: Uint8Array;
  counter = 0;
  private pub!: CryptoKey;
  private priv!: CryptoKey;
  coseKey!: Uint8Array;

  private constructor(kind: Kind, rpId: string, uv: boolean, be: boolean, bs: boolean) {
    this.kind = kind;
    this.rpId = rpId;
    this.uv = uv;
    this.be = be;
    this.bs = bs;
    this.credentialId = crypto.getRandomValues(new Uint8Array(32));
  }

  static async make(kind: Kind = 'es256', rpId = 'example.test', opts: { uv?: boolean; be?: boolean; bs?: boolean } = {}): Promise<SoftAuthenticator> {
    const a = new SoftAuthenticator(kind, rpId, opts.uv ?? true, opts.be ?? false, opts.bs ?? false);
    if (kind === 'es256') {
      const k = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
      a.priv = k.privateKey;
      const jwk = (await crypto.subtle.exportKey('jwk', k.publicKey)) as JsonWebKey;
      a.coseKey = encodeCbor(new Map<number, Enc>([[1, 2], [3, -7], [-1, 1], [-2, b64u(jwk.x!)], [-3, b64u(jwk.y!)]]));
    } else if (kind === 'ed25519') {
      const k = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
      a.priv = k.privateKey;
      const jwk = (await crypto.subtle.exportKey('jwk', k.publicKey)) as JsonWebKey;
      a.coseKey = encodeCbor(new Map<number, Enc>([[1, 1], [3, -8], [-1, 6], [-2, b64u(jwk.x!)]]));
    } else {
      const k = (await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
      a.priv = k.privateKey;
      const jwk = (await crypto.subtle.exportKey('jwk', k.publicKey)) as JsonWebKey;
      a.coseKey = encodeCbor(new Map<number, Enc>([[1, 3], [3, -257], [-1, b64u(jwk.n!)], [-2, b64u(jwk.e!)]]));
    }
    return a;
  }

  get alg(): number {
    return this.kind === 'es256' ? -7 : this.kind === 'ed25519' ? -8 : -257;
  }

  get id(): string {
    return toBase64Url(this.credentialId);
  }

  private async sign(data: Uint8Array): Promise<Uint8Array> {
    if (this.kind === 'es256') return derFromRaw(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.priv, data as BufferSource)));
    if (this.kind === 'ed25519') return new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, this.priv, data as BufferSource));
    return new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, this.priv, data as BufferSource));
  }

  private flagsByte(extra: number): number {
    return 0x01 | (this.uv ? 0x04 : 0) | (this.be ? 0x08 : 0) | (this.bs ? 0x10 : 0) | extra;
  }

  private clientData(type: string, o: Options, fallbackType: string): Uint8Array {
    const cd: Record<string, unknown> = { type: o.type ?? fallbackType, challenge: o.challenge, origin: o.origin ?? 'https://example.test', crossOrigin: o.crossOrigin ?? false };
    return new TextEncoder().encode(JSON.stringify(cd));
  }

  async create(o: Options & { challenge: string }): Promise<RegistrationResponse> {
    const rpHash = await sha256(new TextEncoder().encode(o.rpId ?? this.rpId));
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, o.signCount ?? 0);
    const idLen = Uint8Array.of(this.credentialId.length >> 8, this.credentialId.length & 255);
    const authData = concat(rpHash, Uint8Array.of(o.flags ?? this.flagsByte(0x40)), counter, new Uint8Array(16), idLen, this.credentialId, this.coseKey);
    const cd = this.clientData('create', o, 'webauthn.create');
    let attStmt: Enc = new Map();
    let fmt = 'none';
    if (o.fmt === 'packed') {
      fmt = 'packed';
      attStmt = new Map<string, Enc>([['alg', this.alg], ['sig', await this.sign(concat(authData, await sha256(cd)))]]);
    } else if (o.fmt === 'other') fmt = 'tpm';
    const attestationObject = encodeCbor(new Map<string, Enc>([['fmt', fmt], ['attStmt', attStmt], ['authData', authData]]));
    return { id: this.id, rawId: this.id, type: 'public-key', response: { clientDataJSON: toBase64Url(cd), attestationObject: toBase64Url(attestationObject), transports: ['internal'] } };
  }

  async get(o: Options & { challenge: string }): Promise<AuthenticationResponse> {
    const rpHash = await sha256(new TextEncoder().encode(o.rpId ?? this.rpId));
    this.counter += 1;
    const counter = new Uint8Array(4);
    new DataView(counter.buffer).setUint32(0, o.signCount ?? this.counter);
    const authData = concat(rpHash, Uint8Array.of(o.flags ?? this.flagsByte(0)), counter);
    const cd = this.clientData('get', o, 'webauthn.get');
    const sig = await this.sign(concat(authData, await sha256(cd)));
    const userHandle = o.userHandle === undefined ? undefined : o.userHandle === null ? null : toBase64Url(o.userHandle);
    return { id: this.id, rawId: this.id, type: 'public-key', response: { clientDataJSON: toBase64Url(cd), authenticatorData: toBase64Url(authData), signature: toBase64Url(sig), ...(userHandle !== undefined ? { userHandle } : {}) } };
  }
}
