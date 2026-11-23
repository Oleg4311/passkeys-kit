import type { Miniflare } from 'miniflare';
export function buildWorker(): void;
export function makeMiniflare(opts?: { port?: number; bindings?: Record<string, string> }): Miniflare;
