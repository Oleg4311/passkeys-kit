// Miniflare с собранным Worker: общий код для тестов и локального сервера. Статику (бинding ASSETS) отдаёт каталог site/.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize } from 'node:path';
import { Miniflare } from 'miniflare';

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json', '.png': 'image/png', '.css': 'text/css' };

export function buildWorker() {
  execFileSync(process.execPath, ['scripts/build-worker.mjs'], { stdio: 'ignore' });
}

export function makeMiniflare({ port, bindings = {} } = {}) {
  const root = join(process.cwd(), 'site');
  return new Miniflare({
    host: '127.0.0.1',
    ...(port ? { port } : {}),
    modules: true,
    scriptPath: 'worker/dist/index.mjs',
    durableObjects: { AUTH: { className: 'AuthDO', useSQLite: true } },
    serviceBindings: {
      ASSETS: async (request) => {
        const url = new URL(request.url);
        const rel = normalize(decodeURIComponent(url.pathname)).replace(/^([/\\])+/, '');
        let file = join(root, rel);
        if (!file.startsWith(root)) return new Response('forbidden', { status: 403 });
        if (existsSync(file) && statSync(file).isDirectory()) file = join(file, 'index.html');
        if (!existsSync(file)) return new Response('not found', { status: 404 });
        return new Response(readFileSync(file), { headers: { 'content-type': TYPES[extname(file)] ?? 'application/octet-stream', 'cache-control': 'no-store' } });
      },
    },
    bindings,
    compatibilityDate: '2026-08-01',
  });
}
