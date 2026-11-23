// Локальный сервер: страница и API на одном адресе, как после деплоя. Нужен для e2e и ручной проверки: http://127.0.0.1:4176/
import { buildWorker, makeMiniflare } from './mf.mjs';

buildWorker();
const mf = makeMiniflare({ port: 4176, bindings: { RATE_PER_MINUTE: '5000' } }) // e2e шлёт запросы с одного адреса;
await mf.ready;
console.log('http://127.0.0.1:4176/');
process.on('SIGINT', async () => {
  await mf.dispose();
  process.exit(0);
});
