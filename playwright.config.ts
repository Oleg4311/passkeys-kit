import { defineConfig, devices } from '@playwright/test';

// BASE_URL задаётся для проверки опубликованной версии, иначе тесты идут на локальной сборке. Адрес localhost, а не 127.0.0.1:
// WebAuthn не принимает IP-адреса в качестве rpId.
const live = process.env.BASE_URL;

export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  reporter: [['list']],
  use: { baseURL: live ?? 'http://localhost:4176/' },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['Pixel 7'] } },
  ],
  webServer: live
    ? undefined
    : {
        command: 'npm run build && node scripts/dev-server.mjs',
        url: 'http://localhost:4176/api/health',
        reuseExistingServer: !process.env.CI,
        timeout: 120_000,
      },
});
