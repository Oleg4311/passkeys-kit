import AxeBuilder from '@axe-core/playwright';
import { expect, test, type BrowserContext, type CDPSession, type Page } from '@playwright/test';

const uniq = (): string => 'user' + Math.random().toString(36).slice(2, 9);

interface Device {
  cdp: CDPSession;
  id: string;
}

/** Виртуальный аутентификатор Chromium: настоящий протокол CTAP2, ключи с хранением на устройстве, проверка пользователя пройдена. */
async function addDevice(context: BrowserContext, page: Page): Promise<Device> {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  });
  return { cdp, id: authenticatorId };
}

async function signUp(page: Page, name: string): Promise<void> {
  await page.goto('./');
  await page.getByLabel('Имя пользователя').fill(name);
  await page.getByRole('button', { name: 'Создать passkey' }).click();
  await expect(page.getByTestId('whoami')).toContainText(name);
}

test('регистрация, выход и вход по passkey без ввода имени', async ({ page, context }) => {
  await addDevice(context, page);
  const name = uniq();
  await signUp(page, name);
  await expect(page.getByTestId('credential')).toHaveCount(1);
  await page.getByRole('button', { name: 'Выйти' }).click();
  await expect(page.getByRole('heading', { name: 'Вход без пароля' })).toBeVisible();
  await page.getByRole('button', { name: 'Войти по passkey' }).click();
  await expect(page.getByTestId('whoami')).toContainText(name);
  await page.reload();
  await expect(page.getByTestId('whoami')).toContainText(name); // сессия живёт в куке
  await expect(page.getByTestId('credential')).toContainText('подписей: 2'); // Chrome считает и подпись при создании ключа: регистрация даёт 1, вход 2
});

test('кука сессии: HttpOnly, Secure, SameSite=Strict и недоступна из скрипта страницы', async ({ page, context }) => {
  await addDevice(context, page);
  await signUp(page, uniq());
  const cookies = (await context.cookies()).filter((c) => c.name === '__Host-sid');
  expect(cookies).toHaveLength(1);
  expect(cookies[0]).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Strict', path: '/' });
  expect(await page.evaluate(() => document.cookie)).toBe('');
});

test('вход без аккаунта: чужое устройство без ключей получает понятный отказ', async ({ page, context }) => {
  await addDevice(context, page);
  await page.goto('./');
  await page.getByRole('button', { name: 'Войти по passkey' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
});

test('имя занято: второй человек не может его занять', async ({ browser, page, context }) => {
  await addDevice(context, page);
  const name = uniq();
  await signUp(page, name);
  const ctx2 = await browser.newContext();
  const page2 = await ctx2.newPage();
  await addDevice(ctx2, page2);
  await page2.goto('./');
  await page2.getByLabel('Имя пользователя').fill(name);
  await page2.getByRole('button', { name: 'Создать passkey' }).click();
  await expect(page2.getByRole('alert')).toContainText('уже занято');
  await ctx2.close();
});

test('второй ключ: то же устройство не регистрируется дважды, другое добавляется, удаление и защита последнего ключа', async ({ page, context }) => {
  const first = await addDevice(context, page);
  await signUp(page, uniq());
  await page.getByRole('button', { name: 'Добавить ещё один ключ' }).click();
  await expect(page.getByText('уже зарегистрирован на устройстве')).toBeVisible();
  await expect(page.getByTestId('credential')).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Удалить ключ 1' })).toBeVisible();
  await page.getByRole('button', { name: 'Удалить ключ 1' }).click();
  await expect(page.getByText('Нельзя удалить последний ключ')).toBeVisible();

  await first.cdp.send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: first.id });
  await addDevice(context, page); // «второе устройство»
  await page.getByRole('button', { name: 'Добавить ещё один ключ' }).click();
  await expect(page.getByTestId('credential')).toHaveCount(2);
  await page.getByRole('button', { name: 'Удалить ключ 1' }).click();
  await expect(page.getByTestId('credential')).toHaveCount(1);
  await page.getByRole('button', { name: 'Выйти' }).click();
  await page.getByRole('button', { name: 'Войти по passkey' }).click();
  await expect(page.getByTestId('whoami')).toBeVisible();
});

test('копия ключа: счётчик подписей не вырос → вход отклонён, ключ заблокирован', async ({ page, context }) => {
  const dev = await addDevice(context, page);
  const name = uniq();
  await signUp(page, name);
  for (let i = 0; i < 2; i++) {
    await page.getByRole('button', { name: 'Выйти' }).click();
    await page.getByRole('button', { name: 'Войти по passkey' }).click();
    await expect(page.getByTestId('whoami')).toContainText(name);
  }
  await expect(page.getByTestId('credential')).toContainText('подписей: 3');
  await page.getByRole('button', { name: 'Выйти' }).click();
  // «клон»: тот же закрытый ключ, но счётчик начинается заново
  const { credentials } = await dev.cdp.send('WebAuthn.getCredentials', { authenticatorId: dev.id });
  expect(credentials).toHaveLength(1);
  await dev.cdp.send('WebAuthn.clearCredentials', { authenticatorId: dev.id });
  await dev.cdp.send('WebAuthn.addCredential', { authenticatorId: dev.id, credential: { ...credentials[0]!, signCount: 0 } });
  await page.getByRole('button', { name: 'Войти по passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('скопирован');
  // и повторный вход тем же ключом теперь закрыт
  await page.getByRole('button', { name: 'Войти по passkey' }).click();
  await expect(page.getByRole('alert')).toContainText('заблокирован');
});

test('чужой аутентификатор без проверки пользователя не проходит: сервер требует UV', async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: true, hasUserVerification: false, automaticPresenceSimulation: true },
  });
  await page.goto('./');
  await page.getByLabel('Имя пользователя').fill(uniq());
  await page.getByRole('button', { name: 'Создать passkey' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByTestId('whoami')).toHaveCount(0);
});

test('доступность и отсутствие горизонтальной прокрутки', async ({ page, context }) => {
  await addDevice(context, page);
  await page.goto('./');
  expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  await signUp(page, uniq());
  expect((await new AxeBuilder({ page }).analyze()).violations.map((v) => v.id)).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
});
