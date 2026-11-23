# passkeys-kit

[![CI](https://github.com/Oleg4311/passkeys-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/Oleg4311/passkeys-kit/actions/workflows/ci.yml)
[Релизы](https://github.com/Oleg4311/passkeys-kit/releases)

**Вход по passkey (WebAuthn) на Cloudflare Workers, где всё написано с нуля и сверено с независимой реализацией.** Разбор CBOR и COSE, проверка регистрации и входа по спецификации W3C, одноразовые challenge, сессии, обнаружение скопированных ключей. В рабочем коде ни одной зависимости: только Web Crypto.

**Попробовать:** https://passkeys-kit.olegbelii4311.workers.dev/ (нужен браузер с passkey: Chrome, Safari, Edge, Firefox) · [English](#english)

## Что умеет

| Часть | Что делает |
|---|---|
| `src/cbor.ts` | Строгий разбор CBOR (RFC 8949): без неопределённой длины, тегов, повторных ключей, хвоста, вложенности глубже 16 |
| `src/cose.ts` | Ключи COSE → Web Crypto: **ES256, EdDSA (Ed25519), RS256**; строгий DER для подписей ECDSA |
| `src/webauthn.ts` | `verifyRegistration` и `verifyAuthentication`: challenge, origin, rpId, флаги UP/UV/BE/BS, подпись, счётчик, аттестация `none` и `packed` (самоподпись) |
| `src/service.ts` | Регистрация, вход без имени (discoverable credentials), несколько ключей на аккаунт, сессии, блокировка ключа-клона |
| `worker/` | Cloudflare Worker и Durable Object: защита от CSRF, `__Host-` кука, ограничение частоты, заголовки безопасности (CSP) |

Вход идёт **без ввода имени**: устройство само предлагает ключ. Сервер при этом не даёт отличить «такого пользователя нет» от «проверка не пройдена».

## Что проверено

- **Сверка с независимой реализацией.** Те же ответы (корректные и испорченные) проверяются нашим кодом и `@simplewebauthn/server` 14.1.0: **668 случаев**, все вердикты совпадают, кроме осознанных расхождений в нашу строгую сторону (см. ниже). Случаи: 12 видов порчи при регистрации, 9 при входе, три алгоритма, два формата аттестации, комбинации счётчика, побитовая порча каждого поля ответа.
- **Находка сверки.** SimpleWebAuthn принимает ECDSA-подпись с испорченной DER-оболочкой (лишние байты после подписи, неверный тег последовательности): одну и ту же подпись можно записать несколькими способами. Подделать подпись так нельзя, но мы такие подписи отклоняем, и это закреплено тестом.
- **CBOR.** Все стандартные примеры из приложения A RFC 8949; любой обрыв корректного документа отвергается; 3000 случайных структур туда-обратно; 30 000 случайных и мутированных входов: только `CborError`, без зависаний.
- **Мутации.** Вручную ломались 10 проверок: подпись, счётчик, rpId, origin (по префиксу), UV, цепочка x5c, строгость DER, challenge, пауза в регистрации (гонка), блокировка до проверки подписи. Каждая ловится тестами.
- **Гонка при регистрации.** Два одновременных запроса на одно имя: место получает ровно один (20 раундов). Тест красный, если вернуть паузу между чтением и записью.
- **Настоящий браузер.** Playwright с виртуальным аутентификатором Chromium (протокол CTAP2): регистрация, выход, вход без имени, второй ключ, удаление, защита последнего ключа, аутентификатор без проверки пользователя отклоняется, **копия ключа со сброшенным счётчиком блокируется**. Кука `__Host-sid` проверяется на `HttpOnly`, `Secure`, `SameSite=Strict`. Десктоп и телефон, axe без нарушений. После каждого деплоя те же сценарии идут на живом адресе.
- 54 теста (`node:test`), 16 сценариев Playwright, `tsc --strict`.

## Безопасность в деталях

- **Challenge** случайный (32 байта), одноразовый (сгорает при любой попытке), живёт 5 минут, привязан к виду операции (регистрация или вход).
- **Сессии**: случайный токен в `HttpOnly; Secure; SameSite=Strict` куке с префиксом `__Host-`; в хранилище только его SHA-256; срок 7 дней.
- **CSRF**: изменяющие запросы принимаются только с `Origin`, равным адресу сервиса, и только как JSON.
- **rpId и origin** берутся из адреса запроса (на Workers его определяет маршрутизация Cloudflare); с чужого адреса запрос не пройдёт.
- **Клон ключа**: если счётчик подписей не растёт, вход отклоняется, а ключ блокируется. Блокировка ставится только после проверки подписи: зная идентификатор ключа, заблокировать его нельзя.
- **Нельзя остаться без доступа по ошибке**: последний ключ аккаунта удалить нельзя.
- **Заголовки страницы**: CSP (`default-src 'none'`, скрипты только свои, `frame-ancestors 'none'`), `nosniff`, `no-referrer`, ограничение Permissions-Policy.
- Ограничение частоты: 120 попыток регистрации и входа в минуту с одного адреса.

## Честные ограничения

- **Аттестация только `none` и `packed` с самоподписью.** Цепочки сертификатов (TPM, Apple, Android Key, FIDO MDS) не проверяются: сервис просит `attestation: "none"`, а чужие форматы отклоняет. Для случаев, когда нужно знать модель ключа, пригодится SimpleWebAuthn.
- **Строгий DER может отклонить редкие нестандартные устройства.** Все проверенные виртуальные и программные аутентификаторы подписывают канонически; на настоящих ключах (YubiKey, Windows Hello, iCloud Keychain, Google Password Manager) проверка не проводилась: у меня их нет.
- **Один Durable Object на всё приложение.** Просто и последовательно, но не масштабируется на большую нагрузку: для неё данные нужно делить по пользователям.
- **Нет восстановления аккаунта.** Потеряли все ключи, потеряли аккаунт. Для настоящей системы нужны резервные коды или второй способ входа.
- **Нет подсказки по имени при входе.** Вход только через ключи, найденные на устройстве; нельзя ввести имя и получить список ключей (так сервис не раскрывает существование имён).
- **Демо-хранилище.** Имена и открытые ключи лежат в Durable Object; удаления аккаунта целиком нет.
- Расширения WebAuthn (PRF, largeBlob), подтверждение транзакций и кросс-доменные фреймы не поддерживаются.

## Разработка

```
npm install
npm test            # CBOR, WebAuthn, сверка с SimpleWebAuthn, сервис, настоящий Worker в Miniflare
npm run typecheck
npm run build       # страница в site/
npm run e2e         # Playwright (один раз: npx playwright install chromium); локальный сервер поднимется сам
npm run serve       # http://localhost:4176/
```

Адрес для локальной проверки именно `localhost`: WebAuthn не принимает IP-адреса как rpId. При настроенном прокси добавьте `NO_PROXY=127.0.0.1,localhost`. Деплой идёт из CI (секреты репозитория `CLOUDFLARE_API_TOKEN` и `CLOUDFLARE_ACCOUNT_ID`).

Лицензия: MIT. Сделано с помощью Claude.

---

## English

**passkeys-kit** is a from-scratch WebAuthn (passkey) implementation for Cloudflare Workers with zero runtime dependencies: strict CBOR and COSE parsing (ES256, EdDSA, RS256), registration and authentication verification per W3C Level 3, one-time challenges, `__Host-` session cookies, CSRF protection, usernameless sign-in with discoverable credentials, and **clone detection** (a non-increasing signature counter locks the credential, and only after the signature verifies).

Verified against the independent `@simplewebauthn/server` on 668 valid and corrupted responses (verdicts agree except deliberate stricter behavior on our side — the comparison found that SimpleWebAuthn accepts ECDSA signatures with a corrupted DER envelope), with the RFC 8949 vectors, fuzzing, ten manual mutations, a registration race test, and a real Chromium with a virtual CTAP2 authenticator (also against the live deployment after each deploy). Honest limits: attestation `none`/self-packed only, not tried on physical security keys, one Durable Object for the whole app, no account recovery. MIT licensed. Built with Claude.

**Try it:** https://passkeys-kit.olegbelii4311.workers.dev/
