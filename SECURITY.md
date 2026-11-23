# Политика безопасности

## Как сообщить об уязвимости

Пожалуйста, **не создавайте публичный issue**. Сообщите приватно через GitHub: вкладка **Security** → **Report a vulnerability**
([создать сообщение](https://github.com/Oleg4311/passkeys-kit/security/advisories/new)).

Укажите, что именно не так, как это воспроизвести и какая версия затронута. Я постараюсь ответить в течение недели, но это проект одного человека, поэтому сроки не гарантирую.

## Поддерживаемые версии

Исправления выходят для последней версии: ветка `main` и последний релиз.

## Что считается уязвимостью

Принятый ответ, который должен быть отклонён (подделка подписи, чужой origin или rpId, повтор challenge, обход счётчика подписей), вход или регистрация под чужим именем, кража или подделка сессии, обход защиты от CSRF, ограничения частоты или размера запроса, зависание или аварийное завершение при разборе CBOR, утечка открытых или закрытых данных в ответах, блокировка чужого ключа без владения им.

## Что вне области

Отсутствие проверки цепочек аттестации (описано в README), отсутствие восстановления аккаунта, уже известные проблемы в зависимостях (их закрывает Dependabot), массовые обращения к демо-серверу (защита должна стоять на уровне правил Cloudflare), атаки, требующие физического доступа к устройству, и отчёты без способа воспроизведения.

---

## English

Please report vulnerabilities privately via GitHub Security Advisories (**Security** → **Report a vulnerability**) and do not open a public issue. Include what is wrong, how to reproduce it and which version is affected. This is a one-person project, so response times are best-effort. Only the latest release and `main` receive fixes. In scope: accepting responses that must be rejected (forged signature, wrong origin/rpId, challenge replay, counter bypass), impersonation, session theft or forgery, CSRF/rate/size bypass, crashes or hangs in CBOR parsing, data leaks, locking someone else's credential. Out of scope: missing attestation chain verification and account recovery (documented), known dependency issues, volumetric abuse of the demo server.
