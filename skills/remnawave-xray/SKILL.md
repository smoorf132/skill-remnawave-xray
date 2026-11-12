---
name: remnawave-xray
description: >-
  Use when working with a Remnawave VPN stack — designing, generating, or debugging
  selfsteal nodes built on VLESS + Reality + XTLS-Vision (Xray-core), Caddy selfsteal
  masking, and mihomo (Clash.Meta) client configs. Triggers on: Remnawave panel/node,
  selfsteal, Reality/Vision handshake, xray config, Caddyfile, mihomo/clash yaml,
  routing/сплит-туннель, гео-разблок (OpenAI/Gemini), WARP outbound,
  "нода не подключается", "Reality палится", "handshake fail", генерация конфигов нод.
  Covers stack reference, config generation with validated defaults, an executable
  consistency validator, and symptom→cause→fix diagnostics.
---

# Remnawave-Xray — selfsteal-ноды (Xray Reality + Caddy + mihomo)

Скилл под конкретный стек: **Remnawave** (оркестратор панель→нода) → **Xray-core**
(VLESS+Reality+XTLS-Vision на ноде) → **Caddy** (selfsteal-заглушка на той же машине) →
**mihomo/Clash.Meta** (клиент). Три режима: справочник, генератор конфигов, диагностика.

Данные собраны из первоисточников (исходники XTLS/Xray-core, wiki mihomo, docs.rw,
selfsteal.sh DigneZzZ) на 2026-07-01, пересверены по исходникам на тегах Panel 3.4.10 /
Node 3.4.5 / Xray v26.11.9 / mihomo v1.19.34 и по release notes Caddy 2.11.9 на 2026-11-12.
Факты, помеченные в подфайлах как «НЕТОЧНО» — проверять под свою версию.

## Когда использовать

- Поднять/починить selfsteal-ноду (Xray Reality + Caddy на одном сервере).
- Сгенерировать рабочий конфиг: Xray inbound, Caddyfile, mihomo yaml.
- Разобрать симптом: нода offline, Reality палится/handshake fail, Caddy 502, mihomo не коннектится.
- Не запутаться в специфике: порты, ключи, что с чем совпадает, что выпилено из ядра.

## Архитектура в двух словах

```
                         :443 (0.0.0.0)
  клиент mihomo ──TLS──►  Xray-core (VLESS+Reality+Vision)
                            │
              Reality-auth OK ├─► расшифровка VLESS, проксирование трафика юзера
                            │
              auth FAIL ─────┴─► прозрачный форвард (raw TCP + PROXY-proto xver:1)
                                  ──► Caddy  :9443 (127.0.0.1)  ──► реальный сайт-заглушка
                                      Caddy :80 (0.0.0.0) держит ACME HTTP-01 сам
```

Смысл selfsteal: `dest` Reality = **твой собственный** домен с настоящим ACME-сертом и
реальным сайтом за Caddy. Активный пробинг видит обычный сайт — неотличимо. Детали и
таблица портов → `reference/architecture.md`.

## Железные инварианты (нарушишь — не работает или палится)

1. **Порт 443.** Не-443 ядро само помечает warning'ом → быстрый бан IP. Слушать только 443.
2. **Согласованность selfsteal:** `realitySettings.dest` → локальный Caddy (напр. `127.0.0.1:9443`);
   `serverNames` == `SELF_STEAL_DOMAIN`; `SELF_STEAL_PORT` совпадает в Caddyfile (`https_port`)
   и в Xray `dest`. Разъехались — handshake или заглушка ломаются.
3. **Домен selfsteal — DNS-only (серое облако), НЕ под Cloudflare-proxy.** Оранжевое облако
   терминирует TLS у себя, ключа Reality не имеет → ломает и ACME, и сам Reality. (Не путать
   с отдельной техникой Reality+CDN/XHTTP — это другой инбаунд, см. xray-reality.md.)
4. **Flow только `xtls-rprx-vision`**, одинаковый на сервере и клиенте, только поверх raw TCP.
   Legacy XTLS-flow (`-direct/-splice/-origin`) — мёртвая ошибка в коде.
5. **Клиент (mihomo): `client-fingerprint` обязателен** при `reality-opts` — без него handshake
   не поднимется (`REALITY is based on uTLS...`). `global-client-fingerprint` выпилен в 1.19.27 —
   только per-proxy.
6. **Ключи:** privateKey/publicKey — ровно 32 байта; publicKey клиента = `xray x25519 -i "<server privateKey>"`;
   shortId ≤16 hex, чётная длина; на клиенте — единственное число `serverName`/`shortId`
   (множественное = ошибка парсинга).
7. **Никаких `apple`/`icloud` в `serverNames`** (ядро выдаёт warning + бан по GFW). Никакого `allowInsecure`
   (выпилен в v26.2.6). `show: false` в проде.
8. **Инфра ноды:** `network_mode: host` для Xray и Caddy; порт **80** открыт (ACME); порт ноды
   (control-API панель→нода) открыт только для IP панели; связь панель→нода двухслойная (mTLS + JWT RS256,
   `SECRET_KEY` = base64-JSON с сертами). Внутренний API Xray — `127.0.0.1:61000`/unix-socket (не «61001»), не трогать.
9. **`minClientVer` у Reality-сервера — зависит от версии ядра, не угадывать.** Дефолт
   `"minClientVer": "26.3.27"` появился в июле 2026 и есть в v26.7.28 (ноды 3.1.1–3.4.3) —
   там он молча отсекает старые клиенты. С v26.9.9 (нода ≥ 3.4.4) дефолт **снят** — без явного поля
   версия клиента не проверяется. Нужен порог — задавать `minClientVer` явно в `realitySettings`.
   Сначала `docker exec remnanode xray version`, потом выводы.
10. **VLESS и Trojan без шифрования наружу запрещены ядром с v26.7.28.** Outbound без
   `security` (TLS/Reality) и без VLESS Encryption на **публичный** адрес роняет конфиг
   на старте: `vless without TLS or other encryption is prohibited unless the server
   address is a private IP or domain`. Приватные IP и домены (`127.0.0.1`, локалка)
   по-прежнему можно — на них держится связка «нода → локальный сервис». Бьёт по
   plain-мостам «нода → публичный origin»: там нужен Reality/TLS либо VLESS Encryption.
11. **Ноды держать на Xray ≥ v26.10.31 (нода ≥ 3.4.4), панель ≥ 3.4.8.** v26.10.31 выключил MPTCP
   на listener'ах по умолчанию (в Linux-ядре — удалённая уязвимость в MPTCP, Go включал его сам);
   v26.10.21 убрал скомпрометированные корневые сертификаты из встроенного набора; панель 3.4.3 и
   3.4.8 закрыли обход авторизации `/api/backend-tools` и чтение файлов сертификатов. Ядро Linux
   на ноде обновить тоже — отключение MPTCP в Xray закрывает только сам Xray.

## Куда смотреть

| Задача | Файл |
|---|---|
| Как устроена нода, порты, потоки данных, xver/proxy_protocol | `reference/architecture.md` |
| Reality/Vision: параметры, dest, ключи, post-quantum, анти-пробинг, что выпилено | `reference/xray-reality.md` |
| Caddy selfsteal: Caddyfile, ACME, listener_wrappers, DNS-only домен | `reference/caddy-selfsteal.md` |
| mihomo клиент: yaml, VLESS+Reality запись, DNS/rules/sniffer/tun, грабли | `reference/mihomo.md` |
| Панель: Config Profile→Inbound→Host, node-agent, автогенерация pubkey | `reference/remnawave.md` |
| Другие транспорты: xhttp / ws / grpc / httpupgrade / mkcp / hysteria (HY2) | `reference/transports.md` |
| Другие протоколы: vmess / trojan / ss / wireguard / VLESS-Encryption + статус HY2/TUIC/AnyTLS | `reference/protocols.md` |
| Routing: сплит-туннель РФ, гео-разблок (OpenAI/Gemini), WARP outbound, geosite/geoip | `reference/routing.md` |
| Сгенерировать конфиг под параметры + команды ключей | `generators.md` |
| Проверить готовый конфиг на согласованность (скрипт) | `python validate.py <config.json> [Caddyfile]` |
| Что-то не работает / палится → симптом→причина→фикс | `diagnostics.md` |
| Готовые обезличенные боевые шаблоны (selfsteal / CDN-мост / балансир / mihomo / SRR) | `examples/` |

## Версии стека (на 2026-11-12 — сверять перед деплоем)

| Компонент | Версия | Формат |
|---|---|---|
| Remnawave panel | 3.4.10 (2026-11-10) | semver, образ `remnawave/backend:3` |
| Remnawave node | 3.4.5 (2026-11-09) | semver, внутри Xray v26.11.9 |
| Xray-core | v26.11.9 | CalVer `vYY.M.D` |
| Caddy | 2.11.9 | semver |
| mihomo (Clash.Meta) | 1.19.34 | линейка `v1.19.x` |

Ядро отдельно не ставится: нода несёт его в образе (`ARG XRAY_CORE_VERSION` в её Dockerfile) —
версия ядра на ноде определяется версией ноды, а не выбирается.

Какая нода какое ядро несёт (по `docker/Dockerfile` на тегах ноды):

| Нода | Xray-core |
|---|---|
| 3.1.1 … 3.4.3 | v26.7.28 |
| 3.4.4 | v26.10.31 |
| 3.4.5 | v26.11.9 |

То есть всё, что менялось в ядре с августа по октябрь, приезжает на ноду одним скачком при
переходе 3.4.3 → 3.4.4. Что именно ломается/меняется — `diagnostics.md`, первый раздел.

Чем проверить актуальность (версии тут — снимок на дату сборки):

```
docker exec remnanode xray version            # ядро на ноде
docker exec caddy-selfsteal caddy version     # Caddy
# У XTLS часть релизов помечена pre-release, и /releases/latest отдаёт последний НЕ-pre тег.
# На 2026-11-12 он совпал с самым свежим (v26.11.9), но в августе отдавал v26.3.27 при
# актуальном v26.7.28. Надёжнее брать первый из списка:
curl -s 'https://api.github.com/repos/XTLS/Xray-core/releases?per_page=1' | grep tag_name
curl -s https://api.github.com/repos/remnawave/panel/releases/latest | grep tag_name
curl -s https://api.github.com/repos/remnawave/node/releases/latest | grep tag_name
curl -s https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | grep tag_name
```

## Режимы

- **Справочник** — вопрос по стеку: открыть нужный `reference/*.md`, ответить по факту, не по памяти.
- **Генератор** — нужен конфиг: `generators.md`, заполнить плейсхолдеры, прогнать чеклист согласованности,
  затем `python validate.py <config.json> [Caddyfile]` — исполняемая проверка тех же инвариантов.
- **Диагностика** — сломано: `diagnostics.md`, от симптома к причине, дать команды проверки.
