# Remnawave: панель, нода, подписки

Panel **3.4.10** / Node **3.4.5** (⇄ Xray-core v26.11.9). Сверено с исходниками `remnawave/backend`
на теге 3.4.10 и `remnawave/node` на теге 3.4.5 (схемы, `.env.sample`, Dockerfile) и release notes
3.3.0…3.4.10; часть — с живой панели. Панель и нода версионируются раздельно, но в 3.4.x идут рядом.

⚠️ **3.0.0 — мажор с ломающим API.** Всё, что ходило в панель по UUID пользователя, переписывается;
детали ниже в «Panel API v3». На конфиги Xray/Caddy это не влияет — ломается интеграция, не стек.

## Компоненты

| Компонент | Образ | Роль |
|---|---|---|
| Backend (панель) | `remnawave/backend:3` | NestJS API + БД-логика. Внутри PM2-кластер: `api` (масштаб `API_INSTANCES`), `scheduler`, `processor`. |
| Frontend | (в том же backend-образе) | React, отдельного контейнера в проде нет. |
| Node (RemnaNode) | `remnawave/node` | TS-агент, **гоняет Xray-core**. |
| Subscription-page | `remnawave/subscription-page` | человекочитаемая страница подписки, `APP_PORT=3010`. |
| xtls-sdk | npm `@remnawave/xtls-sdk` | обёртка над gRPC Xray-core API (крипто, pbk из privateKey). |

**Панель НЕ содержит Xray** — без ноды проксировать некуда. Prod compose = 3 сервиса:
`remnawave` (3000/3001), `remnawave-db` (`postgres:18.4`), `remnawave-redis` (`valkey:9-alpine`, unix-socket).

## Иерархия (ключевая ментальная модель)

```
Config Profile (полный Xray JSON) ──> Inbound(ы) ──> Host(ы) ──> отдаются в подписку
        │                                  │
        └── privateKey Reality здесь       └── Internal Squad включает Inbound(ы) юзеру
        └── активен на Node(ах)
```

- **Config Profile** = целый Xray-core JSON («шаблон» для ноды). Одна Нода ↔ ровно один активный Профиль;
  Профиль ↔ несколько Нод возможно. `clients: []` в инбаундах **всегда пустой** — панель инжектит юзеров
  динамически при пуше конфига на ноду. `privateKey` Reality живёт прямо в `realitySettings` профиля, из БД не выходит.
- **Inbound** — конкретный протокол внутри профиля (VLESS+Reality и т.п.), идентифицируется `tag`.
- **Host** = «шлюз» в подписке. Выбирает ровно один Inbound. Порт **наследуется** от инбаунда;
  пустые Advanced-поля → берутся из инбаунда. С 3.x у хоста есть собственное поле `nodes[]`
  (массив uuid, редактируемое в create/update) — привязка к нодам стала явной, а не только
  косвенной «через профиль». Старое правило «прямой связи host↔node нет» больше не верно.
- **Internal Squad** = группа доступа: какие Inbound'ы доступны юзеру (аддитивно, юзер в нескольких).
  **External Squad** (≥2.2.0) = переопределение Templates/Settings для группы.
- **Snippets** — переиспользуемые куски `outbounds`/`routing` across профилей (правишь раз — меняется везде).

## Поля Host (схема 3.4.10, `libs/contract/models/hosts.schema.ts`)

`remark`, `address` (домен предпочтительнее IP — при смене IP ноды подписки не переиздавать), `port` (наследуется),
`sni` (пусто → из `serverNames` инбаунда), `host`, `path`, `alpn`, `fingerprint`, `securityLayer` (DEFAULT/TLS),
`tags[]`, `isHidden` (не в обычной подписке — только через `injectHosts`), `isDisabled`, `pinnedPeerCertSha256`,
`verifyPeerCertByName` (cert-pinning), `mihomoX25519`/`mihomoIpVersion`, `overrideSniFromAddress`,
`keepSniBlank`, `internalSquads.{mode, squads[]}`, `excludeFromSubscriptionTypes[]`, `xrayJsonTemplateUuid`,
`viewPosition`, `inbound.{configProfileUuid, configProfileInboundUuid}`, `mapper`, `includeInSrrRules[]`.

Появились в 3.3.0…3.4.10:

- **`internalSquads`** вместо плоского `excludedInternalSquads[]` (3.4.0): `mode` = `EXCLUDE` (скрыть
  хост от перечисленных сквадов) или `ALLOW_ONLY` (показывать только им; пустой список в этом режиме
  не проходит валидацию). Интеграции, писавшие `excludedInternalSquads`, переделать.
- **`mapper` — Host Mapper** (3.3.0): список операций `copy` / `set` / `unset`, которыми хост
  дописывает итоговый клиентский конфиг. `from` — путь в **сыром инбаунде** профиля
  (`streamSettings.tlsSettings.alpn`, `streamSettings.realitySettings.serverNames.0`) либо в самом
  хосте с префиксом `$host.` (`$host.securityOptions.serverName` — SNI, реально ушедший в конфиг);
  `to` — путь в генерируемом конфиге клиента (для Xray-Json, Mihomo и Sing-box — свои наборы
  операций). Не нашёл источник — операция пропускается, ключ не создаётся. Это штатная замена
  ручной правки шаблонов ради одного поля.
- **`includeInSrrRules[]`** (3.4.9): хост отдаётся только в ответах Response Rules с перечисленными
  **именами**; пусто — во всех. Позволяет держать «хост только для Happ» без отдельных сквадов.
- **Клонирование хоста** — отдельная ручка API (3.4.4).

Появились к 3.2.3 (в снимке 2.8.0 их не было), актуальны и в 3.4.10:

- `nodes[]` — явная привязка хоста к нодам (см. выше).
- `finalMask` — проброс объекта `finalmask` ядра (маски потока: `fragment`, `salamander`, `udphop`, `xmc` и др. — список в `transports.md`).
- `vlessRouteId` (0…65535) — идентификатор маршрута VLESS.
- `shuffleHost` — перемешивание.
- `serverDescription` (≤30 символов) — подпись сервера в клиенте.
- `xhttpExtraParams`, `muxParams`, `sockoptParams` — сырые объекты, уезжают в соответствующие секции конфига.
- **3.2.3:** `cipherSuites` из `tlsSettings` инбаунда теперь доезжает до Xray-Json и Base64-подписок
  (раньше терялся) — парная фича к «TLS client: support more cipherSuites for unsafe fingerprint» в v26.7.28.

## Установка ноды

Обязательных ENV по-прежнему **два**: `NODE_PORT` (слушает internal API от панели; в примерах 2222,
настраиваемо) + `SECRET_KEY` (выдаёт панель). `SECRET_KEY` — это base64-JSON
`{caCertPem, jwtPublicKey, nodeCertPem, nodeKeyPem}`: нода поднимает HTTPS с **mTLS**
(`minVersion TLSv1.3`, `rejectUnauthorized`) + поверх **JWT RS256**. Связь строго **панель → нода**
(панель — клиент). Firewall ноды: `NODE_PORT` открыть **только для IP панели**.

Необязательные ENV ноды (схема 3.4.5, все с дефолтами):

| ENV | Дефолт | Зачем |
|---|---|---|
| `SNI_VERIFICATION` | `false` | нода принимает control-подключение только с «правильным» SNI, выведенным из CA и JWT-ключа; остальным — не отвечает как нода. Прячет `NODE_PORT` от сканеров |
| `NFTABLES_TABLE_NAME` | `remnanode` | имя nft-таблицы плагинов — менять, если на хосте две ноды |
| `NFTABLES_LOGGING` | `true` | логирование правил плагинов |
| `NFTABLES_ACCEPT_REPLY_TRAFFIC` | `false` | пропускать ответный трафик в фильтрах |
| `SUPPRESS_DUPLICATE_INSTANCE_WARNING` | `false` | заглушить предупреждение о втором экземпляре |

Парная настройка на панели — `SERVICE_SNI_VERIFICATION` (дефолт `true`, 3.4.5): панель с 3.3.0
сама выводит и шлёт SNI при подключении к нодам. Включать `SNI_VERIFICATION=true` на ноде имеет
смысл только при панели ≥ 3.3.0, иначе панель до ноды не достучится.

- Нет ENV `SSL_CERT`/`APP_PORT` у ноды. TLS-серты для TLS-транспортов монтируются со стороны панели
  (`/var/lib/remnawave/configs/xray/ssl/`), для Reality **не нужны**.
- **Порт 61001 — миф.** Внутренний control-API Xray в 3.4.x — **абстрактные unix-сокеты** со случайным
  суффиксом (`xtls-api-<rnd>` для gRPC ядра, `rwint-<rnd>` для внутреннего REST ноды), TCP-порта нет вовсе;
  `127.0.0.1:61000` встречается только на старых сборках. Нода авто-инжектит служебный инбаунд `REMNAWAVE_API_INBOUND` (`protocol: tunnel`, в UI не виден).
  Всё это loopback/socket — наружу не выставляется, в firewall не трогать.
- Гео-файлы монтировать **по одному файлу** в `/usr/local/share/xray/` (иначе затрёшь дефолтные). Логи Xray —
  том `/var/log/remnanode` + **обязателен logrotate**. CLI: `docker exec -it remnanode cli` (`--dump-config`), `xlogs`.
- **Node 3.1.1: гео-файлы докачиваются самой нодой перед стартом ядра.** Раньше корректно описанный
  объект `geodata` в конфиге не спасал на первом запуске — Xray не мог скачать файлы, которых ещё нет,
  и падал. Теперь недостающее нода тянет сама, а дальнейшие обновления Xray делает по своему cron.
  Прочие правки 3.1.1: `webhookUrl` в плагине Torrent Blocker, фикс зависания процесса ядра.
- **Node 3.4.4 / 3.4.5 — в первую очередь обновление ядра** (v26.10.31 → v26.11.9, см. таблицу в
  `../SKILL.md`). 3.4.5 дополнительно: нода перестала затирать `routing.script` (Lua-роутинг ядра),
  плагины обновлены до `@remnawave/node-plugins` 0.9.0. 3.4.3 — базовый образ Node.js 24.22 (security).
- **Интеграции ноды** (3.3.0): опциональные компоненты, которые ставятся в образ ноды и управляются
  с панели (`docker/integrations/` в репозитории ноды); смена набора интеграций перезапускает ноду.
  Рядом появились geocheck-ручки и «Node SSH» (3.4.0). Детали по конкретным интеграциям — docs.rw,
  здесь не сверялись (**НЕТОЧНО**).

## ENV панели (ключевое)

**`APP_SECRET`** (`openssl rand -hex 64`) — с 3.0.0 один секрет вместо пары `JWT_AUTH_SECRET` +
`JWT_API_TOKENS_SECRET`; старые имена панель 3.x не читает. Дальше — `FRONT_END_DOMAIN` (CORS),
`SUB_PUBLIC_DOMAIN` (домен+путь подписки), `APP_PORT` (3000), `METRICS_PORT` (3001), `API_INSTANCES` (1/max),
`METRICS_USER`/`METRICS_PASS`, вебхуки (`WEBHOOK_ENABLED`/`WEBHOOK_URL`/`WEBHOOK_SECRET_HEADER` ≥32),
telegram-нотификации, `EXPIRATION_NOTIFICATIONS`/bandwidth — **брать из актуального `.env.sample`**, а не со
страницы docs (там устарело/неполно). Панель обязательно за reverse-proxy на `127.0.0.1`, на root-пути домена.

Новое в `.env.sample` 3.4.x:

- `SERVICE_SNI_VERIFICATION=true` — см. «Установка ноды».
- `SHORT_UUID_METHOD` = `nanoid` (дефолт, длина `SHORT_UUID_LENGTH` 16…64) / `uuid` / `custom`
  (`SHORT_UUID_CUSTOM_PATTERN`, токены `{nanoid:N}` `{alpha:N}` `{digits:N}` `{hex:N}` `{uuid}`, итог
  16–64 символа и не меньше ~64 бит случайности) — формат идентификатора в ссылке подписки (3.4.0).

Prod-compose панели не менялся: `remnawave/backend:3`, `postgres:18.4`, `valkey/valkey:9-alpine`.

## Подписки

- Формат по User-Agent: **Mihomo** / **Xray-json** / **Sing-box** / **Base64** (fallback). Браузер → веб-страница.
- `pbk=` в `vless://` — публичный ключ, **выводится панелью из `privateKey`** инбаунда на лету (приватный не покидает
  профиль). Остальные параметры ссылки — проекция полей Host + фикс `encryption=none`/`flow=xtls-rprx-vision`.
- **Response Rules (SRR)** — упорядоченные правила по заголовкам запроса → `responseType`
  (`MIHOMO`/`XRAY_JSON`/`XRAY_BASE64`/`SINGBOX`/`STASH`/`BROWSER`/`BLOCK`/`STATUS_CODE_404`/`STATUS_CODE_451`/
  `SOCKET_DROP`...). Переопределяют External Squads. Модификация `respondWithRemarks` (3.3.0) подменяет
  тело ответа списком remark'ов-заглушек («обновите приложение»): если в массиве больше одного
  элемента, настоящие хосты не отдаются. Дефолтный набор правил обновлён в 3.4.4.
  Эталон: `../examples/subscription-response-rules.json` (Happ/Karing/Shadowrocket/Mihomo/xray-checker + HWID-проверка).
- **`injectHosts`** (директива `remnawave` в XRAY_JSON-шаблоне, ≥2.6.3) — подставляет outbound'ы **скрытых** хостов
  (`isHidden`) по `selector` (`uuids`/`remarkRegex`/`tagRegex`/`sameTagAsRecipient`) для сборки балансировщиков/мостов
  на клиенте. Панель вырезает объект `remnawave` из итога. Эталон: `../examples/xray-balancer-leastload.json`,
  `../examples/xray-balancer-random.json` (`remnawave.injectHosts` + `burstObservatory` + `leastLoad`/`random` balancer).

## Прочее

- **Backup — НЕ встроен** (community-инструменты). Monitoring — Prometheus `/metrics` + Grafana dashboard **25064**.
- CLI панели (`docker exec -it remnawave cli`): reset superadmin, enable password auth, **Get SECRET_KEY for Node**, reset certs.
- **Node Plugins** (≥2.7.0): Torrent Blocker (webhook Xray PR #5722, нужен Xray ≥26.3.27), Ingress/Egress Filter,
  Connection Drop — требуют `cap_add: NET_ADMIN` + nftables + ядро ≥5.7.

## Panel API v3 — что сломалось при переходе с 2.8.x

Всё это про **интеграции** (боты, админки, экспортеры). Конфигов Xray и Caddy не касается.

- **Пользователь адресуется числовым `id`, поля `uuid` у него больше нет.** Все ручки `{uuid}` стали
  `{userId}`. Интеграции, хранившие UUID юзера, придётся перевязать.
- Точечные ручки поиска **удалены** (`by-telegram-id`, `by-email`, `by-tag`) → `GET /api/users/stream`
  с фильтрами `telegramId` / `email` / `tag`.
- `/api/ip-control` → **`/api/connections`**, параметр `userUuids` → `userIds`.
- `DELETE` отвечает **204/202 без тела** (было 200 с телом). Bulk-операции больше не возвращают
  `{ affectedRows: N }` — узнать, сколько зацепило, нечем.
- Поля подписки `profileTitle` / `profileUpdateInterval` / `supportLink` уехали **в заголовки ответа**.
- Доки на фиксированном пути `/api/backend-tools`; `SWAGGER_PATH` / `SCALAR_PATH` / `IS_DOCS_ENABLED` убраны.

Прежние гетчи, которые остались в силе: `tag` инбаунда — UPPERCASE; в `create_user` бывают скрытые 400;
`/api/bandwidth-stats/nodes` — даты только `YYYY-MM-DD`; Config Profile нормализует `network: raw` ↔ `tcp`
в клиентской ссылке для совместимости.

## Прочее в 3.2.x

- **Сниппеты приняли `geodata` и `dns`** + опциональный перезапуск затронутых нод после правки (3.2.3).
- `REDIS_USERNAME` в ENV; нодам можно назначать IP-адреса с разными флагами (3.2.3).

## Что добавили 3.3.x – 3.4.x (кроме полей Host выше)

- **Shared Lists** (3.3.0) — общие списки, переиспользуемые в настройках; в 3.4.0 поменялись
  API-маршруты списков, а в именах сниппетов и списков разрешили `/`.
- **Теги** у Config Profiles, subpage-конфигов, плагинов нод, шаблонов подписки, Internal и External
  Squads (3.4.0) — для фильтрации в UI/API.
- **Плагины нод:** `rulePlacement` у Torrent Blocker (3.3.1), схема post-start-плагина (3.4.5),
  починена перестановка плагинов.
- **Подписки:** переменные «дата следующего сброса трафика» (3.4.4); mapper применяется и к
  не-query параметрам base64-ссылки (3.4.0); обновлён дефолтный Sing-box-шаблон (3.4.0);
  исправлено имя поля транспортных опций в генераторе Xray-Json (3.4.5).
- **Безопасность (обновляться обязательно):** 3.4.3 — обход авторизации `/api/backend-tools` через
  путь в смешанном регистре; 3.4.8 — ограничено чтение файлов сертификатов; 3.4.7 — исправлена
  генерация x25519 public key (если на 3.4.6 подписки отдавали кривой `pbk` — причина здесь);
  3.4.6 — образ на Node.js 24.22.1 (security-релиз).

Xray-детали инбаунда → `xray-reality.md`. Как selfsteal-нода собирается физически → `architecture.md`.