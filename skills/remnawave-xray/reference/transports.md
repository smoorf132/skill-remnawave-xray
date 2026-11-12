# Xray-транспорты (streamSettings.method, он же network)

Транспорт — как оборачивается протокол (VLESS/VMess/Trojan/Shadowsocks). `raw` покрыт в
`xray-reality.md`. Здесь остальные. Сверено с исходниками `infra/conf/` на теге **v26.11.9** и
офиц. xtls.github.io; XHTTP/hysteria/masque/xdrive свежие — уровень доверия помечен.

Имя поля: канон — `method`, `network` оставлен алиасом (панель и старые конфиги пишут `network`).
Значения, которые ядро принимает: `raw`(`tcp`), `xhttp`(`splithttp`), `mkcp`(`kcp`), `grpc`,
`websocket`(`ws`), `httpupgrade`, `hysteria`, `masque`, `xdrive`. `h2`/`h3`/`http`/`quic` —
удалены, конфиг с ними не стартует.

## Матрица security x network (жёсткое ограничение)

| security | Совместимые транспорты |
|---|---|
| `reality` | **только** `raw`, `xhttp`, `grpc` |
| `tls` | все (`raw`, `xhttp`, `mkcp`, `grpc`, `websocket`, `httpupgrade`, `hysteria`) |
| `none` | любой (без шифрования транспорта — только за CDN/локально) |

`flow: xtls-rprx-vision` — **только `raw`**. Reality поверх XHTTP/gRPC → `flow` НЕ указывать.
`masque` и `xdrive` в матрицу не внесены: с Reality они не работают (ядро: `REALITY only supports
RAW, XHTTP and gRPC for now.`), остальное — см. их разделы ниже.

## Когда что

| Транспорт | Когда | Детект/минус |
|---|---|---|
| `raw` (+Reality) | дефолт для прямых нод, макс. маскировка | — (эталон) |
| `xhttp` | за CDN (Cloudflare/фронт), гибкий HTTP/2-3, padding | сложность, спека нестабильна |
| `websocket` | за CDN, широкая совместимость клиентов | fingerprint `ALPN=http/1.1`; ядро на старте пишет deprecation-warning → «XHTTP H2 & H3» |
| `httpupgrade` | легче WS за CDN (без двусторонней рамки WS) | тот же warning → XHTTP |
| `grpc` | за CDN/H2-инфра, мультиплекс | нет fallback по пути, active-probe риск; warning → «XHTTP stream-up H2» |
| `mkcp` | UDP, высокие потери/пинг (мобильные) | не за CDN, характерный трафик |
| `hysteria` | QUIC/UDP, потери/дальние линки, port-hopping | свежее (см. ниже), QUIC палится по-своему |
| `masque` | IETF CONNECT-IP (RFC 9484) поверх H3/H2, в т.ч. клиент к WARP | появился в сентябре 2026, не обкатан |
| `xdrive` | прокси через чужое хранилище (Google Drive / S3 / шаблон) в обход IP-вайтлистов | экзотика, жёсткие требования (ниже) |

Warning'и у ws/httpupgrade/grpc — «non-removal deprecated»: транспорты не удаляют, конфиг работает,
но новое на них строить не стоит.

## XHTTP (`xhttpSettings`) — flagship для CDN

Офиц. reference-страницы НЕТ, спека в [Discussion #4113](https://github.com/XTLS/Xray-core/discussions/4113)
(автор RPRX). **Уровень доверия: средний — API меняется, сверять перед использованием.**

- `host`, `path` (обяз., совпадает на upload/download), `mode`:
  `auto` (TLS+H2→stream-up; REALITY→stream-one; иначе packet-up) | `packet-up` | `stream-up` | `stream-one`.
- `extra`:
  - `xmux`: `maxConcurrency` (напр. `"16-32"`), `maxConnections`, `cMaxReuseTimes`, `cMaxLifetimeMs`,
    `hMaxRequestTimes`, `hMaxReusableSecs`, `hKeepAlivePeriod`.
    Дефолты, когда блок `xmux` не задан вовсе: `maxConnections: 3` (снижен с 6 в v26.7.28,
    «anti-TSPU»), `hMaxRequestTimes: 600-900`, `hMaxReusableSecs: 1800-3000`. Упёрся в потолок
    скорости — поднимай `maxConnections` явно.
    ⚠️ **`maxConnections` и `maxConcurrency` вместе нельзя** — ядро падает на старте:
    `maxConnections cannot be specified together with maxConcurrency`. Задал `maxConcurrency`
    (как в боевом примере) — `maxConnections` не трогать, и наоборот.
  - v26.7.28: **клиент больше не дописывает завершающий `/` к `path`**, когда `sessionID` и `seq`
    размещены не в пути. Совпадение путей на upload/download проверять после обновления.
  - padding/obfs: `xPaddingBytes` (`"100-1000"`), `xPaddingKey/Header/Method/Placement/ObfsMode`,
    `uplinkHTTPMethod` (с v26.10.31 сервер принимает и `OPTIONS`), `noGRPCHeader`, `noSSEHeader`,
    `scMaxEachPostBytes`, `scMinPostsIntervalMs`, `scMaxBufferedPosts`, `scStreamUpServerSecs`,
    `downloadSettings` (несовместим с `mode: stream-one`).
  - `h2Params` (v26.10.31, сервер) — сырые параметры HTTP/2-сервера. Формат в доке не описан —
    **НЕТОЧНО**, смотреть PR #7295 перед использованием.

**Боевой пример** (`../examples/xray-cdn-bridge.json`, RU-XHTTP-CDN): `listen: 127.0.0.1`, `security: none`
(TLS терминирует CDN/реверс-прокси спереди), `host: <CDN_FRONT_HOST>`, `mode: packet-up`, `path` под
легитимный API-путь, `xmux.maxConcurrency: "16-32"`, padding `xPaddingMethod: tokenish`,
`xPaddingPlacement: queryInHeader`, `uplinkHTTPMethod: GET`.

ℹ️ Запрет незашифрованного из v26.7.28 (см. `protocols.md`) касается **только outbound**. Такой
inbound с `security: none` за CDN законен и дальше: он слушает `127.0.0.1`, а TLS снимает фронт.
Проверять надо второе плечо — тот outbound, которым нода уходит на публичный адрес.

## WebSocket (`wsSettings`)

`path` (deflt `/`, поддерживает `?ed=2560` — Early Data), `host`, `headers` (только клиент),
`heartbeatPeriod` (0 = не слать Ping), `acceptProxyProtocol` (inbound). Обычно `security: none` за CDN
(TLS у CDN) или `tls`. Пример в `../examples/xray-cdn-bridge.json` (RU-WS-CDN, path под Next.js/API).

## gRPC (`grpcSettings`)

`serviceName`, `authority`, `multiMode` (BETA, deflt false), `user_agent`, `idle_timeout` (сек, min 10),
`health_check_timeout` (deflt 20), `permit_without_stream` (deflt false), `initial_windows_size` (deflt 0).
Fallback по пути не умеет — риск active-probing без TLS-обёртки.

## HTTPUpgrade (`httpupgradeSettings`)

`path` (deflt `/`), `host`, `headers`, `acceptProxyProtocol`. Легче WS (одностороннее HTTP Upgrade),
за CDN. Офиц. тоже подталкивают к XHTTP.

## mKCP (`kcpSettings`)

UDP-транспорт для линков с потерями. Поля: `mtu` (~1350), `tti` (~50мс), `uplinkCapacity`/`downlinkCapacity`
(Мбит), `congestion` (bool), `readBufferSize`/`writeBufferSize` (МБ), `seed` (пароль обфускации),
`header.type` (обфускация под трафик: `none`/`srtp`/`utp`/`wechat-video`/`dtls`/`wireguard`). Жрёт больше
CPU/полосы, не за CDN. **Проверять актуальные дефолты под версию.**

## Hysteria (`network: "hysteria"` + `hysteriaSettings`) — QUIC/HY2

Полноценный **Hysteria 2 в ядре**: outbound+transport с **v26.1.23**, inbound+transport с **v26.3.27**.
`protocol: "hysteria"` жёстко `version: 2` (иначе ядро отклоняет старт). Требует **настоящий TLS-серт**
(`security: tls` + `tlsSettings.certificates`) — Reality тут не при чём.

Реализация обновлена до официального Hysteria **v2.12.2** (август 2026).

Поля (settings — уровень протокола; hysteriaSettings — транспорт):
- `settings`: inbound — `version: 2`, `clients[].auth`/`email`/`level`; outbound — `version: 2`, `address`, `port`.
- `streamSettings.hysteriaSettings` — в v26.11.9 всего четыре поля: `version: 2`, **`auth`** (на клиенте
  пароль идёт СЮДА, не в `settings`!), `udpIdleTimeout`, **`masquerade`** (`{type:"file", dir:"/var/www"}` —
  отдаёт реальный сайт неавторизованным, HY2-аналог selfsteal). Полей `up`/`down`/`udphop`/`congestion`
  здесь больше нет — всё переехало в `finalmask`.
- **QUIC-параметры — `streamSettings.finalmask.quicParams`**: `congestion` (reno/bbr/brutal/force-brutal;
  hysteria дефолт **brutal**), `bbrProfile` (conservative/standard/aggressive), `brutalUp`/`brutalDown`,
  окна (`init*/max*ReceiveWindow`), `maxIdleTimeout`, `keepAlivePeriod`, `disablePathMTUDiscovery`.
  ⚠️ `brutalUp`/`brutalDown` — **строки с единицами** (`"100mbps"`; b/k/m/g/t + `bps`), не числа:
  тип в ядре строковый, голое число в JSON не распарсится.
- **Port hopping — отдельная UDP-маска** (с v26.9.9): `finalmask.udp: [{ "type": "udphop",
  "settings": { "mode", "interval", "remoteIPs", "remotePorts" } }]`. Ключа `udpHop` внутри `quicParams`
  больше нет. Серверная сторона по-прежнему слушает ОДИН порт, диапазон заворачивается на него `iptables`.
- **Salamander-обфускация** — тоже UDP-маска: `finalmask.udp: [{ "type": "salamander", "settings": { "password" } }]`.
- **Клиент mihomo**: `type: hysteria2`, `ports: 443-8443` + `hop-interval` (port hopping), `password`, `up`/`down`,
  `obfs: salamander` + `obfs-password`, `sni`, `skip-cert-verify`, `alpn: [h3]`.
- Шероховатости (молодая фича): рассинхрон Salamander, HY2 inbound иногда принимает UDP но не отвечает (таймаут
  #5921). На критичном проде тестировать.

Пример сервера (из core-tutorial):
```json
{ "tag": "hy2-in", "listen": "0.0.0.0", "port": 443, "protocol": "hysteria",
  "settings": { "version": 2, "clients": [{ "auth": "<PASS>", "email": "user" }] },
  "streamSettings": { "network": "hysteria", "security": "tls",
    "tlsSettings": { "certificates": [{ "certificateFile": "/etc/ssl/cert.pem", "keyFile": "/etc/ssl/key.pem" }] },
    "hysteriaSettings": { "version": 2, "masquerade": { "type": "file", "dir": "/var/www" } },
    "finalmask": { "quicParams": { "congestion": "brutal", "brutalUp": "100mbps", "brutalDown": "300mbps" } } } }
```

## Congestion control (`finalmask.quicParams.congestion`)

`reno` / `bbr` / `brutal` / `force-brutal`. Дефолты: XHTTP поверх H3 → `bbr`; Hysteria → `brutal`
(требует задать `brutalUp`/`brutalDown` — фиксированная полоса, отсюда стабильность на потерях).

## Finalmask — общий слой масок (куда всё переезжает)

`streamSettings.finalmask` = `{ tcp: [...], udp: [...], quicParams: {...} }`, каждая маска —
`{ "type": "...", "settings": {...} }`. С сентября 2026 транспорты ядра построены поверх него.

| Слой | Типы масок (v26.11.9) |
|---|---|
| `tcp` | `filter`, `header-custom`, `fragment`, `sudoku`, `xmc` |
| `udp` | `filter`, `header-custom`, `mkcp-legacy`, `noise`, `salamander`, `sudoku`, `xdns`, `xicmp`, `realm`, `udphop` |

- **`fragment` и `noises` из Freedom-outbound сюда мигрируют**: ядро пишет deprecation-warning и
  шлёт в `finalmask.tcp` (`fragment`) и `finalmask.udp` (`noise`). Старое пока работает.
- **`filter`** (v26.10.21, inbound) — фильтр по IP источника: `allowedSourceIPs` / `blockedSourceIPs`.
  Удобно закрыть служебный инбаунд без nftables.
- `xdns`: в октябре 2026 переименованы ключи (`name`→`names`, `type`+`addr`→`addrs`) — старые
  примеры из обсуждений не копировать.

## MASQUE (`method: "masque"`) — **НЕТОЧНО, свежее**

Сентябрь–октябрь 2026: outbound и inbound `protocol: "masque"` (IETF CONNECT-IP, RFC 9484) плюс
одноимённый транспорт; клиент умеет H3 и H2 (Extended CONNECT), XMUX (`maxConnections: 1` по
умолчанию), режим `warp` — MASQUE-подключение к Cloudflare WARP как альтернатива WireGuard-outbound.
Reference-страницы в доке на момент сверки не искал; поля смотреть в `infra/conf/masque.go` и PR
#6807 / #6844 / #6878. В Remnawave-подписки штатно не заведён — использовать как outbound ноды.

## XDRIVE (`method: "xdrive"`) — **НЕТОЧНО, экзотика**

Прокси поверх чужого хранилища: `service` = `local` / `google-drive` / `s3` / `template`
(старое написание `"Google Drive"` — deprecated). Смысл — пройти там, где доступен только вайтлист
крупных сервисов. Ядро жёстко требует: протокол **только VLESS**, **VLESS Encryption обязателен**
(`xray vlessenc`), `flow` запрещён, на клиенте включён `mux` (без отрицательных `concurrency` /
`xudpConcurrency`, без `xudpProxyUDP443: "skip"`). Нарушение — отказ старта с текстом
`the xdrive transport needs ...`. Не замена Reality: зависит от квот и доступности сервиса.

Матрица/flow → `xray-reality.md`. Протоколы (что кладётся В транспорт) → `protocols.md`.