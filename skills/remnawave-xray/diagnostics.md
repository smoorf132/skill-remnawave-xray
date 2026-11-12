# Диагностика: симптом → причина → фикс

## Сначала — какое ядро на ноде

`docker exec remnanode xray version`. От ответа зависит половина диагнозов ниже:
ноды 3.1.1–3.4.3 несут v26.7.28, 3.4.4 — v26.10.31, 3.4.5 — v26.11.9.

## Обновил ноду до 3.4.4 / 3.4.5 (Xray v26.10.31 / v26.11.9) — что изменилось

Переход 3.4.3 → 3.4.4 привозит сразу три месяца изменений ядра.

| Симптом | Причина | Фикс |
|---|---|---|
| Старые клиенты, отвалившиеся летом, **снова подключаются** | дефолт `minClientVer: "26.3.27"` снят в v26.9.9 — версия клиента без явного поля не проверяется | так и задумано. Нужен порог — задать `minClientVer` в `realitySettings` явно |
| TLS-outbound ноды (мост на свой сервер с приватным/корпоративным CA) перестал проходить проверку сертификата | TLS-клиент ядра теперь доверяет **встроенному** набору RootCAs, а не системному хранилищу; часть корней из набора убрана | `tlsSettings.useSystemCA: true` на этом outbound либо `pinnedPeerCertSha256`. Reality-плечи не затронуты |
| Xray не стартует: `maxConnections cannot be specified together with maxConcurrency` | в `xmux` заданы оба поля | оставить одно |
| HY2-конфиг не стартует / port hopping пропал | `udpHop` вынесен из `quicParams` в UDP-маску `finalmask.udp[{type:"udphop"}]`; `brutalUp`/`brutalDown` — строки с единицами, не числа | переписать по `reference/transports.md` (раздел Hysteria) |
| В логе warning'и про `fragment` / `noises` в Freedom, `finalRules.blockDelay`, WebSocket/gRPC/HTTPUpgrade | deprecation: `fragment`/`noises` → Finalmask, `blockDelay` → `delay`, транспорты → XHTTP | не авария. Перенести при следующей правке профиля |
| WARP/WireGuard-outbound ведёт себя иначе с доменным `endpoint` | `domainStrategy` из WireGuard-outbound удалён, поле игнорируется | убрать поле; при необходимости задать `remoteDNS` |
| Клиенты с `fingerprint: chrome` стали выглядеть иначе в DPI-логах | с v26.11.9 `chrome` = отпечаток Chrome 155 (касается ядра **клиента**) | ничего; если банят по fingerprint — обновлять клиентское ядро |
| После обновления перестал работать MPTCP на входящих | v26.10.31 выключил MPTCP на listener'ах (уязвимость в Linux-ядре) | оставить выключенным; обновить ядро ОС |

## Нода на 3.1.x – 3.4.3 (Xray v26.7.28) — старые грабли, ещё актуальны для неё

| Симптом | Причина | Фикс |
|---|---|---|
| Часть юзеров разом отвалилась, у остальных всё хорошо; в логах ноды тишина | на v26.7.28 Reality-сервер по умолчанию требует `minClientVer: "26.3.27"` — клиенты на старом ядре отсекаются на хендшейке | обновить ноду до ≥ 3.4.4 (дефолт снят) или обновить клиент. Явный `minClientVer` пониже — тоже вариант |
| Xray не стартует после обновления: `vless without TLS or other encryption is prohibited unless the server address is a private IP or domain` | с v26.7.28 запрещён VLESS/Trojan **outbound** без шифрования на публичный адрес (в v26.11.9 запрет на месте) | на этом плече включить `security: tls`/`reality` или VLESS Encryption (`xray vlessenc`). Для Trojan только TLS. Приватные адреса (`127.0.0.1`) по-прежнему разрешены |
| То же сообщение, хотя outbound записан в упрощённой плоской форме и адрес приватный | баг проверки v26.7.28 для плоской формы, починен в v26.9.9 | обновить ноду до ≥ 3.4.4 либо переписать outbound через `vnext` |
| Xray не стартует, ругань на `security`/`method` у VMess или Shadowsocks | в v26.7.28 выпилены «пустые» шифры: VMess `none`/`zero`, SS `none`/`plain` | сменить на настоящий шифр (`auto` у VMess, `2022-blake3-*`/`aes-256-gcm` у SS) |
| После апдейта просела скорость на XHTTP | дефолт `xmux.maxConnections` снижен с 6 до 3 (действует и в v26.11.9) | выставить значение явно в `extra.xmux` |
| Нода ≥ 3.1.1 больше не падает на старте из-за geodata | так и задумано: нода докачивает недостающие гео-файлы до запуска ядра | ничего не делать; ручные костыли с предзагрузкой можно убрать |

## Панель 3.3.x – 3.4.x

| Симптом | Причина | Фикс |
|---|---|---|
| После включения `SNI_VERIFICATION=true` на ноде панель её не видит | панель старее 3.3.0 не шлёт нужный SNI, либо на панели `SERVICE_SNI_VERIFICATION=false` | панель ≥ 3.3.0 и `SERVICE_SNI_VERIFICATION=true` (дефолт), либо выключить проверку на ноде |
| Подписка отдаёт неверный `pbk`, клиенты ловят `processed invalid connection` | баг генерации x25519 public key в 3.4.6 | обновить панель до ≥ 3.4.7 |
| Интеграция пишет `excludedInternalSquads` и получает 400 | поле заменено на `internalSquads: { mode, squads }` (3.4.0) | переписать вызов; `ALLOW_ONLY` требует непустой список |
| Хост пропал из подписки у части клиентов | у хоста заполнен `includeInSrrRules` — он отдаётся только в ответах правил с этими именами | очистить поле или добавить имя нужного правила |
| В подписке вместо серверов одна-две строки-заглушки | сработало Response Rule с `respondWithRemarks` | так задумано (напр. «обновите приложение»); проверить условия правила |

## Reality / Xray (ошибки в логах)

| Сообщение / симптом | Причина | Фикс |
|---|---|---|
| `REALITY: processed invalid connection` (клиент) + `received real certificate` | AuthKey не прошёл: неверный `password`/pbk или `shortId`, либо реальный MITM | pbk = `xray x25519 -i "<privateKey>"`; сверить shortId; проверить что нет CDN перед target |
| `processed invalid connection ... failed to read client hello` (сервер) | сканер/пробер без валидного ClientHello | фоновый шум; тревога — если от твоих юзеров с одного ISP (возможен DPI) |
| `please fill in a valid value for "target"` | `target`/`dest` не парсится | формат `host:port` / порт / unix-путь |
| `invalid PROXY protocol version, "xver" only accepts 0, 1, 2` | `xver` вне диапазона | 0/1/2 |
| `invalid "privateKey"` / `invalid "password"` | длина != 32 байта после base64 | перегенерировать `xray x25519`, не путать Private/Public |
| `non-empty "serverNames", please use "serverName"` | вставили серверные (мн.ч.) поля в клиент | на клиенте единственное число: `serverName`/`shortId` |
| `too long "shortIds[i]"` / `invalid "shortIds[i]"` | >16 hex / нечётная длина / не-hex | `openssl rand -hex 8` |
| `unknown "fingerprint"` / `unsafe` | опечатка/запрещённое значение | `chrome`/`firefox`/`randomized` |
| `REALITY only supports RAW, XHTTP and gRPC for now.` | `security: reality` с другим транспортом (ws/httpupgrade/hysteria/masque/xdrive) | сменить транспорт или security |
| `does not support TLS 1.3, REALITY handshake cannot establish` | fingerprint не даёт TLS1.3 key-share | современный fingerprint |
| warning `Choosing apple, icloud... may get your IP blocked` | `apple`/`icloud` в serverNames | сменить target/serverNames |
| `REALITY is based on uTLS, please set a client-fingerprint` (mihomo) | нет `client-fingerprint` при `reality-opts` | добавить `client-fingerprint: chrome` |

## Нода не подключается к панели

| Симптом | Причина | Фикс |
|---|---|---|
| нода `disconnected` в панели, Xray не стартует | панель не достучалась (панель→нода) | firewall ноды: открыть `NODE_PORT` для IP панели; проверить `docker logs remnanode` |
| mTLS/JWT ошибки в логах ноды | битый/чужой `SECRET_KEY` | пересоздать: панель CLI → «Get SECRET_KEY for Node», вставить в `.env` ноды |
| нода поднялась, юзеры не коннектятся | норма, что `clients: []` в профиле — панель инжектит; проверь что нода активна и Host привязан к инбаунду | Squad включает инбаунд, Host выбирает его |
| рассинхрон времени → handshake fail | часы ноды/клиента разъехались | NTP на ноде и клиенте |

## Caddy

| Симптом | Причина | Фикс |
|---|---|---|
| Caddy-контейнер не стартует | порт `<SELF_STEAL_PORT>` занят или синтаксис Caddyfile | `docker logs caddy`; `ss -tlnp`; `caddy validate` |
| Reality-заглушка отдаёт 502 / пусто | `target` Xray не совпал с портом Caddy, Caddy не поднялся | `SELF_STEAL_PORT` один и тот же в Xray `target` и Caddy `https_port` |
| `400 Bad Request` на `:80`, `client_ip=127.0.0.1` | `servers { }` без адреса → proxy_protocol протёк на 80 | `servers 127.0.0.1:<PORT> { ... }` (адресный скоуп) |
| ACME не выпускает серт | 80 закрыт / TLS-ALPN на занятом 443 / домен под Cloudflare / rate-limit | открыть 80; `disable_tlsalpn_challenge`; домен DNS-only; не пересоздавать серт в цикле |
| в логах реальный IP = 127.0.0.1 | `xver:1`, но нет `proxy_protocol` враппера (или наоборот) | согласовать `xver` ↔ `listener_wrappers.proxy_protocol` |

## mihomo (клиент)

| Симптом | Причина | Фикс |
|---|---|---|
| Reality-прокси не поднимается | нет `client-fingerprint` | добавить per-proxy; `global-client-fingerprint` мёртв с 1.19.27 |
| TUN сломался после обновления клиента до ≥ 1.19.32 | дефолтный `stack` стал `mips` | задать `stack: mixed` (или `gvisor`/`system`) явно |
| нет DNS / всё отваливается | DNS-петля (домен прокси через прокси) или `default-nameserver` с доменом | `default-nameserver` только IP; хост прокси → `proxy-server-nameserver` |
| часть приложений без интернета | `fake-ip` без полного перехвата (не весь трафик в TUN) | TUN/системный прокси на весь трафик, либо в `fake-ip-filter` |
| старт падает на geodata | GitHub недоступен из региона | `geox-url` на зеркало (jsdelivr) |
| RU-домены идут через прокси (не DIRECT) | сломан rule-provider `behavior: domain` (примешан IP-CIDR) | не мешать типы в domain-файле (issue #1400) |

## Reality палится (работает, но банят IP)

Проверить по `reference/xray-reality.md` → анти-пробинг чек-лист: порт 443; разумный `target` (TLS1.3+H2, свой ASN, не
мега-бренд); `xtls-rprx-vision`; актуальный fingerprint; `show:false`; не сотни юзеров на один IP; NTP.
Иран/жёсткий DPI: репутация IP, симметрия трафика, объём — см. раздел в `reference/xray-reality.md`.

## Диагностические команды

```
# Xray
xray run -test -c /path/config.json        # валидация конфига
xray tls ping <serverName>                 # TLS1.3 / X25519MLKEM768 / серт target
docker exec -it remnanode cli              # --dump-config (холодный конфиг)
docker exec remnanode xlogs                # логи Xray ноды

# Порты / сеть
ss -tlnp                                   # кто слушает 443/80/9443/NODE_PORT
ss -tlnp | grep -E ':(443|80|9443)'
curl -I http://<domain>                    # редирект на HTTPS (Caddy :80)
openssl s_client -connect <ip>:443 -servername <domain> </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
                                           # какой серт отдаёт 443 (при провале Reality-auth — серт заглушки)

# Caddy
docker logs caddy --tail 100
caddy validate --config /etc/caddy/Caddyfile

# Нода / панель
docker logs remnanode --tail 100 -t
docker exec -it remnawave pm2 monit        # состояние api/scheduler/processor
curl -f http://127.0.0.1:3001/health       # health панели
```

Параметры и их валидация → `reference/xray-reality.md`. Согласованность → `generators.md`.