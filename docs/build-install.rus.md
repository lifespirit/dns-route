# Сборка и установка

[English version](build-install.md) · [К README](../README.rus.md)

## Требования

- Linux: операции с маршрутами и conntrack зависят от Linux.
- Go версии 1.23 или новее.
- Доступ к Go-модулям при первой сборке.
- Права root либо capabilities, достаточные для привязки DNS-порта 53 и изменения маршрутов/conntrack.
- Рабочая точка назначения маршрутов: интерфейс AmneziaWG/WireGuard, TUN-интерфейс или настроенный BGP-peer.

SQLite подключается как Go-модуль; отдельный сервер SQLite не нужен. CLI `sqlite3` требуется только для необязательной офлайн-проверки или начальной настройки.

## Сборка из исходников

```bash
cd /path/to/dns-route

go mod download
go test ./...
go build -trimpath -o dns-route .
```

Уменьшенная release-сборка:

```bash
go build -trimpath -ldflags='-s -w' -o dns-route .
```

## Установка бинарного файла

```bash
sudo install -Dm755 dns-route /usr/bin/dns-route
sudo install -d -m755 /var/lib/dns-route
```

Первый запуск вручную:

```bash
sudo /usr/bin/dns-route \
  -db /var/lib/dns-route/config.db \
  -http 127.0.0.1:8080
```

База и необходимые таблицы создаются автоматически. В пустой базе нет ни DNS-listener'ов, ни upstream, поэтому до использования демона как resolver нужно настроить оба раздела в web-панели.

## Первичная настройка через web-панель

Откройте локально `http://127.0.0.1:8080` либо сделайте SSH-forward:

```bash
ssh -L 8080:127.0.0.1:8080 router.example
```

Далее настройте:

1. **Settings → Listen addresses**: например `127.0.0.1:53`, `192.168.1.1:53` или `[fd00::1]:53`.
2. **Upstreams**: например `1.1.1.1:53`/`udp` либо `https://dns.google/dns-query`/`https`.
3. **Settings → Routing**: целевой интерфейс, IPv4/IPv6-шлюзы, таблицу и режим маршрутизации.
4. **Special domains**: домены, ответы которых должны создавать маршруты.

Если нужен только DNS-forwarding, список специальных доменов можно оставить пустым. Маршрутные параметры используются лишь при обработке ответа для специального домена.

## systemd

В репозитории есть `dns-route.service`, но его `ExecStart` содержит пример адреса конкретной сети. Проверьте unit перед установкой.

```bash
sudo install -Dm644 dns-route.service /etc/systemd/system/dns-route.service
sudo systemctl edit --full dns-route.service
```

Консервативный пример unit-файла:

```ini
[Unit]
Description=DNS route daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
StateDirectory=dns-route
ExecStart=/usr/bin/dns-route -http 127.0.0.1:8080 -db /var/lib/dns-route/config.db
Restart=on-failure
RestartSec=2s

[Install]
WantedBy=multi-user.target
```

Запуск:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dns-route.service
sudo systemctl status dns-route.service
```

Логи:

```bash
journalctl -u dns-route.service -f
```

### Запуск после туннеля

Когда целевой интерфейс должен гарантированно существовать до обработки DNS-ответов, добавьте соответствующую зависимость. Для `awg-quick` это может выглядеть так:

```ini
[Unit]
After=network-online.target awg-quick@awg0.service
Wants=network-online.target awg-quick@awg0.service
```

Для старта самих DNS-listener'ов эта зависимость не обязательна: отсутствующие адреса остаются в состоянии pending и повторно привязываются каждые три секунды. Но создать маршрут до появления целевого интерфейса невозможно.

## Права сервиса

Самый простой вариант — запуск от root. Ограниченному сервису обычно нужны минимум:

- `CAP_NET_BIND_SERVICE` для порта 53;
- `CAP_NET_ADMIN` для создания маршрутов и удаления conntrack-записей.

Пример:

```ini
[Service]
User=dns-route
Group=dns-route
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true
```

Пользователь сервиса должен иметь права чтения/записи базы и чтения всех файловых CSV-источников. Ограниченную capabilities-конфигурацию обязательно проверьте на целевом дистрибутиве: LSM, namespaces и дополнительные hardening-параметры systemd могут потребовать корректировки.

## Необязательная начальная настройка через SQL

Перед прямым изменением базы остановите сервис:

```bash
sudo systemctl stop dns-route
sudo sqlite3 /var/lib/dns-route/config.db <<'SQL'
INSERT INTO listen_addrs(addr, enabled)
VALUES ('127.0.0.1:53', 1)
ON CONFLICT(addr) DO UPDATE SET enabled=1;

INSERT INTO upstreams(addr, proto, enabled, priority)
VALUES ('1.1.1.1:53', 'udp', 1, 100)
ON CONFLICT(addr) DO UPDATE SET proto='udp', enabled=1, priority=100;
SQL
sudo systemctl start dns-route
```

Не редактируйте SQLite параллельно с web-панелью без понимания блокировок и runtime reload. Предпочтительный способ настройки — web-интерфейс.

## Обновление

1. Сохраните резервную копию базы.
2. Соберите и установите новый бинарный файл.
3. Перезапустите сервис.
4. Проверьте `/`, `/statistics`, `/metrics` и журнал.

```bash
sudo cp -a /var/lib/dns-route/config.db /var/lib/dns-route/config.db.backup
sudo install -Dm755 dns-route /usr/bin/dns-route
sudo systemctl restart dns-route.service
```

Инициализация схемы идемпотентна: при запуске создаются отсутствующие таблицы и поддерживаемые compatibility-колонки.

## Резервное копирование

Постоянное состояние хранится в SQLite. Содержимое внешних источников в базу не копируется — их файлы и URL нужно сохранять отдельно.

```bash
sudo systemctl stop dns-route
sudo cp -a /var/lib/dns-route/config.db /backup/config.db
sudo systemctl start dns-route
```

SQLite работает в WAL-режиме. Остановка сервиса перед файловой копией гарантирует полный checkpoint в основном файле. Для онлайн-копирования используйте штатный механизм backup SQLite, а не копирование одного `config.db`.

## Проверка работы

```bash
curl --fail http://127.0.0.1:8080/
curl --fail http://127.0.0.1:8080/metrics
curl --fail http://127.0.0.1:8080/routes/errors
```

DNS:

```bash
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com AAAA
dig +tcp @127.0.0.1 example.com A
```

Маршруты:

```bash
ip route show table 101
ip -6 route show table 101
ip rule show
```
