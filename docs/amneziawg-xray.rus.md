# Варианты использования с AmneziaWG и Xray

[English version](amneziawg-xray.md) · [К README](../README.rus.md)

Ниже приведены типовые схемы. Имена интерфейсов, адреса, Xray outbound и параметры маскировки AmneziaWG нужно адаптировать под реальную сеть.

## Что делает и чего не делает dns-route

`dns-route` умеет:

- выбирать DNS upstream по доменному суффиксу;
- находить выбранные специальные домены;
- извлекать A/AAAA-адреса из DNS-ответов;
- создавать маршруты через Linux-интерфейс и шлюз;
- анонсировать полученные префиксы через BGP.

Он не умеет:

- создавать или настраивать туннель AmneziaWG;
- направлять трафик непосредственно в SOCKS- или HTTP-прокси;
- генерировать routing rules Xray;
- самостоятельно ставить mark на пакеты приложений;
- удалять динамические маршруты после истечения DNS TTL.

Поэтому SOCKS-only outbound Xray нельзя указать как `wg_interface`. Нужен L3-интерфейс, TUN-адаптер, настоящий next-hop router либо отдельная схема transparent proxy.

## Схема 1: выбранные домены напрямую через AmneziaWG

Самая простая split-routing схема:

```text
клиент LAN
   |
   | DNS
   v
 dns-route -- маршруты в table 101 --> awg0 --> VPN-сервер
```

### 1. Отключите автоматический default route

Если выбором занимается dns-route, конфигурация AmneziaWG не должна устанавливать системный default route. Для `awg-quick` используйте аналог:

```ini
[Interface]
Address = 10.66.66.2/24
Table = off
# Здесь остаются PrivateKey, Jc, Jmin, Jmax, S1..S4, H1..H4 и другие AWG-параметры.

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example:443
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

`AllowedIPs` должны разрешать назначения, которые будут отправляться в туннель, а `Table=off` не даёт `awg-quick` добавить собственные default routes.

### 2. Создайте отдельную policy table

```bash
ip rule add priority 10100 lookup 101
ip -6 rule add priority 10100 lookup 101
```

Правило без source/destination сначала ищет маршрут в table 101. При отсутствии совпадения Linux продолжает обработку последующих rules и обычно доходит до main table.

Сохраните правила через systemd-networkd, NetworkManager, `PostUp` либо отдельный systemd unit.

### 3. Обеспечьте достижимость tunnel gateway

Для IPv4 dns-route требует шлюз, который должен быть достижим в той же таблице.

Если `awg0` использует подключённую сеть вроде `10.66.66.2/24`, peer `10.66.66.1` обычно является on-link. При адресе интерфейса `/32` добавьте явный маршрут:

```bash
ip route replace 10.66.66.1/32 dev awg0 table 101
```

Для IPv6 `wg_gateway_v6` можно оставить пустым — тогда dns-route создаёт device-only маршруты через `awg0`.

### 4. Настройте dns-route

```text
wg_interface       = awg0
wg_gateway_v4      = 10.66.66.1
wg_gateway_v6      = <пусто либо IPv6 peer туннеля>
route_mode         = kernel
route_table        = 101
route_ipv4         = 1
route_ipv6         = 1 или 0
lookup_cidr        = 1
reply_before_route = 0
```

Добавьте домены на странице **Special domains**:

```text
example.org
*.cdn.example.net
```

Обычный `example.org` включает apex и все поддомены. `*.cdn.example.net` включает только поддомены.

### 5. Проверьте

```bash
dig @192.168.1.1 example.org A
ip route show table 101
ip route get <полученный-ip>
```

При `lookup_cidr=1` созданный маршрут может быть шире конкретного адреса. Число попыток и ошибок lookup видно на странице статистики.

### Рекомендуемый порядок systemd

```ini
[Unit]
After=network-online.target awg-quick@awg0.service
Wants=network-online.target awg-quick@awg0.service
```

Если dns-route запустится первым, его DNS-listener'ы всё равно смогут восстановиться позже. Но до появления `awg0` маршрутизация не заработает, поэтому зависимость особенно полезна при `reply_before_route=0`.

## Схема 2: DNS выбранных зон через Xray, трафик через AmneziaWG

Xray можно использовать как локальный DNS-транспорт, а клиентский трафик продолжать маршрутизировать через `awg0`.

```text
DNS *.remote.example -> dns-route -> 127.0.0.1:5353 -> Xray outbound
адрес из ответа       -> dns-route table 101 -> awg0
```

Распространённая схема — локальный `dokodemo-door`, DNS-пакеты которого принудительно отправляются через proxy outbound. JSONC-фрагмент для существующей конфигурации Xray:

```jsonc
{
  "inbounds": [
    {
      "tag": "dns-through-proxy",
      "listen": "127.0.0.1",
      "port": 5353,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "1.1.1.1",
        "port": 53,
        "network": "tcp,udp"
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "inboundTag": ["dns-through-proxy"],
        "outboundTag": "proxy"
      }
    ]
  }
}
```

Outbound с tag `proxy` должен уже существовать в полной конфигурации Xray.

В dns-route добавьте conditional forward zone:

```text
Domain suffix: *.remote.example
Upstream:      127.0.0.1:5353
Protocol:      udp
```

Зона совпадает и с apex. Чтобы отправлять через Xray все DNS-запросы, добавьте `127.0.0.1:5353` как default upstream.

Важно: это меняет только способ DNS-разрешения. TCP/UDP-трафик клиентов идёт по Linux routes, поэтому backend AmneziaWG настраивается отдельно.

## Схема 3: TUN-адаптер Xray как целевой интерфейс

Имя `wg_interface` историческое. Kernel backend требуется только Linux L3-интерфейс и, для IPv4, достижимый next hop. Поэтому можно использовать TUN-интерфейс, передающий пакеты в Xray или tun2socks:

```text
wg_interface  = xray0
wg_gateway_v4 = 198.18.0.1
route_table   = 101
route_mode    = kernel
```

TUN-реализация должна:

- создать `xray0` до обработки маршрутов;
- принимать пакеты к произвольным динамически найденным назначениям;
- предоставить рабочий IPv4 next hop;
- не отправлять соединение к собственному proxy-серверу обратно в себя;
- поддерживать TCP и UDP, если нужны оба протокола.

Точная настройка TUN зависит от сборки Xray или программы, создающей интерфейс. Если есть только SOCKS/HTTP inbound и нет L3-интерфейса, dns-route не сможет направить туда маршруты напрямую.

## Схема 4: отдельные таблицы dns-route и Xray fwmark

Динамические назначения dns-route и sockets Xray удобнее держать в разных таблицах:

```text
table 101: префиксы dns-route -> awg0
table 300: sockets Xray с mark -> выбранный default tunnel path
```

Пример rules:

```bash
ip rule add priority 1000 fwmark 0x300/0x300 lookup 300
ip rule add priority 10100 lookup 101
```

Если Xray ставит Linux mark `0x300`, в десятичном виде это `768`. Типовой фрагмент socket options:

```jsonc
{
  "streamSettings": {
    "sockopt": {
      "mark": 768
    }
  }
}
```

Проверьте поддержку и точное расположение `sockopt` в outbound для установленной версии Xray.

Table 300 может содержать default route через нужный туннель, а table 101 — только префиксы dns-route. Для физического endpoint AmneziaWG/Xray обязательно создайте более приоритетное исключение через WAN, иначе транспортное соединение туннеля может попасть внутрь самого себя.

Пример исключения:

```bash
ip route replace 203.0.113.10/32 via 192.168.1.1 dev eth0 table main
```

Подставьте реальный endpoint VPN/прокси и WAN gateway.

## Схема 5: анонс префиксов на отдельный маршрутизатор

Если хост dns-route не должен сам пересылать трафик, используйте `route_mode=bgp` или `kernel+bgp` и BGP-peer с маршрутизатором, на котором настроена политика AmneziaWG/Xray.

```text
DNS клиента -> dns-route -> встроенный GoBGP -> router -> AWG/Xray
```

- `bgp`: только анонсы; после рестарта префиксы возвращаются по мере новых DNS-ответов.
- `kernel+bgp`: сначала точный локальный маршрут, затем анонс; при запуске и ручном route reload BGP восстанавливается из выбранной kernel-таблицы.
- `bgp_next_hop_v4`/`bgp_next_hop_v6` должны указывать адрес, реально пригодный peer'у для пересылки.
- Включите `bgp_require_established`, если при падении BGP-сессии DNS-запрос должен завершаться ошибкой, а не продолжать работу.

## Примеры выбора DNS upstream

### Публичный DNS по умолчанию, локальный для `.lan`

```text
default upstream: 1.1.1.1:853 / tls
forward zone lan: 127.0.0.1:5353 / udp
```

### Региональный DNS для `.ru`

```text
default upstream: 1.1.1.1:853 / tls
forward zone ru: 77.88.8.8:53 / udp
```

### DNS через Xray только для одного суффикса

```text
default upstream: 192.168.1.1:53 / udp
forward zone remote.example: 127.0.0.1:5353 / udp
```

## Диагностика

### DNS-ответ есть, но маршрут не появился

```bash
curl http://127.0.0.1:8080/routes/errors
ip link show awg0
ip route show table 101
journalctl -u dns-route -n 200
```

Убедитесь, что имя совпадает со специальным доменом, а запрос имеет тип A или AAAA. `dig example.org ANY` не запускает извлечение маршрута из A/AAAA.

### Ошибка `network is unreachable` для gateway

IPv4 gateway туннеля не достижим в выбранной таблице. Добавьте on-link/host route до шлюза либо используйте подключённую tunnel subnet.

### Первое соединение идёт старым путём

При `reply_before_route=0` DNS ждёт установки маршрута. При `reply_before_route=1` conntrack сбрасывается только когда dns-route может доказать создание нового kernel-маршрута; приложению всё равно может понадобиться retry.

### Xray получает DNS, но не трафик приложения

Forward zone управляет только DNS-пакетами, отправленными в Xray. Для трафика приложения нужен L3 target, TUN, transparent proxy либо маршрут через AmneziaWG.

### После создания маршрута появился loop

Добавьте явные WAN-исключения для endpoint AmneziaWG/Xray и проверьте priority fwmark rules.
