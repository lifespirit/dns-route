# dns-route

[Русская версия](README.rus.md)

`dns-route` is a Linux DNS proxy that turns selected DNS answers into dynamic routes. It can forward DNS over UDP, TCP, DNS-over-TLS, or DNS-over-HTTPS, serve local A/AAAA records, load domain lists from CSV files or URLs, and program Linux or BGP routes for addresses returned for selected domains.

The daemon is intended for split-routing deployments where only particular domains should use a tunnel, a dedicated gateway, or a downstream router.

```text
client DNS query
      |
      v
+-------------+       +----------------------+
|  dns-route  | ----> | default/zone upstream|
+-------------+       +----------------------+
      |
      +-- local A/AAAA or NODATA response
      |
      +-- special-domain match
              |
              +-- optional Team Cymru prefix lookup
              |
              +-- Linux route / embedded BGP announcement
```

## Features

- DNS listeners on multiple IPv4 and IPv6 addresses, over both UDP and TCP.
- Pending listener retry for interfaces that appear after daemon startup.
- Optional Linux `IP_FREEBIND`/`IPV6_FREEBIND` support.
- Default upstreams and longest-suffix conditional forwarding zones.
- UDP, TCP, DoT, and DoH upstream transports with TLS certificate verification.
- Upstream priorities, randomized balancing inside the same priority, UDP-to-TCP fallback, and a failure circuit breaker.
- Positive DNS response cache with request-aware keys and decreasing TTL values.
- Persistent local A/AAAA records, wildcard records, multi-value answers, and explicit NODATA rules.
- Persistent and external CSV sources for special domains and local DNS records.
- Route creation from A and AAAA answers only for selected special domains.
- Optional Team Cymru DNS TXT lookup to replace host routes with covering BGP prefixes.
- Route backends: Linux kernel, embedded GoBGP, or `kernel+bgp`.
- Optional reply-before-route mode with asynchronous route installation and conntrack reset after a newly installed kernel route.
- SQLite-backed transactional configuration and an embedded web admin panel.
- Runtime pages, statistics, route diagnostics, and Prometheus metrics.
- Graceful shutdown on `SIGINT` and `SIGTERM`.

## Quick start

Requirements: Linux and Go 1.23 or newer.

```bash
go mod download
go test ./...
go build -o dns-route .

sudo install -Dm755 dns-route /usr/bin/dns-route
sudo mkdir -p /var/lib/dns-route
sudo /usr/bin/dns-route \
  -db /var/lib/dns-route/config.db \
  -http 127.0.0.1:8080
```

Open `http://127.0.0.1:8080`, then:

1. Add at least one DNS listen address, for example `127.0.0.1:53`.
2. Add at least one default upstream, for example `1.1.1.1:53` with protocol `udp`.
3. Configure the route interface, gateways, route table, and route families.
4. Add special domains whose resolved addresses must be routed.

Each configured DNS address creates both a UDP and a TCP listener.

> [!WARNING]
> The admin HTTP interface currently has no built-in authentication or TLS. Keep it on loopback or place it behind a trusted authenticated reverse proxy and firewall.

## Documentation

| Topic | English | Russian |
|---|---|---|
| Build, installation, systemd, upgrades | [Build and installation](docs/build-install.md) | [Сборка и установка](docs/build-install.rus.md) |
| CLI flags, SQLite settings, listeners, upstreams, routing and BGP | [Configuration reference](docs/configuration.md) | [Описание параметров](docs/configuration.rus.md) |
| Deployment patterns with AmneziaWG and Xray | [AmneziaWG and Xray](docs/amneziawg-xray.md) | [AmneziaWG и Xray](docs/amneziawg-xray.rus.md) |
| Special-domain and DNS-record CSV import | [Domain import](docs/domain-import.md) | [Импорт доменов](docs/domain-import.rus.md) |

## Web endpoints

| Path | Purpose |
|---|---|
| `/` | Runtime state and route backend status |
| `/settings` | Listeners and routing settings |
| `/upstreams` | Default upstreams and conditional forwarding zones |
| `/special-domains` | Domains whose DNS answers trigger routing |
| `/dns-records` | Local A/AAAA/NODATA records and external sources |
| `/statistics` | Runtime counters and circuit state |
| `/metrics` | Prometheus exposition format |
| `/routes/errors` | Recent kernel route errors as JSON |

## Routing model

A route is considered only when all of the following are true:

- the queried name matches a configured special-domain pattern;
- the query type is `A` or `AAAA`;
- routing for that address family is enabled;
- the DNS answer contains an address of the requested family.

With `lookup_cidr=1`, dns-route queries Team Cymru and uses a covering prefix when one is available. Otherwise it falls back to `/32` for IPv4 or `/128` for IPv6.

`route_table=0` means Linux main table `254`. A dedicated policy-routing table is usually safer for split routing and avoids interference from unrelated routes already present in the main table.

## License

See [LICENSE](LICENSE).
