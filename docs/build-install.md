# Build and installation

[Русская версия](build-install.rus.md) · [Back to README](../README.md)

## Requirements

- Linux. Route and conntrack operations are Linux-specific.
- Go 1.23 or newer.
- Network access to download Go modules during the first build.
- Root privileges, or a service account with enough capabilities to bind DNS port 53 and modify routes/conntrack.
- A working route target such as an AmneziaWG/WireGuard interface, a TUN interface, or a configured BGP peer.

SQLite is linked through the Go module; a separate SQLite server is not required. The `sqlite3` CLI is optional and useful only for offline inspection or bootstrap configuration.

## Build from source

```bash
cd /path/to/dns-route

go mod download
go test ./...
go build -trimpath -o dns-route .
```

A smaller release binary can be built with:

```bash
go build -trimpath -ldflags='-s -w' -o dns-route .
```

## Install the binary

```bash
sudo install -Dm755 dns-route /usr/bin/dns-route
sudo install -d -m755 /var/lib/dns-route
```

Run it manually for the first configuration:

```bash
sudo /usr/bin/dns-route \
  -db /var/lib/dns-route/config.db \
  -http 127.0.0.1:8080
```

The database and all required tables are created automatically. An empty database has no DNS listeners and no upstreams, so configure both through the web panel before using the daemon as a resolver.

## Initial configuration through the web panel

Open `http://127.0.0.1:8080` locally, or use SSH port forwarding:

```bash
ssh -L 8080:127.0.0.1:8080 router.example
```

Then configure:

1. **Settings → Listen addresses**: for example `127.0.0.1:53`, `192.168.1.1:53`, or `[fd00::1]:53`.
2. **Upstreams**: for example `1.1.1.1:53`/`udp` or `https://dns.google/dns-query`/`https`.
3. **Settings → Routing**: target interface, IPv4/IPv6 gateways, route table, and route mode.
4. **Special domains**: domains whose answers must produce routes.

If only DNS forwarding is needed, leave the special-domain list empty. Route settings are used only when a special-domain answer is processed.

## systemd

The repository contains `dns-route.service`, but its `ExecStart` line contains an example site address. Review it before installation.

```bash
sudo install -Dm644 dns-route.service /etc/systemd/system/dns-route.service
sudo systemctl edit --full dns-route.service
```

A conservative unit example is:

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

Enable and start it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now dns-route.service
sudo systemctl status dns-route.service
```

Follow logs with:

```bash
journalctl -u dns-route.service -f
```

### Starting after a tunnel

When the route target must exist before DNS answers are processed, add the appropriate dependency. For an `awg-quick` unit this may look like:

```ini
[Unit]
After=network-online.target awg-quick@awg0.service
Wants=network-online.target awg-quick@awg0.service
```

This ordering is not mandatory for DNS listener startup. Unavailable listener addresses remain pending and are retried every three seconds. Route installation, however, cannot succeed until the configured route interface exists.

## Service privileges

Running as root is the simplest option. A restricted service normally needs at least:

- `CAP_NET_BIND_SERVICE` to bind port 53;
- `CAP_NET_ADMIN` to create routes and delete conntrack entries.

Example:

```ini
[Service]
User=dns-route
Group=dns-route
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true
```

The service user must also be able to read/write the database and read every configured filesystem CSV source. Test capability-restricted deployments on the target distribution because LSM policy, namespaces, and hardened systemd options can impose additional restrictions.

## Optional SQL bootstrap

Stop the service before directly editing the database:

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

Do not edit SQLite concurrently with web changes unless you understand the locking and runtime reload consequences. The web panel is the preferred configuration path.

## Upgrade

1. Back up the database.
2. Build and install the new binary.
3. Restart the service.
4. Check `/`, `/statistics`, `/metrics`, and the journal.

```bash
sudo cp -a /var/lib/dns-route/config.db /var/lib/dns-route/config.db.backup
sudo install -Dm755 dns-route /usr/bin/dns-route
sudo systemctl restart dns-route.service
```

Schema initialization is idempotent and creates missing tables or supported compatibility columns at startup.

## Backup and restore

The persistent state is the SQLite database. External source contents are not copied into it; keep their source files or URLs available separately.

```bash
sudo systemctl stop dns-route
sudo cp -a /var/lib/dns-route/config.db /backup/config.db
sudo systemctl start dns-route
```

SQLite uses WAL mode. Stopping the service before a file-level backup ensures the main database contains a complete checkpoint. Online backups should use SQLite's backup facilities rather than copying only `config.db`.

## Health checks

```bash
curl --fail http://127.0.0.1:8080/
curl --fail http://127.0.0.1:8080/metrics
curl --fail http://127.0.0.1:8080/routes/errors
```

DNS checks:

```bash
dig @127.0.0.1 example.com A
dig @127.0.0.1 example.com AAAA
dig +tcp @127.0.0.1 example.com A
```

Routing checks:

```bash
ip route show table 101
ip -6 route show table 101
ip rule show
```
