# Configuration reference

[Русская версия](configuration.rus.md) · [Back to README](../README.md)

## Configuration model

`dns-route` stores persistent configuration in SQLite. The web panel writes the database transactionally and activates the new runtime configuration before committing it. If runtime activation fails, the database transaction is rolled back.

The daemon has only two command-line flags. All DNS and routing behavior is configured in SQLite, normally through the web panel.

## Command-line flags

| Flag | Default | Description |
|---|---:|---|
| `-db` | `/var/lib/dns-route/config.db` | SQLite database path. The database and missing tables are created at startup. |
| `-http` | `127.0.0.1:8080` | Address of the embedded admin HTTP server. |

Example:

```bash
dns-route -db /var/lib/dns-route/config.db -http 127.0.0.1:8080
```

## Settings

Settings are stored in the `settings(key, value)` table. Boolean values accept `1`, `true`, `yes`, or `on`; other values are false. The web panel writes booleans as `1` or `0`.

| Key | Default | Description |
|---|---:|---|
| `wg_interface` | empty | Linux interface used by the kernel route backend. The historical name is retained, but the interface can be any suitable L3 interface, not only WireGuard. |
| `wg_gateway_v4` | empty | Required IPv4 next hop for kernel routes created from A answers. |
| `wg_gateway_v6` | empty | Optional IPv6 next hop. When empty, IPv6 routes are installed as device-only routes. |
| `route_mode` | `kernel` | `kernel`, `bgp`, or `kernel+bgp`. |
| `route_table` | `0` | Linux route table. `0` is interpreted as main table `254`. |
| `route_ipv4` | `true` | Create/announce routes from A answers. |
| `route_ipv6` | `true` | Create/announce routes from AAAA answers. |
| `local_record_ttl` | `60` | Default TTL for local records whose stored TTL is `0`. Must be non-negative. |
| `lookup_cidr` | `true` | Query Team Cymru DNS TXT for a covering prefix. The name is retained for compatibility. |
| `reply_before_route` | `false` | Reply immediately and create routes asynchronously instead of waiting for route installation. |
| `listener_freebind` | `false` | Use Linux `IP_FREEBIND`/`IPV6_FREEBIND` for DNS listener addresses that do not yet exist. |
| `bgp_local_asn` | empty | Local ASN, required for BGP modes. |
| `bgp_router_id` | empty | Non-zero IPv4 router ID, required for BGP modes. |
| `bgp_peer_address` | empty | IPv4 or IPv6 BGP peer address. |
| `bgp_peer_asn` | empty | Peer ASN. |
| `bgp_local_address` | empty | Optional source address for the BGP TCP connection; must use the same family as the peer. |
| `bgp_next_hop_v4` | empty | Required IPv4 next hop when IPv4 BGP routing is enabled. |
| `bgp_next_hop_v6` | empty | Required IPv6 next hop when IPv6 BGP routing is enabled. |
| `bgp_password` | empty | Optional TCP MD5 password. The panel never renders the stored value. |
| `bgp_multihop_ttl` | `1` | BGP multihop TTL, from 1 to 255. Values above 1 enable eBGP multihop. |
| `bgp_require_established` | `false` | Consider BGP routes ready only while the peer is Established. |

### Route modes

#### `kernel`

Routes are installed in the selected Linux route table with `netlink.RouteReplace`.

- IPv4 requires `wg_interface` and `wg_gateway_v4`.
- IPv6 requires `wg_interface`; `wg_gateway_v6` is optional.
- A covering route already present in the backend snapshot can suppress creation of a more specific route.

A dedicated policy-routing table is recommended for split routing. Main table `254` normally contains a default route, which can affect coverage checks.

#### `bgp`

Routes are announced through an embedded GoBGP speaker and are not installed in the Linux route table.

The desired route set is process-local. After a full daemon restart it is rebuilt from new matching DNS answers.

#### `kernel+bgp`

The exact prefix is first installed in the selected Linux route table and then announced through BGP. On startup and manual **Reload routes**, the selected kernel table is used to rebuild the BGP desired set.

If announcement of a new desired set is incomplete, stale BGP routes are not withdrawn during that failed reconciliation.

## DNS listeners

Listener rows are stored in `listen_addrs`:

```sql
CREATE TABLE listen_addrs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  addr TEXT NOT NULL UNIQUE,
  enabled INTEGER NOT NULL DEFAULT 1
);
```

Examples:

```text
127.0.0.1:53
192.168.1.1:53
[fd00::1]:53
```

Each enabled address creates both a UDP and TCP DNS listener.

When an address cannot be bound:

- with `listener_freebind=0`, it remains pending and is retried every three seconds;
- with `listener_freebind=1`, the daemon asks Linux to allow binding before the address exists.

Changing listener configuration reconciles active and pending listeners without restarting the process.

## Default upstreams

Default upstreams are stored in `upstreams`:

```sql
CREATE TABLE upstreams (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  addr TEXT NOT NULL UNIQUE,
  proto TEXT NOT NULL DEFAULT 'auto',
  enabled INTEGER NOT NULL DEFAULT 1,
  priority INTEGER NOT NULL DEFAULT 100
);
```

Supported protocols:

| Stored value | Canonical transport |
|---|---|
| `auto` | Inferred from scheme or port; port 853 means DoT, otherwise UDP |
| `udp`, `dns` | Classic DNS over UDP |
| `tcp` | Classic DNS over TCP |
| `tls`, `dot` | DNS-over-TLS |
| `https`, `doh` | DNS-over-HTTPS POST with `application/dns-message` |

Address examples:

```text
1.1.1.1
1.1.1.1:53
[2606:4700:4700::1111]:53
udp://1.1.1.1:53
tcp://192.0.2.53:53
tls://dns.example:853
https://dns.example/dns-query
```

For DoT, use a hostname when certificate validation depends on the DNS name. An IP literal is used as the TLS server name and therefore requires a certificate valid for that IP.

For UDP upstreams, a truncated response is retried over TCP automatically.

### Priority and balancing

Lower numeric priority is attempted first. Upstreams with the same priority are shuffled for each request. The web form currently creates entries with priority `100`; custom priorities can be written through SQLite:

```sql
UPDATE upstreams SET priority=10 WHERE addr='192.168.1.53:53';
UPDATE upstreams SET priority=100 WHERE addr='1.1.1.1:53';
```

After an offline database edit, restart the service. If the database is changed while the daemon is running, use **Reload config**.

### Circuit breaker

An upstream circuit opens after two consecutive network or retryable DNS failures. The initial cooldown is 30 seconds and increases up to five minutes. A half-open probe can close the circuit after a successful request.

`SERVFAIL` and `REFUSED` responses are treated as retryable DNS failures and allow the next upstream to be tried. If every attempted upstream only returns one of these codes, the last such response can be returned to the client.

## Conditional forwarding zones

Zones are stored in `forward_zones`, with their upstreams in `forward_zone_upstreams`.

A zone entered as `*.ru`, `.ru`, or `ru` is normalized to `ru`. It matches both the apex and subdomains:

```text
ru
example.ru
www.example.ru
```

When several zones match, the longest domain suffix wins. A matching zone does not fall back to default upstreams if all of its own upstreams fail.

Example:

```text
*.ru  -> 77.88.8.8:53
*.lan -> 127.0.0.1:5353
default -> 1.1.1.1:853
```

Zone upstreams have the same transport and priority rules as default upstreams.

## Local DNS records

Persistent records are stored in `dns_records`:

```sql
CREATE TABLE dns_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL,
  ttl INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1
);
```

Supported types are `A` and `AAAA`.

- Empty `value` means an authoritative `NOERROR` response without addresses: NODATA.
- Several rows for the same name/type create a multi-value answer.
- `ttl=0` means `local_record_ttl`.
- A normal name matches only itself.
- `*.example.com` matches subdomains but not `example.com` itself.
- A local answer is not sent to an upstream.

Local records can also trigger route creation when their name matches the special-domain list.

## Special domains and route selection

Special-domain patterns are stored in `special_domains` and can also come from external sources.

Pattern semantics:

| Pattern | Matches |
|---|---|
| `example.com` | `example.com` and every subdomain |
| `*.example.com` | subdomains only; not the apex |

A DNS answer causes route processing only when:

1. the query contains exactly one question;
2. the name matches a special-domain pattern;
3. the query type is A or AAAA;
4. the corresponding `route_ipv4` or `route_ipv6` option is enabled;
5. the answer contains addresses of that family.

CNAME records are not themselves routed, but A/AAAA records present in the same answer section are collected.

### Prefix selection

With `lookup_cidr=1`, dns-route queries:

- `origin.asn.cymru.com` for IPv4;
- `origin6.asn.cymru.com` for IPv6.

A valid covering prefix is used. `/32` and `/128` results are ignored as aggregation results and the normal host-prefix fallback is used instead. Any lookup or parsing failure also falls back to `/32` or `/128`.

The Team Cymru query uses the default upstream policy, not a conditional forwarding zone.

### Reply ordering

With `reply_before_route=0`:

- dns-route waits for route processing;
- route failure produces `SERVFAIL` instead of the DNS answer.

With `reply_before_route=1`:

- the DNS answer is returned immediately;
- route processing is queued;
- if a new kernel route was actually installed, conntrack entries involving the destination address are deleted so a connection that raced the route installation can be retried through the new path.

## DNS cache

The cache stores positive responses with a non-zero minimum TTL. Negative and empty-answer responses are not cached.

The cache key includes:

- selected forwarding policy and upstream set;
- normalized complete DNS request except the transaction ID;
- question type and class;
- flags and EDNS data contained in the request.

TTL values in Answer, Authority, and Additional sections decrease by the time already spent in the cache. OPT/TKEY/TSIG pseudo-record TTL fields are not modified.

## Reload actions

| Action | Behavior |
|---|---|
| **Reload config** / `POST /reload` | Rereads SQLite and reuses the active external-source snapshots. Performs no source HTTP/file I/O. |
| **Reload routes** / `POST /routes/reload` | Reloads route backends and clears route-manager caches. In `kernel+bgp`, mirrors the selected kernel table into BGP. |
| **Reload sources** / `POST /record/sources/refresh` | Loads both DNS-record and special-domain sources, parses all of them, and activates the new snapshots only if the complete refresh succeeds. |

Web changes to normal settings are activated immediately and do not require pressing **Reload config**.

## Runtime and observability

Useful endpoints:

```text
/                  runtime state
/statistics        counters and upstream circuits
/metrics           Prometheus metrics
/routes/errors     recent kernel route diagnostics as JSON
```

Important metric groups include:

- DNS query, cache, local-answer, forwarding, and SERVFAIL counters;
- route additions, errors, queue drops, lookup attempts, and conntrack resets;
- listener state and bind retries;
- route-mode and BGP state gauges;
- per-upstream circuit state and request outcomes;
- per-forward-policy selection and result counters.

## Security notes

- The admin server has no built-in authentication, authorization, CSRF protection, or HTTPS. Bind it to loopback or protect it externally.
- HTTP external sources can change routing and local DNS behavior. Use HTTPS or trusted local files, restrict filesystem permissions, and control who can change source locations.
- DoT and DoH validate certificates. There is currently no separate custom CA or insecure-skip-verify setting.
- Direct SQLite edits bypass form-level validation until the configuration is loaded.
