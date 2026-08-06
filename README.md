# dns-route

DNS proxy with:
- SQLite-backed config
- Web admin panel
- Separate web pages for Runtime, Settings, Upstreams, Special domains and DNS records
- local A/AAAA records with wildcard support
- empty local A/AAAA values act as NODATA rules: the daemon replies NOERROR with no addresses and does not forward the query upstream
- special domains route programming via netlink
- IPv4 routing from A answers and IPv6 routing from AAAA answers
- independent route toggles in the UI: `route_ipv4` and `route_ipv6`
- route manager with IP/prefix dedupe, snapshot cache and on-demand route reload
- Prometheus metrics

Routing notes:
- Team Cymru prefixes `/32` for IPv4 and `/128` for IPv6 are ignored as prefix-lookup results; in that case the daemon falls back to the normal host route.
- A answers are routed as IPv4 routes; without Team Cymru lookup they are added as `/32`.
- AAAA answers are routed as IPv6 routes; without Team Cymru lookup they are added as `/128`.
- `wg_gateway_v4` is required for IPv4 routes installed through the kernel backend.
- `wg_gateway_v6` is optional for IPv6 routes. If it is empty, AAAA routes are added as dev-only routes via `wg_interface`.
- `lookup_cidr` is kept as a compatibility setting name, but it now uses Team Cymru DNS TXT lookups to resolve IP addresses to BGP prefixes (`origin.asn.cymru.com` for IPv4 and `origin6.asn.cymru.com` for IPv6). WHOIS/RIR `CIDR:` lookup is no longer used.

Build:

```bash
go get
go build .
```

Run:

```bash
./dns-route -http 127.0.0.1:9010 -db ./config.db
```

## Embedded BGP (experimental)

The default `route_mode` is `kernel`, so upgrading does not enable BGP automatically. The supported modes are:

- `kernel` — install routes only in the configured Linux route table.
- `bgp` — announce routes only through the embedded GoBGP speaker. The in-memory table is rebuilt from DNS answers after a full process restart.
- `kernel+bgp` — install the exact prefix in the configured Linux route table first, then announce the same prefix through BGP. Startup and the manual route reload mirror the configured kernel table into BGP.

BGP settings are available on the web admin Settings page. The form validates the route mode, table number, ASNs, router ID, peer/source addresses, next hops and multihop TTL before saving. The configured TCP MD5 password is never rendered back into HTML: leave the password field empty to keep it, or use the clear checkbox to remove it.

The same values can still be written directly to the existing `settings` table. Example for IPv4 `kernel+bgp`:

```sql
INSERT INTO settings(key, value) VALUES
  ('route_mode', 'kernel+bgp'),
  ('bgp_local_asn', '65001'),
  ('bgp_router_id', '192.0.2.10'),
  ('bgp_peer_address', '192.0.2.1'),
  ('bgp_peer_asn', '65000'),
  ('bgp_local_address', '192.0.2.10'),
  ('bgp_next_hop_v4', '192.0.2.10'),
  ('bgp_multihop_ttl', '1'),
  ('bgp_require_established', 'false')
ON CONFLICT(key) DO UPDATE SET value = excluded.value;
```

For IPv6 routing, set `bgp_next_hop_v6` to the address that the peer must use as next hop. `bgp_next_hop_v4` and `bgp_next_hop_v6` are required only for enabled route families. `bgp_local_address` is optional. A multihop TTL greater than `1` enables eBGP multihop.

After an offline database change, start or restart the service. If the database was edited while dns-route was running, send `POST /reload`. `POST /routes/reload` rereads the configured kernel table and mirrors it into BGP in `kernel+bgp` mode without reloading unrelated configuration.

The admin and statistics pages show the peer state, backend readiness, ephemeral desired-prefix count and embedded GoBGP Loc-RIB count. Prometheus exports the same state through `dns_route_bgp_*` metrics and exposes the selected mode through `dns_route_route_mode_info`.

## DNS-record CSV configuration

The DNS records page supports persistent CSV import/export and external CSV sources.

CSV rows use these forms:

```text
test.lan
test.lan,A
test.lan,AAAA
test.lan,A,
test.lan,AAAA,
test.lan,A,192.0.2.10
test.lan,AAAA,2001:db8::10
```

- one column creates NOERROR/NODATA records for both A and AAAA;
- `name,A` and `name,A,` create NODATA only for A;
- `name,AAAA` and `name,AAAA,` create NODATA only for AAAA;
- a non-empty third column creates a static record of the selected type;
- repeated address rows for the same name and type create a multi-value answer.

A normal web import replaces every persistent A/AAAA row for each name present in the uploaded file and stores the imported result in SQLite. Names absent from the file remain unchanged. The CSV format has no TTL column, so imported rows use `ttl=0`, which means the configured default local-record TTL. Export includes only persistent enabled records from SQLite; external source contents are not exported.

A source can be an `http://` or `https://` URL, a `file:///absolute/path.csv` URL, or a normal filesystem path. **Reload sources** explicitly downloads HTTP sources and rereads filesystem sources, then atomically replaces the in-memory source snapshot. If any source fails, the previous snapshot remains active. Normal **Reload config** reuses that snapshot and performs no source file or network I/O. Newly added sources, or sources whose mode changed, remain pending until the next source reload. Source contents are never inserted into `dns_records`. Sources are applied in database-id order as the lower-priority layer; later sources win for the same name and family, while enabled persistent SQLite records have final priority.

Each source has its own **NO_DATA only** option. When enabled, dns-route reads only the first two CSV columns and ignores all later columns. Therefore an address supplied by a public list can never become a DNS answer: `name,A,203.0.113.10` is treated as `name,A`, and `name,AAAA,2001:db8::10` is treated as `name,AAAA`.
