# dns-route

DNS proxy with:
- SQLite-backed config
- Web admin panel
- local A/AAAA records with wildcard support
- empty local A/AAAA values act as NODATA rules: the daemon replies NOERROR with no addresses and does not forward the query upstream
- special domains route programming via netlink
- IPv4 routing from A answers and IPv6 routing from AAAA answers
- independent route toggles in the UI: `route_ipv4` and `route_ipv6`
- route manager with IP/CIDR dedupe, snapshot cache and on-demand route reload
- Prometheus metrics

Routing notes:
- A answers are routed as IPv4 routes; without CIDR lookup they are added as `/32`.
- AAAA answers are routed as IPv6 routes; without CIDR lookup they are added as `/128`.
- `wg_gateway_v4` overrides legacy `wg_gateway` for IPv4 routes.
- `wg_gateway_v6` is optional for IPv6 routes. If it is empty, AAAA routes are added as dev-only routes via `wg_interface`; if legacy `wg_gateway` contains an IPv6 address, it is used as IPv6 fallback.
- `lookup_cidr` now accepts both IPv4 and IPv6 `CIDR:` whois fields.

Run:

```bash
go run . -db /var/lib/dns-route/config.db -http 127.0.0.1:8080
```
