# dns-route

DNS proxy with:
- SQLite-backed config
- Web admin panel
- local A/AAAA records with wildcard support
- empty local A/AAAA values act as NODATA rules: the daemon replies NOERROR with no addresses and does not forward the query upstream
- special domains route programming via netlink
- route manager with IP/CIDR dedupe, snapshot cache and on-demand route reload
- Prometheus metrics

Run:

```bash
go run . -db /var/lib/dns-route/config.db -http 127.0.0.1:8080
```
