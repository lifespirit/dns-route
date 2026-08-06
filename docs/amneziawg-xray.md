# Deployment patterns with AmneziaWG and Xray

[Русская версия](amneziawg-xray.rus.md) · [Back to README](../README.md)

This document describes common integration patterns. Interface names, addresses, Xray outbound definitions, and AmneziaWG obfuscation parameters are examples and must be adapted to the actual deployment.

## What dns-route does and does not do

`dns-route` can:

- choose a DNS upstream by domain suffix;
- identify selected special domains;
- extract A/AAAA addresses from their DNS answers;
- install routes through a Linux interface/gateway;
- announce the resulting prefixes through BGP.

It does not:

- create or configure an AmneziaWG tunnel;
- send traffic directly into a SOCKS or HTTP proxy;
- generate Xray routing rules;
- mark application packets by itself;
- remove dynamically created routes when DNS records expire.

A SOCKS-only Xray outbound therefore cannot be used as `wg_interface`. An L3 interface, a TUN adapter, a real next-hop router, or an external transparent-proxy policy is required.

## Pattern 1: selected domains directly through AmneziaWG

This is the simplest split-routing design:

```text
LAN client
   |
   | DNS
   v
 dns-route -- creates routes in table 101 --> awg0 --> VPN server
```

### 1. Keep automatic default routes disabled

A typical AmneziaWG configuration should not install a system-wide default route when dns-route is responsible for selection. With `awg-quick`, use the equivalent of:

```ini
[Interface]
Address = 10.66.66.2/24
Table = off
# PrivateKey, Jc, Jmin, Jmax, S1..S4, H1..H4, and other AWG options stay here.

[Peer]
PublicKey = <server-public-key>
Endpoint = vpn.example:443
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

`AllowedIPs` must permit the destinations that will be sent into the tunnel, but `Table=off` prevents `awg-quick` from adding its own default routes.

### 2. Create a dedicated policy table

```bash
ip rule add priority 10100 lookup 101
ip -6 rule add priority 10100 lookup 101
```

A rule without a source or destination selector first looks in table 101. If table 101 has no matching route, Linux continues to later rules, normally reaching the main table.

Persist these rules with systemd-networkd, NetworkManager, `PostUp`, or a dedicated systemd unit.

### 3. Make the tunnel next hop reachable

For IPv4, dns-route requires a gateway. The gateway must be reachable in the same table.

When `awg0` uses a connected subnet such as `10.66.66.2/24`, the peer gateway `10.66.66.1` is normally on-link. With a `/32` interface address, add an explicit route:

```bash
ip route replace 10.66.66.1/32 dev awg0 table 101
```

For IPv6, `wg_gateway_v6` may be left empty; dns-route then creates device-only routes through `awg0`.

### 4. Configure dns-route

Use these settings:

```text
wg_interface       = awg0
wg_gateway_v4      = 10.66.66.1
wg_gateway_v6      = <empty, or the tunnel IPv6 peer>
route_mode         = kernel
route_table        = 101
route_ipv4         = 1
route_ipv6         = 1 or 0
lookup_cidr        = 1
reply_before_route = 0
```

Add the domains on the **Special domains** page, for example:

```text
example.org
*.cdn.example.net
```

A normal `example.org` pattern includes the apex and all subdomains. `*.cdn.example.net` includes only subdomains.

### 5. Verify

```bash
dig @192.168.1.1 example.org A
ip route show table 101
ip route get <returned-ip>
```

When `lookup_cidr=1`, the installed route can be broader than the exact returned address. Use the statistics page to see lookup attempts and failures.

### Recommended systemd ordering

```ini
[Unit]
After=network-online.target awg-quick@awg0.service
Wants=network-online.target awg-quick@awg0.service
```

If dns-route starts first, its DNS listeners can still recover later. Route processing will fail until `awg0` exists, so ordering is useful when `reply_before_route=0`.

## Pattern 2: DNS for selected zones through Xray, traffic through AmneziaWG

Xray can be used as a local DNS transport while dns-route continues to install client traffic routes through `awg0`.

```text
*.remote.example DNS -> dns-route -> 127.0.0.1:5353 -> Xray outbound
returned destination -> dns-route route table 101 -> awg0
```

A common Xray pattern is a local `dokodemo-door` DNS inlet whose traffic is forced through a proxy outbound. The following is a JSONC fragment to merge into an existing Xray configuration:

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

The `proxy` outbound must already exist in the complete Xray configuration.

In dns-route add a conditional forward zone:

```text
Domain suffix: *.remote.example
Upstream:      127.0.0.1:5353
Protocol:      udp
```

The zone also matches its apex. To make all DNS requests use Xray, add `127.0.0.1:5353` as the default upstream instead.

Important: this only changes how DNS is resolved. Client TCP/UDP traffic follows Linux routes, so configure the AmneziaWG route backend separately.

## Pattern 3: use an Xray-compatible TUN adapter as the route target

The setting name `wg_interface` is historical. The kernel backend only needs a Linux L3 interface and, for IPv4, a reachable next hop. Therefore a TUN interface feeding Xray or tun2socks can be used:

```text
wg_interface  = xray0
wg_gateway_v4 = 198.18.0.1
route_table   = 101
route_mode    = kernel
```

The TUN implementation must:

- create `xray0` before route processing;
- accept packets for arbitrary dynamically learned destinations;
- provide a usable IPv4 next hop for dns-route;
- avoid routing its own proxy-server connection back into itself;
- handle both TCP and UDP if both are expected.

Exact TUN configuration depends on the Xray build or the front-end that creates the TUN device. If the deployment exposes only SOCKS/HTTP inbounds and no L3 interface, dns-route cannot route to it directly.

## Pattern 4: separate dns-route destinations and Xray-marked traffic

It is often cleaner to keep dynamic destination routes and Xray process marks in different tables:

```text
table 101: prefixes learned by dns-route -> awg0
table 300: Xray-marked sockets -> chosen default tunnel path
```

Example policy rules:

```bash
ip rule add priority 1000 fwmark 0x300/0x300 lookup 300
ip rule add priority 10100 lookup 101
```

If Xray sets Linux socket mark `0x300`, the corresponding decimal value is `768`. A common Xray socket-option fragment is:

```jsonc
{
  "streamSettings": {
    "sockopt": {
      "mark": 768
    }
  }
}
```

Confirm support and the exact placement of `sockopt` in the outbound protocol used by the installed Xray version.

Table 300 can contain a default route through the desired tunnel, while table 101 contains only dns-route-generated prefixes. Protect the physical endpoint of AmneziaWG/Xray with a higher-priority WAN route or rule; otherwise the tunnel's own transport connection can recursively enter the tunnel.

Example endpoint exception:

```bash
ip route replace 203.0.113.10/32 via 192.168.1.1 dev eth0 table main
```

Use the real VPN/proxy endpoint and WAN gateway.

## Pattern 5: dns-route announces prefixes to another router

When the machine running dns-route should not be the forwarding gateway, use `route_mode=bgp` or `kernel+bgp` and peer with a router that owns the AmneziaWG/Xray policy.

```text
client DNS -> dns-route -> embedded GoBGP -> router -> AWG/Xray path
```

- `bgp`: only announce prefixes; after restart, prefixes reappear as matching DNS answers are seen.
- `kernel+bgp`: install exact prefixes locally first and mirror the selected kernel table into BGP on startup/manual route reload.
- Set `bgp_next_hop_v4`/`bgp_next_hop_v6` to an address the peer can actually use for forwarding.
- Enable `bgp_require_established` when DNS replies must fail rather than proceed while the BGP session is down.

## DNS source selection examples

### Public DNS by default, local DNS for `.lan`

```text
default upstream: 1.1.1.1:853 / tls
forward zone lan: 127.0.0.1:5353 / udp
```

### Regional DNS for `.ru`

```text
default upstream: 1.1.1.1:853 / tls
forward zone ru: 77.88.8.8:53 / udp
```

### Xray-proxied DNS for one suffix

```text
default upstream: 192.168.1.1:53 / udp
forward zone remote.example: 127.0.0.1:5353 / udp
```

## Troubleshooting

### DNS answer is returned, but no route appears

Check:

```bash
curl http://127.0.0.1:8080/routes/errors
ip link show awg0
ip route show table 101
journalctl -u dns-route -n 200
```

Verify that the queried name matches a special-domain pattern and that the request type is A/AAAA. `dig example.org ANY` does not trigger A/AAAA route extraction.

### `network is unreachable` for the gateway

The IPv4 tunnel gateway is not reachable in the selected route table. Add an on-link/host route to the gateway or use a connected tunnel subnet.

### First connection uses the old path

Enable `reply_before_route=0` to wait for route installation. With `reply_before_route=1`, dns-route resets conntrack only when it can prove that a new kernel route was installed; application retries may still be required.

### Xray receives DNS but not application traffic

A DNS forwarding zone only controls DNS packets sent to Xray. Configure an L3 route target, TUN adapter, transparent proxy, or AmneziaWG route for application traffic.

### Route appears but traffic loops

Add explicit exceptions for the AmneziaWG or Xray server endpoint through the physical WAN. Also verify Xray marks and policy-rule priority ordering.
