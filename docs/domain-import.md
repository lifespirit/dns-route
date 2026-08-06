# Domain import and external sources

[Русская версия](domain-import.rus.md) · [Back to README](../README.md)

`dns-route` has two independent domain-list mechanisms:

1. **Special domains** decide which A/AAAA answers trigger route programming.
2. **DNS records** provide local A, AAAA, or NODATA answers and prevent forwarding those queries upstream.

Importing a name into one list does not automatically add it to the other.

## General CSV rules

Both importers:

- accept UTF-8 text and an optional UTF-8 BOM on the first field;
- use standard CSV quoting rules;
- trim surrounding whitespace;
- ignore empty rows;
- ignore rows whose first field starts with `#` or `;`;
- reject the whole import when a non-ignored row is invalid;
- limit input to 32 MiB;
- normalize names to lower case and remove a trailing dot.

The web upload request has a small multipart overhead allowance in addition to the 32 MiB CSV content limit.

## Special-domain CSV

Special domains are the route-selection list.

### Accepted rows

Each non-empty row has one meaningful column:

```text
example.com
*.example.net
```

A header containing only `domain` or `pattern` is accepted:

```csv
domain
example.com
*.example.net
```

Extra columns are allowed only when all of them are empty. This is accepted:

```csv
example.com,
```

This is rejected:

```csv
example.com,comment
```

### Matching semantics

```text
example.com
```

matches:

```text
example.com
www.example.com
a.b.example.com
```

while:

```text
*.example.com
```

matches only subdomains and does not match the apex `example.com`.

### Persistent import behavior

Uploading a special-domain CSV:

- inserts new patterns into `special_domains`;
- re-enables an existing duplicate;
- ignores duplicate rows inside the file;
- does **not** remove persistent patterns absent from the file;
- activates the resulting configuration transactionally.

Use the delete action in the panel or direct database maintenance to remove old persistent patterns.

### Export behavior

Export writes enabled persistent rows from `special_domains`, sorted by pattern. External-source contents are not included.

## DNS-record CSV

DNS-record CSV controls local authoritative A/AAAA/NODATA answers.

### Accepted forms

```text
test.lan
test.lan,
test.lan,A
test.lan,AAAA
test.lan,A,
test.lan,AAAA,
test.lan,A,192.0.2.10
test.lan,AAAA,2001:db8::10
```

Meaning:

| Row | Result |
|---|---|
| `test.lan` | NODATA for both A and AAAA |
| `test.lan,` | Same as one-column form |
| `test.lan,A` or `test.lan,A,` | NODATA for A only |
| `test.lan,AAAA` or `test.lan,AAAA,` | NODATA for AAAA only |
| `test.lan,A,192.0.2.10` | Static A answer |
| `test.lan,AAAA,2001:db8::10` | Static AAAA answer |

A header is accepted when its first fields are `domain,type` or `name,type`.

Only one to three columns are supported. `A` values must be IPv4 and `AAAA` values must be IPv6.

### Wildcard records

DNS-record names can use a leading wildcard:

```csv
*.ads.example,A
*.ads.example,AAAA
```

This matches subdomains but not `ads.example` itself.

### Multi-value answers

Repeat address rows for the same name and family:

```csv
service.lan,A,192.0.2.10
service.lan,A,192.0.2.11
service.lan,AAAA,2001:db8::10
```

Duplicate addresses are ignored.

### Ordering inside one CSV file

For each name and family, the last mode transition is deterministic:

- a NODATA row replaces all previously collected addresses for that family;
- a later address replaces NODATA;
- further distinct addresses are appended.

Example:

```csv
service.lan,A,192.0.2.10
service.lan,A
service.lan,A,192.0.2.20
service.lan,A,192.0.2.21
```

Final result: `192.0.2.20` and `192.0.2.21`.

### Persistent import behavior

For every name present in the uploaded file, dns-route first deletes all persistent A and AAAA rows for that normalized name and then inserts the imported families.

Consequences:

- names absent from the file remain unchanged;
- if only A is specified for a name, its old AAAA rows are also removed because replacement is per name;
- imported rows use `ttl=0`, meaning the current `local_record_ttl` setting;
- the complete mutation and runtime activation are transactional.

### Export behavior

Export contains enabled persistent records only. External-source records are not included.

When both A and AAAA are NODATA, export uses the compact one-column form. Other families are written as separate rows.

## External sources

Both special domains and DNS records can be loaded from external sources.

Supported locations:

```text
https://example.net/list.csv
http://192.168.1.10/list.csv
file:///etc/dns-route/list.csv
/etc/dns-route/list.csv
relative/path/list.csv
```

Supported URL schemes are `http`, `https`, and `file`. A location without a scheme is treated as a filesystem path.

### Snapshot model

External source contents are parsed into immutable in-memory snapshots. They are never copied into `special_domains` or `dns_records`.

Adding or editing a source changes only its configuration. The new contents remain pending until **Reload sources** succeeds.

Normal **Reload config**:

- rereads SQLite settings;
- reuses active source snapshots;
- performs no source file or HTTP access.

**Reload sources**:

1. loads every enabled DNS-record source;
2. loads every enabled special-domain source;
3. parses all files;
4. builds a complete candidate configuration;
5. activates all new snapshots together.

If any source fails to download, open, or parse, the previous active snapshots remain in use.

### Source ordering and precedence

Special-domain sources are additive: all valid patterns from active sources and persistent SQLite rows are included.

DNS-record sources are layered in database ID order:

1. earlier external source;
2. later external source overrides the same name/family;
3. enabled persistent SQLite records are applied last and have final priority.

An external source can override only a family it explicitly sets. Omitted families continue to come from lower layers.

## DNS-record source: NO_DATA only

Each DNS-record source has a **NO_DATA only** option.

When enabled:

- only the first two CSV columns are considered;
- every third and later column is ignored;
- an address row becomes a NODATA rule for the selected family.

Example source row:

```csv
tracker.example,A,203.0.113.10
```

With **NO_DATA only** enabled, it is treated as:

```csv
tracker.example,A
```

This mode is useful for importing public blocklists without trusting address values from the source.

A one-column row still blocks both A and AAAA.

## Pi-hole-style blocklist example

A simple one-domain-per-line list can be imported as DNS records:

```text
# tracking domains
tracker.example
ads.example
telemetry.example
```

Each name produces NODATA for A and AAAA. It does not redirect to `0.0.0.0` or `::`; the response is `NOERROR` with an empty answer section.

The same file imported as **Special domains** has a completely different effect: answers remain normal, but returned addresses are routed.

## Combined example

### `special-domains.csv`

```csv
pattern
example.org
*.media.example.net
```

### `dns-records.csv`

```csv
name,type,value
router.lan,A,192.168.1.1
router.lan,AAAA,fd00::1
ads.example,A
ads.example,AAAA
*.telemetry.example,A
*.telemetry.example,AAAA
```

Effects:

- `example.org` and its subdomains trigger route programming;
- only subdomains of `media.example.net` trigger routing;
- `router.lan` is answered locally;
- `ads.example` and telemetry subdomains receive NODATA.

## Automation with local files

Create files readable by the dns-route service:

```bash
sudo install -d -m755 /etc/dns-route
sudo install -m644 special-domains.csv /etc/dns-route/special-domains.csv
sudo install -m644 dns-records.csv /etc/dns-route/dns-records.csv
```

Add these source locations in the panel:

```text
/etc/dns-route/special-domains.csv
/etc/dns-route/dns-records.csv
```

After replacing a file, press **Reload sources**. A service restart alone loads the configured sources during initial startup, but normal config reload intentionally reuses the current snapshots.

For scheduled source updates, download to a temporary file and rename atomically before triggering the refresh:

```bash
curl --fail --output /etc/dns-route/list.csv.new https://example.net/list.csv
mv /etc/dns-route/list.csv.new /etc/dns-route/list.csv
curl --fail -X POST http://127.0.0.1:8080/record/sources/refresh
```

Protect the admin endpoint before automating HTTP POST requests.

## Troubleshooting imports

### `CSV contains no ...`

The file contained only empty rows, comments, or a header.

### Invalid column count

Special domains require one meaningful column. DNS records support at most three columns unless the source uses **NO_DATA only**, where later columns are deliberately ignored.

### An imported DNS name removed an old family

Persistent DNS import replaces both A and AAAA rows for every name present in the file. Include every family that must remain for that name.

### A new external source is shown as pending/not loaded

Press **Reload sources**. Adding a source does not perform source I/O during the configuration transaction.

### Refresh failed and old data is still active

This is expected atomic behavior. Fix the failing source and run **Reload sources** again.

## Security considerations

- Treat remote CSV files as routing and DNS configuration, not passive data.
- Prefer HTTPS and controlled publishers.
- A changed special-domain list can redirect large destination prefixes when Team Cymru aggregation is enabled.
- A DNS-record source can suppress or replace name resolution.
- Filesystem sources are opened with the daemon's privileges; restrict who can change their locations and contents.
