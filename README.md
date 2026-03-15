# reverse_proxy

A SOCKS5 proxy with a Burp Suite-style terminal UI for inspecting HTTP/HTTPS traffic.

## Features

- **SOCKS5 proxy** with CONNECT support (IPv4, IPv6, domain names)
- **Burp-style TUI**: host sidebar, HTTP history table, request/response detail pane
- **Multiple view modes**: Raw (human-readable text), Headers, and Hex dump
- **HTTP auto-detection**: displays HTTP payloads as readable text, binary as hex
- **TLS MITM interception**: decrypt and inspect HTTPS traffic with `--mitm` flag
- **Request interception**: pause, edit, and forward/drop outgoing requests before they reach the server
- **Payload capture**: up to 1 MB per direction per connection

## Building

```bash
go build -o socks5proxy .
```

## Usage

```bash
# Listen on a random available port
./socks5proxy

# Listen on a specific port
./socks5proxy -port 1080

# Enable TLS interception
./socks5proxy -port 1080 -mitm

# Enable database capture
./socks5proxy -port 1080 -db capture.db

# All features
./socks5proxy -port 1080 -mitm -db capture.db
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-port` | `0` | Port to listen on (0 = random) |
| `-mitm` | `false` | Enable TLS MITM interception |
| `-ca-cert` | `ca.pem` | Path to CA certificate file |
| `-ca-key` | `ca-key.pem` | Path to CA private key file |
| `-db` | `""` | Path to SQLite database for traffic capture (empty = disabled) |
| `-filter` | | Intercept filter as `field:regex` (repeatable, see below) |

### Keyboard Controls

| Key | Action |
|-----|--------|
| `Tab` / `Shift+Tab` | Cycle focus between panes (hosts, table, detail) |
| `1` | Show request payload |
| `2` | Show response payload |
| `r` | Raw view (human-readable text) |
| `h` | Headers view |
| `x` | Hex dump view |
| `i` | Toggle request interception on/off |
| `F` (shift+f) | Open filter management dialog |
| `C` (shift+c) | Clear all intercept filters |
| `Ctrl+F` | Forward intercepted request (from editor) |
| `Ctrl+X` | Drop intercepted connection (from editor) |
| `d` | Toggle database capture on/off |
| `S` (shift+s) | Save all closed connections to database |
| `q` | Quit |

## Testing with curl

```bash
# Plain HTTP
curl --socks5 127.0.0.1:1080 http://example.com

# HTTPS with MITM (trust the generated CA for this request)
curl --socks5 127.0.0.1:1080 --cacert ca.pem https://example.com
```

## Configuring a browser to use the proxy

### Set the SOCKS5 proxy

**Firefox:**
1. Go to Settings > Network Settings > Manual proxy configuration
2. Set SOCKS Host to `127.0.0.1`, Port to `1080` (or whichever port you chose)
3. Select SOCKS v5

**Chrome / Chromium (command line):**
```bash
google-chrome --proxy-server="socks5://127.0.0.1:1080"
```

**System-wide (Linux):**
```bash
export ALL_PROXY=socks5://127.0.0.1:1080
```

### Trusting the CA certificate for HTTPS interception

When using `--mitm`, the proxy generates a CA certificate (`ca.pem`) on first run. Browsers will show certificate warnings because they don't trust this CA. To fix this, import the CA into your browser or OS trust store.

**Firefox:**
1. Go to Settings > Privacy & Security > Certificates > View Certificates
2. Go to the Authorities tab
3. Click Import and select the `ca.pem` file
4. Check "Trust this CA to identify websites" and click OK

**Chrome / Chromium:**
1. Go to `chrome://settings/certificates`
2. Go to the Authorities tab
3. Click Import and select the `ca.pem` file
4. Check "Trust this certificate for identifying websites" and click OK

**Linux (system-wide):**
```bash
sudo cp ca.pem /usr/local/share/ca-certificates/socks5proxy-ca.crt
sudo update-ca-certificates
```

**macOS (system-wide):**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca.pem
```

**Windows:**
```powershell
Import-Certificate -FilePath ca.pem -CertStoreLocation Cert:\LocalMachine\Root
```

> **Important:** Only trust this CA on machines you control and for testing/development purposes. Remove it from your trust store when you're done to avoid security risks.

## Request Interception

Press `i` to toggle intercept mode. When enabled, each new outgoing request is paused before reaching the server:

1. The detail pane switches to an editable text area showing the raw request
2. Edit the request freely (modify headers, body, URL, etc.)
3. Press `Ctrl+F` to forward the edited request to the server
4. Press `Ctrl+X` to drop the connection entirely

Requests queue up while you're editing — the status bar shows how many are waiting. This works with both plain HTTP and TLS-intercepted HTTPS traffic.

### Intercept Filters

By default, intercept mode pauses **all** requests. Use filters to only pause requests matching specific patterns. Filters are OR'd together (any match triggers interception).

Two filter types are supported: **regex** filters match against a specific field, and **awk** filters give you full programmability.

**Regex filters (from the CLI):**
```bash
# Only intercept requests to example.com
./socks5proxy -port 1080 -filter "host:example\.com"

# Only intercept POST requests with JSON bodies
./socks5proxy -port 1080 -filter "method:POST" -filter "content-type:json"

# Multiple filters (any match pauses the request)
./socks5proxy -port 1080 -filter "url:/api/login" -filter "body:password"
```

**Awk filters (from the CLI):**
```bash
# Intercept POST requests to any /api/ endpoint
./socks5proxy -port 1080 -filter 'awk:method == "POST" && url ~ /\/api\//'

# Intercept requests with bodies larger than 1KB
./socks5proxy -port 1080 -filter 'awk:body_len + 0 > 1024 { print }'

# Intercept requests containing "password" or "token" anywhere
./socks5proxy -port 1080 -filter 'awk:/password|token/ { print }'

# Complex: intercept JSON POSTs to login endpoints on specific hosts
./socks5proxy -port 1080 -filter 'awk:method == "POST" && host ~ /auth\./ && content_type ~ /json/ && url ~ /login/ { print }'
```

**From the TUI:**
- Press `F` to open the filter management dialog
- Type a filter in `field:regex` or `awk:expression` format and press Enter
- Select a filter and press Enter to delete it
- Press Escape to close
- Press `C` to clear all filters

**Regex filter fields:**

| Field | Matches against |
|-------|----------------|
| `host` | Destination host:port (e.g. `example.com:443`) |
| `url` / `path` | Request URL path (e.g. `/api/users`) |
| `method` | HTTP method (GET, POST, PUT, etc.) |
| `content-type` / `ct` / `mime` | Content-Type header value |
| `body` | Request body content |
| `header` / `headers` | All headers concatenated |

**Awk filter variables:**

| Variable | Description |
|----------|-------------|
| `method` | HTTP method (GET, POST, etc.) |
| `url` | Request URL path |
| `host` | Destination host:port |
| `proto` | Protocol (HTTP/1.1, etc.) |
| `content_type` | Content-Type header value |
| `body_len` | Body length in bytes |
| `headers` | All headers as newline-delimited string |
| `$0` | Full raw request (each line is a record) |

The awk expression receives the full raw request on stdin. If awk produces **any output**, the filter matches. Use `{ print }` after a condition, or rely on awk's default print behavior with pattern matching (e.g. `/regex/`). Awk filters have a 5-second timeout.

## Database Capture

When started with `-db capture.db`, all completed connections are automatically saved to a SQLite database. You can toggle capture on/off at runtime with `d`, or manually save all closed connections with `S`.

### Schema

```sql
CREATE TABLE connections (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    proxy_id        INTEGER NOT NULL,
    target          TEXT NOT NULL,
    client_addr     TEXT NOT NULL,
    start_time      DATETIME NOT NULL,
    end_time        DATETIME,
    status          TEXT NOT NULL,
    tls_intercepted BOOLEAN NOT NULL DEFAULT 0,
    request_data    BLOB,
    response_data   BLOB
);
```

### Querying captured data

```bash
# List all captured connections
sqlite3 capture.db "SELECT id, target, status, length(request_data), length(response_data) FROM connections;"

# View a specific request payload as text
sqlite3 capture.db "SELECT CAST(request_data AS TEXT) FROM connections WHERE id = 1;"

# View a specific response payload as text
sqlite3 capture.db "SELECT CAST(response_data AS TEXT) FROM connections WHERE id = 1;"

# Find requests to a specific host
sqlite3 capture.db "SELECT * FROM connections WHERE target LIKE '%example.com%';"
```
