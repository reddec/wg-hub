# wg-hub

No-brainer, dumb simple HTTP(S) REST API for WireGuard.

- 0 (zero) external code dependencies
- requires `wg` tools and (unless `ephemeral` enable) `wg-quick`
- Focuses on linux
- Single binary
- TLS (optional) and access key (optional) protection

> Note: currently it doesn't create a new WireGuard interface if it doesn't exist.

## Requirements

- Linux system with WireGuard support
- `wg` command-line tools installed
- `wg-quick` (unless running in ephemeral mode)
- Go 1.21+ (for building from source)

## Installation

### From Releases

- Download the latest release from [Releases](https://github.com/reddec/trusted-cgi/releases/latest)
- Unpack the archive
- Move the binary to your `$PATH`

### From Source

```bash
git clone <repository-url>
cd wg-hub
go build -o wg-hub main.go
```

### Running

Make sure your WireGuard interface is up and configured:

```bash
# Create and configure your WireGuard interface
sudo wg-quick up wg0

# Run wg-hub
sudo ./wg-hub -interface wg0
```

**Note:** Root privileges are typically required to modify WireGuard configurations.

## Usage

Supports command flags and environment variables.

```bash
wg-hub [options]
```

### Command-line flags:

- `-bind` - Binding address (default: `:8080`) `[$WG_HUB_HTTP_BIND]`
- `-access-token` - Protect HTTP requests with Authorization header `[$WG_HUB_TTP_ACCESS_TOKEN]`
- `-interface` - WireGuard interface name (default: `wg0`) `[$WG_HUB_INTERFACE]`
- `-tls-enabled` - Enable HTTPS (default: `false`) `[$WG_HUB_TLS_ENABLED]`
- `-tls-cert` - TLS certificate file path `[$WG_HUB_TLS_CERT]`
- `-tls-key` - TLS private key file path `[$WG_HUB_TLS_KEY]`
- `-ephemeral` - Do not save config on changes, eliminates wg-quick dependency (default: `false`) `[$WG_HUB_EPHEMERAL]`

### Examples:

```bash
# Basic usage
wg-hub

# With custom port and interface
wg-hub -bind :9090 -interface wg1

# With TLS enabled
wg-hub -tls-enabled -tls-cert /path/to/cert.pem -tls-key /path/to/key.pem

# With access token protection
wg-hub -access-token "your-secret-token"

# Ephemeral mode (no config persistence)
wg-hub -ephemeral

# Using environment variables
WG_HUB_HTTP_BIND=:9090 WG_HUB_INTERFACE=wg1 wg-hub
```

## API

It's literally just few endpoints.

### Endpoints

#### `GET /`

Get current WireGuard network information including all peers.

**Response:**

```json
{
  "interface": "wg0",
  "listen_port": 51831,
  "public_key": "base64-encoded-public-key",
  "fw_mark": "off",
  "peers": [
    {
      "public_key": "base64-encoded-public-key",
      "endpoint": "ip:port",
      "allowed_ips": [
        "10.0.0.2/32"
      ],
      "latest_handshake": "2023-01-01T12:00:00Z",
      "transfer_rx": 1024,
      "transfer_tx": 2048
    }
  ]
}
```

#### `POST /peers`

Create a new WireGuard peer.

**Request body:**

```json
{
  "allowed_ips": [
    "10.0.0.2/32"
  ],
  "endpoint": "192.168.1.100:51820",
  "keepalive": 25,
  "keys": {
    "private_key": "base64-encoded-private-key",
    "public_key": "base64-encoded-public-key"
  }
}
```

**Required fields:**

- `allowed_ips` - Array of CIDR blocks this peer is allowed to use

**Optional fields:**

- `endpoint` - Peer's endpoint address
- `keepalive` - Keep-alive interval in seconds
- `keys` - Key pair (if not provided, will be auto-generated)

**Response:**
Returns the created peer configuration including generated keys (if any).

#### `POST /peers/{peer}`

Update an existing peer configuration.

**URL Parameters:**

- `peer` - Base64-encoded public key of the peer

**Request body:**

```json
{
  "allowed_ips": [
    "10.0.0.2/32"
  ],
  "endpoint": "192.168.1.100:51820",
  "keepalive": 25
}
```

**Response:** `204 No Content`

#### `DELETE /peers/{peer}`

Remove a peer from the WireGuard configuration.

**URL Parameters:**

- `peer` - Base64-encoded public key of the peer

**Response:** `204 No Content`

### Authentication

If an access token is configured, include it in the `Authorization` header:

```
Authorization: your-access-token
```

### Example Usage

```bash
# Get network info
curl http://localhost:8080/

# Create a new peer
curl -X POST http://localhost:8080/peers \
  -H "Content-Type: application/json" \
  -d '{"allowed_ips": ["10.0.0.2/32"]}'

# Update a peer
curl -X POST http://localhost:8080/peers/C8F+FKk3hgR0z0lWOjbPcJ9skNNmEqjukAOqekiHmkM= \
  -H "Content-Type: application/json" \
  -d '{"allowed_ips": ["10.0.0.2/32"], "endpoint": "192.168.1.100:51820"}'

# Delete a peer
curl -X DELETE http://localhost:8080/peers/C8F+FKk3hgR0z0lWOjbPcJ9skNNmEqjukAOqekiHmkM=
```