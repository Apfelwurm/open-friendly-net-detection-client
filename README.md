# Friendly Network Detection (FND) Client

A Debian-packaged system service that identifies the current "friendly" network via a cryptographically verified reverse handshake with configured FND servers. Exposes the detected network ID through a local UNIX domain socket for other applications.

## Features

- Configurable networks with associated server public keys (Ed25519) and optional fallback server IP list.
- DHCP custom option discovery of server IP (option number configurable; uses 224 in examples).
- Rtnetlink monitoring to trigger re-detection on network changes (configurable).
- Periodic polling cadence (configurable).
- Reverse handshake: client sends UDP probe with ephemeral TCP listen port + nonce, server connects back presenting X.509 (Ed25519) certificate and signature over nonce. Client validates and maps to network id.
- Atomic publication of network id to `/run/fnd/network_id` and single-line response service on UNIX socket `/run/fnd/socket`.

## Architecture Overview

1. Service starts and loads configuration from `/etc/fnd-client/config.yaml`.
2. Opens UNIX domain socket (mode 0666; protocol read-only) and writes current state file.
3. Optional: subscribes to rtnetlink groups for link / IPv4 address changes.
4. On triggers (startup, signal, netlink event, interval expiry): build server candidate list (DHCP provided + fallbacks) and attempt reverse handshake sequentially.
5. First successful handshake sets the current network id. Failure of all candidates sets `unknown`.

## Security Model

- Server authentication only (client unauthenticated) via pinned Ed25519 raw public key (base64) embedded in configuration.
- Short-lived 32-byte nonce prevents replay; stale nonces purged after 30 seconds.
- Certificate is only used as a container for Ed25519 key (no CA validation); raw key pinning provides trust.

## Configuration

Example `/etc/fnd-client/config.yaml`:

```yaml
poll_interval_seconds: 900
react_to_netlink: true
handshake_timeout_seconds: 10
custom_dhcp_option: 224
networks:
  office:
    pubkey: "Base64RawEd25519Key=="
    fallback_servers: ["10.0.0.10", "10.0.0.11"]
  lab:
    pubkey: "AnotherBase64Key=="
    fallback_servers: ["192.168.50.5"]
```

## DHCP Integration

Append to `/etc/dhcp/dhclient.conf`:

```conf
option fnd-server-ip code 224 = ip-address;
request subnet-mask, broadcast-address, time-offset, routers,
        domain-name, domain-name-servers, host-name, fnd-server-ip;
script "/usr/lib/fnd-client/dhclient-hook.sh";
```

Hook script stores the IP in `/run/fnd/dhcp_server_ip` and signals the daemon (SIGUSR1) to re-check.

## Build & Packaging

Debian packaging metadata under `fnd-client/debian/`. GitHub Actions workflow builds and publishes `.deb` releases from `main`. Dependabot keeps dependencies updated.

Local build:

```bash
debuild -us -uc
```

## Socket Protocol

Connecting to the UNIX socket returns a single line: the network id or `unknown` then closes.

## License

MIT
