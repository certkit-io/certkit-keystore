# CertKit Keystore

[![CI](https://github.com/certkit-io/certkit-keystore/actions/workflows/ci.yml/badge.svg)](https://github.com/certkit-io/certkit-keystore/actions/workflows/ci.yml) [![Release](https://github.com/certkit-io/certkit-keystore/actions/workflows/release.yml/badge.svg)](https://github.com/certkit-io/certkit-keystore/actions/workflows/release.yml)

CertKit Keystore is a lightweight service that generates and stores private keys on your own infrastructure. It integrates with [CertKit](https://certkit.io) to automate certificate lifecycle management while ensuring that private key material never leaves your environment.

## Advantages
- **Private keys never traverse the network.** CSR generation happens on the keystore; only the public CSR is sent to CertKit.
- **Your security posture improves.** Keys live on infrastructure you control. No third parties have access.
- **CertKit compromise does not expose your keys.** There is nothing to exfiltrate because we never had the keys.

## Security Model

- **Ed25519 request signing.** Every API call from the keystore to CertKit is signed with an Ed25519 keypair generated at install time. The private signing key never leaves the machine.
- **TLS 1.3 minimum.** The keystore exposes an HTTPS endpoint for agents to retrieve certificates. It enforces TLS 1.3 with an automatically managed server certificate that rotates before expiry with zero downtime.
- **ECDSA P-256 local CA.** The keystore runs its own certificate authority for internal TLS. Server certificates are issued with 90-day lifetimes and rotated automatically at the 60-day mark.
- **Restrictive file permissions.** All private key files are written with mode `0600` (owner read/write only). Config files containing signing credentials use the same permissions.
- **Machine identity binding.** Each keystore instance reports a stable hardware-derived machine ID, allowing you to cross-reference deployments in the CertKit dashboard.
- **Agent request validation.** When a CertKit Agent retrieves a certificate from the keystore, the request is validated against CertKit's API before any key material is served.

## Keystore Prerequisites

- **A machine to host it.** Supply a server or VM to host the keystore.
- **URL that agents will talk to.** Know the domain/IP and port that agents will connect to the keystore on.
- **Storage directory.** Provide a folder path where the certificates are stored.

## Installation

### Linux

```bash
curl -fsSL https://github.com/certkit-io/certkit-keystore/releases/latest/download/install.sh | sudo bash
```

Or with a registration key pre-set:

```bash
export CERTKIT_REGISTRATION_KEY=appid.keystoreid
curl -fsSL https://github.com/certkit-io/certkit-keystore/releases/latest/download/install.sh | sudo bash
```

### Windows (PowerShell, elevated)

```powershell
irm https://github.com/certkit-io/certkit-keystore/releases/latest/download/install.ps1 | iex
```

Both installers download the latest release binary, verify its SHA256 checksum, and run `certkit-keystore install`, which prompts for the required configuration:

```
Registration key (abc.xyz123): myapp.ks01
Storage directory [/etc/certkit-keystore/certificates]:
Host (hostname or IP): keystore.example.com
Port [443]:
Config file path [/etc/certkit-keystore/config.json]:
```

The service is registered and started automatically (systemd on Linux, Windows Service on Windows).

### Manual Install

```bash
certkit-keystore install --key myapp.ks01 --host keystore.example.com
```

All flags can also be passed non-interactively for automated deployments. The registration key can be provided via the `CERTKIT_REGISTRATION_KEY` environment variable.

## How It Works

1. **Install.** The keystore registers with CertKit using a one-time registration key and generates an Ed25519 signing keypair.
2. **Poll.** Every 30 seconds, the keystore polls CertKit for pending CSR requests and issued certificates.
3. **Generate.** When a CSR is requested, the keystore generates a private key locally (ECDSA P-256 or RSA 2048) and submits only the CSR.
4. **Store.** Issued certificates are written to disk alongside their locally generated keys. Status is reported back to CertKit.
5. **Serve.** CertKit Agents retrieve certificates from the keystore over HTTPS. Each request is authenticated through CertKit before key material is released.

## Configuration

The keystore is configured via a JSON file created during installation. Default locations:

| Platform | Config | Storage |
|----------|--------|---------|
| Linux | `/etc/certkit-keystore/config.json` | `/etc/certkit-keystore/certificates` |
| Windows | `C:\ProgramData\CertKit\certkit-keystore\config.json` | `C:\ProgramData\CertKit\certkit-keystore\certificates` |

Environment variables:

| Variable | Purpose |
|----------|---------|
| `CERTKIT_REGISTRATION_KEY` | Registration key for non-interactive install |
| `CERTKIT_API_BASE` | Override the CertKit API URL |

## Service Management

```bash
# Linux
sudo systemctl status certkit-keystore
sudo systemctl restart certkit-keystore
journalctl -u certkit-keystore -f
```

```powershell
# Windows
Get-Service certkit-keystore
Restart-Service certkit-keystore
# Logs: Event Viewer > Application > Source: CertKit
# File log: C:\ProgramData\CertKit\certkit-keystore\certkit-keystore.log
```


## License

See [LICENSE](./LICENSE) for more info.
