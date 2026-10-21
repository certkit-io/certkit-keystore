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
curl -fsSL https://app.certkit.io/keystore/latest/install.sh | sudo bash
```

Or with a registration key pre-set:

```bash
export CERTKIT_REGISTRATION_KEY=accountid.keystoreid
curl -fsSL https://app.certkit.io/keystore/latest/install.sh | sudo bash
```

### Windows (PowerShell, elevated)

```powershell
irm https://app.certkit.io/keystore/latest/install.ps1 | iex
```

Both installers download the latest release binary, verify its SHA256 checksum, and run `certkit-keystore install`, which prompts for the required configuration:

```
Registration key (abc.xyz123): myaccount.ks01
Host (hostname or IP): keystore.example.com
Port [443]:
Storage directory [/etc/certkit-keystore/certificates]:
```

The registration key is shown in CertKit under Settings > Keystore. The service is registered and started automatically (systemd on Linux, Windows Service on Windows). On Windows the script installs the service with the signed MSI; pass `-Binary` to use the raw binary install instead.

### Windows MSI

`certkit-keystore-windows-amd64.msi` is attached to every release. Double-click it for a setup wizard, or install silently:

```powershell
msiexec /i certkit-keystore-windows-amd64.msi /qn REGISTRATIONKEY=myaccount.ks01 HOST=keystore.example.com
```

Optional properties: `PORT` (default `443`) and `STORAGEDIR` (default `C:\ProgramData\CertKit\certkit-keystore\certificates`). These are only needed on first install; running a newer MSI upgrades in place and keeps the existing configuration. Uninstalling removes the service, firewall rule, and config file, but never the stored certificates.

### Manual Install

```bash
certkit-keystore install --key myaccount.ks01 --host keystore.example.com
```

All flags can also be passed non-interactively for automated deployments. The registration key can be provided via the `CERTKIT_REGISTRATION_KEY` environment variable.

## How It Works

1. **Install.** The keystore registers with CertKit using a one-time registration key and generates an Ed25519 signing keypair. One keystore serves a whole CertKit account; you choose which certificate collections use it in CertKit.
2. **Poll.** Every 30 seconds, the keystore polls CertKit for pending CSR requests and issued certificates in those collections.
3. **Generate.** When a CSR is requested, the keystore generates a private key locally (ECDSA P-256, ECDSA P-384, RSA 2048, or RSA 4096) and submits only the CSR.
4. **Store.** Issued certificates are written to disk alongside their locally generated keys. Status is reported back to CertKit.
5. **Serve.** CertKit Agents retrieve certificates from the keystore over HTTPS. Each request is authenticated through CertKit before key material is released.

### Automatic Updates

When CertKit signals that a new release is available, the keystore downloads the new binary, verifies its SHA256 checksum, swaps it into place, and exits so the service manager (systemd or the Windows SCM) restarts it on the new version. Keystores running in containers are not self-updated.

On Windows the update must also carry a valid Authenticode signature from the same publisher that signed the running keystore; otherwise it is rejected and the current version keeps running. Unsigned builds therefore never update themselves.

## Configuration

The keystore is configured via a JSON file created during installation. The config file always lives in the location below; the storage directory is chosen at install time (defaults shown):

| Platform | Config | Storage |
|----------|--------|---------|
| Linux | `/etc/certkit-keystore/config.json` | `/etc/certkit-keystore/certificates` |
| Windows | `C:\ProgramData\CertKit\certkit-keystore\config.json` | `C:\ProgramData\CertKit\certkit-keystore\certificates` |

The config does not list collections: CertKit tells the keystore which collections it serves on every poll.

### Storage layout

```
certificates/                     storage directory
├── ca/                           the keystore's CA and HTTPS server certificate and keys
├── collections/
│   └── <collection id>/
│       └── <certificate id>/
│           ├── metadata.json     which issued certificate is current
│           ├── <sha1>/           cert.pem, chain.pem, key.pem (csr.pem when the keystore generated the key)
│           └── csr/              csr.pem and key.pem while a certificate request is pending
└── private-cas/
    └── <CA id>/                  key.pem for a CertKit private CA whose key the keystore holds,
                                  with cert.pem (and csr.pem for a CA signed by your own root)
```

All private keys are encrypted at rest. For private CAs kept on the keystore, CertKit holds only the certificates: the keystore generates the CA keys and signs every certificate and CRL those CAs issue.

Environment variables:

| Variable | Purpose |
|----------|---------|
| `CERTKIT_REGISTRATION_KEY` | Registration key for non-interactive install |
| `CERTKIT_API_BASE` | Override the CertKit API URL |

## Upgrading from v1

Re-run the install command for your platform. The existing configuration, signing key and stored certificates are kept, and nothing has to be entered again:

- On first start, v2 upgrades `config.json` to version 2 (the collection ID it held is no longer needed).
- v1 stored certificates directly in the storage directory. On the first poll, each certificate CertKit still sends is moved into `collections/<collection id>/`. Until then it is served from where it is.

A v1 keystore keeps working without the upgrade, but serves a single collection and can't hold private CA keys.

## Backups

Back up `config.json` and the storage directory together. Stored private keys are encrypted with a key CertKit holds for this keystore's registration, and `config.json` holds the identity that fetches it: a storage directory restored under a different registration can't be read, so the keystore moves it aside and starts over. This matters most for private CAs that keep their keys on the keystore, because those keys exist nowhere else.

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
