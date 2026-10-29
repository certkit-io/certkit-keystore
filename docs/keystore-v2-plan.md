# Keystore v2: one keystore per account

Status: implemented (2026-10-19), not committed or released. Builds on the unreleased encryption-at-rest work ([encryption-at-rest-plan.md](encryption-at-rest-plan.md)); both ship together as keystore v2.0.0.

Repos: this one, and the CertKit app (`c:\Source\CertKit\Frontend\src\CertkitFrontend`, branch `keystore-enc`).

## Decisions

Confirmed with the user:

- A keystore belongs to an **account** (customer), not a collection. Collections **opt in** to it from their Keystore page. Opting in can't be undone in the UI.
- **Storage layout:** `<storage>/collections/<collection id>/<certificate id>/…`, with `ca/` unchanged and `private-cas/` new. v1 certificate folders are moved into place when a poll says which collection they belong to.
- **config.json lists no collections.** CertKit is the source of truth and sends them, with names, on every poll.
- **v1 keystores** keep working on the v1 API, but serve at most one collection. Opting in a second collection requires the keystore to run v2.
- **Private CAs** can keep their keys on the keystore: CertKit-generated root + issuing, root-only, and bring-your-own-root subordinates. It's chosen at creation, only with an approved v2 keystore. Existing CAs keep their keys in CertKit.
- **CRLs of keystore-held CAs** are valid for 7 days and re-signed daily, so they survive about 6 days of keystore downtime. CertKit-held CAs keep 24h/18h.
- **Mixed use is allowed:** collections that don't use the keystore can issue from a keystore-held CA. The keystore signs, and CertKit holds those leaf keys as it does for every certificate in such a collection.
- Install keeps the config at the fixed per-platform path and never prompts for it. `--config` stays as a flag because `run-local.ps1` needs it.

## CertKit data model

`SQL/alter-2026-10-19-keystore-v2.sql` (needs `alter-2026-10-13-keystore-encryption-key.sql` first):

- `keystores` is rebuilt without `application_id`, with `customer_id UNIQUE`. New columns: `api_version` (1 or 2, the API the keystore last used; NULL until it talks to CertKit), `os_version`, `architecture`, `install_type`, `run_as_user`, `ip_addresses`.
- `keystore_applications (keystore_id, application_id UNIQUE, created)`: the opted-in collections. Both foreign keys cascade.
- **Migration of existing rows:**
  - Each account keeps its installed keystore, or its oldest one if none was installed.
  - The other, never-installed slots are deleted, with their logs and statuses.
  - The collection each kept keystore was created for becomes its first opt-in.
  - Installed keystores get `api_version` 1.
  - The id sequence is preserved, so ids of deleted keystores (which appear in registration keys) are never reused.
- **Safety:** the alter runs under `.bail on` inside a transaction. It stops, changing nothing, if any account has more than one installed keystore, or if anything is left pointing at a missing keystore.

`SQL/alter-2026-10-19-keystore-private-ca.sql`:

- `certificate_authorities.keystore_id` (no foreign key on purpose: when the keystore is deleted, the CA still says where its key was).
- `keystore_signing_requests`: work queued for the keystore. Answered requests are deleted, except a signed leaf (`signed`), which waits for CertGeneratorJob.

Both are folded into `init.sql`.

## Keystore API v2 (`/api/keystore/v2/…`)

Request signing is unchanged. `KeystoreApiV2Controller.cs` serves v2; `KeystoreApiController.cs` keeps serving v1 on the new tables.

| Call | Notes |
|---|---|
| `register-keystore` | `{registration_key, public_key, host_info}`. The key is `{account_sqid}.{keystore_sqid}`. Keys handed out before v2 (`{collection_sqid}.{keystore_sqid}`) are still accepted for any collection of the same account. |
| `{id}/host-info` | `{host_info, ca_certificate}`, sent at every startup, even before approval. An empty CA certificate keeps the stored one. Reinstalls over existing storage now always tell CertKit the CA agents must trust. |
| `{id}/encryption-key`, `{id}/update-ca-info`, `{id}/log` | Same as v1. |
| `{id}/poll` | `{collections: [{id, name, certificates: [...]}], signingRequests: [...]}`. Certificates use the v1 shape. Returns 403 until approved. |
| `{id}/set-csr`, `{id}/update-status` | Carry `collectionId`, which must agree with the certificate. An empty `statuses` list clears old statuses. |
| `{id}/validate-agent-request` | Returns `{valid, collection_id, certificate_id}`. The keystore serves that certificate, never the one the request body names. |
| `{id}/signing-result` | Private CA results (below). Returns 404 when CertKit no longer wants the result. |

`host_info` carries version, hostname, machine_id, operating_system, os_version, architecture, timezone, host_type, install_type (`msi`, `windows-service`, `systemd`, `container` or `other`), run_as_user, ip_addresses, keystore_base_url, path_to_bin, path_to_config, storage_dir and service_name.

**Agent fetch check (v1 and v2):**

- The agent is approved and its collection uses this keystore.
- The signature covers the body.
- The body's `config_id` is one of the agent's configurations, and `certificate_id` is the certificate that configuration deploys.

v1 only checked that the agent belonged to the keystore's collection, so any agent in it could fetch any certificate's key. With one keystore holding every opted-in collection's keys, this check is what keeps collections apart.

## Keystore changes

- **Config version 2:**
  - `account_id` replaces `application_id`.
  - A v1 config is upgraded on load. One that never registered keeps its old collection key, which CertKit accepts.
  - `SaveConfig` is atomic.
- **Storage:**
  - Paths take a collection.
  - `AdoptLegacyCert` moves v1 folders into `collections/` on each poll. If the move fails, the certificate reports GeneralError and the old folder keeps serving agents.
  - `ReadLatestCert` falls back to the old location until the move happens.
  - IDs from CertKit must be `[A-Za-z0-9_-]`.
- **Startup:** register (v2) → encryption key → start over / migrate → EnsureCA → **host-info** → TLS → poll loop. Signing requests are processed after the certificates in each poll.
- **Status page:**
  - One box per collection, plus "Other Stored Certificates" and "Private CA Keys".
  - "Manage in CertKit" goes to `/settings/keystore`.
- **README:** key format, storage layout, upgrading from v1, backups.

## Private CAs on the keystore

The keystore acts as a signer: CertKit builds every X.509 profile (the same `RootCaExtensions` / `IssuingCaExtensions` / `LeafExtensions` helpers its own signing uses) and sends extensions DER-encoded. The keystore generates keys (stored encrypted under `private-cas/<ca id>/`), adds the key identifiers, and signs with Go's `x509`. Requests ride the 30s poll:

| Type | What the keystore does | CertKit on the result |
|---|---|---|
| `create_ca` | Root key + self-signed root; issuing key + issuing cert (two-tier) | Checks subject, serial, issuer and signature; activates the rows; queues the first CRL |
| `rotate_ca` | New issuing key, signed by the stored root key | Activates the new CA and moves definitions to it (only then); queues its CRL |
| `create_csr` | BYOR subordinate key + CSR | Stores the CSR. Import then matches the CSR's public key and requires SKI and CRL-Sign key usage, which the keystore needs to sign CRLs |
| `issue_certificate` | Leaf for the given SPKI (keystore CSR, or a key CertKit generated for a non-keystore collection) | Checks it and marks it `signed`; CertGeneratorJob's next run saves and deploys it like any new certificate (`AwaitKeystoreSignature`) |
| `sign_crl` | CRL with the given number, thisUpdate = now, 7-day validity | Verifies the signature and number, stores the CRL (never replacing a newer one) |

Keys are generated before anything is signed, and reused when a request is delivered again. A failed request is shown on the CA pages, with Try Again for CA operations. A failed leaf or CRL is replaced by a fresh request on the next job run.

**Deleting the keystore** leaves its CAs unable to sign. The admin delete dialog names them.

## UI (CertKit)

- **Collection Keystore page:**
  - No keystore on the account: the existing text.
  - Keystore exists, collection not opted in: what switching means, a large "cannot be undone" warning, the old-agent warning, and the v1 limit. Only admins can opt in.
  - Collection opted in: status, this collection's certificate storage, and a Keystore Settings link for admins.
- **Settings → Keystore:**
  - Status, install snippet or approval, and upgrade instructions.
  - Synced collections with per-collection counts and status, and the collections not using the keystore.
  - Keystore-held private CAs.
  - Keystore, Host and CA & TLS details.
- **Admin customer page:**
  - The keystore is managed at customer level: add it, or delete it with the type-"delete" dialog.
  - Each collection shows whether it uses the keystore.
  - Deleting a collection no longer deletes the keystore, and its warning says so.
- **Private CA pages:**
  - Create offers a key location.
  - The list marks keystore-held CAs and "Waiting for Keystore".
  - The complete page handles waiting for the keystore (retry, cancel).
  - Details shows pending rotations and keystore CRL status.

## Deploying

1. Copy `/data/app.db`, then run on prod, in order: `alter-2026-10-13-keystore-encryption-key.sql`, `alter-2026-10-19-keystore-v2.sql`, `alter-2026-10-19-keystore-private-ca.sql`.
2. Deploy the CertKit app right after. Old app code fails on the new `keystores` table (no `application_id`), so keep the gap short or stop the app during the alter. Agent polls look up keystores, and the agents retry.
3. Release the keystore (v2.0.0). v1 keystores keep working until their owners re-run the install command.

## Verification done

- **Alter:** run on a copy of the local dev DB (5 keystores), plus synthetic cases: three slots with one installed (extras removed, sequence kept), and two installed (stops, database unchanged).
- **CertKit tests:** 66 keystore/private-CA tests pass, including the existing PrivateCaServiceTests after the profile refactor. They cover a C# fake keystore for the signing protocol, signed agent-fetch checks, opt-in rules and registration key formats. Full suite: 535 pass. The 7 failures are in code these changes don't touch: live DNS, external TLS endpoints, ACME profiles, a DNS DB path that resolves relative to the test build's folder, and an agent-inventory filter test.
- **Keystore tests:** `go build`, `vet` and `test` pass on Windows; `build` and `vet` pass with `GOOS=linux`.
- **Cross-language:** the real Go `privateca.Sign` signed requests CertKit built, and CertKit applied the results. Covered: every CA type and key algorithm, BYOR, leaves on both key paths, revocation (CRL verified with BouncyCastle), and rotation.
- **Live run:** keystore code against a local v2 CertKit over HTTP.
  - A v1 config and v1 storage were upgraded, and the old-style key registered through v2.
  - Host info was stored, the poll returned 403 until approval, then collections came through.
  - The CSR round trip, the v1 folder move and update-status all worked.
  - A keystore-held CA was created and its CRL signed; OpenSSL verified the CRL served from `/pki/crl/…`.
  - Not exercised: an agent fetching over the keystore's HTTPS (covered by unit tests on both sides).

## Not done / follow-ups

- No automatic reissue when a keystore is deleted. Certificates whose keys only existed on it need reissuing.
- Keys of deleted or cancelled keystore-held CAs stay in the keystore's `private-cas/` folder.
- CertKit still doesn't send keystore self-update signals (`updateAvailable`). v1 → v2 upgrades are manual: re-run the install command.
- Public docs (`CertKitOther/documentation`) need the account-level keystore, opt-in, and keystore-held CAs.
