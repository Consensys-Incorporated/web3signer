# PostgreSQL-Backed Bulk Key Loading (eth2/BLS)

## 1. Problem and goal

Web3Signer's `eth2` mode loads BLS validator signing keys from Azure Key Vault secrets or AWS Secrets Manager secrets, one HTTP call per secret. At 20,000 keys this takes roughly 8 minutes at startup and on every `/reload`. `eth1`/secp256k1 mode is unaffected — it uses Azure Keys/AWS KMS purely for remote signing, so key material never leaves the vault and there is nothing to bulk-fetch.

This feature replaces the per-key vault calls with envelope encryption: BLS private keys are pre-encrypted by an external provisioning process and stored in PostgreSQL. Web3Signer performs one streaming bulk `SELECT`, exactly one vault call per *tenant* (not per key) to unwrap that tenant's Data Encryption Key (DEK), then decrypts every key belonging to that tenant locally and in parallel. Target: full reload of 20,000 keys across 5 tenants in under 1 second, with exactly 5 vault calls.

This document covers the loading (read) side only. Provisioning (writing rows) is a separate, external process — section 5 below is the contract that process must satisfy for Web3Signer to be able to decrypt what it writes.

## 2. Architecture

Two-tier envelope encryption, one KEK (Key Encrypting Key) per tenant:

- **KEK**: lives in a vault — Azure Key Vault, AWS KMS, or HashiCorp Vault's Transit secrets engine. It never leaves the vault; every use is a remote unwrap/decrypt API call.
- **DEK (Data Encryption Key)**: AES-256, one per tenant, generated at provisioning time. Stored in PostgreSQL wrapped by the tenant's KEK. Unwrapped once per tenant per load cycle (cached for 15 minutes), not once per key.
- **BLS private key**: encrypted at rest with the tenant's DEK using AES-256-GCM, stored per validator key row.

Loading flow:
1. One streaming JDBC query (`fetchSize=1000`, forward-only, read-only) returns every `(tenant, key)` row, ordered by tenant.
2. Rows are grouped by tenant as they stream. For each new tenant encountered, its DEK is resolved via a single vault call (or served from a 15-minute in-memory cache).
3. Each tenant's rows are decrypted in parallel across a small worker pool (sized to available CPU cores, capped at 8).
4. Decrypted keys are wrapped as `BlsArtifactSigner`s and swapped into Web3Signer's signer registry atomically — the existing `/reload` endpoint and signer-provider machinery need no changes to support this.

### New Gradle module: `keys-postgres`

Sits between `keystorage` and `signing` in the dependency graph:

```
common → keystorage → keys-postgres → signing → slashing-protection → core → commandline → app
```

It depends only on `common` and `keystorage` (reusing existing Azure/AWS/HashiCorp SDK client-building code), plus HikariCP, the PostgreSQL JDBC driver, and Caffeine. It has no dependency on Teku/BLS types — it returns a generic `DecryptedBlsKey(keyIdentifier, rawSecretKeyBytes)` DTO. The one class that does need Teku types, `BlsPostgresBulkLoader`, lives in the `signing` module (which now depends on `keys-postgres`) and mirrors the existing `BlsAwsBulkLoader`.

Flyway migration SQL is packaged into the distribution but **never run automatically** — Web3Signer only checks a `database_version` table at startup and fails fast with a clear message if it doesn't match, exactly like the existing `slashing-protection` module's convention. Running migrations against a production database is an operator responsibility.

## 3. Schema

```sql
CREATE TABLE tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    vault_type VARCHAR(32) NOT NULL,        -- 'AZURE' | 'AWS_KMS' | 'HASHICORP'
    kek_key_id VARCHAR(1024) NOT NULL,      -- vault-specific KEK reference (key name/version, ARN, or Transit key name)
    encrypted_dek BYTEA NOT NULL,           -- DEK wrapped by the tenant's KEK; 12-byte IV || ciphertext || 16-byte GCM tag
    dek_version INTEGER NOT NULL DEFAULT 1, -- bumped by provisioning whenever the DEK is rotated
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

CREATE TABLE bls_signing_keys (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    key_identifier VARCHAR(256) NOT NULL,   -- BLS public key hex; also used as AAD
    encrypted_bls_key BYTEA NOT NULL,       -- 12-byte IV || ciphertext || 16-byte GCM tag
    dek_version INTEGER NOT NULL,           -- version of the tenant DEK this row was encrypted under
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key_identifier)
);
CREATE INDEX idx_bls_signing_keys_tenant_id ON bls_signing_keys (tenant_id);

CREATE TABLE database_version (id INTEGER PRIMARY KEY, version INTEGER NOT NULL);
INSERT INTO database_version (id, version) VALUES (1, 1);
```

Notable design choices:

1. **`encrypted_dek` lives once per tenant, not once per key row.** Storing it per-row would duplicate the same wrapped-DEK blob across every one of a tenant's (potentially 20,000) keys, and risks the per-row copy drifting out of sync with the tenant's canonical value during a rotation. A single canonical value per tenant matches the "one vault call per tenant" model exactly.
2. **`dek_version` exists on both tables.** Key rotation tooling is out of scope for this feature, but reserving the column now avoids a breaking schema change later, and — more immediately — lets the read side's DEK cache key on `(tenant, dek_version)` instead of just `tenant`, so a rotation is automatically treated as a cache miss rather than silently serving a stale DEK for up to 15 minutes.
3. **`vault_type` is a plain string**, not a Postgres enum type, so a future additional backend doesn't require an `ALTER TYPE` migration.

## 4. Cryptography

- **Algorithm**: AES-256-GCM, no padding. On-disk/on-wire layout for both `encrypted_dek` and `encrypted_bls_key`: **`IV (12 bytes, random) || ciphertext || GCM tag (16 bytes)`**.
- **IV/nonce**: a fresh random 12-byte IV per row. For `n` random 96-bit IVs sharing one key, birthday-bound collision probability is `≈ n²/2^97`; at `n = 20,000` that is `≈ 2.5×10⁻²¹` — around 30 orders of magnitude below any conventional audit threshold, and NIST SP 800-38D's own cap for safe random-IV reuse under one key is roughly 2³² invocations. No counter-based or derived-nonce scheme is required.
- **Additional Authenticated Data (AAD) is mandatory.** Every `encrypted_bls_key` ciphertext must be bound, via `Cipher.updateAAD(...)`, to the identity of its own row: `(tenant_id, key_identifier, dek_version)`. Every `encrypted_dek` ciphertext must be bound to `(tenant_id, dek_version)`. **This is the single most important contract in this document** — the read side always verifies AAD and fails closed (`AEADBadTagException`) if it doesn't match, which is what stops a ciphertext being silently decrypted under the wrong row's identity if it's ever copied or moved between rows in the database. If the provisioning side does not set matching AAD, every decrypt will fail.
- **Vault-backed KEKs only.** There is no environment-variable or local-passphrase KEK option — every tenant's DEK-unwrap is a genuine remote call to an auditable, access-controlled vault API (Azure Key Vault, AWS KMS, or HashiCorp Vault Transit). No raw KEK material is ever constructed or held by Web3Signer.
- **DEK caching**: resolved DEKs are cached in memory for 15 minutes, keyed by `(tenant, dek_version)`, and the underlying bytes are wiped (zeroed) once no in-flight decrypt operation is using them.
- **Memory hygiene**: decrypted BLS private key bytes are wiped (`Arrays.fill(..., 0)`) immediately after being consumed into the BLS key object.

### AAD encoding

Both the write side (provisioning) and the read side (Web3Signer) must construct byte-for-byte identical AAD. The encoding is **length-prefixed fields**, not delimited/concatenated strings, to avoid ambiguity (e.g. `tenant="A"`, `key="BC"` must never collide with `tenant="AB"`, `key="C"`):

```
AAD = LEN(field_1) || field_1_bytes || LEN(field_2) || field_2_bytes || ... || dek_version (4 bytes, big-endian)

Where each LEN(field) is a 4-byte big-endian unsigned integer giving the length of field_bytes,
and each field's *_bytes is its UTF-8 encoding (for tenant_id / key_identifier, which are text).
```

- **AAD for a `bls_signing_keys` row**: `LEN(tenant_id) || tenant_id (UTF-8) || LEN(key_identifier) || key_identifier (UTF-8) || dek_version (4-byte BE int)`
- **AAD for a `tenants.encrypted_dek` value**: `LEN(tenant_id) || tenant_id (UTF-8) || dek_version (4-byte BE int)`

`tenant_id` here is the tenant's `name` (a stable, human-assigned string), not the numeric surrogate `id` — this keeps the AAD independent of database-internal identifiers.

## 5. Provisioning-side contract (for whoever builds the write side)

Web3Signer never writes to these tables. Whatever process provisions tenants and keys must produce data conforming exactly to the schema and cryptographic contract above. This section is written to be usable regardless of what language that process is implemented in.

### 5.1 Per-vault-type notes for producing `encrypted_dek`

- **AWS KMS**: call `Encrypt` (or `GenerateDataKey` if generating a fresh DEK at the same time) against the tenant's KMS key, passing `EncryptionContext = {"tenant_id": <tenant name>}` if using KMS's own AAD-equivalent. Store the returned ciphertext blob directly in `encrypted_dek` — it is not the `IV||ciphertext||tag` format described above (that layout only applies to values *we* encrypt with our own AES-GCM code, i.e. the DEK-wrapping step done locally, not via a vault's own wrap API). If instead using a vault's raw `Encrypt` API as the "local AES-GCM" step is not applicable, the value stored is whatever the vault's decrypt call expects as input — for KMS that's the `Encrypt` API's ciphertext blob.
- **Azure Key Vault**: call `CryptographyClient.encrypt`/`wrapKey` against the tenant's Key Vault key. Store the returned ciphertext/wrapped-key bytes verbatim.
- **HashiCorp Vault Transit**: call `POST {vaultAddr}/v1/{mount}/encrypt/{tenantKeyName}` with the DEK as the plaintext body. Vault's response `data.ciphertext` is a text token of the form `vault:v1:<base64>` — store the **UTF-8 bytes of that string verbatim** in `encrypted_dek`, not a decoded/binary form.

`kek_key_id` on the `tenants` row must hold whatever reference the corresponding `KekResolver` needs to call the unwrap operation again later: an Azure key name/version, a full AWS KMS key ARN, or a HashiCorp Transit key name.

### 5.2 Example `INSERT` statements

The ciphertext/AAD computation must happen in application code before the `INSERT` — Postgres's `pgcrypto` extension does not support GCM mode, so this cannot be done in raw SQL.

```sql
INSERT INTO tenants (name, vault_type, kek_key_id, encrypted_dek, dek_version)
VALUES (:tenant_name, :vault_type, :kek_key_id, :wrapped_dek_bytes, :dek_version);

INSERT INTO bls_signing_keys (tenant_id, key_identifier, encrypted_bls_key, dek_version)
VALUES (:tenant_id, :bls_pubkey_hex, :iv_ciphertext_tag_bytes, :dek_version);
```

### 5.3 Worked encrypt examples

The AAD-building step is shown separately from the cipher call in each example below — building it inline is the most likely place for a subtle, hard-to-diagnose mismatch (field order, length-prefix encoding, or string encoding differences between languages).

**Java** (identical primitives to what Web3Signer's read side uses):

```java
static byte[] buildRowAad(String tenantId, String keyIdentifier, int dekVersion) {
  ByteArrayOutputStream out = new ByteArrayOutputStream();
  DataOutputStream dos = new DataOutputStream(out);
  byte[] tenantBytes = tenantId.getBytes(StandardCharsets.UTF_8);
  byte[] keyBytes = keyIdentifier.getBytes(StandardCharsets.UTF_8);
  dos.writeInt(tenantBytes.length); dos.write(tenantBytes);
  dos.writeInt(keyBytes.length);    dos.write(keyBytes);
  dos.writeInt(dekVersion);
  return out.toByteArray();
}

static byte[] encryptBlsKey(byte[] dek, byte[] plaintext, String tenantId, String keyIdentifier, int dekVersion)
    throws GeneralSecurityException {
  byte[] iv = new byte[12];
  SecureRandom.getInstanceStrong().nextBytes(iv);
  Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
  cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, iv));
  cipher.updateAAD(buildRowAad(tenantId, keyIdentifier, dekVersion));
  byte[] ciphertextAndTag = cipher.doFinal(plaintext); // GCM appends the 16-byte tag automatically
  ByteBuffer buf = ByteBuffer.allocate(iv.length + ciphertextAndTag.length);
  buf.put(iv).put(ciphertextAndTag);
  return buf.array();
}
```

**Python** (`cryptography` library — `AESGCM` concatenates ciphertext and tag for you; only the IV needs manual prepending):

```python
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def build_row_aad(tenant_id: str, key_identifier: str, dek_version: int) -> bytes:
    tenant_bytes = tenant_id.encode("utf-8")
    key_bytes = key_identifier.encode("utf-8")
    return (
        struct.pack(">I", len(tenant_bytes)) + tenant_bytes +
        struct.pack(">I", len(key_bytes)) + key_bytes +
        struct.pack(">I", dek_version)
    )

def encrypt_bls_key(dek: bytes, plaintext: bytes, tenant_id: str, key_identifier: str, dek_version: int) -> bytes:
    iv = os.urandom(12)
    aad = build_row_aad(tenant_id, key_identifier, dek_version)
    ciphertext_and_tag = AESGCM(dek).encrypt(iv, plaintext, aad)
    return iv + ciphertext_and_tag
```

**Node.js** (`crypto` module — GCM ciphertext and tag are returned separately and must be concatenated manually, in the same order as the other two languages):

```javascript
const crypto = require('crypto');

function buildRowAad(tenantId, keyIdentifier, dekVersion) {
  const tenantBytes = Buffer.from(tenantId, 'utf8');
  const keyBytes = Buffer.from(keyIdentifier, 'utf8');
  const tenantLen = Buffer.alloc(4); tenantLen.writeUInt32BE(tenantBytes.length);
  const keyLen = Buffer.alloc(4); keyLen.writeUInt32BE(keyBytes.length);
  const version = Buffer.alloc(4); version.writeUInt32BE(dekVersion);
  return Buffer.concat([tenantLen, tenantBytes, keyLen, keyBytes, version]);
}

function encryptBlsKey(dek, plaintext, tenantId, keyIdentifier, dekVersion) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', dek, iv);
  cipher.setAAD(buildRowAad(tenantId, keyIdentifier, dekVersion));
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]);
}
```

The same pattern (only the AAD fields change — `(tenant_id, dek_version)` instead of `(tenant_id, key_identifier, dek_version)`) applies to locally wrapping a DEK, if a vault's own wrap API is not used for that step.

### 5.4 Verifying provisioned data before relying on it

Web3Signer's own acceptance tests seed their fixtures using the exact same encrypt-side code the production decrypt path verifies against (a small `encrypt(...)` counterpart to the internal `AesGcmKeyCipher`/`AadCodec` classes) — this guarantees the tests validate the real contract rather than a self-consistent-but-wrong approximation of it. Anyone building a provisioning tool is encouraged to do the same: write one row using the pseudocode above, then confirm Web3Signer can load it (start it against a test database with `--postgres-keystore-enabled=true` and check `/api/v1/eth2/publicKeys`) before provisioning at scale.

### 5.5 Key rotation and lifecycle operations

None of this is implemented by Web3Signer — it's the provisioning side's responsibility end-to-end. It's documented here because the read side's behavior (what it caches, what it re-checks on reload, what it fails closed on) constrains how these operations must be sequenced to be safe.

**DEK rotation (generating brand-new DEK bytes for a tenant) is the expensive operation**, since every one of that tenant's `bls_signing_keys` rows is encrypted under the DEK and must be re-encrypted. Safe procedure, all inside a single database transaction:

1. Generate a new DEK (version `N+1`) and wrap it with the tenant's KEK.
2. Re-encrypt every one of the tenant's `bls_signing_keys` rows under the new DEK: new random IV per row, AAD rebuilt with `dek_version = N+1`, and update both `encrypted_bls_key` and `dek_version` in the same `UPDATE` statement per row — a row whose ciphertext was updated but whose `dek_version` column still says `N` (or vice versa) will fail every future decrypt with an AAD mismatch.
3. Only once every row is confirmed re-encrypted, update `tenants.encrypted_dek` and `tenants.dek_version` to `N+1` — this is the "publish" step. Do this in the same transaction as step 2, not a separate one.
4. Commit. PostgreSQL's per-statement snapshot under the default `READ COMMITTED` isolation means a concurrent `PostgresBulkKeyLoader.loadAll()` query sees either entirely the pre-rotation state or entirely the post-rotation state, never a mix — the read side needs no locking or awareness of an in-progress rotation as long as the rotation is one commit.
5. No action is needed on the read side to pick this up: the DEK cache is keyed on `(tenant, dek_version)`, so the version bump is automatically a cache miss on the next load/reload, triggering fresh KEK resolution. Trigger a `POST /reload` (or wait for the next scheduled one) to make the rotation take effect; there's no push-based invalidation.
6. Once the rotation is confirmed stable, the old DEK bytes and old wrapped-DEK ciphertext can be discarded — Web3Signer never retains a superseded version once its cache entry is evicted or replaced.

**KEK rotation (rotating the vault-side key itself) is comparatively cheap**, and — importantly — does **not** require touching `bls_signing_keys` or bumping `dek_version` at all, since the DEK's own bytes don't change, only what wraps them:

- **AWS KMS**: if using KMS's built-in automatic key rotation (new backing material under the same key ID/ARN), nothing needs to change in the `tenants` row at all — KMS transparently decrypts ciphertext wrapped under prior key material for the same key ID.
- **Azure Key Vault**: key rotation creates a new key *version*. Re-wrap the existing DEK bytes under the new version, then update `tenants.kek_key_id` (to the new `<key-name>/<key-version>`) and `tenants.encrypted_dek` together, in one transaction/statement.
- **HashiCorp Vault Transit**: similar to Azure — Transit key rotation creates a new key version; re-wrap (`transit/encrypt`) under the new version and update `tenants.encrypted_dek` (the `vault:vN:...` token's version prefix changes accordingly; `kek_key_id`, i.e. the Transit key *name*, is typically unchanged).
- In all cases, update the `tenants` row (new `kek_key_id`/`encrypted_dek`) *before* revoking the old KEK version's decrypt permission in the vault — otherwise a read still resolving against the stale row could fail transiently.
- Because `dek_version` doesn't change, a running Web3Signer instance won't notice a KEK rotation until its cached DEK entry naturally expires (15-minute TTL) and it re-resolves — at which point it reads the tenant row fresh, unwraps with the new KEK, and gets back the identical DEK bytes. This is intentionally transparent; trigger a manual `/reload` only if the cutover needs to happen sooner than the TTL.

**Adding a new key** to an existing tenant: encrypt it under that tenant's *current* DEK/`dek_version`, `INSERT` the row, and trigger a reload (or wait for the next scheduled one/restart). No vault call is needed for this specific key beyond what's already cached for the tenant.

**Removing a key**: `DELETE` the row from `bls_signing_keys` and trigger a reload — `DefaultArtifactSignerProvider.load()` rebuilds its signer map from scratch on every load rather than merging into the previous one, so a deleted row is guaranteed to disappear from the active signer set on the next reload, not just fail to be added. Two caveats worth knowing:
- This schema has no soft-delete column (e.g. an `enabled`/`revoked_at` flag) today — hard deletion is the only supported mechanism. A future migration could add one if an audit trail of revoked keys is wanted, with the loader's query adding a `WHERE` filter; not implemented as of this writing.
- Removal only takes effect on the next reload/restart, not immediately. If a key needs to stop signing sooner than that, note that the existing Key Manager API's dynamic key removal endpoint only applies to keys with a *mutable* origin (`BlsArtifactSigner.isReadOnlyKey()` returns `true` for every origin except `FILE_KEYSTORE`) — Postgres-loaded keys are read-only through that API, same as Azure/AWS/GCP-loaded keys today, so a reload (or restart) is the only way to revoke a Postgres-loaded key at runtime.

## 6. CLI

New option group on the existing `eth2` subcommand (alongside the existing Azure/AWS/GCP option groups — this is not a new subcommand):

- `--postgres-keystore-enabled`, `--postgres-keystore-db-url`, `--postgres-keystore-db-username`, `--postgres-keystore-db-password`, `--postgres-keystore-db-pool-configuration-file`, `--postgres-keystore-dek-cache-ttl-minutes` (default 15), `--postgres-keystore-decryption-parallelism` (hidden; default `min(8, available CPU cores)`), `--postgres-keystore-db-health-check-timeout-milliseconds`.
- Separate, dedicated credential option groups per KEK backend (`--postgres-keystore-azure-*`, `--postgres-keystore-aws-kms-*`, `--postgres-keystore-hashicorp-*`) — intentionally not shared with the existing Azure/AWS bulk-secret-scan credential options, since "unwrap N specific keys" and "list an entire vault" are different privilege scopes that may reasonably use different identities.

## 7. Operational notes

- **Thread count auto-scales to available cores** (capped at 8), not a hardcoded literal — on a 1-vCPU host or a CPU-limited container, running more CPU-bound decrypt threads than cores buys no parallelism and only adds context-switch overhead, competing with the rest of the application for that single core.
- **No new reload mechanism.** The existing `/reload` endpoint already re-runs the full signer-loading pipeline atomically; wiring this loader into that existing pipeline is sufficient to get correct reload behavior, including the "unaffected tenants incur zero additional vault calls within the 15-minute cache window" property.
- **Migrations are never run automatically.** Operators must apply `V00001__initial.sql` (and any future migrations) themselves before enabling `--postgres-keystore-enabled`; Web3Signer only verifies the applied version matches what it expects and refuses to start otherwise.
