CREATE TABLE tenants (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    vault_type VARCHAR(32) NOT NULL,
    kek_key_id VARCHAR(1024) NOT NULL,
    encrypted_dek BYTEA NOT NULL,
    dek_version INTEGER NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (name)
);

CREATE TABLE bls_signing_keys (
    id BIGSERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL REFERENCES tenants(id),
    key_identifier VARCHAR(256) NOT NULL,
    encrypted_bls_key BYTEA NOT NULL,
    dek_version INTEGER NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key_identifier)
);

CREATE INDEX idx_bls_signing_keys_tenant_id ON bls_signing_keys (tenant_id);

CREATE TABLE database_version (
    id INTEGER PRIMARY KEY,
    version INTEGER NOT NULL
);
INSERT INTO database_version (id, version) VALUES (1, 1);
