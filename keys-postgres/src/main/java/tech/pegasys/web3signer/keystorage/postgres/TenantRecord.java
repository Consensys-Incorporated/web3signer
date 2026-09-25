/*
 * Copyright 2026 Consensys Software Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.web3signer.keystorage.postgres;

import org.apache.tuweni.bytes.Bytes;

/**
 * A tenant row from the {@code tenants} table, as needed to resolve its DEK.
 *
 * @param id the tenant's surrogate id (used for joining to {@code bls_signing_keys})
 * @param name the tenant's stable name - used (not {@code id}) as the AAD tenant identifier, and as
 *     the {@code KekResolver} cache key
 * @param vaultType one of "AZURE", "AWS_KMS", "HASHICORP" - selects which {@code KekResolver} to
 *     use
 * @param kekKeyId the vault-specific KEK reference (key name/version, ARN, or Transit key name)
 * @param encryptedDek the tenant's DEK, wrapped by its KEK
 * @param dekVersion the version of the DEK - bumped by provisioning on rotation
 */
public record TenantRecord(
    int id, String name, String vaultType, String kekKeyId, Bytes encryptedDek, int dekVersion) {}
