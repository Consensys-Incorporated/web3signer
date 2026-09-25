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
package tech.pegasys.web3signer.keystorage.postgres.kek;

import tech.pegasys.web3signer.keystorage.postgres.TenantRecord;

/**
 * Resolves a tenant's DEK by unwrapping it via that tenant's Key Encrypting Key (KEK), which lives
 * in a vault and never leaves it. Each implementation performs exactly one remote vault operation
 * per call - callers are expected to cache the result (see {@code TenantDekCache}) so that a full
 * reload makes exactly one vault call per distinct tenant, not per key.
 */
public interface KekResolver {

  /** The {@code tenants.vault_type} value this resolver handles, e.g. "AWS_KMS". */
  String vaultType();

  /**
   * Unwraps the given tenant's DEK.
   *
   * @param tenant the tenant whose DEK is being resolved
   * @return the tenant's plaintext DEK bytes
   * @throws KekResolutionException if the vault call fails or the tenant's KEK reference is invalid
   */
  byte[] unwrapDek(TenantRecord tenant) throws KekResolutionException;
}
