/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.dsl.tls.support;

import tech.pegasys.web3signer.core.config.ClientAuthConstraints;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;

import java.io.File;
import java.util.Optional;

public class BasicClientAuthConstraints implements ClientAuthConstraints {

  private final Optional<File> knownClientsFile;
  private final Optional<TrustStoreOptions> trustStoreOptions;
  private final boolean allowCaClients;

  public BasicClientAuthConstraints(final Optional<File> knownClientsFile) {
    this(knownClientsFile, false);
  }

  public BasicClientAuthConstraints(
      final Optional<File> knownClientsFile, final boolean allowCaClients) {
    this(knownClientsFile, Optional.empty(), allowCaClients);
  }

  private BasicClientAuthConstraints(
      final Optional<File> knownClientsFile,
      final Optional<TrustStoreOptions> trustStoreOptions,
      final boolean allowCaClients) {
    this.knownClientsFile = knownClientsFile;
    this.trustStoreOptions = trustStoreOptions;
    this.allowCaClients = allowCaClients;
  }

  public static BasicClientAuthConstraints fromFile(final File knownClientsFile) {
    return new BasicClientAuthConstraints(Optional.ofNullable(knownClientsFile));
  }

  public static BasicClientAuthConstraints fromTrustStore(
      final TrustStoreOptions trustStoreOptions) {
    return new BasicClientAuthConstraints(Optional.empty(), Optional.of(trustStoreOptions), false);
  }

  public static BasicClientAuthConstraints caOnly() {
    return new BasicClientAuthConstraints(Optional.empty(), true);
  }

  @SuppressWarnings("removal") // overrides the deprecated interface method
  @Deprecated(forRemoval = true)
  @Override
  public Optional<File> getKnownClientsFile() {
    return knownClientsFile;
  }

  @Override
  public Optional<TrustStoreOptions> getTrustStoreOptions() {
    return trustStoreOptions;
  }

  @SuppressWarnings("removal") // overrides the deprecated interface method
  @Deprecated(forRemoval = true)
  @Override
  public boolean isCaAuthorizedClientAllowed() {
    return allowCaClients;
  }
}
