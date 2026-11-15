/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.keystorage.hashicorp.config;

import tech.pegasys.web3signer.keystorage.hashicorp.TrustStoreType;

import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;

/** Value equality so connections with identical trust settings can share an HttpClient. */
public class TlsOptions {

  private final Optional<TrustStoreType> trustStoreType;
  private final Path trustStorePath;
  private final String trustStorePassword;

  public TlsOptions(
      final Optional<TrustStoreType> trustStoreType,
      final Path trustStorePath,
      final String trustStorePassword) {
    this.trustStoreType = trustStoreType;
    this.trustStorePath = trustStorePath;
    this.trustStorePassword = trustStorePassword;
  }

  public Optional<TrustStoreType> getTrustStoreType() {
    return trustStoreType;
  }

  public Path getTrustStorePath() {
    return trustStorePath;
  }

  public String getTrustStorePassword() {
    return trustStorePassword;
  }

  // a class rather than a record: a record's toString() would print the password
  @Override
  public boolean equals(final Object o) {
    if (this == o) {
      return true;
    }
    if (!(o instanceof TlsOptions that)) {
      return false;
    }
    return trustStoreType.equals(that.trustStoreType)
        && Objects.equals(trustStorePath, that.trustStorePath)
        && Objects.equals(trustStorePassword, that.trustStorePassword);
  }

  @Override
  public int hashCode() {
    return Objects.hash(trustStoreType, trustStorePath, trustStorePassword);
  }
}
