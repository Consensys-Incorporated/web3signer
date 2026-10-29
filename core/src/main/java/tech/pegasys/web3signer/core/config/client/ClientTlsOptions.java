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
package tech.pegasys.web3signer.core.config.client;

import tech.pegasys.web3signer.core.config.KeyStoreOptions;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;

import java.nio.file.Path;
import java.util.Optional;

public interface ClientTlsOptions {
  Optional<KeyStoreOptions> getKeyStoreOptions();

  /**
   * Fingerprint allowlist of trusted servers.
   *
   * @deprecated use {@link #getTrustStoreOptions()}
   */
  @Deprecated(forRemoval = true)
  Optional<Path> getKnownServersFile();

  /**
   * Truststore holding the certificates (or issuing CAs) of trusted servers. Replaces the JVM's
   * default CAs.
   */
  Optional<TrustStoreOptions> getTrustStoreOptions();

  /**
   * Whether the JVM's default CAs are trusted. Only applies without a truststore.
   *
   * @deprecated only used with {@link #getKnownServersFile()}; without a truststore the JVM's
   *     default CAs are used
   */
  @Deprecated(forRemoval = true)
  boolean isCaAuthEnabled();
}
