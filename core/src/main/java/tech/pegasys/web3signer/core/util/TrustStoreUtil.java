/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.core.util;

import tech.pegasys.web3signer.core.InitializationException;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;
import tech.pegasys.web3signer.keystorage.common.TrustStoreLoader;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.util.Optional;

import io.vertx.core.net.TrustOptions;

public final class TrustStoreUtil {

  private TrustStoreUtil() {}

  /**
   * Creates Vert.x trust options trusting only the certificates in the given truststore, like the
   * standard {@code javax.net.ssl.trustStore} it replaces the JVM's default CAs. The truststore
   * format (PEM, PKCS#12 or JKS) is detected from the file content.
   *
   * @param trustStoreOptions the truststore and its optional password file
   * @return trust options to validate peer certificates with
   * @throws InitializationException if the truststore cannot be loaded or contains no trusted
   *     certificates
   */
  public static TrustOptions createTrustOptions(final TrustStoreOptions trustStoreOptions) {
    try {
      final Optional<String> password = readPassword(trustStoreOptions.passwordFile());
      return TrustOptions.wrap(
          TrustStoreLoader.createTrustManagerFactory(trustStoreOptions.trustStoreFile(), password));
    } catch (final NoSuchFileException e) {
      throw new InitializationException(
          "TLS truststore or truststore password file not found: " + e.getFile(), e);
    } catch (final IOException | GeneralSecurityException e) {
      throw new InitializationException(
          "Failed to load TLS truststore "
              + trustStoreOptions.trustStoreFile()
              + ": "
              + e.getMessage(),
          e);
    }
  }

  private static Optional<String> readPassword(final Optional<Path> passwordFile)
      throws IOException {
    if (passwordFile.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(FileUtil.readFirstLineFromFile(passwordFile.get()));
  }
}
