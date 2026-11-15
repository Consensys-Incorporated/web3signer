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
package tech.pegasys.web3signer.commandline.config.client;

import static tech.pegasys.web3signer.commandline.DefaultCommandValues.BOOL_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.FILE_FORMAT_HELP;

import tech.pegasys.web3signer.core.config.KeyStoreOptions;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;
import tech.pegasys.web3signer.core.config.client.ClientTlsOptions;

import java.nio.file.Path;
import java.util.Optional;

import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;

public class PicoCliClientTlsOptions implements ClientTlsOptions {
  @SuppressWarnings("UnusedVariable")
  @Option(
      names = "--downstream-http-tls-enabled",
      description = "Flag to enable TLS connection to web3 provider. Defaults to disabled.",
      paramLabel = BOOL_FORMAT_HELP,
      arity = "0..1")
  private boolean tlsEnabled = false;

  @Mixin private PicoCliKeyStoreOptions keyStoreOptions;

  @Option(
      names = "--downstream-http-tls-known-servers-file",
      description =
          "Deprecated, use --downstream-http-tls-truststore-file. File of trusted web3 provider "
              + "hostnames, ports and certificate fingerprints.",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path knownServersFile;

  @Option(
      names = "--downstream-http-tls-truststore-file",
      description =
          "Truststore of trusted web3 provider certificates or their CAs (PKCS#12, JKS or PEM). "
              + "Replaces the JVM's default CAs.",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path trustStoreFile;

  @Option(
      names = "--downstream-http-tls-truststore-password-file",
      description = "File containing the truststore password (not needed for PEM).",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path trustStorePasswordFile;

  @Option(
      names = "--downstream-http-tls-ca-auth-enabled",
      description =
          "Deprecated, only applies to --downstream-http-tls-known-servers-file. If set, also "
              + "trusts the JVM's default CAs. Defaults to enabled.",
      arity = "1")
  private Boolean caAuthEnabled = null;

  @Override
  public Optional<KeyStoreOptions> getKeyStoreOptions() {
    if (keyStoreOptions.getKeyStoreFile() == null && keyStoreOptions.getPasswordFile() == null) {
      return Optional.empty();
    }
    return Optional.of(keyStoreOptions);
  }

  @SuppressWarnings("removal") // overrides the deprecated interface method
  @Deprecated(forRemoval = true)
  @Override
  public boolean isCaAuthEnabled() {
    return caAuthEnabled == null || caAuthEnabled;
  }

  @Deprecated(forRemoval = true)
  public boolean isCaAuthEnabledSpecified() {
    return caAuthEnabled != null;
  }

  @SuppressWarnings("removal") // overrides the deprecated interface method
  @Deprecated(forRemoval = true)
  @Override
  public Optional<Path> getKnownServersFile() {
    return Optional.ofNullable(knownServersFile);
  }

  @Override
  public Optional<TrustStoreOptions> getTrustStoreOptions() {
    if (trustStoreFile == null) {
      return Optional.empty();
    }
    return Optional.of(
        new TrustStoreOptions(trustStoreFile, Optional.ofNullable(trustStorePasswordFile)));
  }

  public Path getTrustStorePasswordFile() {
    return trustStorePasswordFile;
  }

  public boolean isTlsEnabled() {
    return tlsEnabled;
  }
}
