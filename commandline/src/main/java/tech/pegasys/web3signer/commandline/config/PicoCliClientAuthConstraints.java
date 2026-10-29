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
package tech.pegasys.web3signer.commandline.config;

import static tech.pegasys.web3signer.commandline.DefaultCommandValues.BOOL_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.FILE_FORMAT_HELP;

import tech.pegasys.web3signer.core.config.ClientAuthConstraints;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;

import java.io.File;
import java.nio.file.Path;
import java.util.Optional;

import picocli.CommandLine.Option;

public class PicoCliClientAuthConstraints implements ClientAuthConstraints {

  @Option(
      names = "--tls-known-clients-file",
      description =
          "Deprecated, use --tls-truststore-file. File of authorized client certificate fingerprints.",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private File tlsKnownClientsFile = null;

  @Option(
      names = "--tls-truststore-file",
      description =
          "Truststore of authorized client certificates or their CAs (PKCS#12, JKS or PEM).",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path tlsTrustStoreFile = null;

  @Option(
      names = "--tls-truststore-password-file",
      description = "File containing the truststore password (not needed for PEM).",
      paramLabel = FILE_FORMAT_HELP,
      arity = "1")
  private Path tlsTrustStorePasswordFile = null;

  @Option(
      names = "--tls-allow-ca-clients",
      description =
          "Deprecated, use --tls-truststore-file. If set to true, allows clients signed by the "
              + "JVM's default CAs. (Default: false)",
      paramLabel = BOOL_FORMAT_HELP,
      arity = "1")
  private Boolean tlsAllowCaClients = false;

  @SuppressWarnings("removal") // overrides the deprecated interface method
  @Deprecated(forRemoval = true)
  @Override
  public Optional<File> getKnownClientsFile() {
    return Optional.ofNullable(tlsKnownClientsFile);
  }

  @Override
  public Optional<TrustStoreOptions> getTrustStoreOptions() {
    if (tlsTrustStoreFile == null) {
      return Optional.empty();
    }
    return Optional.of(
        new TrustStoreOptions(tlsTrustStoreFile, Optional.ofNullable(tlsTrustStorePasswordFile)));
  }

  Path getTrustStorePasswordFile() {
    return tlsTrustStorePasswordFile;
  }

  @SuppressWarnings("removal") // overrides the deprecated interface method
  @Deprecated(forRemoval = true)
  @Override
  public boolean isCaAuthorizedClientAllowed() {
    return tlsAllowCaClients;
  }
}
