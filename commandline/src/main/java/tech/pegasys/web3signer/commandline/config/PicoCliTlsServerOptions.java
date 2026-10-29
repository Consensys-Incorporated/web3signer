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
import tech.pegasys.web3signer.core.config.TlsOptions;

import java.io.File;
import java.util.Optional;

import picocli.CommandLine;
import picocli.CommandLine.Option;

public class PicoCliTlsServerOptions implements TlsOptions {

  @Option(
      names = "--tls-keystore-file",
      description =
          "Path to a PKCS#12 formatted keystore; used to enable TLS on inbound connections.",
      arity = "1",
      paramLabel = FILE_FORMAT_HELP)
  private File keyStoreFile = null;

  @Option(
      names = "--tls-keystore-password-file",
      description = "Path to a file containing the password used to decrypt the keystore.",
      arity = "1",
      paramLabel = FILE_FORMAT_HELP)
  private File keyStorePasswordFile = null;

  @Option(
      names = "--tls-allow-any-client",
      description =
          "If set to true, disables TLS client authentication; client certificates are not "
              + "requested. Cannot be used with --tls-truststore-file, --tls-known-clients-file or "
              + "--tls-allow-ca-clients. (Default: false)",
      paramLabel = BOOL_FORMAT_HELP,
      arity = "1")
  Boolean tlsAllowAnyClient = false; // package level access for validator

  @CommandLine.Mixin
  PicoCliClientAuthConstraints clientAuthConstraints; // package level access for validator

  @Override
  public File getKeyStoreFile() {
    return keyStoreFile;
  }

  @Override
  public File getKeyStorePasswordFile() {
    return keyStorePasswordFile;
  }

  @Override
  public Optional<ClientAuthConstraints> getClientAuthConstraints() {
    // assuming custom validation method has been called.
    return tlsAllowAnyClient ? Optional.empty() : Optional.of(clientAuthConstraints);
  }
}
