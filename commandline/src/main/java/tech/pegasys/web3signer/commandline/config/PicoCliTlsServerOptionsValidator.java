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

import java.io.File;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import picocli.CommandLine;

/**
 * This class provides similar validation for TLS options as PicoCli ArgGroups (which cannot be used
 * due to limitations of config file/environment value provider).
 */
public class PicoCliTlsServerOptionsValidator {
  private static final Logger LOG = LogManager.getLogger();
  private final CommandLine.Model.CommandSpec spec;
  private final PicoCliTlsServerOptions picoCliTlsServerOptions;

  public PicoCliTlsServerOptionsValidator(
      final CommandLine.Model.CommandSpec spec,
      final PicoCliTlsServerOptions picoCliTlsServerOptions) {
    this.spec = spec;
    this.picoCliTlsServerOptions = picoCliTlsServerOptions;
  }

  @SuppressWarnings("removal") // validates the deprecated known clients file and CA clients
  public void validate() throws CommandLine.ParameterException {
    final File keyStoreFile = picoCliTlsServerOptions.getKeyStoreFile();
    final File keyStorePasswordFile = picoCliTlsServerOptions.getKeyStorePasswordFile();

    // no need to further validate if keystore file/password are not specified
    if (keyStoreFile == null && keyStorePasswordFile == null) {
      return;
    }

    // if tls keystore is specified, the password file must be specified.
    if (onlyOneInitialized(keyStoreFile, keyStorePasswordFile)) {
      throw new CommandLine.ParameterException(
          spec.commandLine(),
          "--tls-keystore-file must be specified together with --tls-keystore-password-file");
    }

    final PicoCliClientAuthConstraints clientAuthConstraints =
        picoCliTlsServerOptions.clientAuthConstraints;
    final boolean trustStoreSpecified = clientAuthConstraints.getTrustStoreOptions().isPresent();
    final boolean knownClientsFileSpecified =
        clientAuthConstraints.getKnownClientsFile().isPresent();
    final boolean caClientsAllowed = clientAuthConstraints.isCaAuthorizedClientAllowed();

    if (!trustStoreSpecified && clientAuthConstraints.getTrustStorePasswordFile() != null) {
      throw new CommandLine.ParameterException(
          spec.commandLine(), "--tls-truststore-password-file requires --tls-truststore-file");
    }

    if (trustStoreSpecified && knownClientsFileSpecified) {
      throw new CommandLine.ParameterException(
          spec.commandLine(),
          "--tls-truststore-file cannot be specified together with the deprecated --tls-known-clients-file");
    }

    if (trustStoreSpecified && caClientsAllowed) {
      throw new CommandLine.ParameterException(
          spec.commandLine(),
          "--tls-truststore-file cannot be specified when --tls-allow-ca-clients is set to true; add the CA certificates to the truststore instead");
    }

    if (picoCliTlsServerOptions.tlsAllowAnyClient
        && (trustStoreSpecified || knownClientsFileSpecified || caClientsAllowed)) {
      throw new CommandLine.ParameterException(
          spec.commandLine(),
          "--tls-allow-any-client cannot be set to true when --tls-truststore-file or --tls-known-clients-file is specified or --tls-allow-ca-clients is set to true");
    }

    if (!picoCliTlsServerOptions.tlsAllowAnyClient
        && !trustStoreSpecified
        && !knownClientsFileSpecified
        && !caClientsAllowed) {
      throw new CommandLine.ParameterException(
          spec.commandLine(),
          "--tls-truststore-file must be specified if both --tls-allow-any-client and --tls-allow-ca-clients are set to false");
    }

    if (knownClientsFileSpecified) {
      LOG.warn(
          "--tls-known-clients-file is deprecated and will be removed in a future release. "
              + "Use --tls-truststore-file and --tls-truststore-password-file instead.");
    }
    if (caClientsAllowed) {
      LOG.warn(
          "--tls-allow-ca-clients is deprecated and will be removed in a future release. "
              + "Add the client CA certificates to --tls-truststore-file instead.");
    }
  }

  private static boolean onlyOneInitialized(final Object o1, final Object o2) {
    return (o1 == null) != (o2 == null);
  }
}
