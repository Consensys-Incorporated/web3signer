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
package tech.pegasys.web3signer.signing.config.metadata;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.keystorage.common.TrustStoreLoader;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnection;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpException;
import tech.pegasys.web3signer.keystorage.hashicorp.TrustStoreType;
import tech.pegasys.web3signer.keystorage.hashicorp.VaultAuthMethod;
import tech.pegasys.web3signer.keystorage.hashicorp.config.ConnectionParameters;
import tech.pegasys.web3signer.keystorage.hashicorp.config.KeyDefinition;
import tech.pegasys.web3signer.keystorage.hashicorp.config.KubernetesAuthOptions;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.common.io.Files;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public abstract class AbstractArtifactSignerFactory implements ArtifactSignerFactory {
  private static final Logger LOG = LogManager.getLogger();
  private static final AtomicBoolean KNOWN_SERVERS_DEPRECATION_LOGGED = new AtomicBoolean();

  final HashicorpConnectionFactory hashicorpConnectionFactory;
  final Path configsDirectory;
  private final AzureKeyVaultFactory azureKeyVaultFactory;

  protected AbstractArtifactSignerFactory(
      final HashicorpConnectionFactory hashicorpConnectionFactory,
      final Path configsDirectory,
      final AzureKeyVaultFactory azureKeyVaultFactory) {
    this.hashicorpConnectionFactory = hashicorpConnectionFactory;
    this.configsDirectory = configsDirectory;
    this.azureKeyVaultFactory = azureKeyVaultFactory;
  }

  protected Bytes extractBytesFromVault(final AzureSecretSigningMetadata metadata) {
    final AzureKeyVault azureVault = azureKeyVaultFactory.createAzureKeyVault(metadata);

    return azureVault
        .fetchSecret(metadata.getSecretName())
        .map(Bytes::fromHexString)
        .orElseThrow(
            () ->
                new SigningMetadataException(
                    "secret '" + metadata.getSecretName() + "' doesn't exist"));
  }

  protected Bytes extractBytesFromVault(final HashicorpSigningMetadata metadata) {
    final Optional<TlsOptions> tlsOptions = buildTlsOptions(metadata);

    try {
      final ConnectionParameters connectionParameters =
          ConnectionParameters.newBuilder()
              .withServerHost(metadata.getServerHost())
              .withServerPort(metadata.getServerPort())
              .withTlsOptions(tlsOptions.orElse(null))
              .withTimeoutMs(metadata.getTimeout())
              .withHttpProtocolVersion(metadata.getHttpProtocolVersion())
              .build();
      final HashicorpConnection connection =
          hashicorpConnectionFactory.create(connectionParameters);

      final String token;
      if (metadata.getAuthMethod() == VaultAuthMethod.KUBERNETES) {
        if (metadata.getKubernetesRole() == null || metadata.getKubernetesRole().isBlank()) {
          throw new SigningMetadataException(
              "kubernetesRole must be provided when using KUBERNETES auth method");
        }
        final Path resolvedTokenPath =
            metadata.getKubernetesServiceAccountTokenPath() != null
                ? makeRelativePathAbsolute(metadata.getKubernetesServiceAccountTokenPath())
                : null;
        final KubernetesAuthOptions kubernetesAuthOptions =
            new KubernetesAuthOptions(
                metadata.getKubernetesRole(), resolvedTokenPath, metadata.getKubernetesAuthPath());
        token = connection.authenticateWithKubernetes(kubernetesAuthOptions);
      } else {
        if (metadata.getToken() == null || metadata.getToken().isBlank()) {
          throw new SigningMetadataException("token must be provided when using TOKEN auth method");
        }
        token = metadata.getToken();
      }

      final String secret =
          connection.fetchKey(
              new KeyDefinition(
                  metadata.getKeyPath(), Optional.ofNullable(metadata.getKeyName()), token));
      return Bytes.fromHexString(secret);
    } catch (final SigningMetadataException e) {
      throw e;
    } catch (final HashicorpException e) {
      throw new SigningMetadataException(e.getMessage(), e);
    } catch (final Exception e) {
      throw new SigningMetadataException("Failed to fetch secret from hashicorp vault", e);
    }
  }

  @SuppressWarnings("removal") // deprecated tlsKnownServersPath
  private Optional<TlsOptions> buildTlsOptions(final HashicorpSigningMetadata metadata) {
    if (!metadata.getTlsEnabled()) {
      return Optional.empty();
    }

    final Path trustStoreFile = metadata.getTlsTruststoreFile();
    final Path trustStorePasswordFile = metadata.getTlsTruststorePasswordFile();
    final Path knownServerFile = metadata.getTlsKnownServerFile();

    if (trustStoreFile == null && trustStorePasswordFile != null) {
      throw new SigningMetadataException("tlsTruststorePasswordFile requires tlsTruststoreFile");
    }

    if (trustStoreFile != null) {
      if (knownServerFile != null) {
        throw new SigningMetadataException(
            "tlsTruststoreFile cannot be specified together with the deprecated tlsKnownServersPath");
      }
      return Optional.of(buildTrustStoreTlsOptions(trustStoreFile, trustStorePasswordFile));
    }

    if (knownServerFile == null) {
      return Optional.of(new TlsOptions(Optional.empty(), null, null)); // use CA Auth
    }

    if (KNOWN_SERVERS_DEPRECATION_LOGGED.compareAndSet(false, true)) {
      LOG.warn(
          "Hashicorp signing metadata 'tlsKnownServersPath' is deprecated and will be removed in a "
              + "future release. Use 'tlsTruststoreFile' and 'tlsTruststorePasswordFile' instead.");
    }
    final Path configRelativeKnownServerPath = makeRelativePathAbsolute(knownServerFile);
    if (!configRelativeKnownServerPath.toFile().exists()) {
      throw new SigningMetadataException(
          String.format("Known servers file (%s) does not exist.", configRelativeKnownServerPath));
    }
    return Optional.of(
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), knownServerFile, null));
  }

  private TlsOptions buildTrustStoreTlsOptions(
      final Path trustStoreFile, final Path trustStorePasswordFile) {
    final Path trustStorePath = makeRelativePathAbsolute(trustStoreFile);
    final boolean pem;
    try {
      pem = TrustStoreLoader.isPem(trustStorePath);
    } catch (final IOException e) {
      throw new SigningMetadataException("Unable to read truststore file: " + trustStorePath, e);
    }

    if (pem) {
      return new TlsOptions(Optional.of(TrustStoreType.PEM), trustStorePath, null);
    }
    if (trustStorePasswordFile == null) {
      throw new SigningMetadataException(
          "tlsTruststorePasswordFile must be specified for a PKCS#12 or JKS truststore");
    }
    // PKCS12 marks a password-protected keystore; TrustStoreLoader detects PKCS#12 or JKS
    return new TlsOptions(
        Optional.of(TrustStoreType.PKCS12),
        trustStorePath,
        loadPassword(makeRelativePathAbsolute(trustStorePasswordFile)));
  }

  protected String loadPassword(final Path passwordFile) {
    try {
      final String password = Files.asCharSource(passwordFile.toFile(), UTF_8).readFirstLine();
      if (password == null || password.isBlank()) {
        throw new SigningMetadataException("Keystore password cannot be empty: " + passwordFile);
      }
      return password;
    } catch (final FileNotFoundException e) {
      throw new SigningMetadataException("Keystore password file not found: " + passwordFile, e);
    } catch (final IOException e) {
      final String errorMessage =
          format(
              "Unexpected IO error while reading keystore password file [%s]: %s",
              passwordFile, e.getMessage());
      throw new SigningMetadataException(errorMessage, e);
    }
  }

  protected Path makeRelativePathAbsolute(final Path path) {
    return path.isAbsolute() ? path : configsDirectory.resolve(path);
  }

  public abstract KeyType getKeyType();
}
