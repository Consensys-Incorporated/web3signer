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
package tech.pegasys.web3signer.tests.keystorage;

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnection;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.web3signer.keystorage.hashicorp.TrustStoreType;
import tech.pegasys.web3signer.keystorage.hashicorp.config.ConnectionParameters;
import tech.pegasys.web3signer.keystorage.hashicorp.config.KeyDefinition;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;
import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.keystore.hashicorp.dsl.HashicorpNode;

import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.Collections;
import java.util.Optional;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class HashicorpVaultAccessAcceptanceTest {

  private static final Logger LOG = LogManager.getLogger();

  private HashicorpNode hashicorpNode;

  private final String SECRET_KEY = "storedSecetKey";
  private final String SECRET_VALUE = "secretValue";
  private final String KEY_SUBPATH = "acceptanceTestSecret";

  @AfterEach
  void cleanup() {
    try {
      if (hashicorpNode != null) {
        hashicorpNode.shutdown();
        hashicorpNode = null;
      }
    } catch (final Exception e) {
      LOG.error("Failed to shutdown Hashicorp Node.", e);
    }
  }

  @Test
  void keyCanBeExtractedFromVault() {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(false);
    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(hashicorpNode.getHost())
            .withServerPort(hashicorpNode.getPort())
            .withTimeoutMs(30_000L)
            .build();
    final KeyDefinition key =
        new KeyDefinition(
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            Optional.of(SECRET_KEY),
            hashicorpNode.getVaultToken());

    final String secretData = fetchSecretFromVault(connectionParameters, key);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void keyCanBeExtractedFromVaultOverTlsUsingWhitelist(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    final Path fingerprintFile =
        CertificateHelpers.createFingerprintFile(
            testDir,
            hashicorpNode.getServerCertificate().get(),
            Optional.of(hashicorpNode.getPort()));

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), fingerprintFile, null);
    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(hashicorpNode.getHost())
            .withServerPort(hashicorpNode.getPort())
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(30_000L)
            .build();
    final KeyDefinition key =
        new KeyDefinition(
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            Optional.of(SECRET_KEY),
            hashicorpNode.getVaultToken());

    final String secretData = fetchSecretFromVault(connectionParameters, key);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingPkcs12Certificate(@TempDir final Path testDir) {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path trustStorePath =
        CertificateHelpers.createPkcs12TrustStore(
            testDir, hashicorpNode.getServerCertificate().get(), TRUST_STORE_PASSWORD);

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.PKCS12), trustStorePath, TRUST_STORE_PASSWORD);
    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(hashicorpNode.getHost())
            .withServerPort(hashicorpNode.getPort())
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(30_000L)
            .build();
    final KeyDefinition key =
        new KeyDefinition(
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            Optional.of(SECRET_KEY),
            hashicorpNode.getVaultToken());

    final String secretData = fetchSecretFromVault(connectionParameters, key);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingJksCertificate(@TempDir final Path testDir) {
    final String TRUST_STORE_PASSWORD = "password";
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path trustStorePath =
        CertificateHelpers.createJksTrustStore(
            testDir, hashicorpNode.getServerCertificate().get(), TRUST_STORE_PASSWORD);

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.JKS), trustStorePath, TRUST_STORE_PASSWORD);
    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(hashicorpNode.getHost())
            .withServerPort(hashicorpNode.getPort())
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(30_000L)
            .build();
    final KeyDefinition key =
        new KeyDefinition(
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            Optional.of(SECRET_KEY),
            hashicorpNode.getVaultToken());

    final String secretData = fetchSecretFromVault(connectionParameters, key);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  @Test
  void canConnectToHashicorpVaultUsingPemCertificate(@TempDir final Path testDir)
      throws IOException, CertificateEncodingException {
    hashicorpNode = HashicorpNode.createAndStartHashicorp(true);

    hashicorpNode.addSecretsToVault(
        Collections.singletonMap(SECRET_KEY, SECRET_VALUE), KEY_SUBPATH);

    final Path trustStorePath = testDir.resolve("cert.crt");
    hashicorpNode.getServerCertificate().get().writeCertificateToFile(trustStorePath);

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.PEM), trustStorePath, null);
    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(hashicorpNode.getHost())
            .withServerPort(hashicorpNode.getPort())
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(30_000L)
            .build();
    final KeyDefinition key =
        new KeyDefinition(
            hashicorpNode.getHttpApiPathForSecret(KEY_SUBPATH),
            Optional.of(SECRET_KEY),
            hashicorpNode.getVaultToken());

    final String secretData = fetchSecretFromVault(connectionParameters, key);

    assertThat(secretData).isEqualTo(SECRET_VALUE);
  }

  private String fetchSecretFromVault(
      final ConnectionParameters connectionParameters, final KeyDefinition key) {
    try (HashicorpConnectionFactory factory = new HashicorpConnectionFactory()) {
      final HashicorpConnection connection = factory.create(connectionParameters);
      return connection.fetchKey(key);
    }
  }
}
