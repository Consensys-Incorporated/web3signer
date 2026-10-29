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
package tech.pegasys.web3signer.keystorage.hashicorp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.spy;

import tech.pegasys.web3signer.keystorage.hashicorp.config.ConnectionParameters;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import com.google.common.io.Resources;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

public class HashicorpConnectionFactoryTest {

  final String CONFIGURED_HOST = "Host";

  @Test
  @SuppressWarnings("removal") // deprecated WHITELIST truststore type
  void invalidWhiteListFileCausesConnectionToThrowHashicorpException() throws IOException {
    final File invalidWhitelist = File.createTempFile("invalid", ".whitelist");
    Files.writeString(invalidWhitelist.toPath(), "Invalid Whitelist content");

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), invalidWhitelist.toPath(), null);
    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(10L)
            .build();

    try (final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory()) {
      assertThatThrownBy(() -> connectionFactory.create(params))
          .isInstanceOf(HashicorpException.class);
    }
  }

  @Test
  @SuppressWarnings("removal") // deprecated WHITELIST truststore type
  void missingAndUncreatableWhiteListThrowsHashicorpException() {
    final Path invalidFile = Path.of("/missingUnCreatable.whitelist");

    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.WHITELIST), invalidFile, null);
    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(10L)
            .build();
    try (final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory()) {
      assertThatThrownBy(() -> connectionFactory.create(params))
          .isInstanceOf(HashicorpException.class)
          .hasMessage("Unable to initialise connection to hashicorp vault.");
    }
  }

  @Test
  void httpClientIsInitialisedWithTlsIfTlsIsInConfiguration() {
    final URL sslCertificate = Resources.getResource("tls/cert1.pfx");
    final Path keystorePath = Path.of(sslCertificate.getPath());

    final TlsOptions tlsOptions =
        spy(new TlsOptions(Optional.of(TrustStoreType.PKCS12), keystorePath, "password"));
    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(10L)
            .build();

    try (final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory()) {
      connectionFactory.create(params);
    }

    // methods will be called first during validation, second when truststore to be initialized.
    Mockito.verify(tlsOptions, Mockito.times(2)).getTrustStorePath();
    Mockito.verify(tlsOptions, Mockito.times(2)).getTrustStorePassword();
  }

  @Test
  void defaultPortIsUsedByConnectionParametersIfNonConfigured() {
    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTimeoutMs(10L)
            .build();

    assertThat(params.getVaultURI().getPort()).isEqualTo(8200);
  }

  @ParameterizedTest
  @ValueSource(strings = {"JKS", "PKCS12", "PEM", "WHITELIST"})
  void allCustomTlsTrustOptionsRequireANonNullPathElseThrowsHashicorpException(String trustType) {
    final TlsOptions tlsOptions =
        new TlsOptions(Optional.of(TrustStoreType.fromString(trustType).get()), null, null);

    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(10L)
            .build();
    try (final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory()) {
      assertThatThrownBy(() -> connectionFactory.create(params))
          .isInstanceOf(HashicorpException.class);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"JKS", "PKCS12"})
  void missingPasswordForTrustStoreThrowsHashicorpException(String trustType) throws IOException {
    final File tempFile = File.createTempFile("trustStore", ".tmp");
    tempFile.deleteOnExit();
    final TlsOptions tlsOptions =
        new TlsOptions(
            Optional.of(TrustStoreType.fromString(trustType).get()), tempFile.toPath(), null);

    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTlsOptions(tlsOptions)
            .withTimeoutMs(10L)
            .build();
    try (final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory()) {
      assertThatThrownBy(() -> connectionFactory.create(params))
          .isInstanceOf(HashicorpException.class);
    }
  }

  @Test
  void createAfterCloseRaiseException() {
    final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory();
    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTimeoutMs(10L)
            .build();
    connectionFactory.create(params);
    connectionFactory.close();
    assertThatThrownBy(() -> connectionFactory.create(params))
        .isInstanceOf(HashicorpException.class)
        .hasMessage("HashicorpConnectionFactory is closed");
  }

  @Test
  void repeatedCloseWithoutException() {
    final HashicorpConnectionFactory connectionFactory = new HashicorpConnectionFactory();
    final ConnectionParameters params =
        ConnectionParameters.newBuilder()
            .withServerHost(CONFIGURED_HOST)
            .withTimeoutMs(10L)
            .build();
    connectionFactory.create(params);
    connectionFactory.close();
    connectionFactory.close();
  }
}
