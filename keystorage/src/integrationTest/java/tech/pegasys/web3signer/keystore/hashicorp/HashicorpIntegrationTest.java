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
package tech.pegasys.web3signer.keystore.hashicorp;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockserver.model.HttpRequest.request;
import static org.mockserver.model.HttpResponse.response;

import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnection;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpException;
import tech.pegasys.web3signer.keystorage.hashicorp.TrustStoreType;
import tech.pegasys.web3signer.keystorage.hashicorp.config.ConnectionParameters;
import tech.pegasys.web3signer.keystorage.hashicorp.config.KeyDefinition;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HttpsURLConnection;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockserver.configuration.Configuration;
import org.mockserver.integration.ClientAndServer;
import org.mockserver.logging.MockServerLogger;
import org.mockserver.socket.tls.KeyStoreFactory;

class HashicorpIntegrationTest {

  private static final String DEFAULT_HOST = "localhost";
  private static final String KEY_PATH = "/v1/secret/data/DBEncryptionKey";
  private static final String ROOT_TOKEN = "token";
  private static final String EXPECTED_KEY_STRING =
      "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";

  private HashicorpConnectionFactory factory;

  @BeforeEach
  void setup() {
    factory = new HashicorpConnectionFactory();
  }

  @AfterEach
  void cleanup() {
    if (factory != null) {
      factory.close();
    }
  }

  @Test
  void hashicorpVaultReturnsEncryptionKey() {
    final ClientAndServer clientAndServer = new ClientAndServer(0);
    clientAndServer
        .when(request().withPath(".*"))
        .respond(
            response()
                .withStatusCode(200)
                .withBody("{\"data\":{\"data\":{\"value\":\"" + EXPECTED_KEY_STRING + "\"}}}"));

    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(DEFAULT_HOST)
            .withServerPort(clientAndServer.getLocalPort())
            .build();
    final KeyDefinition key = new KeyDefinition(KEY_PATH, Optional.empty(), ROOT_TOKEN);

    final HashicorpConnection connection = factory.create(connectionParameters);
    final String keyFetched = connection.fetchKey(key);

    assertThat(keyFetched).isEqualTo(EXPECTED_KEY_STRING);
  }

  @Test
  void hashicorpVaultReturnsEncryptionKeyOverTls() {

    KeyStoreFactory keyStoreFactory =
        new KeyStoreFactory(Configuration.configuration(), new MockServerLogger());
    keyStoreFactory.loadOrCreateKeyStore();
    HttpsURLConnection.setDefaultSSLSocketFactory(keyStoreFactory.sslContext().getSocketFactory());

    final ClientAndServer clientAndServer = new ClientAndServer(0);
    clientAndServer
        .when(request().withPath(".*"))
        .respond(
            response()
                .withStatusCode(200)
                .withBody("{\"data\":{\"data\":{\"value\":\"" + EXPECTED_KEY_STRING + "\"}}}"));

    final TlsOptions tlsOptions =
        new TlsOptions(
            Optional.of(TrustStoreType.JKS),
            Path.of(keyStoreFactory.keyStoreFileName),
            KeyStoreFactory.KEY_STORE_PASSWORD);
    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(DEFAULT_HOST)
            .withServerPort(clientAndServer.getLocalPort())
            .withTlsOptions(tlsOptions)
            .build();
    final KeyDefinition key = new KeyDefinition(KEY_PATH, Optional.empty(), ROOT_TOKEN);

    final HashicorpConnection connection = factory.create(connectionParameters);
    final String keyFetched = connection.fetchKey(key);

    assertThat(keyFetched).isEqualTo(EXPECTED_KEY_STRING);
  }

  @Test
  void exceptionThrownWhenHashicorpVaultAccessTimeout() throws IOException {
    final ClientAndServer clientAndServer = new ClientAndServer(0);
    clientAndServer
        .when(request().withPath(".*"))
        .respond(response().withDelay(TimeUnit.SECONDS, 5));

    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(DEFAULT_HOST)
            .withServerPort(clientAndServer.getLocalPort())
            .withTimeoutMs(1L)
            .build();
    final KeyDefinition key = new KeyDefinition(KEY_PATH, Optional.empty(), ROOT_TOKEN);

    final HashicorpConnection connection = factory.create(connectionParameters);
    assertThatThrownBy(() -> connection.fetchKey(key))
        .isInstanceOf(HashicorpException.class)
        .hasMessageContaining("timed out");
  }

  @Test
  void exceptionThrownWhenHashicorpVaultReturnInvalidStatusCode() throws IOException {
    final ClientAndServer clientAndServer = new ClientAndServer(0);
    clientAndServer.when(request().withPath(".*")).respond(response().withStatusCode(500));

    final ConnectionParameters connectionParameters =
        ConnectionParameters.newBuilder()
            .withServerHost(DEFAULT_HOST)
            .withServerPort(clientAndServer.getLocalPort())
            .build();
    final KeyDefinition key = new KeyDefinition(KEY_PATH, Optional.empty(), ROOT_TOKEN);

    final HashicorpConnection connection = factory.create(connectionParameters);
    assertThatThrownBy(() -> connection.fetchKey(key))
        .isInstanceOf(HashicorpException.class)
        .hasMessage(
            "Error communicating with Hashicorp vault: Received invalid Http status code 500.");
  }
}
