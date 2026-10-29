/*
 * Copyright 2019 ConsenSys AG.
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
package tech.pegasys.web3signer.tests.tls;

import static io.restassured.RestAssured.given;
import static java.nio.file.Files.writeString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.fail;
import static org.hamcrest.text.IsEqualIgnoringCase.equalToIgnoringCase;
import static tech.pegasys.web3signer.dsl.tls.TlsClientHelper.createRequestSpecification;
import static tech.pegasys.web3signer.dsl.tls.support.CertificateHelpers.populateFingerprintFile;
import static tech.pegasys.web3signer.dsl.utils.WaitUtils.waitFor;
import static tech.pegasys.web3signer.tests.AcceptanceTestBase.DEFAULT_CHAIN_ID;

import tech.pegasys.web3signer.core.config.ClientAuthConstraints;
import tech.pegasys.web3signer.core.config.TlsOptions;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ConfigurationChainId;
import tech.pegasys.web3signer.dsl.signer.Signer;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.tls.BasicTlsOptions;
import tech.pegasys.web3signer.dsl.tls.ClientTlsConfig;
import tech.pegasys.web3signer.dsl.tls.TlsCertificateDefinition;
import tech.pegasys.web3signer.dsl.tls.support.BasicClientAuthConstraints;
import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Optional;
import javax.net.ssl.SSLHandshakeException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class ServerSideTlsAcceptanceTest {

  // To create a PKCS12 keystore file (containing a privKey and Certificate:
  // Read
  // https://www.digitalocean.com/community/tutorials/openssl-essentials-working-with-ssl-certificates-private-keys-and-csrs
  // To make this simpler, have a config file, containing:
  //  [req]
  //  distinguished_name = req_distinguished_name
  //  x509_extensions = v3_req
  //  prompt = no
  //  [req_distinguished_name]
  //  C = AU
  //  ST = QLD
  //  L = Brisbane
  //  O = PegaSys
  //  OU = Prod Dev
  //  CN = localhost
  //  [v3_req]
  //  keyUsage = keyEncipherment, dataEncipherment
  //  extendedKeyUsage = serverAuth
  //  subjectAltName = @alt_names
  //  [alt_names]
  //  DNS.1 = localhost
  //  IP.1 = 127.0.0.1
  // 1. Create a CSR and private key
  // CMD    = openssl req -newkey rsa:2048 -nodes -keyout domain.key -out domain.csr -config conf
  // OUTPUT = domain.csr, and domain.key in the current working directory
  // 2. Generate self-signed certificate
  // CMD    = openssl req -key domain.key -new -x509 -days 365 -out cert.crt -config conf
  // OUTPUT = cert.crt in the current working directory
  // 3. Convert to PKCS12
  // openssl pkcs12 -export -inkey domain.key -in cert.crt -out cert1.pfx
  //
  @TempDir Path dataPath;

  final TlsCertificateDefinition cert1 =
      TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "password");
  final TlsCertificateDefinition cert2 =
      TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

  private Signer signer = null;

  @AfterEach
  void cleanup() {
    if (signer != null) {
      signer.shutdown();
      signer = null;
    }
  }

  private Signer createTlsSigner(
      final TlsCertificateDefinition serverPresentedCerts,
      final TlsCertificateDefinition clientExpectedCert,
      final TlsCertificateDefinition clientCertInServerWhitelist,
      final TlsCertificateDefinition clientToPresent,
      final int fixedListenPort,
      final boolean useConfigFile) {

    try {
      final SignerConfigurationBuilder configBuilder =
          new SignerConfigurationBuilder()
              .withHttpPort(fixedListenPort)
              .withUseConfigFile(useConfigFile)
              .withMode("eth1")
              .withChainIdProvider(new ConfigurationChainId(DEFAULT_CHAIN_ID));

      final ClientAuthConstraints clientAuthConstraints;
      if (clientCertInServerWhitelist != null) {
        final Path fingerPrintFilePath = dataPath.resolve("known_clients");
        populateFingerprintFile(fingerPrintFilePath, clientCertInServerWhitelist, Optional.empty());
        clientAuthConstraints = BasicClientAuthConstraints.fromFile(fingerPrintFilePath.toFile());
      } else {
        clientAuthConstraints = null;
      }

      final Path passwordPath = dataPath.resolve("keystore.passwd");
      if (serverPresentedCerts.getPassword() != null) {
        writeString(passwordPath, serverPresentedCerts.getPassword());
      }

      final TlsOptions serverOptions =
          new BasicTlsOptions(
              serverPresentedCerts.getPkcs12File(),
              passwordPath.toFile(),
              Optional.ofNullable(clientAuthConstraints));
      configBuilder.withServerTlsOptions(serverOptions);

      final ClientTlsConfig clientTlsConfig;
      if (clientExpectedCert != null) {
        clientTlsConfig = new ClientTlsConfig(clientExpectedCert, clientToPresent);
      } else {
        clientTlsConfig = null;
      }

      return new Signer(configBuilder.build(), clientTlsConfig);
    } catch (final Exception e) {
      fail("Failed to create Web3Signer.", e);
      return null;
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void ableToConnectWhenClientExpectsSameCertificateAsThatPresented(final boolean useConfigFile) {
    signer = createTlsSigner(cert1, cert1, null, null, 0, useConfigFile);
    signer.start();
    signer.awaitStartupCompletion();

    signer
        .requestSpec()
        .when()
        .get("/upcheck")
        .then()
        .assertThat()
        .statusCode(200)
        .body(equalToIgnoringCase("OK"));
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void nonTlsClientsCannotConnectToTlsEnabledWeb3Signer(final boolean useConfigFile) {
    // The web3signer object (and in-built requester are already TLS enabled, so need to make a new
    // http client which does not have TLS enabled
    signer = createTlsSigner(cert1, cert1, null, null, 0, useConfigFile);
    signer.start();
    signer.awaitStartupCompletion();

    Runnable request =
        () ->
            given()
                .baseUri(signer.getUrl())
                .when()
                .get("/upcheck")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToIgnoringCase("OK"));

    assertThatThrownBy(request::run).isInstanceOf(SSLHandshakeException.class);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void missingPasswordFileResultsInWeb3SignerExiting(final boolean useConfigFile) {
    // arbitrary listen-port to prevent waiting for portfile (during Start) to be created.
    final TlsCertificateDefinition missingPasswordCert =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", null);
    signer = createTlsSigner(missingPasswordCert, cert1, null, null, 9000, useConfigFile);
    signer.start();
    waitFor(() -> assertThat(signer.isRunning()).isFalse());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void exitsIfPasswordDoesntMatchKeyStoreFile(final boolean useConfigFile) {
    // arbitrary listen-port to prevent waiting for portfile (during Start) to be created.
    final TlsCertificateDefinition wrongPasswordCert =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "wrongPassword");
    signer = createTlsSigner(wrongPasswordCert, cert1, null, null, 9000, useConfigFile);
    signer.start();
    waitFor(() -> assertThat(signer.isRunning()).isFalse());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void clientCannotConnectIfExpectedServerCertDoesntMatchServerSuppliedCert(
      final boolean useConfigFile) {
    signer = createTlsSigner(cert1, cert1, null, null, 0, useConfigFile);
    signer.start();
    signer.awaitStartupCompletion();

    final ClientTlsConfig clientTlsConfig = new ClientTlsConfig(cert2, null);

    Runnable request =
        () ->
            given()
                .spec(createRequestSpecification(Optional.of(clientTlsConfig)))
                .baseUri(signer.getUrl())
                .when()
                .get("/upcheck")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToIgnoringCase("OK"));

    assertThatThrownBy(request::run).isInstanceOf(SSLHandshakeException.class);
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void missingKeyStoreFileResultsInWeb3SignerExiting(final boolean useConfigFile)
      throws IOException {
    final TlsOptions serverOptions =
        new BasicTlsOptions(
            dataPath.resolve("missing_keystore").toFile(),
            Files.writeString(dataPath.resolve("password"), "password").toFile(),
            Optional.empty());

    // Requires arbitrary port to avoid waiting for Ports file
    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withServerTlsOptions(serverOptions)
            .withHttpPort(9000);

    signer = new Signer(configBuilder.withMode("eth2").build(), null);
    signer.start();
    waitFor(() -> assertThat(signer.isRunning()).isFalse());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void clientMissingFromAllowedListCannotConnectToWeb3Signer(final boolean useConfigFile) {
    signer = createTlsSigner(cert1, cert1, cert1, cert1, 0, useConfigFile);
    signer.start();
    signer.awaitStartupCompletion();

    final ClientTlsConfig clientTlsConfig = new ClientTlsConfig(cert1, cert2);

    Runnable request =
        () ->
            given()
                .spec(createRequestSpecification(Optional.of(clientTlsConfig)))
                .baseUri(signer.getUrl())
                .when()
                .get("/upcheck")
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalToIgnoringCase("OK"));

    assertThatThrownBy(request::run).isInstanceOf(IOException.class);
  }

  @ParameterizedTest(name = "useConfigFile={0}, pemTrustStore={1}")
  @CsvSource({"true,false", "false,false", "true,true", "false,true"})
  void clientInServerTrustStoreCanConnectToWeb3Signer(
      final boolean useConfigFile, final boolean pemTrustStore) throws Exception {
    final TlsCertificateDefinition clientCert = generateCertificate("client");
    signer = createTrustStoreTlsSigner(clientCert, pemTrustStore, useConfigFile);
    signer.start();
    signer.awaitStartupCompletion();

    signer
        .requestSpec()
        .when()
        .get("/upcheck")
        .then()
        .assertThat()
        .statusCode(200)
        .body(equalToIgnoringCase("OK"));
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void clientMissingFromServerTrustStoreCannotConnectToWeb3Signer(final boolean useConfigFile)
      throws Exception {
    final TlsCertificateDefinition trustedCert = generateCertificate("trusted");
    final TlsCertificateDefinition untrustedCert = generateCertificate("untrusted");
    signer = createTrustStoreTlsSigner(trustedCert, false, useConfigFile);
    signer.start();
    signer.awaitStartupCompletion();

    final ClientTlsConfig clientTlsConfig = new ClientTlsConfig(cert1, untrustedCert);
    Runnable request =
        () ->
            given()
                .spec(createRequestSpecification(Optional.of(clientTlsConfig)))
                .baseUri(signer.getUrl())
                .when()
                .get("/upcheck")
                .then()
                .assertThat()
                .statusCode(200);

    assertThatThrownBy(request::run).isInstanceOf(IOException.class);
  }

  /**
   * Web3Signer trusting only {@code trustedClient}, as a PKCS#12 or PEM truststore, queried by a
   * client presenting it.
   */
  private Signer createTrustStoreTlsSigner(
      final TlsCertificateDefinition trustedClient,
      final boolean pemTrustStore,
      final boolean useConfigFile)
      throws Exception {
    final Path serverPasswordFile = writeString(dataPath.resolve("keystore.passwd"), "password");
    final TrustStoreOptions trustStoreOptions;
    if (pemTrustStore) {
      final String pem =
          "-----BEGIN CERTIFICATE-----\n"
              + Base64.getMimeEncoder(64, new byte[] {'\n'})
                  .encodeToString(trustedClient.certificates().get(0).getEncoded())
              + "\n-----END CERTIFICATE-----\n";
      trustStoreOptions =
          new TrustStoreOptions(
              writeString(dataPath.resolve("truststore.pem"), pem), Optional.empty());
    } else {
      final Path trustStorePasswordFile =
          writeString(dataPath.resolve("truststore.passwd"), trustedClient.getPassword());
      trustStoreOptions =
          new TrustStoreOptions(
              trustedClient.getPkcs12File().toPath(), Optional.of(trustStorePasswordFile));
    }
    final ClientAuthConstraints clientAuthConstraints =
        BasicClientAuthConstraints.fromTrustStore(trustStoreOptions);
    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth1")
            .withChainIdProvider(new ConfigurationChainId(DEFAULT_CHAIN_ID))
            .withServerTlsOptions(
                new BasicTlsOptions(
                    cert1.getPkcs12File(),
                    serverPasswordFile.toFile(),
                    Optional.of(clientAuthConstraints)));

    return new Signer(configBuilder.build(), new ClientTlsConfig(cert1, trustedClient));
  }

  private TlsCertificateDefinition generateCertificate(final String name) throws IOException {
    final String password = name + "-password";
    final Path keyStore =
        CertificateHelpers.createPkcs12TrustStore(
            Files.createDirectories(dataPath.resolve(name)),
            SelfSignedCertificate.generate(),
            password);
    return new TlsCertificateDefinition(keyStore.toFile(), password);
  }
}
