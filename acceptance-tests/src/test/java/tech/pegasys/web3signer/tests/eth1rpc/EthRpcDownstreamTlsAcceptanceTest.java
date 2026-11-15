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
package tech.pegasys.web3signer.tests.eth1rpc;

import static io.netty.handler.codec.http.HttpResponseStatus.BAD_GATEWAY;
import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.web3j.protocol.core.DefaultBlockParameterName.LATEST;
import static tech.pegasys.web3signer.dsl.tls.support.CertificateHelpers.populateFingerprintFile;

import tech.pegasys.web3signer.core.config.KeyStoreOptions;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;
import tech.pegasys.web3signer.core.config.client.ClientTlsOptions;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ConfigurationChainId;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.tls.TlsCertificateDefinition;
import tech.pegasys.web3signer.dsl.tls.client.BasicClientTlsOptions;
import tech.pegasys.web3signer.dsl.tls.client.BasicKeyStoreOptions;
import tech.pegasys.web3signer.dsl.tls.support.TlsEnabledHttpServerFactory;
import tech.pegasys.web3signer.dsl.utils.MockBalanceReporter;
import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Optional;

import io.vertx.core.http.HttpServer;
import org.bouncycastle.util.Integers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.web3j.protocol.core.methods.request.Transaction;
import org.web3j.protocol.exceptions.ClientConnectionException;
import org.web3j.utils.Convert;

class EthRpcDownstreamTlsAcceptanceTest extends Eth1RpcAcceptanceTestBase {

  private TlsEnabledHttpServerFactory serverFactory;

  @BeforeEach
  void setup() {
    serverFactory = new TlsEnabledHttpServerFactory();
  }

  private void startSigner(
      final TlsCertificateDefinition presentedCert,
      final TlsCertificateDefinition expectedWeb3ProviderCert,
      final int downstreamWeb3Port,
      final Path workDir)
      throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException {

    final Path clientPasswordFile =
        Files.writeString(workDir.resolve("clientKeystorePassword"), presentedCert.getPassword());

    final Path fingerPrintFilePath = workDir.resolve("known_servers");
    final SignerConfigurationBuilder builder =
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(keyFileTempDir)
            .withMode("eth1")
            .withChainIdProvider(new ConfigurationChainId(DEFAULT_CHAIN_ID));
    final Optional<Integer> downstreamWeb3ServerPort =
        Optional.of(Integers.valueOf(downstreamWeb3Port));

    populateFingerprintFile(
        fingerPrintFilePath, expectedWeb3ProviderCert, downstreamWeb3ServerPort);

    final KeyStoreOptions keyStoreOptions =
        new BasicKeyStoreOptions(presentedCert.getPkcs12File().toPath(), clientPasswordFile);
    final ClientTlsOptions clientTlsOptions =
        new BasicClientTlsOptions(keyStoreOptions, Optional.of(fingerPrintFilePath), true);
    builder.withDownstreamTlsOptions(clientTlsOptions).withDownstreamHttpPort(downstreamWeb3Port);

    startSigner(builder.build());
  }

  @Test
  void providesSpecifiedClientCertificateToDownStreamServer(@TempDir Path workDir)
      throws Exception {

    final TlsCertificateDefinition serverCert =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "password");
    final TlsCertificateDefinition web3SignerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

    // Note: the HttpServer always responds with a JsonRpcSuccess, result=300.
    final HttpServer web3ProviderHttpServer =
        serverFactory.create(serverCert, web3SignerCert, workDir);

    startSigner(web3SignerCert, serverCert, web3ProviderHttpServer.actualPort(), workDir);

    assertThat(signer.jsonRpc().ethGetBalance("0x123456", LATEST).send().getBalance())
        .isEqualTo(BigInteger.valueOf(MockBalanceReporter.REPORTED_BALANCE));
  }

  @Test
  void doesNotConnectToServerNotSpecifiedInTrustStore(@TempDir Path workDir) throws Exception {
    final TlsCertificateDefinition serverPresentedCert =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "password");
    final TlsCertificateDefinition web3SignerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");
    final TlsCertificateDefinition web3SignerExpectedServerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

    final HttpServer web3ProviderHttpServer =
        serverFactory.create(serverPresentedCert, web3SignerCert, workDir);

    startSigner(
        web3SignerCert, web3SignerExpectedServerCert, web3ProviderHttpServer.actualPort(), workDir);

    assertThatThrownBy(() -> signer.jsonRpc().ethGetBalance("0x123456", LATEST).send())
        .isInstanceOf(ClientConnectionException.class)
        .hasMessageContaining(String.valueOf(BAD_GATEWAY.code()));

    // ensure submitting a transaction results in the same behaviour
    final Transaction transaction =
        Transaction.createEtherTransaction(
            RICH_BENEFACTOR,
            null,
            GAS_PRICE,
            INTRINSIC_GAS,
            "0x1b00ba00ca00bb00aa00bc00be00ac00ca00da00",
            Convert.toWei("1.75", Convert.Unit.ETHER).toBigIntegerExact());

    assertThatThrownBy(() -> signer.jsonRpc().ethSendTransaction(transaction).send())
        .isInstanceOf(ClientConnectionException.class)
        .hasMessageContaining(String.valueOf(BAD_GATEWAY.code()));
  }

  @Test
  void missingKeyStoreForWeb3SignerResultsInInternalServerError500Return(@TempDir Path workDir)
      throws Exception {
    final TlsCertificateDefinition missingServerCert =
        new TlsCertificateDefinition(
            workDir.resolve("Missing_keyStore").toFile(), "arbitraryPassword");
    final TlsCertificateDefinition serverCert =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "password");
    final TlsCertificateDefinition web3SignerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

    final HttpServer web3ProviderHttpServer =
        serverFactory.create(serverCert, web3SignerCert, workDir);

    startSigner(missingServerCert, web3SignerCert, web3ProviderHttpServer.actualPort(), workDir);

    // the actual connection to downstream server should fail as an internal error (500) since the
    // keystore is invalid ...
    assertThatThrownBy(() -> signer.jsonRpc().ethGetBalance("0x123456", LATEST).send())
        .isInstanceOf(ClientConnectionException.class)
        .hasMessageContaining(String.valueOf(INTERNAL_SERVER_ERROR.code()));
  }

  @Test
  void incorrectPasswordForDownstreamKeyStoreResultsInInternalServerError500Return(
      @TempDir Path workDir) throws Exception {
    final TlsCertificateDefinition serverPresentedCertWithInvalidPassword =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "wrong_password");
    final TlsCertificateDefinition serverCert =
        TlsCertificateDefinition.loadFromResource("tls/cert1.pfx", "password");
    final TlsCertificateDefinition web3signerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

    final HttpServer web3ProviderHttpServer =
        serverFactory.create(serverCert, web3signerCert, workDir);

    startSigner(
        serverPresentedCertWithInvalidPassword,
        web3signerCert,
        web3ProviderHttpServer.actualPort(),
        workDir);

    // the actual connection to downstream server should fail as an internal error (500) since the
    // keystore password is invalid ...
    assertThatThrownBy(() -> signer.jsonRpc().ethGetBalance("0x123456", LATEST).send())
        .isInstanceOf(ClientConnectionException.class)
        .hasMessageContaining(String.valueOf(INTERNAL_SERVER_ERROR.code()));
  }

  @Test
  void connectsToServerInTrustStore(@TempDir Path workDir) throws Exception {
    final TlsCertificateDefinition serverCert = generateCertificate(workDir, "server");
    final TlsCertificateDefinition web3SignerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

    final HttpServer web3ProviderHttpServer =
        serverFactory.create(serverCert, web3SignerCert, workDir);

    startSignerWithTrustStore(
        web3SignerCert, serverCert, web3ProviderHttpServer.actualPort(), workDir);

    assertThat(signer.jsonRpc().ethGetBalance("0x123456", LATEST).send().getBalance())
        .isEqualTo(BigInteger.valueOf(MockBalanceReporter.REPORTED_BALANCE));
  }

  @Test
  void doesNotConnectToServerMissingFromTrustStore(@TempDir Path workDir) throws Exception {
    final TlsCertificateDefinition serverCert = generateCertificate(workDir, "server");
    final TlsCertificateDefinition otherCert = generateCertificate(workDir, "other");
    final TlsCertificateDefinition web3SignerCert =
        TlsCertificateDefinition.loadFromResource("tls/cert2.pfx", "password2");

    final HttpServer web3ProviderHttpServer =
        serverFactory.create(serverCert, web3SignerCert, workDir);

    startSignerWithTrustStore(
        web3SignerCert, otherCert, web3ProviderHttpServer.actualPort(), workDir);

    assertThatThrownBy(() -> signer.jsonRpc().ethGetBalance("0x123456", LATEST).send())
        .isInstanceOf(ClientConnectionException.class)
        .hasMessageContaining(String.valueOf(BAD_GATEWAY.code()));
  }

  private void startSignerWithTrustStore(
      final TlsCertificateDefinition presentedCert,
      final TlsCertificateDefinition trustedServerCert,
      final int downstreamWeb3Port,
      final Path workDir)
      throws IOException {
    final Path clientPasswordFile =
        Files.writeString(workDir.resolve("clientKeystorePassword"), presentedCert.getPassword());
    final Path trustStorePasswordFile =
        Files.writeString(workDir.resolve("truststorePassword"), trustedServerCert.getPassword());

    final ClientTlsOptions clientTlsOptions =
        new BasicClientTlsOptions(
            new BasicKeyStoreOptions(presentedCert.getPkcs12File().toPath(), clientPasswordFile),
            new TrustStoreOptions(
                trustedServerCert.getPkcs12File().toPath(), Optional.of(trustStorePasswordFile)));

    startSigner(
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(keyFileTempDir)
            .withMode("eth1")
            .withChainIdProvider(new ConfigurationChainId(DEFAULT_CHAIN_ID))
            .withDownstreamTlsOptions(clientTlsOptions)
            .withDownstreamHttpPort(downstreamWeb3Port)
            .build());
  }

  private static TlsCertificateDefinition generateCertificate(final Path workDir, final String name)
      throws IOException {
    final String password = name + "-password";
    final Path keyStore =
        CertificateHelpers.createPkcs12TrustStore(
            Files.createDirectories(workDir.resolve(name)),
            SelfSignedCertificate.generate(),
            password);
    return new TlsCertificateDefinition(keyStore.toFile(), password);
  }
}
