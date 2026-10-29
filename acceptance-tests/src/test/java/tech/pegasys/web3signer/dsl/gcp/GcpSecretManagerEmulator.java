/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.dsl.gcp;

import static java.nio.charset.StandardCharsets.US_ASCII;

import tech.pegasys.web3signer.commandline.PicoCliGcpSecretManagerParameters;
import tech.pegasys.web3signer.dsl.tls.TlsCertificateDefinition;
import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.InstantiatingGrpcChannelProvider;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * JVM-wide singleton Testcontainers-backed GCP Secret Manager emulator. Never explicitly stopped;
 * Testcontainers' Ryuk reaper removes the containers at JVM exit.
 *
 * <p>The emulator only serves plaintext gRPC and ignores credentials, while Web3Signer's client
 * always uses TLS and application default credentials. So that Web3Signer needs nothing beyond an
 * endpoint override, it reaches the emulator through an nginx container terminating TLS with a
 * self-signed certificate, and authenticates with a throwaway service-account key. Test code
 * creates its secrets directly against the emulator instead, see {@link #createClient()}.
 */
public final class GcpSecretManagerEmulator {

  private static final Logger LOG = LogManager.getLogger();

  /** Any project name works: the emulator keeps secrets under whatever project it is asked for. */
  public static final String PROJECT_ID = "web3signer-test";

  // Automatically set by the gradle acceptanceTest task from gradle/versions.gradle.
  private static final DockerImageName EMULATOR_IMAGE =
      dockerImageName("gcpSecretManagerEmulatorImage");
  private static final DockerImageName TLS_PROXY_IMAGE =
      dockerImageName("gcpSecretManagerTlsProxyImage");

  private static final String EMULATOR_HOST = "gcp-secret-manager-emulator";
  private static final int EMULATOR_GRPC_PORT = 9090;
  private static final int EMULATOR_HTTP_PORT = 8080;
  private static final int TLS_PROXY_PORT = 443;
  private static final String CERT_PASSWORD = "emulator";
  private static final String NGINX_CONF =
      """
      events {}
      http {
        ssl_certificate /etc/nginx/tls/tls.crt;
        ssl_certificate_key /etc/nginx/tls/tls.key;
        server {
          listen %d ssl;
          http2 on;
          location / {
            grpc_pass grpc://%s:%d;
          }
        }
      }
      """
          .formatted(TLS_PROXY_PORT, EMULATOR_HOST, EMULATOR_GRPC_PORT);

  private static final class Holder {
    private static final GcpSecretManagerEmulator INSTANCE = new GcpSecretManagerEmulator();
  }

  public static GcpSecretManagerEmulator getInstance() {
    return Holder.INSTANCE;
  }

  private static DockerImageName dockerImageName(final String systemProperty) {
    final String image = System.getProperty(systemProperty);
    if (image == null) {
      throw new IllegalStateException("System property [" + systemProperty + "] is missing.");
    }
    return DockerImageName.parse(image);
  }

  private final GenericContainer<?> emulator;
  private final GenericContainer<?> tlsProxy;
  private final TlsCertificateDefinition tlsCertificateDefinition;
  private final Path serviceAccountKeyFile;

  private GcpSecretManagerEmulator() {
    try {
      final Path workDir = Files.createTempDirectory("gcp-secret-manager-emulator");

      final SelfSignedCertificate certificate = SelfSignedCertificate.generate();
      final Path certificateFile = workDir.resolve("tls.crt");
      final Path privateKeyFile = workDir.resolve("tls.key");
      certificate.writeCertificateToFile(certificateFile);
      certificate.writePrivateKeyToFile(privateKeyFile);
      this.tlsCertificateDefinition =
          new TlsCertificateDefinition(
              CertificateHelpers.createPkcs12TrustStore(workDir, certificate, CERT_PASSWORD)
                  .toFile(),
              CERT_PASSWORD);

      this.serviceAccountKeyFile = workDir.resolve("service-account.json");
      writeServiceAccountKey(serviceAccountKeyFile);

      final Network network = Network.newNetwork();
      this.emulator =
          new GenericContainer<>(EMULATOR_IMAGE)
              .withNetwork(network)
              .withNetworkAliases(EMULATOR_HOST)
              .withExposedPorts(EMULATOR_GRPC_PORT, EMULATOR_HTTP_PORT)
              .waitingFor(Wait.forHttp("/healthz").forPort(EMULATOR_HTTP_PORT));
      this.tlsProxy =
          new GenericContainer<>(TLS_PROXY_IMAGE)
              .withNetwork(network)
              .dependsOn(emulator)
              .withCopyToContainer(Transferable.of(NGINX_CONF), "/etc/nginx/nginx.conf")
              .withCopyFileToContainer(
                  MountableFile.forHostPath(certificateFile), "/etc/nginx/tls/tls.crt")
              .withCopyFileToContainer(
                  MountableFile.forHostPath(privateKeyFile), "/etc/nginx/tls/tls.key")
              .withExposedPorts(TLS_PROXY_PORT)
              .waitingFor(Wait.forListeningPort());
      LOG.info(
          "Starting GCP Secret Manager emulator ({}) behind TLS proxy ({})...",
          EMULATOR_IMAGE.asCanonicalNameString(),
          TLS_PROXY_IMAGE.asCanonicalNameString());
      tlsProxy.start();
      LOG.info("GCP Secret Manager emulator listening at {} over TLS", getTlsEndpoint());
    } catch (final Exception e) {
      throw new IllegalStateException("Unable to start GCP Secret Manager emulator", e);
    }
  }

  /**
   * Writes a service-account key for a made-up account. For service accounts the Google client
   * signs its own JWTs with the key rather than exchanging it for a token, so nothing is sent to
   * Google; {@code token_uri} points at a closed local port so an exchange could not leave the
   * machine either. The emulator accepts any credentials.
   */
  private static void writeServiceAccountKey(final Path file) throws Exception {
    final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    final PrivateKey privateKey = keyPairGenerator.generateKeyPair().getPrivate();
    final String privateKeyPem =
        "-----BEGIN PRIVATE KEY-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(US_ASCII))
                .encodeToString(privateKey.getEncoded())
            + "\n-----END PRIVATE KEY-----\n";
    new ObjectMapper()
        .writeValue(
            file.toFile(),
            Map.of(
                "type", "service_account",
                "project_id", PROJECT_ID,
                "private_key_id", "emulator",
                "private_key", privateKeyPem,
                "client_email", "web3signer@" + PROJECT_ID + ".iam.gserviceaccount.com",
                "client_id", "0",
                "token_uri", "https://127.0.0.1:1/token"));
  }

  /**
   * Environment for the Web3Signer process: the throwaway service-account key as application
   * default credentials. Only a Web3Signer subprocess ({@code acctests.runWeb3SignerAsProcess})
   * receives it; in-process, google-auth reads the test JVM's own environment. Web3Signer also has
   * to trust {@link #getTlsCertificateDefinition()} and reach Secret Manager at {@link
   * #getTlsEndpoint()}.
   */
  public Map<String, String> web3SignerEnvironment() {
    return Map.of(
        "GOOGLE_APPLICATION_CREDENTIALS", serviceAccountKeyFile.toAbsolutePath().toString());
  }

  public TlsCertificateDefinition getTlsCertificateDefinition() {
    return tlsCertificateDefinition;
  }

  /**
   * {@code host:port} of the TLS proxy, for Web3Signer's {@value
   * PicoCliGcpSecretManagerParameters#GCP_ENDPOINT_OVERRIDE_OPTION}.
   */
  public String getTlsEndpoint() {
    return host() + ":" + tlsProxy.getMappedPort(TLS_PROXY_PORT);
  }

  /**
   * A client for test code talking to the emulator directly, over plaintext without credentials.
   */
  public SecretManagerServiceClient createClient() throws IOException {
    return SecretManagerServiceClient.create(
        SecretManagerServiceSettings.newBuilder()
            .setCredentialsProvider(NoCredentialsProvider.create())
            .setTransportChannelProvider(
                InstantiatingGrpcChannelProvider.newBuilder()
                    .setEndpoint(host() + ":" + emulator.getMappedPort(EMULATOR_GRPC_PORT))
                    .setChannelConfigurator(channelBuilder -> channelBuilder.usePlaintext())
                    .build())
            .build());
  }

  private String host() {
    // Docker Desktop's published-port userland proxy commonly only forwards the IPv4 loopback
    // address; "localhost" can resolve to the IPv6 loopback first. The self-signed certificate
    // covers 127.0.0.1.
    final String host = tlsProxy.getHost();
    return "localhost".equals(host) ? "127.0.0.1" : host;
  }
}
