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
package tech.pegasys.web3signer.keystore.hashicorp.dsl;

import static java.nio.charset.StandardCharsets.UTF_8;

import tech.pegasys.web3signer.keystore.dsl.ContainerHosts;
import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateEncodingException;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

/**
 * A Hashicorp Vault server in a Testcontainers container. Every instance runs its own container, so
 * tests never share Vault state.
 *
 * <p>The server runs in {@code -dev} mode: in-memory storage, already initialized and unsealed,
 * with a kv-v2 engine at {@code secret/} and a root token chosen by this class. The dev listener is
 * plain HTTP and is what this class uses to write secrets. When TLS is requested, a second listener
 * with a self-signed certificate is added, and that listener is what {@link #getPort()} returns, so
 * the code under test only ever talks TLS.
 */
public class HashicorpNode implements AutoCloseable {
  private static final Logger LOG = LogManager.getLogger();
  private static final org.slf4j.Logger VAULT_PROCESS_LOG =
      LoggerFactory.getLogger(HashicorpNode.class.getName() + ".VaultServer");

  // Automatically set by the gradle acceptanceTest task from gradle/versions.gradle's
  // hashicorpVaultImage.
  // Should be set manually in IDE if not using gradle.
  private static final String IMAGE_PROPERTY = "hashicorpVaultImage";

  private static final String VAULT_ROOT_PATH = "secret";
  private static final int DEV_LISTENER_PORT = 8200;
  private static final int TLS_LISTENER_PORT = 8201;
  private static final String CONTAINER_CERT_FILE = "/vault/tls/server.crt";
  private static final String CONTAINER_KEY_FILE = "/vault/tls/server.key";
  // The vault process does not run as root, so the copied files must be world-readable.
  private static final int READABLE_FILE_MODE = 0644;

  private final Optional<SelfSignedCertificate> serverTlsCertificate;
  private final String vaultToken = UUID.randomUUID().toString();
  private final GenericContainer<?> container;
  private final HttpClient httpClient = HttpClient.newHttpClient();
  private final ObjectMapper objectMapper = new ObjectMapper();

  /**
   * Create a Hashicorp Vault container and start it.
   *
   * <p>System property hashicorpVaultImage should be set before calling this method.
   *
   * @param withTls if TLS should be enabled
   * @return A started instance of HashicorpNode
   */
  public static HashicorpNode createAndStartHashicorp(final boolean withTls) {
    final String image = System.getProperty(IMAGE_PROPERTY);
    if (image == null) {
      throw new IllegalStateException("System property [" + IMAGE_PROPERTY + "] is missing.");
    }

    HashicorpNode hashicorpNode = null;
    try {
      hashicorpNode =
          new HashicorpNode(
              DockerImageName.parse(image),
              withTls ? Optional.of(SelfSignedCertificate.generate()) : Optional.empty());
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      // the caller never receives the node, so nobody else can stop a container that did start
      if (hashicorpNode != null) {
        hashicorpNode.close();
      }
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  private HashicorpNode(
      final DockerImageName image, final Optional<SelfSignedCertificate> serverTlsCertificate)
      throws IOException, CertificateEncodingException {
    this.serverTlsCertificate = serverTlsCertificate;
    this.container =
        new GenericContainer<>(image)
            .withExposedPorts(DEV_LISTENER_PORT)
            .withCommand("server", "-dev")
            .withEnv("VAULT_DEV_ROOT_TOKEN_ID", vaultToken)
            .withEnv("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:" + DEV_LISTENER_PORT)
            .withLogConsumer(new Slf4jLogConsumer(VAULT_PROCESS_LOG))
            // 200 only once vault is initialized, unsealed and active
            .waitingFor(Wait.forHttp("/v1/sys/health").forPort(DEV_LISTENER_PORT));
    if (serverTlsCertificate.isPresent()) {
      addTlsListener(serverTlsCertificate.get());
    }
  }

  private void start() {
    LOG.info("Starting vault server container ({})", container.getDockerImageName());
    container.start();
  }

  /** Stops and removes the container. Safe to call more than once. */
  @Override
  public void close() {
    LOG.info("Shutting down Vault server container...");
    container.stop();
  }

  public String getVaultToken() {
    return vaultToken;
  }

  public String getHost() {
    return ContainerHosts.reachableHost(container.getHost());
  }

  /** The port vault is reached on by the code under test: the TLS listener if TLS is enabled. */
  public int getPort() {
    return container.getMappedPort(
        serverTlsCertificate.isPresent() ? TLS_LISTENER_PORT : DEV_LISTENER_PORT);
  }

  public Optional<SelfSignedCertificate> getServerCertificate() {
    return serverTlsCertificate;
  }

  public String getHttpApiPathForSecret(final String secretPath) {
    return "/v1/" + VAULT_ROOT_PATH + "/data/" + secretPath;
  }

  /* Note: Path should be the "subpath" of the secret - not the full HTTP path.
   The full HTTP Path will be returned.
  */
  public String addSecretsToVault(final Map<String, String> entries, final String path) {
    LOG.info("creating the secret in vault that contains the private key.");
    final JsonNode response = post(getHttpApiPathForSecret(path), Map.of("data", entries));
    if (!response.path("data").hasNonNull("created_time")) {
      throw new IllegalStateException("Unexpected response writing secret: " + response);
    }
    LOG.info("The secret with keys {} was created successfully.", entries.keySet());
    return getHttpApiPathForSecret(path);
  }

  /**
   * Adds a TLS listener next to the dev listener. The dev listener stays plain HTTP, which lets
   * this class write secrets without trusting the self-signed certificate.
   */
  private void addTlsListener(final SelfSignedCertificate certificate)
      throws IOException, CertificateEncodingException {
    final Map<String, Object> config =
        Map.of(
            "listener",
            Map.of(
                "tcp",
                Map.of(
                    "address",
                    "0.0.0.0:" + TLS_LISTENER_PORT,
                    "tls_min_version",
                    "tls12",
                    "tls_cert_file",
                    CONTAINER_CERT_FILE,
                    "tls_key_file",
                    CONTAINER_KEY_FILE)));
    container
        .withEnv("VAULT_LOCAL_CONFIG", objectMapper.writeValueAsString(config))
        .withExposedPorts(DEV_LISTENER_PORT, TLS_LISTENER_PORT)
        .withCopyToContainer(
            Transferable.of(certificate.certificatePem(), READABLE_FILE_MODE), CONTAINER_CERT_FILE)
        .withCopyToContainer(
            Transferable.of(certificate.privateKeyPem(), READABLE_FILE_MODE), CONTAINER_KEY_FILE);
  }

  /** POSTs to the plain dev listener. Vault treats POST and PUT alike. */
  private JsonNode post(final String path, final Object body) {
    try {
      final HttpRequest request =
          HttpRequest.newBuilder(
                  URI.create(
                      "http://"
                          + getHost()
                          + ":"
                          + container.getMappedPort(DEV_LISTENER_PORT)
                          + path))
              .header("Content-Type", "application/json")
              .header("X-Vault-Token", vaultToken)
              .POST(
                  HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body), UTF_8))
              .build();
      final HttpResponse<String> response =
          httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() / 100 != 2) {
        throw new IllegalStateException(
            String.format(
                "Vault POST %s failed with status %d: %s",
                path, response.statusCode(), response.body()));
      }
      return objectMapper.readTree(response.body());
    } catch (final IOException e) {
      throw new IllegalStateException("Vault POST " + path + " failed", e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted calling vault POST " + path, e);
    }
  }
}
