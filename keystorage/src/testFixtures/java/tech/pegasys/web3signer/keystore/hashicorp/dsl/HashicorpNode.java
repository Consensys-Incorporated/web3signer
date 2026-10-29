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

import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Map;
import java.util.Optional;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * A Hashicorp Vault server in a Testcontainers container, initialized, unsealed and with a kv-v2
 * engine mounted at {@code secret}. Every instance runs its own container with in-memory storage,
 * so tests never share Vault state.
 */
public class HashicorpNode {
  private static final Logger LOG = LogManager.getLogger();
  private static final org.slf4j.Logger VAULT_PROCESS_LOG =
      LoggerFactory.getLogger(HashicorpNode.class.getName() + ".VaultServer");

  // Automatically set by the gradle acceptanceTest task from gradle/versions.gradle's
  // hashicorpVaultImage.
  // Should be set manually in IDE if not using gradle.
  private static final String IMAGE_PROPERTY = "hashicorpVaultImage";

  private static final String VAULT_ROOT_PATH = "secret";
  private static final int VAULT_PORT = 8200;
  private static final String CONTAINER_CERT_FILE = "/vault/tls/server.crt";
  private static final String CONTAINER_KEY_FILE = "/vault/tls/server.key";
  // The vault process does not run as root, so the copied files must be world-readable.
  private static final int READABLE_FILE_MODE = 0644;

  private final Optional<SelfSignedCertificate> serverTlsCertificate;
  private final GenericContainer<?> container;
  private final ObjectMapper objectMapper = new ObjectMapper();

  // initialized after start
  private HttpClient httpClient;
  private String vaultToken;

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

    try {
      final HashicorpNode hashicorpNode =
          new HashicorpNode(
              DockerImageName.parse(image),
              withTls ? Optional.of(SelfSignedCertificate.generate()) : Optional.empty());
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  private HashicorpNode(
      final DockerImageName image, final Optional<SelfSignedCertificate> serverTlsCertificate)
      throws IOException, GeneralSecurityException {
    this.serverTlsCertificate = serverTlsCertificate;
    this.container =
        new GenericContainer<>(image)
            .withExposedPorts(VAULT_PORT)
            .withCommand("server")
            .withEnv("VAULT_LOCAL_CONFIG", serverConfig())
            // disable_mlock makes the IPC_LOCK capability unnecessary
            .withEnv("SKIP_SETCAP", "true")
            .withLogConsumer(new Slf4jLogConsumer(VAULT_PROCESS_LOG))
            .waitingFor(Wait.forLogMessage(".*Vault server started!.*", 1));
    if (serverTlsCertificate.isPresent()) {
      copyTlsFilesToContainer(serverTlsCertificate.get());
    }
  }

  private void start() throws IOException, GeneralSecurityException {
    LOG.info("Starting vault server container ({})", container.getDockerImageName());
    container.start();
    httpClient = createHttpClient();

    unseal(initVault());
    enableHashicorpKeyValueV2Engine();
  }

  public void shutdown() {
    if (container.isRunning()) {
      LOG.info("Shutting down Vault server container...");
      container.stop();
    } else {
      LOG.info("Vault server container is not running.");
    }
  }

  public String getVaultToken() {
    return vaultToken;
  }

  public String getHost() {
    // "localhost" can resolve to the IPv6 loopback first, while Docker commonly publishes ports on
    // the IPv4 loopback only, which the TLS certificate also names. Pin to 127.0.0.1 in that case.
    final String host = container.getHost();
    return "localhost".equals(host) ? "127.0.0.1" : host;
  }

  public int getPort() {
    return container.getMappedPort(VAULT_PORT);
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
    final JsonNode response =
        sendRequest("POST", getHttpApiPathForSecret(path), Map.of("data", entries));
    if (!response.path("data").hasNonNull("created_time")) {
      throw new IllegalStateException("Unexpected response writing secret: " + response);
    }
    LOG.info("The secret with keys {} was created successfully.", entries.keySet());
    return getHttpApiPathForSecret(path);
  }

  private String serverConfig() throws IOException {
    final Map<String, Object> tcpListener =
        serverTlsCertificate.isPresent()
            ? Map.of(
                "address",
                "0.0.0.0:" + VAULT_PORT,
                "tls_min_version",
                "tls12",
                "tls_cert_file",
                CONTAINER_CERT_FILE,
                "tls_key_file",
                CONTAINER_KEY_FILE)
            : Map.of("address", "0.0.0.0:" + VAULT_PORT, "tls_disable", true);
    final Map<String, Object> config =
        Map.of(
            "storage",
            Map.of("inmem", Map.of()),
            "disable_mlock",
            true,
            "default_lease_ttl",
            "168h",
            "max_lease_ttl",
            "720h",
            "listener",
            Map.of("tcp", tcpListener));
    return objectMapper.writeValueAsString(config);
  }

  private void copyTlsFilesToContainer(final SelfSignedCertificate certificate)
      throws IOException, GeneralSecurityException {
    final Path certificateFile = Files.createTempFile("at_dsl_cert", ".crt");
    final Path privateKeyFile = Files.createTempFile("at_dsl_priv", ".key");
    certificate.writeCertificateToFile(certificateFile);
    certificate.writePrivateKeyToFile(privateKeyFile);

    container
        .withCopyFileToContainer(
            MountableFile.forHostPath(certificateFile, READABLE_FILE_MODE), CONTAINER_CERT_FILE)
        .withCopyFileToContainer(
            MountableFile.forHostPath(privateKeyFile, READABLE_FILE_MODE), CONTAINER_KEY_FILE);
  }

  private HttpClient createHttpClient() throws IOException, GeneralSecurityException {
    if (serverTlsCertificate.isEmpty()) {
      return HttpClient.newHttpClient();
    }

    final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
    trustStore.load(null, null);
    trustStore.setCertificateEntry("vault", serverTlsCertificate.get().getCertificate());
    final TrustManagerFactory trustManagerFactory =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trustManagerFactory.init(trustStore);
    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
    return HttpClient.newBuilder().sslContext(sslContext).build();
  }

  /** Initializes vault, keeping the root token, and returns the single unseal key. */
  private String initVault() {
    LOG.info("Initializing Hashicorp vault ...");
    final JsonNode response =
        sendRequest("PUT", "/v1/sys/init", Map.of("secret_shares", 1, "secret_threshold", 1));
    vaultToken = response.path("root_token").asText(null);
    if (vaultToken == null || !response.path("keys_base64").has(0)) {
      throw new IllegalStateException("Unexpected response initializing vault: " + response);
    }
    LOG.info("Hashicorp vault is initialized");
    return response.path("keys_base64").get(0).asText();
  }

  private void unseal(final String unsealKey) {
    LOG.info("Unseal Hashicorp vault ...");
    final JsonNode response = sendRequest("PUT", "/v1/sys/unseal", Map.of("key", unsealKey));
    if (response.path("sealed").asBoolean(true)) {
      throw new IllegalStateException("Vault is still sealed: " + response);
    }
    LOG.info("Hashicorp vault is unsealed");
  }

  private void enableHashicorpKeyValueV2Engine() {
    LOG.info("Mounting /secret kv-v2 in Hashicorp vault ...");
    sendRequest(
        "POST",
        "/v1/sys/mounts/" + VAULT_ROOT_PATH,
        Map.of("type", "kv", "options", Map.of("version", "2")));
    LOG.info("Hashicorp vault kv-v2 /secret is mounted");
  }

  private String vaultUrl() {
    return String.format(
        "%s://%s:%d", serverTlsCertificate.isPresent() ? "https" : "http", getHost(), getPort());
  }

  private JsonNode sendRequest(final String method, final String path, final Object body) {
    try {
      final HttpRequest.Builder request =
          HttpRequest.newBuilder(URI.create(vaultUrl() + path))
              .header("Content-Type", "application/json")
              .method(
                  method,
                  HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body)));
      if (vaultToken != null) {
        request.header("X-Vault-Token", vaultToken);
      }
      final HttpResponse<String> response =
          httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() / 100 != 2) {
        throw new IllegalStateException(
            String.format(
                "Vault %s %s failed with status %d: %s",
                method, path, response.statusCode(), response.body()));
      }
      return response.body().isEmpty()
          ? objectMapper.createObjectNode()
          : objectMapper.readTree(response.body());
    } catch (final IOException e) {
      throw new IllegalStateException("Vault " + method + " " + path + " failed", e);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Interrupted calling vault " + method + " " + path, e);
    }
  }
}
