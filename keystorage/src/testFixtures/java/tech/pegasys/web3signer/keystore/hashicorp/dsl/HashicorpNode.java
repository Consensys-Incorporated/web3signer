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

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.keystore.dsl.certificates.SelfSignedCertificate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.awaitility.Awaitility;
import org.zeroturnaround.exec.ProcessExecutor;
import org.zeroturnaround.exec.ProcessResult;
import org.zeroturnaround.exec.stream.LogOutputStream;
import org.zeroturnaround.exec.stream.slf4j.Slf4jStream;

public class HashicorpNode {
  private static final Logger LOG = LogManager.getLogger();
  private static final Logger VAULT_PROCESS_LOG =
      LogManager.getLogger(HashicorpNode.class + ".VaultServer");

  // automatically sets by gradle test tasks. Should be set manually in IDE if not using gradle
  private static final String vaultBinary = System.getProperty("vaultBinary");

  private static final String VAULT_ROOT_PATH = "secret";

  private final Optional<SelfSignedCertificate> serverTlsCertificate;
  private final Path vaultPath;
  private final Pattern portPattern = Pattern.compile(".*cluster address: \".*:(\\d+)\".*");
  private final ObjectMapper objectMapper = new ObjectMapper();

  private static final String HOST = "127.0.0.1";
  private final AtomicInteger port = new AtomicInteger(0);

  // initialized after start
  private HashicorpVaultCommands hashicorpVaultCommands;
  private Future<ProcessResult> serverFuture;
  private String vaultToken;

  /**
   * Create a local Hashicorp Vault process and start it.
   *
   * <p>System property vaultInstallDir and vaultBinary should be set before calling this method.
   *
   * @param withTls if TLS should be enabled
   * @return A started instance of HashicorpNode
   */
  public static HashicorpNode createAndStartHashicorp(final boolean withTls) {
    if (vaultBinary == null) {
      throw new IllegalStateException("System property [vaultBinary] is missing.");
    }

    final Path vault = Path.of(vaultBinary);
    if (!vault.toFile().exists()) {
      throw new IllegalStateException("Vault binary doesn't exist. " + vault.toString());
    }

    try {
      final HashicorpNode hashicorpNode =
          withTls
              ? new HashicorpNode(vault, SelfSignedCertificate.generate())
              : new HashicorpNode(vault, null);
      hashicorpNode.start();
      return hashicorpNode;
    } catch (final Exception e) {
      throw new RuntimeException("Failed to create Hashicorp Node.", e);
    }
  }

  private HashicorpNode(final Path vaultPath, final SelfSignedCertificate serverTlsCertificate) {
    this.vaultPath = vaultPath;
    this.serverTlsCertificate = Optional.ofNullable(serverTlsCertificate);
  }

  void start()
      throws IOException, CertificateEncodingException, TimeoutException, InterruptedException {
    startVaultServer();
    hashicorpVaultCommands = new HashicorpVaultCommands(vaultPath.toString(), vaultUrl());

    final HashicorpVaultTokens hashicorpVaultTokens = initVault();
    unseal(hashicorpVaultTokens.getUnsealKey());
    enableHashicorpKeyValueV2Engine();
  }

  // Start vault server. Sets port variable once started.
  private void startVaultServer() throws IOException, CertificateEncodingException {
    LOG.info("Starting vault server");
    final AtomicBoolean serverStarted = new AtomicBoolean(false);
    serverFuture =
        new ProcessExecutor(vaultPath.toString(), "server", "-config=" + getVaultServerConfig())
            .readOutput(true)
            .redirectOutput(
                new LogOutputStream() {
                  @Override
                  protected void processLine(final String line) {
                    VAULT_PROCESS_LOG.info(line);

                    // process Vault port (i.e. cluster port - 1)
                    final Matcher matcher = portPattern.matcher(line);
                    if (matcher.find()) {
                      port.set(Integer.parseInt(matcher.group(1)) - 1);
                    }

                    if (line.contains("Vault server started!")) {
                      serverStarted.set(true);
                    }
                  }
                })
            .destroyOnExit()
            .start()
            .getFuture();

    Awaitility.await().atMost(5, TimeUnit.SECONDS).untilTrue(serverStarted);
  }

  public void shutdown() {
    if (serverFuture != null) {
      LOG.info("Shutting down Vault server Process...");
      serverFuture.cancel(true);
      serverFuture = null;
    } else {
      LOG.info("Vault server process is not running.");
    }
  }

  public String getVaultToken() {
    return vaultToken;
  }

  public String getHost() {
    return HOST;
  }

  public int getPort() {
    return port.intValue();
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
    final String secretPutPath = String.join("/", VAULT_ROOT_PATH, path);
    for (final Map.Entry<String, String> entry : entries.entrySet()) {
      try {
        final String commandOutput =
            executeCommandAndGetOutput(
                hashicorpVaultCommands.putSecretCommand(
                    entry.getKey(), entry.getValue(), secretPutPath));

        assertThat(commandOutput.contains("created_time")).isTrue();
      } catch (final IOException | InterruptedException | TimeoutException e) {
        throw new RuntimeException("Error adding secrets to vault", e);
      }

      LOG.info("The secret ({}) was created successfully.", entry.getKey());
    }
    return getHttpApiPathForSecret(path);
  }

  private Path getVaultServerConfig() throws IOException, CertificateEncodingException {
    final String config =
        "{\"storage\": {\"inmem\":{}}, \"disable_mlock\": true, "
            + "\"default_lease_ttl\": \"168h\", \"max_lease_ttl\": \"720h\", "
            + "\"listener\": {\"tcp\": {"
            + "\"address\":\"127.0.0.1:0\""
            + ","
            + tlsEnvConfig()
            + "}}}";

    final Path configFile = Files.createTempFile("at_vault_config", ".json");
    return Files.writeString(configFile, config);
  }

  private String tlsEnvConfig() throws IOException, CertificateEncodingException {
    if (!isTlsEnabled()) {
      return "\"tls_disable\":\"true\"";
    }

    final Path certificate = Files.createTempFile("at_dsl_cert", ".crt");
    final Path privateKey = Files.createTempFile("at_dsl_priv", ".key");

    serverTlsCertificate.get().writeCertificateToFile(certificate);
    serverTlsCertificate.get().writePrivateKeyToFile(privateKey);

    return String.format(
        "\"tls_min_version\": \"tls12\", \"tls_cert_file\": \"%s\", \"tls_key_file\": \"%s\"",
        certificate, privateKey);
  }

  private boolean isTlsEnabled() {
    return serverTlsCertificate.isPresent();
  }

  private String vaultUrl() {
    return String.format("%s://%s:%d", isTlsEnabled() ? "https" : "http", getHost(), getPort());
  }

  private HashicorpVaultTokens initVault()
      throws InterruptedException, TimeoutException, IOException {
    LOG.info("Initializing Hashicorp vault ...");

    final String commandOutput = executeCommandAndGetOutput(hashicorpVaultCommands.initCommand());

    final String rootToken;
    final String unsealKey;
    try {
      final JsonNode jsonNode = objectMapper.readTree(commandOutput);
      rootToken = jsonNode.get("root_token").asText();
      final JsonNode unsealKeyJsonNodeArray = jsonNode.get("unseal_keys_b64");
      assertThat(unsealKeyJsonNodeArray.isArray()).isTrue();
      unsealKey = unsealKeyJsonNodeArray.get(0).asText();
    } catch (IOException e) {
      throw new RuntimeException("Error in parsing json output from vault unseal command", e);
    }
    assertThat(rootToken).isNotNull();
    assertThat(unsealKey).isNotNull();
    LOG.info("Hashicorp vault is initialized");

    this.vaultToken = rootToken;
    return new HashicorpVaultTokens(unsealKey, rootToken);
  }

  private void unseal(final String unsealKey)
      throws InterruptedException, TimeoutException, IOException {
    LOG.info("Unseal Hashicorp vault ...");
    final String commandOutput =
        executeCommandAndGetOutput(hashicorpVaultCommands.unseal(unsealKey));

    try {
      final JsonNode jsonNode = objectMapper.readTree(commandOutput);
      assertThat(jsonNode.get("sealed").asBoolean()).isFalse();
    } catch (IOException e) {
      throw new RuntimeException("Error in parsing json output from vault unseal command", e);
    }

    LOG.info("Hashicorp vault is unsealed");
  }

  private void enableHashicorpKeyValueV2Engine()
      throws InterruptedException, TimeoutException, IOException {
    LOG.info("Mounting /secret kv-v2 in Hashicorp vault ...");
    final String commandOutput =
        executeCommandAndGetOutput(
            hashicorpVaultCommands.enableSecretEngineCommand(VAULT_ROOT_PATH));
    assertThat(commandOutput.contains("Success")).isTrue();
    LOG.info("Hashicorp vault kv-v2 /secret is mounted");
  }

  private String executeCommandAndGetOutput(final String[] command)
      throws InterruptedException, TimeoutException, IOException {
    return new ProcessExecutor(command)
        .readOutput(true)
        .redirectOutput(Slf4jStream.of(getClass()).asInfo())
        .environment(getEnvironmentMap())
        .destroyOnExit()
        .execute()
        .outputUTF8();
  }

  private Map<String, String> getEnvironmentMap() {
    final Map<String, String> environment = new HashMap<>();
    environment.put("VAULT_SKIP_VERIFY", "true");
    if (vaultToken != null) {
      environment.put("VAULT_TOKEN", vaultToken);
    }
    return environment;
  }
}
