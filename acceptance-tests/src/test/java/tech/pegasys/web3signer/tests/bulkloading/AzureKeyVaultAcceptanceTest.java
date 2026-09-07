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
package tech.pegasys.web3signer.tests.bulkloading;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static tech.pegasys.web3signer.core.config.HealthCheckNames.KEYS_CHECK_AZURE_BULK_LOADING;
import static tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil.getHealtcheckKeysLoaded;
import static tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil.getHealthcheckErrorCount;
import static tech.pegasys.web3signer.keystorage.azure.AzureKeyVault.createUsingClientSecretCredentials;

import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.dsl.azure.AzureKeyVaultEmulator;
import tech.pegasys.web3signer.dsl.azure.MockAzureAuthorityExtension;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultParameters;
import tech.pegasys.web3signer.signing.config.DefaultAzureKeyVaultParameters;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

public class AzureKeyVaultAcceptanceTest extends AcceptanceTestBase {
  private static final Logger LOG = LogManager.getLogger();
  private static final AzureKeyVaultEmulator EMULATOR = AzureKeyVaultEmulator.getInstance();

  @RegisterExtension
  static final MockAzureAuthorityExtension MOCK_AUTHORITY = new MockAzureAuthorityExtension();

  private static AzureOverrides emulatorOverrides() {
    return new AzureOverrides(
        Optional.of(URI.create(EMULATOR.getVaultUrl())),
        Optional.of(URI.create(MOCK_AUTHORITY.getAuthorityHostUrl())),
        Optional.of(EMULATOR.getTrustCertificatePath()));
  }

  /**
   * These keys are expected to be pre-seeded in the Azure Key Vault emulator. The first secret is
   * multivalue with 10 keys. The second secret is created with single value/key and tagged with
   * ENV:TEST.
   *
   * @return list of expected BLS public keys in hex format
   */
  static List<String> expectedBLSPubKeys() {
    return getBLSSecretsFromEmulator(emulatorOverrides()).stream()
        .filter(
            azureSecret ->
                azureSecret.tags() != null
                    && AzureKeyVaultEmulator.FIXTURE_TAG_VALUE.equals(
                        azureSecret.tags().get(AzureKeyVaultEmulator.FIXTURE_TAG_KEY)))
        .flatMap(azureSecret -> azureSecret.values().stream())
        .map(
            secret ->
                BLSSecretKey.fromBytes(Bytes32.fromHexString(secret)).toPublicKey().toHexString())
        .toList();
  }

  static List<String> expectedBLSPubKeyWithTag(final String tagKey, final String tagValue) {
    return getBLSSecretsFromEmulator(emulatorOverrides()).stream()
        .filter(
            azureSecret ->
                azureSecret.tags() != null
                    && azureSecret.tags().containsKey(tagKey)
                    && azureSecret.tags().get(tagKey).equals(tagValue))
        .flatMap(azureSecret -> azureSecret.values().stream())
        .map(
            secret ->
                BLSSecretKey.fromBytes(Bytes32.fromHexString(secret)).toPublicKey().toHexString())
        .toList();
  }

  /**
   * Expected SECP256K1 public keys pre-seeded in the Azure Key Vault emulator.
   *
   * @return list of expected SECP256K1 public keys in hex format
   */
  static List<String> expectedSECPPubKeys() {
    return getSECPKeysFromEmulator(emulatorOverrides()).stream()
        .filter(
            azureKey ->
                azureKey.tags() != null
                    && AzureKeyVaultEmulator.FIXTURE_TAG_VALUE.equals(
                        azureKey.tags().get(AzureKeyVaultEmulator.FIXTURE_TAG_KEY)))
        .map(AzureKeyVault.AzureKey::publicKeyHex)
        .toList();
  }

  static List<String> expectedSECPPubKeyWithTag(final String tagKey, final String tagValue) {
    return getSECPKeysFromEmulator(emulatorOverrides()).stream()
        .filter(
            azureSecret ->
                azureSecret.tags() != null
                    && azureSecret.tags().containsKey(tagKey)
                    && azureSecret.tags().get(tagKey).equals(tagValue))
        .map(AzureKeyVault.AzureKey::publicKeyHex)
        .toList();
  }

  @VisibleForTesting
  public static List<AzureKeyVault.AzureKey> getSECPKeysFromEmulator(
      final AzureOverrides azureOverrides) {
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      final AzureKeyVault azureKeyVault =
          createUsingClientSecretCredentials(
              "unused",
              "unused",
              AzureKeyVaultEmulator.TENANT_ID,
              "unused",
              executor,
              60,
              azureOverrides);

      final var azureKeys = azureKeyVault.getAzureKeys();
      assertThat(azureKeys).isNotEmpty();
      return azureKeys;
    }
  }

  public static List<AzureKeyVault.AzureSecret> getBLSSecretsFromEmulator(
      final AzureOverrides azureOverrides) {
    try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
      final AzureKeyVault azureKeyVault =
          createUsingClientSecretCredentials(
              "unused",
              "unused",
              AzureKeyVaultEmulator.TENANT_ID,
              "unused",
              executor,
              60,
              azureOverrides);

      return azureKeyVault.getAzureSecrets();
    }
  }

  @ParameterizedTest(name = "{index} - {0} useConfigFile={1}")
  @MethodSource("keyTypeAndConfigFileCombos")
  void ensureSecretsInKeyVaultAreLoadedAndReportedViaPublicKeysApi(
      final KeyType keyType, final boolean useConfigFile) {
    final List<String> expectedPubKeys =
        keyType == KeyType.BLS ? expectedBLSPubKeys() : expectedSECPPubKeys();

    final AzureKeyVaultParameters azureParams =
        new DefaultAzureKeyVaultParameters(
            "unused",
            "unused",
            AzureKeyVaultEmulator.TENANT_ID,
            "unused",
            Map.of(AzureKeyVaultEmulator.FIXTURE_TAG_KEY, AzureKeyVaultEmulator.FIXTURE_TAG_VALUE),
            60,
            true,
            emulatorOverrides());

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withMode(calculateMode(keyType))
            .withAzureKeyVaultParameters(azureParams)
            .withUseConfigFile(useConfigFile)
            .withOverriddenCA(EMULATOR.getTlsCertificateDefinition());

    startSigner(configBuilder.build());

    final Response response = signer.callApiPublicKeys(keyType);
    response
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(expectedPubKeys.toArray()));

    final Response healthcheckResponse = signer.healthcheck();
    healthcheckResponse
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("status", equalTo("UP"));

    final String jsonBody = healthcheckResponse.body().asString();
    final int keysLoaded = getHealtcheckKeysLoaded(jsonBody, KEYS_CHECK_AZURE_BULK_LOADING);
    assertThat(keysLoaded).isEqualTo(expectedPubKeys.size());
  }

  static Stream<Arguments> keyTypeAndConfigFileCombos() {
    return Stream.of(
        Arguments.of(KeyType.BLS, true),
        Arguments.of(KeyType.BLS, false),
        Arguments.of(KeyType.SECP256K1, true),
        Arguments.of(KeyType.SECP256K1, false));
  }

  @ParameterizedTest(name = "{index} - KeyType: {0}")
  @EnumSource(KeyType.class)
  void azureSecretsViaTag(final KeyType keyType) {
    final AzureKeyVaultParameters azureParams =
        new DefaultAzureKeyVaultParameters(
            "unused",
            "unused",
            AzureKeyVaultEmulator.TENANT_ID,
            "unused",
            Map.of("ENV", "TEST"),
            60,
            true,
            emulatorOverrides());

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withMode(calculateMode(keyType))
            .withAzureKeyVaultParameters(azureParams)
            .withUseConfigFile(true)
            .withOverriddenCA(EMULATOR.getTlsCertificateDefinition());

    startSigner(configBuilder.build());

    final List<String> expectedPubKey =
        keyType == KeyType.BLS
            ? expectedBLSPubKeyWithTag("ENV", "TEST")
            : expectedSECPPubKeyWithTag("ENV", "TEST");
    final Response response = signer.callApiPublicKeys(keyType);
    response
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(expectedPubKey.toArray()));

    // the tag filter will return only valid keys. The healthcheck should be UP
    final Response healthcheckResponse = signer.healthcheck();
    healthcheckResponse
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("status", equalTo("UP"));

    // keys loaded should be >= 1 and error count should be 0
    final String jsonBody = healthcheckResponse.body().asString();
    final int keysLoaded = getHealtcheckKeysLoaded(jsonBody, KEYS_CHECK_AZURE_BULK_LOADING);
    final int errorCount = getHealthcheckErrorCount(jsonBody, KEYS_CHECK_AZURE_BULK_LOADING);
    assertThat(keysLoaded).isNotZero();
    assertThat(errorCount).isZero();
  }

  /**
   * Diagnostic: bulk-loads 500 SECP256K1 keys with an isolated tag and logs elapsed time. The
   * cached {@code AzureKeyVault} reuses its HTTP client, connection pool, and AAD token across all
   * keys. The generous startup timeout keeps this a timing measurement rather than a flaky gate.
   */
  @Test
  void largeNumberOfSecpKeysCanBeBulkLoaded() {
    final String tagKey = "BULK_LOAD_STRESS";
    final String tagValue = "true";
    final int keyCount = 500;
    EMULATOR.seedAdditionalSecpKeys(keyCount, Map.of(tagKey, tagValue));

    final AzureKeyVaultParameters azureParams =
        new DefaultAzureKeyVaultParameters(
            "unused",
            "unused",
            AzureKeyVaultEmulator.TENANT_ID,
            "unused",
            Map.of(tagKey, tagValue),
            60,
            true,
            emulatorOverrides());

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withMode(calculateMode(KeyType.SECP256K1))
            .withAzureKeyVaultParameters(azureParams)
            .withUseConfigFile(true)
            .withOverriddenCA(EMULATOR.getTlsCertificateDefinition())
            .withStartupTimeout(Duration.ofMinutes(5));

    final long startNanos = System.nanoTime();
    startSigner(configBuilder.build());
    final Duration elapsed = Duration.ofNanos(System.nanoTime() - startNanos);
    LOG.info(
        "Bulk-loaded {} Azure SECP256K1 keys in {} ms ({} ms/key)",
        keyCount,
        elapsed.toMillis(),
        elapsed.toMillis() / (double) keyCount);

    final Response healthcheckResponse = signer.healthcheck();
    healthcheckResponse
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("status", equalTo("UP"));

    final String jsonBody = healthcheckResponse.body().asString();
    final int keysLoaded = getHealtcheckKeysLoaded(jsonBody, KEYS_CHECK_AZURE_BULK_LOADING);
    final int errorCount = getHealthcheckErrorCount(jsonBody, KEYS_CHECK_AZURE_BULK_LOADING);
    assertThat(errorCount).isZero();
    assertThat(keysLoaded).isEqualTo(keyCount);
  }

  @ParameterizedTest
  @EnumSource(KeyType.class)
  void invalidVaultParametersFailsToLoadKeys(final KeyType keyType) {
    // a definitely-unbound local port (requires root, never listening) gives a real, deterministic
    // connection failure once "vault name" no longer drives routing.
    final AzureKeyVaultParameters azureParams =
        new DefaultAzureKeyVaultParameters(
            "unused",
            "unused",
            AzureKeyVaultEmulator.TENANT_ID,
            "unused",
            Map.of(),
            60,
            true,
            new AzureOverrides(
                Optional.of(URI.create("https://localhost:1")),
                Optional.of(URI.create(MOCK_AUTHORITY.getAuthorityHostUrl())),
                Optional.of(EMULATOR.getTrustCertificatePath())));

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withMode(calculateMode(keyType))
            .withAzureKeyVaultParameters(azureParams)
            .withUseConfigFile(true)
            .withOverriddenCA(EMULATOR.getTlsCertificateDefinition());

    startSigner(configBuilder.build());

    final Response response = signer.callApiPublicKeys(keyType);
    response.then().statusCode(200).contentType(ContentType.JSON).body("", hasSize(0));

    signer
        .healthcheck()
        .then()
        .statusCode(503)
        .contentType(ContentType.JSON)
        .body("status", equalTo("DOWN"));
  }

  @ParameterizedTest
  @EnumSource(KeyType.class)
  void envVarsAreUsedToDefaultAzureParams(final KeyType keyType) {
    // This ensures env vars correspond to the WEB3SIGNER_<subcommand>_<option> syntax
    final String envPrefix = keyType == KeyType.BLS ? "WEB3SIGNER_ETH2_" : "WEB3SIGNER_ETH1_";
    final Map<String, String> env =
        Map.of(
            envPrefix + "AZURE_VAULT_ENABLED",
            "true",
            envPrefix + "AZURE_VAULT_NAME",
            "unused",
            envPrefix + "AZURE_CLIENT_ID",
            "unused",
            envPrefix + "AZURE_CLIENT_SECRET",
            "unused",
            envPrefix + "AZURE_TENANT_ID",
            AzureKeyVaultEmulator.TENANT_ID,
            envPrefix + "XAZURE_ENDPOINT_OVERRIDE",
            EMULATOR.getVaultUrl(),
            envPrefix + "XAZURE_AUTHORITY_HOST_OVERRIDE",
            MOCK_AUTHORITY.getAuthorityHostUrl(),
            envPrefix + "XAZURE_TRUST_CERTIFICATE_OVERRIDE",
            EMULATOR.getTrustCertificatePath().toString(),
            envPrefix + "AZURE_TAGS",
            AzureKeyVaultEmulator.FIXTURE_TAG_KEY + "=" + AzureKeyVaultEmulator.FIXTURE_TAG_VALUE);

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withMode(calculateMode(keyType))
            .withEnvironment(env)
            .withUseConfigFile(true)
            .withOverriddenCA(EMULATOR.getTlsCertificateDefinition());

    startSigner(configBuilder.build());

    final Response response = signer.callApiPublicKeys(keyType);
    final List<String> expectedPubKeys =
        keyType == KeyType.BLS ? expectedBLSPubKeys() : expectedSECPPubKeys();
    response
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(expectedPubKeys.toArray()));
  }
}
