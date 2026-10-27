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
package tech.pegasys.web3signer.tests.bulkloading;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.core.IsEqual.equalTo;

import tech.pegasys.web3signer.AwsKmsUtil;
import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AwsVaultParameters;
import tech.pegasys.web3signer.signing.config.AwsVaultParametersBuilder;
import tech.pegasys.web3signer.signing.secp256k1.EthPublicKeyUtils;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.net.URI;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@EnabledIfEnvironmentVariable(
    named = "RW_AWS_ACCESS_KEY_ID",
    matches = ".+",
    disabledReason = "RW_AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "RW_AWS_SECRET_ACCESS_KEY",
    matches = ".+",
    disabledReason = "RW_AWS_SECRET_ACCESS_KEY env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_ACCESS_KEY_ID",
    matches = ".+",
    disabledReason = "AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_SECRET_ACCESS_KEY",
    matches = ".+",
    disabledReason = "AWS_SECRET_ACCESS_KEY env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_REGION",
    matches = ".+",
    disabledReason = "AWS_REGION env variable is required")
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // same instance is shared across test methods
public class AwsKmsAcceptanceTest extends AcceptanceTestBase {
  private static final Logger LOG = LogManager.getLogger();
  private static final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private static final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");
  private static final String RO_AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private static final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");
  private static final String AWS_REGION =
      Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-2");

  // can be pointed to an AWS emulator
  private final Optional<URI> awsEndpointOverride =
      System.getenv("AWS_ENDPOINT_OVERRIDE") != null
          ? Optional.of(URI.create(System.getenv("AWS_ENDPOINT_OVERRIDE")))
          : Optional.empty();
  private AwsKmsUtil awsSecretsManagerUtil;

  public record Key(String keyId, String publicKey, Map<String, String> tags) {}

  private final List<Key> keys = new ArrayList<>();

  @BeforeAll
  void setupAwsResources() {
    awsSecretsManagerUtil =
        new AwsKmsUtil(
            AWS_REGION,
            RW_AWS_ACCESS_KEY_ID,
            RW_AWS_SECRET_ACCESS_KEY,
            Optional.empty(),
            awsEndpointOverride);

    // Tags: Org=Protocols, Env=Dev
    var protocolsKeysTags = Map.of("Org", "Protocols", "Env", "Prod");
    var stakingKeysTags = Map.of("Org", "Staking", "Env", "Prod");
    for (int i = 0; i < 2; i++) {
      final String keyId = awsSecretsManagerUtil.createKey(protocolsKeysTags);
      final ECPublicKey publicKey = awsSecretsManagerUtil.publicKey(keyId);
      keys.add(new Key(keyId, EthPublicKeyUtils.toHexString(publicKey), protocolsKeysTags));
    }

    for (int i = 0; i < 2; i++) {
      final String keyId = awsSecretsManagerUtil.createKey(stakingKeysTags);
      final ECPublicKey publicKey = awsSecretsManagerUtil.publicKey(keyId);
      keys.add(new Key(keyId, EthPublicKeyUtils.toHexString(publicKey), stakingKeysTags));
    }

    // keys with no tags
    for (int i = 0; i < 2; i++) {
      final String keyId = awsSecretsManagerUtil.createKey(Map.of());
      final ECPublicKey publicKey = awsSecretsManagerUtil.publicKey(keyId);
      keys.add(new Key(keyId, EthPublicKeyUtils.toHexString(publicKey), Map.of()));
    }
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void keysAreLoadedFromAwsKmsAndReportedByPublicApi(final boolean useConfigFile) {
    final AwsVaultParameters awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.SPECIFIED)
            .withRegion(AWS_REGION)
            .withAccessKeyId(RO_AWS_ACCESS_KEY_ID)
            .withSecretAccessKey(RO_AWS_SECRET_ACCESS_KEY)
            .withTag("Org", "Protocols")
            .withTag("Env", "Prod")
            .withEndpointOverride(awsEndpointOverride)
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth1")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    final Response response = signer.callApiPublicKeys(KeyType.SECP256K1);
    response
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(keys.get(0).publicKey(), keys.get(1).publicKey()));

    final Response healthcheckResponse = signer.healthcheck();
    healthcheckResponse
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("status", equalTo("UP"));

    final String jsonBody = healthcheckResponse.body().asString();
    final int keysLoaded = getAwsBulkLoadingData(jsonBody, "keys-loaded");
    assertThat(keysLoaded).isEqualTo(2);
  }

  @Test
  void healthCheckErrorCountWhenInvalidCredentialsAreUsed() {
    final boolean useConfigFile = false;
    final AwsVaultParameters invalidCredsParams =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.SPECIFIED)
            .withRegion("us-east-2")
            .withAccessKeyId("invalid")
            .withSecretAccessKey("invalid")
            .withPrefixesFilter(List.of("shouldNotExist/"))
            .withEndpointOverride(Optional.empty())
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth1")
            .withAwsParameters(invalidCredsParams);

    startSigner(configBuilder.build());

    final String healthCheckJsonBody = signer.healthcheck().body().asString();

    int keysLoaded = getAwsBulkLoadingData(healthCheckJsonBody, "keys-loaded");
    int errorCount = getAwsBulkLoadingData(healthCheckJsonBody, "error-count");

    assertThat(keysLoaded).isEqualTo(0);
    assertThat(errorCount).isEqualTo(1);
    assertThat(new JsonObject(healthCheckJsonBody).getString("status")).isEqualTo("DOWN");
  }

  private static int getAwsBulkLoadingData(String healthCheckJsonBody, String dataKey) {
    final JsonObject jsonObject = new JsonObject(healthCheckJsonBody);
    return jsonObject.getJsonArray("checks").stream()
        .map(JsonObject.class::cast)
        .filter(check -> "keys-check".equals(check.getString("id")))
        .flatMap(check -> check.getJsonArray("checks").stream())
        .map(JsonObject.class::cast)
        .filter(check -> "aws-bulk-loading".equals(check.getString("id")))
        .mapToInt(check -> check.getJsonObject("data").getInteger(dataKey))
        .findFirst()
        .orElse(-1);
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void keysAreLoadedFromAwsKmsWithEnvironmentAuthModeAndReportedByPublicApi(
      final boolean useConfigFile) {
    final AwsVaultParameters awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.ENVIRONMENT)
            .withTag("Org", "Staking")
            .withTag("Env", "Prod")
            .withEndpointOverride(awsEndpointOverride)
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth1")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    signer
        .callApiPublicKeys(KeyType.SECP256K1)
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body(
            "",
            containsInAnyOrder(keys.get(2).publicKey(), keys.get(3).publicKey()),
            "",
            hasSize(2));
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void keysWithoutTagsAreLoadedFromAwsKmsAndReportedByPublicApi(final boolean useConfigFile) {
    var awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.SPECIFIED)
            .withRegion(AWS_REGION)
            .withAccessKeyId(RO_AWS_ACCESS_KEY_ID)
            .withSecretAccessKey(RO_AWS_SECRET_ACCESS_KEY)
            .withEndpointOverride(awsEndpointOverride)
            .build();

    var configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth1")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    var response = signer.callApiPublicKeys(KeyType.SECP256K1);
    response
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(keys.stream().map(Key::publicKey).toArray()), "", hasSize(6));

    var healthcheckResponse = signer.healthcheck();
    healthcheckResponse
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("status", equalTo("UP"));

    var jsonBody = healthcheckResponse.body().asString();
    var keysLoaded = getAwsBulkLoadingData(jsonBody, "keys-loaded");
    assertThat(keysLoaded).isEqualTo(6);
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void keysWitSingleTagAreLoadedFromAwsKmsAndReportedByPublicApi(final boolean useConfigFile) {
    var awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.SPECIFIED)
            .withRegion(AWS_REGION)
            .withAccessKeyId(RO_AWS_ACCESS_KEY_ID)
            .withSecretAccessKey(RO_AWS_SECRET_ACCESS_KEY)
            .withEndpointOverride(awsEndpointOverride)
            .withTag("Env", "Prod")
            .build();

    var configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth1")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    var expectedKeysMatchingTag =
        keys.stream()
            .filter(key -> "Prod".equals(key.tags.get("Env")))
            .map(Key::publicKey)
            .toList()
            .toArray();
    var response = signer.callApiPublicKeys(KeyType.SECP256K1);
    response
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(expectedKeysMatchingTag), "", hasSize(4));

    var healthcheckResponse = signer.healthcheck();
    healthcheckResponse
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("status", equalTo("UP"));

    var jsonBody = healthcheckResponse.body().asString();
    var keysLoaded = getAwsBulkLoadingData(jsonBody, "keys-loaded");
    assertThat(keysLoaded).isEqualTo(4);
  }

  @AfterAll
  void cleanUpAwsResources() {
    if (awsSecretsManagerUtil != null) {
      keys.forEach(
          key -> {
            try {
              awsSecretsManagerUtil.deleteKey(key.keyId());
            } catch (final RuntimeException e) {
              LOG.warn("Unexpected error while deleting key {}: {}", key.keyId(), e.getMessage());
            }
          });
    }
  }
}
