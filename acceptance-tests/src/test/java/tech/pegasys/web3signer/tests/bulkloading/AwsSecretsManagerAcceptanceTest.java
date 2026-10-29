/*
 * Copyright 2022 ConsenSys AG.
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
import static tech.pegasys.web3signer.core.config.HealthCheckNames.KEYS_CHECK_AWS_BULK_LOADING;
import static tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil.getHealtcheckKeysLoaded;
import static tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil.getHealthcheckErrorCount;
import static tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil.getHealthcheckStatusValue;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.AwsSecretsManagerUtil;
import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AwsVaultParameters;
import tech.pegasys.web3signer.signing.config.AwsVaultParametersBuilder;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.net.URI;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import io.restassured.http.ContentType;
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
public class AwsSecretsManagerAcceptanceTest extends AcceptanceTestBase {
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
  private AwsSecretsManagerUtil awsSecretsManagerUtil;
  private final List<BLSKeyPair> blsKeyPairs = new ArrayList<>();

  @BeforeAll
  void setupAwsResources() {
    awsSecretsManagerUtil =
        new AwsSecretsManagerUtil(
            AWS_REGION, RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY, awsEndpointOverride);
    final SecureRandom secureRandom = new SecureRandom();

    for (int i = 0; i < 4; i++) {
      final BLSKeyPair blsKeyPair = BLSKeyPair.random(secureRandom);
      awsSecretsManagerUtil.createSecret(
          blsKeyPair.getPublicKey().toString(),
          blsKeyPair.getSecretKey().toBytes().toHexString(),
          Map.of("TagName" + i, "TagValue" + i));
      blsKeyPairs.add(blsKeyPair);
    }
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void secretsAreLoadedFromAWSSecretsManagerAndReportedByPublicApi(final boolean useConfigFile) {
    final AwsVaultParameters awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.SPECIFIED)
            .withRegion(AWS_REGION)
            .withAccessKeyId(RO_AWS_ACCESS_KEY_ID)
            .withSecretAccessKey(RO_AWS_SECRET_ACCESS_KEY)
            .withPrefixesFilter(List.of(awsSecretsManagerUtil.getSecretsManagerPrefix()))
            .withTag("TagName0", "TagValue0")
            .withTag("TagName1", "TagValue1")
            .withEndpointOverride(awsEndpointOverride)
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth2")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    final String healthCheckJsonBody = signer.healthcheck().body().asString();
    int keysLoaded = getHealtcheckKeysLoaded(healthCheckJsonBody, KEYS_CHECK_AWS_BULK_LOADING);

    assertThat(keysLoaded).isEqualTo(2);

    signer
        .callApiPublicKeys(KeyType.BLS)
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body(
            "",
            containsInAnyOrder(
                blsKeyPairs.get(0).getPublicKey().toString(),
                blsKeyPairs.get(1).getPublicKey().toString()),
            "",
            hasSize(2));
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
            .withMode("eth2")
            .withAwsParameters(invalidCredsParams);

    startSigner(configBuilder.build());

    final String healthCheckJsonBody = signer.healthcheck().body().asString();

    int keysLoaded = getHealtcheckKeysLoaded(healthCheckJsonBody, KEYS_CHECK_AWS_BULK_LOADING);
    int errorCount = getHealthcheckErrorCount(healthCheckJsonBody, KEYS_CHECK_AWS_BULK_LOADING);

    assertThat(keysLoaded).isEqualTo(0);
    assertThat(errorCount).isEqualTo(1);
    assertThat(getHealthcheckStatusValue(healthCheckJsonBody)).isEqualTo("DOWN");
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void secretsAreLoadedFromAWSSecretsManagerWithEnvironmentAuthModeAndReportedByPublicApi(
      final boolean useConfigFile) {
    final AwsVaultParameters awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withEnabled(true)
            .withAuthenticationMode(AwsAuthenticationMode.ENVIRONMENT)
            .withPrefixesFilter(List.of(awsSecretsManagerUtil.getSecretsManagerPrefix()))
            .withTag("TagName2", "TagValue2")
            .withTag("TagName3", "TagValue3")
            .withEndpointOverride(awsEndpointOverride)
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth2")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    signer
        .callApiPublicKeys(KeyType.BLS)
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body(
            "",
            containsInAnyOrder(
                blsKeyPairs.get(2).getPublicKey().toString(),
                blsKeyPairs.get(3).getPublicKey().toString()),
            "",
            hasSize(2));
  }

  @AfterAll
  void cleanUpAwsResources() {
    if (awsSecretsManagerUtil != null) {
      blsKeyPairs.forEach(
          keyPair -> {
            final String secretName = keyPair.getPublicKey().toString();
            try {
              awsSecretsManagerUtil.deleteSecret(secretName);
            } catch (final RuntimeException e) {
              LOG.warn(
                  "Unexpected error while deleting key {}{}: {}",
                  awsSecretsManagerUtil.getSecretsManagerPrefix(),
                  secretName,
                  e.getMessage());
            }
          });
      awsSecretsManagerUtil.close();
    }
  }
}
