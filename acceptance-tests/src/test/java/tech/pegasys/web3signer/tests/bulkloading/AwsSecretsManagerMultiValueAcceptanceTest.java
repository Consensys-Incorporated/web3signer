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

import static org.hamcrest.Matchers.containsInAnyOrder;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.web3signer.AwsSecretsManagerUtil;
import tech.pegasys.web3signer.BLSTestUtil;
import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AwsVaultParameters;
import tech.pegasys.web3signer.signing.config.AwsVaultParametersBuilder;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import io.restassured.http.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
public class AwsSecretsManagerMultiValueAcceptanceTest extends AcceptanceTestBase {
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
  private final List<BLSKeyPair> blsKeyPairList = new ArrayList<>(400);

  @BeforeAll
  void setupAwsResources() {
    for (int i = 0; i < 400; i++) {
      blsKeyPairList.add(BLSTestUtil.randomKeyPair(i));
    }

    awsSecretsManagerUtil =
        new AwsSecretsManagerUtil(
            AWS_REGION, RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY, awsEndpointOverride);

    for (int i = 0; i < 4; i++) {
      String multilinePrivKeys =
          blsKeyPairList.subList(i * 100, (i + 1) * 100).stream()
              .map(bls -> bls.getSecretKey().toBytes().toString())
              .collect(Collectors.joining(System.lineSeparator()));
      awsSecretsManagerUtil.createSecret(
          "multi" + i, multilinePrivKeys, Map.of("multivalue", "true"));
    }
  }

  @ParameterizedTest(name = "{index} -> use config file: {0}")
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
            .withTag("multivalue", "")
            .withEndpointOverride(awsEndpointOverride)
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth2")
            .withAwsParameters(awsVaultParameters);

    startSigner(configBuilder.build());

    final List<String> publicKeys =
        blsKeyPairList.stream()
            .map(BLSKeyPair::getPublicKey)
            .map(BLSPublicKey::toHexString)
            .toList();

    signer
        .callApiPublicKeys(KeyType.BLS)
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", containsInAnyOrder(publicKeys.toArray(String[]::new)));
  }

  @AfterAll
  void cleanUpAwsResources() {
    if (awsSecretsManagerUtil != null) {
      for (int i = 0; i < 4; i++) {
        final String secretName = "multi" + i;
        try {
          awsSecretsManagerUtil.deleteSecret(secretName);
        } catch (final RuntimeException e) {
          LOG.warn(
              "Unexpected error while deleting key {}{}: {}",
              awsSecretsManagerUtil.getSecretsManagerPrefix(),
              secretName,
              e.getMessage());
        }
      }
      awsSecretsManagerUtil.close();
    }
  }
}
