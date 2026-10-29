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

import static org.hamcrest.Matchers.hasSize;

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
import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import io.restassured.http.ContentType;
import org.apache.commons.lang3.time.StopWatch;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/*
NOTE: This AT attempts to create and load large number of keys from AWS Secrets Manager which may take several minutes,
hence it should only be manually run in dev/test environment instead of automatically via CI
*/
@EnabledIfEnvironmentVariable(
    named = "AWS_PERF_AT_ENABLED",
    matches = "true",
    disabledReason = "AWS_PERF_AT_ENABLED env variable is required and must be set to true")
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
public class AwsSecretsManagerPerformanceAcceptanceTest extends AcceptanceTestBase {
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
  private static final Integer NUMBER_OF_KEYS =
      Integer.parseInt(Optional.ofNullable(System.getenv("AWS_PERF_AT_KEYS_NUM")).orElse("1000"));
  private static final Duration STARTUP_TIMEOUT = Duration.ofMinutes(10);
  private AwsSecretsManagerUtil awsSecretsManagerUtil;
  private List<BLSKeyPair> blsKeyPairs;

  @BeforeAll
  void setupAwsResources() {
    final StopWatch stopWatch = new StopWatch();
    stopWatch.start();
    awsSecretsManagerUtil =
        new AwsSecretsManagerUtil(
            AWS_REGION, RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY, awsEndpointOverride);
    final SecureRandom secureRandom = new SecureRandom();
    LOG.info("Creating {} AWS keys in Secrets Manager in {}", NUMBER_OF_KEYS, AWS_REGION);
    blsKeyPairs =
        IntStream.range(0, NUMBER_OF_KEYS)
            .parallel()
            .mapToObj(
                __ -> {
                  final BLSKeyPair blsKeyPair = BLSKeyPair.random(secureRandom);
                  awsSecretsManagerUtil.createSecret(
                      blsKeyPair.getPublicKey().toString(),
                      blsKeyPair.getSecretKey().toBytes().toHexString(),
                      Collections.emptyMap());
                  return blsKeyPair;
                })
            .collect(Collectors.toList());
    stopWatch.stop();
    LOG.info("{} Keys created in: {}", NUMBER_OF_KEYS, stopWatch.formatTime());
  }

  @Test
  void largeNumberOfKeysAreLoadedSuccessfully() {
    final AwsVaultParameters awsVaultParameters =
        AwsVaultParametersBuilder.anAwsParameters()
            .withAuthenticationMode(AwsAuthenticationMode.SPECIFIED)
            .withRegion(AWS_REGION)
            .withAccessKeyId(RO_AWS_ACCESS_KEY_ID)
            .withSecretAccessKey(RO_AWS_SECRET_ACCESS_KEY)
            .withPrefixesFilter(List.of(awsSecretsManagerUtil.getSecretsManagerPrefix()))
            .withEndpointOverride(awsEndpointOverride)
            .build();

    final SignerConfigurationBuilder configBuilder =
        new SignerConfigurationBuilder()
            .withMode("eth2")
            .withAwsParameters(awsVaultParameters)
            .withStartupTimeout(STARTUP_TIMEOUT)
            .withLogLevel(Level.INFO);

    final StopWatch stopWatch = new StopWatch();
    stopWatch.start();

    startSigner(configBuilder.build());

    stopWatch.split();
    LOG.info("Web3Signer started in {}", stopWatch.formatSplitTime());

    signer
        .callApiPublicKeys(KeyType.BLS)
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body("", hasSize(NUMBER_OF_KEYS));

    stopWatch.stop();
    LOG.info("Total time taken {}", stopWatch.formatTime());
  }

  @AfterAll
  void cleanUpAwsResources() {
    if (awsSecretsManagerUtil != null) {
      if (blsKeyPairs != null) {
        final StopWatch stopWatch = new StopWatch();
        stopWatch.start();
        blsKeyPairs.parallelStream()
            .forEach(
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
        stopWatch.stop();
        LOG.info("{} keys deleted in {}", NUMBER_OF_KEYS, stopWatch.formatTime());
      }
    }
  }
}
