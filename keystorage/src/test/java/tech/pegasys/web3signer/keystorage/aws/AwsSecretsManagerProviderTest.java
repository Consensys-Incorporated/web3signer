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
package tech.pegasys.web3signer.keystorage.aws;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.util.Optional;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(
    named = "AWS_ACCESS_KEY_ID_TEST2",
    matches = ".+",
    disabledReason = "RW_AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_SECRET_ACCESS_KEY_TEST2",
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
class AwsSecretsManagerProviderTest {

  private final String AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private final String AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");
  private final String AWS_REGION =
      Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-2");
  private final String DIFFERENT_AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID_TEST2");
  private final String DIFFERENT_AWS_SECRET_ACCESS_KEY =
      System.getenv("AWS_SECRET_ACCESS_KEY_TEST2");
  private final String DIFFERENT_AWS_REGION = "us-east-1";

  // can be pointed to an AWS emulator
  private final Optional<URI> awsEndpointOverride =
      System.getenv("AWS_ENDPOINT_OVERRIDE") != null
          ? Optional.of(URI.create(System.getenv("AWS_ENDPOINT_OVERRIDE")))
          : Optional.empty();

  private AwsSecretsManagerProvider awsSecretsManagerProvider;

  private AwsSecretsManager createDefaultSecretsManager() {
    return awsSecretsManagerProvider.createAwsSecretsManager(awsEndpointOverride);
  }

  private AwsSecretsManager createSpecifiedSecretsManager() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION, awsEndpointOverride);
  }

  private AwsSecretsManager createSecretsManagerDifferentKeys() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        DIFFERENT_AWS_ACCESS_KEY_ID,
        DIFFERENT_AWS_SECRET_ACCESS_KEY,
        AWS_REGION,
        awsEndpointOverride);
  }

  private AwsSecretsManager createSecretsManagerDifferentRegion() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, DIFFERENT_AWS_REGION, awsEndpointOverride);
  }

  private AwsSecretsManager createSecretsManagerDifferentKeysDifferentRegion() {
    return awsSecretsManagerProvider.createAwsSecretsManager(
        DIFFERENT_AWS_ACCESS_KEY_ID,
        DIFFERENT_AWS_SECRET_ACCESS_KEY,
        DIFFERENT_AWS_REGION,
        awsEndpointOverride);
  }

  @BeforeEach
  void initializeCacheableAwsSecretsManagerProvider() {
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(4);
  }

  @AfterEach
  void teardown() {
    awsSecretsManagerProvider.close();
  }

  @Test
  void isSameAsCachedSpecifiedSecretsManager() {
    assertThat(createSpecifiedSecretsManager()).isSameAs(createSpecifiedSecretsManager());
  }

  @Test
  void isSameAsCachedDefaultSecretsManager() {
    assertThat(createDefaultSecretsManager()).isSameAs(createDefaultSecretsManager());
  }

  @Test
  void isSameAsCachedDefaultSecretsManagerAfterCachingSpecified() {
    assertThat(createSpecifiedSecretsManager()).isSameAs(createDefaultSecretsManager());
  }

  @Test
  void isSameAsCorrectCachedSecretsManager() {
    assertThat(createDefaultSecretsManager())
        .isNotSameAs(createSecretsManagerDifferentKeys())
        .isNotSameAs(createSecretsManagerDifferentRegion())
        .isNotSameAs(createSecretsManagerDifferentKeysDifferentRegion())
        .isSameAs(createSpecifiedSecretsManager());
  }

  @Test
  void isNotSameAsSecretsManagerDifferentRegion() {
    assertThat(createSecretsManagerDifferentKeys())
        .isNotSameAs(createSecretsManagerDifferentKeysDifferentRegion());
  }

  @Test
  void validateCacheUpperBound() {
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(1);
    assertThat(createDefaultSecretsManager()) // cache miss, create entry
        .isSameAs(createDefaultSecretsManager()) // cache hit
        .isNotSameAs(createSecretsManagerDifferentKeys()) // cache miss, evict & create entry
        .isNotSameAs(createDefaultSecretsManager()); // cache miss
  }

  @Test
  void secretsManagerIsNotCachedWhenCacheSizeIsSetToZero() {
    awsSecretsManagerProvider = new AwsSecretsManagerProvider(0);
    assertThat(createSpecifiedSecretsManager()).isNotSameAs(createSpecifiedSecretsManager());
  }

  @Test
  void validateClose() {
    final AwsSecretsManager awsSecretsManager = createSpecifiedSecretsManager();
    final AwsSecretsManager differentAwsSecretsManager = createSecretsManagerDifferentKeys();
    awsSecretsManagerProvider.close();
    assertThat(createSpecifiedSecretsManager()).isNotSameAs(awsSecretsManager);
    assertThat(createSecretsManagerDifferentKeys()).isNotSameAs(differentAwsSecretsManager);
  }
}
