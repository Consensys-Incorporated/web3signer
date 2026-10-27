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

import static tech.pegasys.web3signer.keystorage.aws.SecretsMaps.SECRET_NAME_PREFIX_A;

import tech.pegasys.web3signer.keystorage.common.MappedResults;

import java.net.URI;
import java.util.AbstractMap.SimpleEntry;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DescribeSecretResponse;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.awssdk.services.secretsmanager.model.Tag;
import software.amazon.awssdk.services.secretsmanager.model.TagResourceRequest;
import software.amazon.awssdk.services.secretsmanager.model.UntagResourceRequest;
import software.amazon.awssdk.services.secretsmanager.model.UpdateSecretRequest;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
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
class AwsSecretsManagerTest {

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

  private AwsSecretsManager awsSecretsManagerDefault;
  private AwsSecretsManager awsSecretsManagerExplicit;
  private AwsSecretsManager awsSecretsManagerInvalidCredentials;
  private SecretsManagerClient testSecretsManagerClient;

  private final SecretsMaps secretsMaps = new SecretsMaps();

  @BeforeAll
  void setup() {
    initAwsSecretsManagers();
    initTestSecretsManagerClient();
    createTestSecrets();
  }

  private void createTestSecrets() {
    secretsMaps
        .getAllSecretsMap()
        .forEach(
            (key, awsSecret) ->
                createOrUpdateSecret(
                    key,
                    awsSecret.getTagKey(),
                    awsSecret.getTagValue(),
                    awsSecret.getSecretValue()));
  }

  @AfterAll
  void teardown() {
    if (awsSecretsManagerDefault != null
        || awsSecretsManagerExplicit != null
        || testSecretsManagerClient != null) {
      closeClients();
    }
  }

  @Test
  void fetchSecretWithDefaultManager() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String key = secretsMap.keySet().stream().findAny().orElseThrow();
    final Optional<String> secret = awsSecretsManagerDefault.fetchSecret(key);
    Assertions.assertThat(secret).hasValue(secretsMap.get(key).getSecretValue());
  }

  @Test
  void fetchSecretWithExplicitManager() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String key = secretsMap.keySet().stream().findAny().orElseThrow();

    final Optional<String> secret = awsSecretsManagerExplicit.fetchSecret(key);
    Assertions.assertThat(secret).hasValue(secretsMap.get(key).getSecretValue());
  }

  @Test
  void fetchSecretWithInvalidCredentialsReturnsEmpty() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String key = secretsMap.keySet().stream().findAny().orElseThrow();
    Assertions.assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> awsSecretsManagerInvalidCredentials.fetchSecret(key))
        .withMessageContaining("Failed to fetch secret from AWS Secrets Manager");
  }

  @Test
  void fetchingNonExistentSecretReturnsEmpty() {
    Optional<String> secret = awsSecretsManagerDefault.fetchSecret(SECRET_NAME_PREFIX_A + "empty");
    Assertions.assertThat(secret).isEmpty();
  }

  @Test
  void emptyFiltersReturnAllSecrets() {
    final MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(Collections.emptyList(), Map.of(), SimpleEntry::new);

    final Set<String> fetchedKeys =
        mappedResults.getValues().stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    Assertions.assertThat(fetchedKeys).containsAll(secretsMaps.getAllSecretsMap().keySet());
  }

  @Test
  void nonExistentTagFiltersReturnsEmpty() {
    MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Map.of("nonexistent-tag-key", "nonexistent-tag-value"),
            SimpleEntry::new);

    Assertions.assertThat(mappedResults.getValues()).isEmpty();
  }

  @Test
  void nonExistentPrefixFilterReturnsEmpty() {
    final MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("nonexistent-secret-prefix"), Map.of(), SimpleEntry::new);

    Assertions.assertThat(mappedResults.getValues()).isEmpty();
  }

  @Test
  void nonExistentPrefixFilterWithTagFilterReturnsEmpty() {
    final MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            List.of("nonexistent-secret-prefix"), Map.of("tagKey1", ""), SimpleEntry::new);

    Assertions.assertThat(mappedResults.getValues()).isEmpty();
  }

  @Test
  void listAndMapSecretsWithPrefix() {
    MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            List.of(SECRET_NAME_PREFIX_A), Map.of(), SimpleEntry::new);

    final Set<String> fetchedKeys =
        mappedResults.getValues().stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    Assertions.assertThat(fetchedKeys).containsAll(secretsMaps.getPrefixASecretsMap().keySet());
    Assertions.assertThat(fetchedKeys)
        .doesNotContainAnyElementsOf(secretsMaps.getPrefixBSecretsMap().keySet());
  }

  @Test
  void listAndMapSecretsWithPrefixAndTags() {
    MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            List.of(SECRET_NAME_PREFIX_A), Map.of("tagKey1", ""), SimpleEntry::new);

    final Set<String> fetchedKeys =
        mappedResults.getValues().stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Map<Boolean, List<Map.Entry<String, AwsSecret>>> expectedSecrets =
        secretsMaps.getPrefixASecretsMap().entrySet().stream()
            .collect(
                Collectors.partitioningBy(
                    entry -> Objects.equals("tagKey1", entry.getValue().getTagKey())));

    Assertions.assertThat(fetchedKeys)
        .containsAll(
            expectedSecrets.get(true).stream().map(Map.Entry::getKey).collect(Collectors.toSet()));
    Assertions.assertThat(fetchedKeys)
        .doesNotContainAnyElementsOf(
            expectedSecrets.get(false).stream().map(Map.Entry::getKey).collect(Collectors.toSet()));
    Assertions.assertThat(fetchedKeys)
        .doesNotContainAnyElementsOf(secretsMaps.getPrefixBSecretsMap().keySet());
  }

  @Test
  void listAndMapSecretsWithMatchingTagKeys() {
    final Map<String, String> expectedTagMap = Map.of("tagKey1", "");

    MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(), expectedTagMap, SimpleEntry::new);

    final Set<String> fetchedKeys =
        mappedResults.getValues().stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Map<Boolean, List<Map.Entry<String, AwsSecret>>> expectedSecrets =
        secretsMaps.getAllSecretsMap().entrySet().stream()
            .collect(
                Collectors.partitioningBy(
                    entry -> expectedTagMap.containsKey(entry.getValue().getTagKey())));

    Assertions.assertThat(fetchedKeys)
        .containsAll(
            expectedSecrets.get(true).stream().map(Map.Entry::getKey).collect(Collectors.toSet()));
    Assertions.assertThat(fetchedKeys)
        .doesNotContainAnyElementsOf(
            expectedSecrets.get(false).stream().map(Map.Entry::getKey).collect(Collectors.toSet()));
  }

  @Test
  void throwsAwayObjectsWhichMapToNull() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String expectedKey = secretsMap.keySet().stream().findAny().orElseThrow();

    MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Map.of(),
            (name, value) -> {
              if (name.equals(expectedKey)) {
                return null;
              }
              return new SimpleEntry<>(name, value);
            });
    final Set<String> fetchedKeys =
        mappedResults.getValues().stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Set<String> expectedKeys =
        secretsMap.keySet().stream()
            .filter(secretValue -> !Objects.equals(expectedKey, secretValue))
            .collect(Collectors.toSet());

    Assertions.assertThat(fetchedKeys).containsAll(expectedKeys);
    Assertions.assertThat(fetchedKeys).doesNotContain(expectedKey);
  }

  @Test
  void throwsAwayObjectsThatFailMapper() {
    final Map<String, AwsSecret> secretsMap = secretsMaps.getAllSecretsMap();
    final String expectedKey = secretsMap.keySet().stream().findAny().orElseThrow();
    MappedResults<SimpleEntry<String, String>> mappedResults =
        awsSecretsManagerExplicit.mapSecrets(
            Collections.emptyList(),
            Map.of(),
            (name, value) -> {
              if (name.equals(expectedKey)) {
                throw new RuntimeException("Arbitrary Failure");
              }
              return new SimpleEntry<>(name, value);
            });

    final Set<String> fetchedKeys =
        mappedResults.getValues().stream().map(SimpleEntry::getKey).collect(Collectors.toSet());

    final Set<String> expectedKeys =
        secretsMap.keySet().stream()
            .filter(secretValue -> !Objects.equals(expectedKey, secretValue))
            .collect(Collectors.toSet());

    Assertions.assertThat(fetchedKeys).containsAll(expectedKeys);
    Assertions.assertThat(fetchedKeys).doesNotContain(expectedKey);
    // we don't know the exact error count since this test is loading all the secrets from our live
    // secret manager and
    // some values fails to load due to read-only user doesn't have authentication on them.
    Assertions.assertThat(mappedResults.getErrorCount()).isGreaterThanOrEqualTo(1);
  }

  @Test
  void mapSecretsWithInvalidCredentialsReturnsError() {
    MappedResults<SimpleEntry<String, String>> result =
        awsSecretsManagerInvalidCredentials.mapSecrets(
            Collections.emptyList(), Map.of(), SimpleEntry::new);

    Assertions.assertThat(result.getErrorCount()).isOne();
    Assertions.assertThat(result.getValues()).isEmpty();
  }

  private void initAwsSecretsManagers() {
    awsSecretsManagerDefault = AwsSecretsManager.createAwsSecretsManager(awsEndpointOverride);
    awsSecretsManagerExplicit =
        AwsSecretsManager.createAwsSecretsManager(
            RO_AWS_ACCESS_KEY_ID, RO_AWS_SECRET_ACCESS_KEY, AWS_REGION, awsEndpointOverride);

    // don't override endpoint for invalid credentials as the emulator doesn't authenticate
    awsSecretsManagerInvalidCredentials =
        AwsSecretsManager.createAwsSecretsManager(
            "invalid", "invalid", AWS_REGION, Optional.empty());
  }

  private void initTestSecretsManagerClient() {
    final AwsBasicCredentials awsBasicCredentials =
        AwsBasicCredentials.create(RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY);
    final StaticCredentialsProvider credentialsProvider =
        StaticCredentialsProvider.create(awsBasicCredentials);
    SecretsManagerClientBuilder builder =
        SecretsManagerClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(AWS_REGION));
    awsEndpointOverride.ifPresent(builder::endpointOverride);

    testSecretsManagerClient = builder.build();
  }

  private void closeClients() {
    closeAwsSecretsManagers();
    closeTestSecretsManager();
  }

  private void closeTestSecretsManager() {
    testSecretsManagerClient.close();
  }

  private void closeAwsSecretsManagers() {
    awsSecretsManagerDefault.close();
    awsSecretsManagerExplicit.close();
    awsSecretsManagerInvalidCredentials.close();
  }

  private void createOrUpdateSecret(
      final String testSecretName,
      final String tagKey,
      final String tagVal,
      final String secretValue) {
    final Tag testSecretTag = Tag.builder().key(tagKey).value(tagVal).build();
    try {
      updateIfDifferentSecretValue(testSecretName, secretValue);
      updateIfDifferentSecretTag(testSecretName, testSecretTag);
    } catch (final ResourceNotFoundException e) {
      createTestSecret(testSecretName, testSecretTag, secretValue);
    }
  }

  private void createTestSecret(final String secretName, final Tag tag, final String secretValue) {
    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder().name(secretName).secretString(secretValue).tags(tag).build();
    testSecretsManagerClient.createSecret(secretRequest);
  }

  private void updateIfDifferentSecretTag(final String secretName, final Tag newTag) {
    final DescribeSecretResponse describeSecretResponse =
        testSecretsManagerClient.describeSecret(
            DescribeSecretRequest.builder().secretId(secretName).build());
    final boolean hasDifferentSecretTag =
        !describeSecretResponse.hasTags() || !describeSecretResponse.tags().equals(List.of(newTag));
    if (hasDifferentSecretTag) {
      testSecretsManagerClient.untagResource(
          UntagResourceRequest.builder()
              .secretId(secretName)
              .tagKeys(
                  describeSecretResponse.tags().stream().map(Tag::key).collect(Collectors.toList()))
              .build());
      testSecretsManagerClient.tagResource(
          TagResourceRequest.builder().secretId(secretName).tags(newTag).build());
    }
  }

  private void updateIfDifferentSecretValue(final String secretName, final String secretValue) {
    final GetSecretValueResponse getSecretValueResponse =
        testSecretsManagerClient.getSecretValue(
            GetSecretValueRequest.builder().secretId(secretName).build());
    final boolean hasDifferentSecretValue =
        !getSecretValueResponse.secretString().equals(secretValue);
    if (hasDifferentSecretValue) {
      testSecretsManagerClient.updateSecret(
          UpdateSecretRequest.builder().secretId(secretName).secretString(secretValue).build());
    }
  }
}
