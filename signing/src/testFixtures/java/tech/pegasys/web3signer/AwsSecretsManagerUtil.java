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
package tech.pegasys.web3signer;

import java.net.URI;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.CreateSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.DeleteSecretRequest;
import software.amazon.awssdk.services.secretsmanager.model.Tag;

public class AwsSecretsManagerUtil {

  private final SecretsManagerClient secretsManagerClient;
  private static final String SECRETS_MANAGER_PREFIX = "signers-aws-integration/";
  private final String secretNamePrefix;

  public AwsSecretsManagerUtil(
      final String region,
      final String accessKeyId,
      final String secretAccessKey,
      Optional<URI> awsEndpointOverride) {
    final AwsBasicCredentials awsBasicCredentials =
        AwsBasicCredentials.create(accessKeyId, secretAccessKey);
    final StaticCredentialsProvider credentialsProvider =
        StaticCredentialsProvider.create(awsBasicCredentials);
    SecretsManagerClientBuilder builder =
        SecretsManagerClient.builder()
            .credentialsProvider(credentialsProvider)
            .region(Region.of(region));
    // useful for testing against an AWS emulator
    awsEndpointOverride.ifPresent(builder::endpointOverride);
    secretsManagerClient = builder.build();

    secretNamePrefix = SECRETS_MANAGER_PREFIX + UUID.randomUUID() + "/";
  }

  public String getSecretsManagerPrefix() {
    return secretNamePrefix;
  }

  public void createSecret(
      final String secretName, final String secretValue, final Map<String, String> tags) {
    Set<Tag> awsTags =
        tags.keySet().stream()
            .map(tagName -> Tag.builder().key(tagName).value(tags.get(tagName)).build())
            .collect(Collectors.toSet());
    final CreateSecretRequest secretRequest =
        CreateSecretRequest.builder()
            .name(secretNamePrefix + secretName)
            .secretString(secretValue)
            .tags(awsTags)
            .build();
    secretsManagerClient.createSecret(secretRequest);
  }

  public void deleteSecret(final String secretName) {
    final DeleteSecretRequest secretRequest =
        DeleteSecretRequest.builder()
            .secretId(secretNamePrefix + secretName)
            .forceDeleteWithoutRecovery(true)
            .build();
    secretsManagerClient.deleteSecret(secretRequest);
  }

  public void close() {
    secretsManagerClient.close();
  }
}
