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
package tech.pegasys.web3signer.keystorage.gcp;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.keystorage.common.SecretValueMapperUtil;

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

import com.google.cloud.secretmanager.v1.AccessSecretVersionRequest;
import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.ListSecretsRequest;
import com.google.cloud.secretmanager.v1.ProjectName;
import com.google.cloud.secretmanager.v1.Secret;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.protobuf.ByteString;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class GcpSecretManager implements Closeable {

  private static final Logger LOG = LogManager.getLogger();
  private final SecretManagerServiceClient secretManagerServiceClient;

  /**
   * @param endpointOverride {@code host:port} to reach Secret Manager at instead of its default
   *     Google Cloud endpoint. The client still uses TLS and application default credentials.
   */
  public GcpSecretManager(final Optional<String> endpointOverride) throws IOException {
    final SecretManagerServiceSettings.Builder settings = SecretManagerServiceSettings.newBuilder();
    endpointOverride.ifPresent(
        endpoint -> {
          LOG.info("Using GCP Secret Manager endpoint override {}", endpoint);
          settings.setEndpoint(endpoint);
        });
    secretManagerServiceClient = SecretManagerServiceClient.create(settings.build());
  }

  @Override
  public void close() throws IOException {
    secretManagerServiceClient.close();
  }

  /**
   * Bulk load secrets.
   *
   * @param projectId GCP Project Id
   * @param filter GCP Resource filter
   * @param mapper The mapper function that can convert secret value to appropriate type
   * @return SecretValueResult with collection of secret values and error count if any.
   */
  public <R> MappedResults<R> mapSecrets(
      final String projectId,
      final Optional<String> filter,
      final BiFunction<String, String, R> mapper) {

    final Set<R> result = ConcurrentHashMap.newKeySet();
    final AtomicInteger errorCount = new AtomicInteger(0);
    try {
      listSecrets(projectId, filter)
          .forEach(
              secretEntry -> {
                try {
                  final Optional<String> secretValue = fetchStringSecret(secretEntry.getName());
                  if (secretValue.isEmpty()) {
                    LOG.warn(
                        "Failed to fetch secret name '{}', and was discarded",
                        secretEntry.getName());
                    errorCount.incrementAndGet();
                  } else {
                    MappedResults<R> multiResult =
                        SecretValueMapperUtil.mapSecretValue(
                            mapper, secretEntry.getName(), secretValue.get());
                    result.addAll(multiResult.getValues());
                    errorCount.addAndGet(multiResult.getErrorCount());
                  }
                } catch (final Exception e) {
                  LOG.warn(
                      "Failed to map secret '{}' to requested object type due to: {}.",
                      secretEntry.getName(),
                      e.getMessage());
                  errorCount.incrementAndGet();
                }
              });
    } catch (final Exception e) {
      LOG.warn("Unexpected error during GCP list-secrets operation", e);
      errorCount.incrementAndGet();
    }
    return MappedResults.newInstance(result, errorCount.intValue());
  }

  private Iterable<Secret> listSecrets(String projectId, Optional<String> filter) {
    final ListSecretsRequest request = listSecretsRequest(projectId, filter);
    return secretManagerServiceClient.listSecrets(request).iterateAll();
  }

  private static ListSecretsRequest listSecretsRequest(String projectId, Optional<String> filter) {
    final ListSecretsRequest.Builder builder = ListSecretsRequest.newBuilder();
    builder.setParent(ProjectName.of(projectId).toString());
    filter.ifPresent(builder::setFilter);
    return builder.build();
  }

  private Optional<String> fetchStringSecret(String secretName) {
    final AccessSecretVersionResponse accessSecretVersionResponse = fetchSecret(secretName);
    if (accessSecretVersionResponse.hasPayload()) {
      SecretPayload payload = accessSecretVersionResponse.getPayload();
      ByteString payloadData = payload.getData();
      return Optional.of(payloadData.toString(StandardCharsets.UTF_8));
    } else {
      return Optional.empty();
    }
  }

  private AccessSecretVersionResponse fetchSecret(String secretName) {
    final AccessSecretVersionRequest accessSecretVersionRequest =
        AccessSecretVersionRequest.newBuilder().setName(secretName + "/versions/latest").build();
    return secretManagerServiceClient.accessSecretVersion(accessSecretVersionRequest);
  }
}
