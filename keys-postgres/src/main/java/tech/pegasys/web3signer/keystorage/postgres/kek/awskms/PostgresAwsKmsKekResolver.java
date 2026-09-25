/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres.kek.awskms;

import tech.pegasys.web3signer.common.config.AwsCredentials;
import tech.pegasys.web3signer.keystorage.postgres.TenantRecord;
import tech.pegasys.web3signer.keystorage.postgres.kek.KekResolutionException;
import tech.pegasys.web3signer.keystorage.postgres.kek.KekResolver;

import java.io.Closeable;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.google.common.base.Splitter;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.KmsClientBuilder;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;

/**
 * Resolves a tenant's DEK by calling AWS KMS's {@code Decrypt} API against the tenant's KMS key
 * (identified by its full ARN in {@code tenants.kek_key_id}). {@code GenerateDataKey} is a
 * provisioning/write-side-only API - this read side only ever calls {@code Decrypt}.
 *
 * <p>One {@link KmsClient} is built and cached per distinct AWS region encountered (parsed from
 * each tenant's key ARN), since a client must be region-scoped but tenants may have keys in
 * different regions.
 */
public class PostgresAwsKmsKekResolver implements KekResolver, Closeable {

  private static final String TENANT_ID_ENCRYPTION_CONTEXT_KEY = "tenant_id";

  private final AwsCredentialsProvider credentialsProvider;
  private final AwsKmsKekCredentials credentials;
  private final Map<String, KmsClient> clientsByRegion = new ConcurrentHashMap<>();

  public PostgresAwsKmsKekResolver(final AwsKmsKekCredentials credentials) {
    this.credentials = credentials;
    this.credentialsProvider = createCredentialsProvider(credentials);
  }

  @Override
  public String vaultType() {
    return "AWS_KMS";
  }

  @Override
  public byte[] unwrapDek(final TenantRecord tenant) {
    final String region = extractRegion(tenant.kekKeyId());
    final KmsClient client = clientsByRegion.computeIfAbsent(region, this::buildClient);
    try {
      final DecryptResponse response =
          client.decrypt(
              DecryptRequest.builder()
                  .keyId(tenant.kekKeyId())
                  .ciphertextBlob(SdkBytes.fromByteArray(tenant.encryptedDek().toArray()))
                  .encryptionContext(Map.of(TENANT_ID_ENCRYPTION_CONTEXT_KEY, tenant.name()))
                  .build());
      return response.plaintext().asByteArray();
    } catch (final RuntimeException e) {
      throw new KekResolutionException(
          "Failed to unwrap DEK for tenant '"
              + tenant.name()
              + "' via AWS KMS: "
              + e.getClass().getSimpleName(),
          e);
    }
  }

  private KmsClient buildClient(final String region) {
    final KmsClientBuilder builder =
        KmsClient.builder().credentialsProvider(credentialsProvider).region(Region.of(region));
    credentials.getEndpointOverride().ifPresent(builder::endpointOverride);
    return builder.build();
  }

  private static String extractRegion(final String kmsKeyArn) {
    final List<String> parts = Splitter.on(':').splitToList(kmsKeyArn);
    if (parts.size() < 4 || !"arn".equals(parts.getFirst())) {
      throw new KekResolutionException(
          "tenants.kek_key_id is not a valid KMS key ARN: " + kmsKeyArn);
    }
    return parts.get(3);
  }

  private static AwsCredentialsProvider createCredentialsProvider(
      final AwsKmsKekCredentials credentials) {
    return switch (credentials.getAuthenticationMode()) {
      case ENVIRONMENT -> DefaultCredentialsProvider.builder().build();
      case SPECIFIED ->
          StaticCredentialsProvider.create(
              toAwsSdkCredentials(
                  credentials
                      .getCredentials()
                      .orElseThrow(
                          () ->
                              new IllegalArgumentException(
                                  "AWS credentials must be provided for SPECIFIED mode"))));
    };
  }

  private static software.amazon.awssdk.auth.credentials.AwsCredentials toAwsSdkCredentials(
      final AwsCredentials credentials) {
    return credentials
        .getSessionToken()
        .<software.amazon.awssdk.auth.credentials.AwsCredentials>map(
            token ->
                AwsSessionCredentials.create(
                    credentials.getAccessKeyId(), credentials.getSecretAccessKey(), token))
        .orElseGet(
            () ->
                AwsBasicCredentials.create(
                    credentials.getAccessKeyId(), credentials.getSecretAccessKey()));
  }

  @Override
  public void close() {
    clientsByRegion.values().forEach(KmsClient::close);
  }
}
