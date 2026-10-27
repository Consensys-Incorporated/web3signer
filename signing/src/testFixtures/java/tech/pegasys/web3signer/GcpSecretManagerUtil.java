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
package tech.pegasys.web3signer;

import java.util.UUID;

import com.google.cloud.secretmanager.v1.AddSecretVersionRequest;
import com.google.cloud.secretmanager.v1.ProjectName;
import com.google.cloud.secretmanager.v1.Replication;
import com.google.cloud.secretmanager.v1.Secret;
import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import com.google.cloud.secretmanager.v1.SecretName;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.protobuf.ByteString;

public class GcpSecretManagerUtil {

  private final SecretManagerServiceClient secretManagerServiceClient;
  private static final String SECRET_MANAGER_PREFIX = "signers-gcp-integration-";
  private final String secretNamePrefix;
  private final String projectId;

  public GcpSecretManagerUtil(
      final String projectId, final SecretManagerServiceClient secretManagerServiceClient) {
    this.secretNamePrefix = SECRET_MANAGER_PREFIX + UUID.randomUUID();
    this.projectId = projectId;
    this.secretManagerServiceClient = secretManagerServiceClient;
  }

  public String getSecretsManagerPrefix() {
    return secretNamePrefix;
  }

  public String createSecret(final String providedSecretName, final String secretValue) {
    final String secretName = secretNamePrefix + providedSecretName;
    final Secret secret =
        Secret.newBuilder()
            .setReplication(
                Replication.newBuilder()
                    .setAutomatic(Replication.Automatic.newBuilder().build())
                    .build())
            .build();
    secretManagerServiceClient.createSecret(ProjectName.of(projectId), secretName, secret);

    final AddSecretVersionRequest request =
        AddSecretVersionRequest.newBuilder()
            .setParent(SecretName.of(projectId, secretName).toString())
            .setPayload(
                SecretPayload.newBuilder().setData(ByteString.copyFromUtf8(secretValue)).build())
            .build();
    secretManagerServiceClient.addSecretVersion(request);
    return secretName;
  }

  public void deleteSecret(final String secretName) {
    secretManagerServiceClient.deleteSecret(SecretName.of(projectId, secretName));
  }

  public void close() {
    secretManagerServiceClient.close();
  }
}
