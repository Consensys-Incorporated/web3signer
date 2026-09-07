/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.signing.config.metadata;

import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AzureAuthenticationMode;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultParameters;

import java.util.Collections;
import java.util.Map;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

@JsonDeserialize(using = AzureSecretSigningMetadataDeserializer.class)
public class AzureSecretSigningMetadata extends SigningMetadata implements AzureKeyVaultParameters {
  public static final String TYPE = "azure-secret";
  private final String clientId;
  private final String clientSecret;
  private final String tenantId;
  private final String vaultName;
  private final String secretName;
  private final AzureAuthenticationMode authenticationMode;
  private final long timeout;
  private final AzureOverrides azureOverrides;

  public AzureSecretSigningMetadata(
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final String vaultName,
      final String secretName,
      final AzureAuthenticationMode azureAuthenticationMode,
      final KeyType keyType,
      final long timeout,
      final AzureOverrides azureOverrides) {
    super(TYPE, keyType != null ? keyType : KeyType.BLS);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tenantId = tenantId;
    this.vaultName = vaultName;
    this.secretName = secretName;
    this.authenticationMode =
        azureAuthenticationMode == null
            ? AzureAuthenticationMode.CLIENT_SECRET
            : azureAuthenticationMode;
    this.timeout = timeout;
    this.azureOverrides = azureOverrides;
  }

  @Override
  public boolean isAzureKeyVaultEnabled() {
    return true;
  }

  @Override
  public AzureAuthenticationMode getAuthenticationMode() {
    return authenticationMode;
  }

  @Override
  public String getKeyVaultName() {
    return vaultName;
  }

  @Override
  public String getTenantId() {
    return tenantId;
  }

  @Override
  public String getClientId() {
    return clientId;
  }

  @Override
  public String getClientSecret() {
    return clientSecret;
  }

  public String getSecretName() {
    return secretName;
  }

  @Override
  public ArtifactSigner createSigner(final ArtifactSignerFactory factory) {
    return factory.create(this);
  }

  @Override
  public Map<String, String> getTags() {
    // tags support is not applicable for config file mode as
    // user is already providing the secret name to load the secret from.
    return Collections.emptyMap();
  }

  @Override
  public long getTimeout() {
    return timeout;
  }

  @Override
  public AzureOverrides getAzureOverrides() {
    return azureOverrides;
  }
}
