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
package tech.pegasys.web3signer.signing.secp256k1.azure;

import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;

import com.fasterxml.jackson.annotation.JsonCreator;

public class AzureConfig {
  private final String keyVaultName;
  private final String keyName;
  private final String keyVersion;
  private final String clientId;
  private final String clientSecret;
  private final String tenantId;
  // empty string means latest in azure
  private static final String KEY_LATEST_VERSION = "";
  private final long timeout;
  private final AzureOverrides azureOverrides;

  @JsonCreator
  public AzureConfig(
      final String keyVaultName,
      final String keyName,
      final String keyVersion,
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final long timeout,
      final AzureOverrides azureOverrides) {
    this.keyVaultName = keyVaultName;
    this.keyName = keyName;
    this.keyVersion = keyVersion;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tenantId = tenantId;
    this.timeout = timeout;
    this.azureOverrides = azureOverrides;
  }

  public AzureConfig(
      final String keyVaultName,
      final String keyName,
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final long timeout) {
    this(
        keyVaultName,
        keyName,
        KEY_LATEST_VERSION,
        clientId,
        clientSecret,
        tenantId,
        timeout,
        AzureOverrides.NONE);
  }

  public String getKeyVaultName() {
    return keyVaultName;
  }

  public String getKeyName() {
    return keyName;
  }

  public String getKeyVersion() {
    return keyVersion;
  }

  public String getClientId() {
    return clientId;
  }

  public String getClientSecret() {
    return clientSecret;
  }

  public String getTenantId() {
    return tenantId;
  }

  public long getTimeout() {
    return timeout;
  }

  public AzureOverrides getAzureOverrides() {
    return azureOverrides;
  }
}
