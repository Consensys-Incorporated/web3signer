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
package tech.pegasys.web3signer.signing.config;

import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DefaultAzureKeyVaultParameters implements AzureKeyVaultParameters {

  private static final long AZURE_DEFAULT_TIMEOUT = 60;
  private static final boolean AZURE_DEFAULT_ENABLED = true;

  private final String keyVaultName;
  private final AzureAuthenticationMode authenticationMode;
  private final String clientId;
  private final String tenantId;
  private final String clientSecret;
  private final Map<String, String> tags = new HashMap<>();
  private final long timeout;
  private final boolean enabled;
  private final AzureOverrides azureOverrides;

  public DefaultAzureKeyVaultParameters(
      final String keyVaultName,
      final String clientId,
      final String tenantId,
      final String clientSecret) {
    this(
        keyVaultName,
        clientId,
        tenantId,
        clientSecret,
        Collections.emptyMap(),
        AZURE_DEFAULT_TIMEOUT,
        AZURE_DEFAULT_ENABLED,
        AzureOverrides.NONE);
  }

  public DefaultAzureKeyVaultParameters(
      final String keyVaultName,
      final String clientId,
      final String tenantId,
      final String clientSecret,
      final Map<String, String> tags) {
    this(
        keyVaultName,
        clientId,
        tenantId,
        clientSecret,
        tags,
        AZURE_DEFAULT_TIMEOUT,
        AZURE_DEFAULT_ENABLED,
        AzureOverrides.NONE);
  }

  public DefaultAzureKeyVaultParameters(
      final String keyVaultName,
      final String clientId,
      final String tenantId,
      final String clientSecret,
      final Map<String, String> tags,
      final long timeout,
      final boolean enabled) {
    this(
        keyVaultName,
        clientId,
        tenantId,
        clientSecret,
        tags,
        timeout,
        enabled,
        AzureOverrides.NONE);
  }

  public DefaultAzureKeyVaultParameters(
      final String keyVaultName,
      final String clientId,
      final String tenantId,
      final String clientSecret,
      final Map<String, String> tags,
      final long timeout,
      final boolean enabled,
      final AzureOverrides azureOverrides) {
    this.keyVaultName = keyVaultName;
    this.clientId = clientId;
    this.tenantId = tenantId;
    this.clientSecret = clientSecret;
    this.authenticationMode = AzureAuthenticationMode.CLIENT_SECRET;
    this.tags.putAll(tags);
    this.timeout = timeout;
    this.enabled = enabled;
    this.azureOverrides = azureOverrides;
  }

  @Override
  public String getKeyVaultName() {
    return keyVaultName;
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

  @Override
  public boolean isAzureKeyVaultEnabled() {
    return enabled;
  }

  @Override
  public AzureAuthenticationMode getAuthenticationMode() {
    return authenticationMode;
  }

  @Override
  public Map<String, String> getTags() {
    return tags;
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
