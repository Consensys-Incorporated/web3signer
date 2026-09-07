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

import java.net.URI;
import java.nio.file.Path;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class AzureKeySigningMetadata extends SigningMetadata {
  public static final String TYPE = "azure-key";
  private final String clientId;
  private final String clientSecret;
  private final String tenantId;
  private final String vaultName;
  private final String keyName;
  private final long timeout;
  private final AzureOverrides azureOverrides;

  @JsonCreator
  public AzureKeySigningMetadata(
      @JsonProperty("clientId") final String clientId,
      @JsonProperty("clientSecret") final String clientSecret,
      @JsonProperty("tenantId") final String tenantId,
      @JsonProperty("vaultName") final String vaultName,
      @JsonProperty("keyName") final String keyName,
      @JsonProperty(value = "keyType") final KeyType keyType,
      @JsonProperty(value = "timeout") final long timeout,
      @JsonProperty("endpointOverride") final String endpointOverride,
      @JsonProperty("authorityHostOverride") final String authorityHostOverride,
      @JsonProperty("trustCertificateOverride") final String trustCertificateOverride) {
    super(TYPE, keyType != null ? keyType : KeyType.SECP256K1);
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tenantId = tenantId;
    this.vaultName = vaultName;
    this.keyName = keyName;
    this.timeout = (timeout != 0) ? timeout : 60;
    this.azureOverrides =
        new AzureOverrides(
            endpointOverride == null ? Optional.empty() : Optional.of(URI.create(endpointOverride)),
            authorityHostOverride == null
                ? Optional.empty()
                : Optional.of(URI.create(authorityHostOverride)),
            trustCertificateOverride == null
                ? Optional.empty()
                : Optional.of(Path.of(trustCertificateOverride)));
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

  public String getVaultName() {
    return vaultName;
  }

  public String getKeyName() {
    return keyName;
  }

  public long getTimeout() {
    return timeout;
  }

  public AzureOverrides getAzureOverrides() {
    return azureOverrides;
  }

  @Override
  public ArtifactSigner createSigner(final ArtifactSignerFactory artifactSignerFactory) {
    return artifactSignerFactory.create(this);
  }
}
