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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.EthSecpArtifactSigner;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultParameters;
import tech.pegasys.web3signer.signing.secp256k1.azure.AzureConfig;
import tech.pegasys.web3signer.signing.secp256k1.azure.AzureKeyVaultSignerFactory;

public class SecpAzureBulkLoader {
  private final AzureKeyVault azureKeyVault;
  private final AzureKeyVaultSignerFactory azureKeyVaultSignerFactory;

  public SecpAzureBulkLoader(
      final AzureKeyVault azureKeyVault,
      final AzureKeyVaultSignerFactory azureKeyVaultSignerFactory) {
    this.azureKeyVault = azureKeyVault;
    this.azureKeyVaultSignerFactory = azureKeyVaultSignerFactory;
  }

  public MappedResults<ArtifactSigner> load(final AzureKeyVaultParameters azureKeyVaultParameters) {
    return azureKeyVault.mapKeyProperties(
        kp -> createSigner(kp.getName(), azureKeyVaultParameters),
        azureKeyVaultParameters.getTags());
  }

  private EthSecpArtifactSigner createSigner(
      final String keyName, final AzureKeyVaultParameters azureKeyVaultParameters) {
    return new EthSecpArtifactSigner(
        azureKeyVaultSignerFactory.createSigner(
            new AzureConfig(
                azureKeyVaultParameters.getKeyVaultName(),
                keyName,
                "",
                azureKeyVaultParameters.getClientId(),
                azureKeyVaultParameters.getClientSecret(),
                azureKeyVaultParameters.getTenantId(),
                azureKeyVaultParameters.getTimeout(),
                azureKeyVaultParameters.getAzureOverrides())));
  }
}
