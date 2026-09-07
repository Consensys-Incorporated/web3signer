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

import tech.pegasys.web3signer.keystorage.hashicorp.HashicorpConnectionFactory;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultFactory;
import tech.pegasys.web3signer.signing.secp256k1.Signer;
import tech.pegasys.web3signer.signing.secp256k1.aws.AwsKmsSignerFactory;
import tech.pegasys.web3signer.signing.secp256k1.azure.AzureConfig;
import tech.pegasys.web3signer.signing.secp256k1.azure.AzureKeyVaultSignerFactory;
import tech.pegasys.web3signer.signing.secp256k1.filebased.CredentialSigner;

import java.io.IOException;
import java.nio.file.Path;
import java.util.function.Function;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.crypto.exception.CipherException;

public class Secp256k1ArtifactSignerFactory extends AbstractArtifactSignerFactory {

  private final AzureKeyVaultSignerFactory azureCloudSignerFactory;
  final AwsKmsSignerFactory awsKmsSignerFactory;
  private final Function<Signer, ArtifactSigner> signerFactory;

  private final boolean needToHash;

  public Secp256k1ArtifactSignerFactory(
      final HashicorpConnectionFactory hashicorpConnectionFactory,
      final Path configsDirectory,
      final AzureKeyVaultSignerFactory azureCloudSignerFactory,
      final Function<Signer, ArtifactSigner> signerFactory,
      final AzureKeyVaultFactory azureKeyVaultFactory,
      final AwsKmsSignerFactory awsKmsSignerFactory,
      final boolean needToHash) {
    super(hashicorpConnectionFactory, configsDirectory, azureKeyVaultFactory);
    this.azureCloudSignerFactory = azureCloudSignerFactory;
    this.awsKmsSignerFactory = awsKmsSignerFactory;
    this.signerFactory = signerFactory;
    this.needToHash = needToHash;
  }

  @Override
  public ArtifactSigner create(final FileRawSigningMetadata fileRawSigningMetadata) {
    final Bytes32 privateKeyBytes = fileRawSigningMetadata.getPrivateKeyBytes();
    final Credentials credentials = Credentials.create(privateKeyBytes.toHexString());
    return createCredentialSigner(credentials);
  }

  @Override
  public ArtifactSigner create(final FileKeyStoreMetadata fileKeyStoreMetadata) {
    final Path keystoreFile = makeRelativePathAbsolute(fileKeyStoreMetadata.getKeystoreFile());
    final Path keystorePasswordFile =
        makeRelativePathAbsolute(fileKeyStoreMetadata.getKeystorePasswordFile());
    try {
      final String password = loadPassword(keystorePasswordFile);
      final Credentials credentials = WalletUtils.loadCredentials(password, keystoreFile.toFile());
      return createCredentialSigner(credentials);
    } catch (final IOException | CipherException e) {
      throw new SigningMetadataException(e.getMessage(), e);
    }
  }

  @Override
  public ArtifactSigner create(final HashicorpSigningMetadata hashicorpMetadata) {
    final Bytes privateKeyBytes = extractBytesFromVault(hashicorpMetadata);
    final Credentials credentials = Credentials.create(privateKeyBytes.toHexString());
    return createCredentialSigner(credentials);
  }

  @Override
  public ArtifactSigner create(final AzureSecretSigningMetadata azureSecretSigningMetadata) {
    final Bytes privateKeyBytes = extractBytesFromVault(azureSecretSigningMetadata);
    final Credentials credentials = Credentials.create(privateKeyBytes.toHexString());
    return createCredentialSigner(credentials);
  }

  @Override
  public ArtifactSigner create(final AzureKeySigningMetadata azureSigningMetadata) {
    final AzureConfig config =
        new AzureConfig(
            azureSigningMetadata.getVaultName(),
            azureSigningMetadata.getKeyName(),
            "",
            azureSigningMetadata.getClientId(),
            azureSigningMetadata.getClientSecret(),
            azureSigningMetadata.getTenantId(),
            azureSigningMetadata.getTimeout(),
            azureSigningMetadata.getAzureOverrides());

    return signerFactory.apply(azureCloudSignerFactory.createSigner(config));
  }

  @Override
  public ArtifactSigner create(final AwsKmsMetadata awsKmsMetadata) {
    return signerFactory.apply(awsKmsSignerFactory.createSigner(awsKmsMetadata));
  }

  private ArtifactSigner createCredentialSigner(final Credentials credentials) {
    return signerFactory.apply(new CredentialSigner(credentials, needToHash));
  }

  @Override
  public KeyType getKeyType() {
    return KeyType.SECP256K1;
  }
}
