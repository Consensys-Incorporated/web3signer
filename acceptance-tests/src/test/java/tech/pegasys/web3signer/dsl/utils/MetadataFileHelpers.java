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
package tech.pegasys.web3signer.dsl.utils;

import static org.assertj.core.api.AssertionsForClassTypes.fail;
import static tech.pegasys.web3signer.bls.keystore.model.Pbkdf2PseudoRandomFunction.HMAC_SHA256;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.model.CipherFunction;
import tech.pegasys.web3signer.bls.keystore.model.CipherParam;
import tech.pegasys.web3signer.bls.keystore.model.CipherSpec;
import tech.pegasys.web3signer.bls.keystore.model.KdfFunction;
import tech.pegasys.web3signer.bls.keystore.model.KdfParam;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.web3signer.bls.keystore.model.SCryptParam;
import tech.pegasys.web3signer.common.config.AwsAuthenticationMode;
import tech.pegasys.web3signer.dsl.HashicorpSigningParams;
import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.keystore.dsl.certificates.CertificateHelpers;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.metadata.AwsKmsMetadata;
import tech.pegasys.web3signer.signing.config.metadata.AwsKmsMetadataDeserializer;

import java.io.IOException;
import java.io.Serializable;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import org.apache.tuweni.bytes.Bytes;

public class MetadataFileHelpers {
  private static final ObjectMapper YAML_OBJECT_MAPPER = YAMLMapper.builder().build();
  private static final Bytes SALT =
      Bytes.fromHexString("0x9ac471d9d421bc06d9aefe2b46cf96d11829c51e36ed0b116132be57a9f8c22b");
  private static final CipherParam IV =
      new CipherParam(Bytes.fromHexString("0xcca2c67ec95a1dd13edd986fea372789"));

  public void createUnencryptedYamlFileAt(
      final Path metadataFilePath, final String privateKey, final KeyType keyType) {
    final Map<String, String> signingMetadata = new HashMap<>();
    signingMetadata.put("type", "file-raw");
    signingMetadata.put("privateKey", privateKey);
    signingMetadata.put("keyType", keyType.name());

    createYamlFile(metadataFilePath, signingMetadata);
  }

  public void createRandomUnencryptedBlsKeys(final Path directory, final int numberOfKeys) {
    final SecureRandom secureRandom = new SecureRandom();
    final MetadataFileHelpers metadataFileHelpers = new MetadataFileHelpers();
    for (int i = 0; i < numberOfKeys; i++) {
      final BLSKeyPair keyPair = BLSKeyPair.random(secureRandom);
      final String privateKey = keyPair.getSecretKey().toBytes().toHexString();
      final Path filename = directory.resolve(keyPair.getPublicKey().toString() + ".yaml");
      metadataFileHelpers.createUnencryptedYamlFileAt(filename, privateKey, KeyType.BLS);
    }
  }

  public void createKeyStoreYamlFileAt(
      final Path metadataFilePath, final BLSKeyPair keyPair, final KdfFunction kdfFunctionType) {
    final String password = "password";

    final Path keystoreFile =
        metadataFilePath.getParent().resolve(keyPair.getPublicKey().toString() + ".json");
    createKeyStoreFile(keystoreFile, password, keyPair, kdfFunctionType);

    createKeyStoreYamlFileAt(metadataFilePath, keystoreFile, password, KeyType.BLS);
  }

  public void createKeyStoreYamlFileAt(
      final Path metadataFilePath,
      final Path keystoreFile,
      final String password,
      final KeyType keyType) {
    final String filename = metadataFilePath.getFileName().toString();
    final String passwordFilename = filename + ".password";
    final Path passwordFile = metadataFilePath.getParent().resolve(passwordFilename);
    createPasswordFile(passwordFile, password);

    final Map<String, String> signingMetadata = new HashMap<>();
    signingMetadata.put("type", "file-keystore");
    signingMetadata.put("keystoreFile", keystoreFile.toString());
    signingMetadata.put("keystorePasswordFile", passwordFile.toString());
    signingMetadata.put("keyType", keyType.name());
    createYamlFile(metadataFilePath, signingMetadata);
  }

  public void createHashicorpYamlFileAt(
      final Path metadataFilePath,
      final HashicorpSigningParams node,
      Optional<String> httpProtocolVersion) {
    try {
      final Map<String, String> signingMetadata = new HashMap<>();

      final boolean tlsEnabled = node.getServerCertificate().isPresent();

      signingMetadata.put("type", "hashicorp");
      signingMetadata.put("serverHost", node.getHost());
      signingMetadata.put("serverPort", Integer.toString(node.getPort()));
      signingMetadata.put("timeout", "10000");
      signingMetadata.put("tlsEnabled", Boolean.toString(tlsEnabled));
      if (tlsEnabled) {
        final Path parentDir = metadataFilePath.getParent();
        final Path knownServerPath =
            CertificateHelpers.createFingerprintFile(
                parentDir, node.getServerCertificate().get(), Optional.of(node.getPort()));

        signingMetadata.put("tlsKnownServersPath", knownServerPath.toString());
      }
      signingMetadata.put("keyPath", node.getSecretHttpPath());
      signingMetadata.put("keyName", node.getSecretName());
      signingMetadata.put("token", node.getVaultToken());
      signingMetadata.put("keyType", node.getKeyType().toString());

      httpProtocolVersion.ifPresent(version -> signingMetadata.put("httpProtocolVersion", version));

      createYamlFile(metadataFilePath, signingMetadata);
    } catch (final Exception e) {
      throw new RuntimeException("Unable to construct hashicorp yaml file", e);
    }
  }

  public void createAzureYamlFileAt(
      final Path metadataFilePath,
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final String keyVaultName,
      final String secretName,
      final AzureOverrides azureOverrides) {
    try {
      final Map<String, String> signingMetadata = new HashMap<>();

      signingMetadata.put("type", "azure-secret");
      signingMetadata.put("clientId", clientId);
      signingMetadata.put("clientSecret", clientSecret);
      signingMetadata.put("tenantId", tenantId);
      signingMetadata.put("vaultName", keyVaultName);
      signingMetadata.put("secretName", secretName);
      putAzureOverrides(signingMetadata, azureOverrides);

      createYamlFile(metadataFilePath, signingMetadata);
    } catch (final Exception e) {
      throw new RuntimeException("Unable to construct azure yaml file", e);
    }
  }

  public void createAzureKeyYamlFileAt(
      final Path metadataFilePath,
      final String clientId,
      final String clientSecret,
      final String keyVaultName,
      final String tenantId,
      final String keyName,
      final AzureOverrides azureOverrides) {
    try {
      final Map<String, String> signingMetadata = new HashMap<>();
      signingMetadata.put("type", "azure-key");
      signingMetadata.put("vaultName", keyVaultName);
      signingMetadata.put("keyName", keyName);
      signingMetadata.put("clientId", clientId);
      signingMetadata.put("clientSecret", clientSecret);
      signingMetadata.put("tenantId", tenantId);
      putAzureOverrides(signingMetadata, azureOverrides);
      createYamlFile(metadataFilePath, signingMetadata);
    } catch (final Exception e) {
      throw new RuntimeException("Unable to construct hashicorp yaml file", e);
    }
  }

  private static void putAzureOverrides(
      final Map<String, String> signingMetadata, final AzureOverrides azureOverrides) {
    azureOverrides
        .endpointOverride()
        .ifPresent(endpoint -> signingMetadata.put("endpointOverride", endpoint.toString()));
    azureOverrides
        .authorityHostOverride()
        .ifPresent(authority -> signingMetadata.put("authorityHostOverride", authority.toString()));
    azureOverrides
        .trustCertificateOverride()
        .ifPresent(
            certificate -> signingMetadata.put("trustCertificateOverride", certificate.toString()));
  }

  public void createAwsYamlFileAt(
      final Path metadataFilePath,
      final String awsRegion,
      final String accessKeyId,
      final String secretAccessKey,
      final String secretName,
      final Optional<URI> awsEndpointOverride) {
    try {
      final Map<String, String> signingMetadata = new HashMap<>();

      signingMetadata.put("type", "aws-secret");
      signingMetadata.put("authenticationMode", "SPECIFIED");
      signingMetadata.put("region", awsRegion);
      signingMetadata.put("accessKeyId", accessKeyId);
      signingMetadata.put("secretAccessKey", secretAccessKey);
      signingMetadata.put("secretName", secretName);
      awsEndpointOverride.ifPresent(
          endpoint -> signingMetadata.put("endpointOverride", endpoint.toString()));

      createYamlFile(metadataFilePath, signingMetadata);
    } catch (final Exception e) {
      throw new RuntimeException("Unable to construct aws yaml file", e);
    }
  }

  public void createAwsYamlFileWithEnvironmentAt(
      final Path metadataFilePath,
      final String awsRegion,
      final String secretName,
      final Optional<URI> awsEndpointOverride) {
    try {
      final Map<String, String> signingMetadata = new HashMap<>();

      signingMetadata.put("type", "aws-secret");
      signingMetadata.put("authenticationMode", "ENVIRONMENT");
      signingMetadata.put("region", awsRegion);
      signingMetadata.put("secretName", secretName);
      awsEndpointOverride.ifPresent(
          endpoint -> signingMetadata.put("endpointOverride", endpoint.toString()));
      createYamlFile(metadataFilePath, signingMetadata);
    } catch (final Exception e) {
      throw new RuntimeException("Unable to construct aws yaml file", e);
    }
  }

  public void createAwsKmsYamlFileAt(
      final Path metadataFilePath,
      final String awsRegion,
      final String accessKeyId,
      final String secretAccessKey,
      final Optional<String> sessionToken,
      final Optional<URI> endpointOverride,
      final String kmsKeyId) {
    try {
      final Map<String, String> signingMetadata = new HashMap<>();

      signingMetadata.put("type", AwsKmsMetadata.TYPE);
      signingMetadata.put(
          AwsKmsMetadataDeserializer.AUTH_MODE, AwsAuthenticationMode.SPECIFIED.toString());
      signingMetadata.put(AwsKmsMetadataDeserializer.REGION, awsRegion);
      signingMetadata.put(AwsKmsMetadataDeserializer.ACCESS_KEY_ID, accessKeyId);
      signingMetadata.put(AwsKmsMetadataDeserializer.SECRET_ACCESS_KEY, secretAccessKey);
      sessionToken.ifPresent(
          token -> signingMetadata.put(AwsKmsMetadataDeserializer.SESSION_TOKEN, token));
      endpointOverride.ifPresent(
          endpoint ->
              signingMetadata.put(
                  AwsKmsMetadataDeserializer.ENDPOINT_OVERRIDE, endpoint.toString()));
      signingMetadata.put(AwsKmsMetadataDeserializer.KMS_KEY_ID, kmsKeyId);

      createYamlFile(metadataFilePath, signingMetadata);
    } catch (final Exception e) {
      throw new RuntimeException("Unable to construct aws-kms yaml file", e);
    }
  }

  private void createPasswordFile(final Path passwordFilePath, final String password) {
    try {
      Files.writeString(passwordFilePath, password);
    } catch (IOException e) {
      fail("Unable to create password file", e);
    }
  }

  private void createKeyStoreFile(
      final Path keyStoreFilePath,
      final String password,
      final BLSKeyPair blsKeyPair,
      final KdfFunction kdfFunctionType) {
    final KdfParam kdfParam =
        kdfFunctionType == KdfFunction.SCRYPT
            ? new SCryptParam(32, SALT)
            : new Pbkdf2Param(32, 262144, HMAC_SHA256, SALT);
    final CipherSpec cipher = new CipherSpec(CipherFunction.AES_128_CTR, IV);
    final KeyStoreData keyStoreData =
        KeyStore.encrypt(blsKeyPair, password, "m/12381/3600/0/0/0", kdfParam, cipher);
    try {
      KeyStoreLoader.saveToFile(keyStoreFilePath, keyStoreData);
    } catch (IOException e) {
      fail("Unable to create keystore file", e);
    }
  }

  private void createYamlFile(
      final Path filePath, final Map<String, ? extends Serializable> signingMetadata) {
    try {
      YAML_OBJECT_MAPPER.writeValue(filePath.toFile(), signingMetadata);
    } catch (final IOException e) {
      fail("Unable to create metadata file.", e);
    }
  }
}
