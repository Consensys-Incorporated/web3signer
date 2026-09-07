/*
 * Copyright 2019 ConsenSys AG.
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
package tech.pegasys.web3signer.tests.signing;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;
import static org.web3j.crypto.Sign.signedMessageToKey;

import tech.pegasys.web3signer.AwsKmsUtil;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ConfigurationChainId;
import tech.pegasys.web3signer.dsl.HashicorpSigningParams;
import tech.pegasys.web3signer.dsl.azure.AzureKeyVaultEmulator;
import tech.pegasys.web3signer.dsl.azure.MockAzureAuthorityExtension;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.utils.MetadataFileHelpers;
import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.keystore.hashicorp.dsl.HashicorpNode;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.secp256k1.EthPublicKeyUtils;
import tech.pegasys.web3signer.tests.bulkloading.AzureKeyVaultAcceptanceTest;

import java.io.File;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;

import com.google.common.collect.Maps;
import com.google.common.io.Resources;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariables;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.web3j.crypto.Hash;
import org.web3j.crypto.Sign;
import org.web3j.crypto.Sign.SignatureData;

public class SecpSigningAcceptanceTest extends SigningAcceptanceTestBase {

  private static final Bytes DATA = Bytes.wrap("42".getBytes(UTF_8));
  private static final String PRIVATE_KEY =
      "8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63";
  public static final String PUBLIC_KEY_HEX_STRING =
      "09b02f8a5fddd222ade4ea4528faefc399623af3f736be3c44f03e2df22fb792f3931a4d9573d333ca74343305762a753388c3422a86d98b713fc91c1ea04842";

  private static final MetadataFileHelpers METADATA_FILE_HELPERS = new MetadataFileHelpers();

  @RegisterExtension
  static final MockAzureAuthorityExtension MOCK_AUTHORITY = new MockAzureAuthorityExtension();

  @Test
  public void signDataWithFileBasedKey() throws URISyntaxException {
    createFileBasedKeyStore();

    signAndVerifySignature();
  }

  @Test
  public void signDigestWithFileBasedKeyWithoutHashing() throws URISyntaxException {
    createFileBasedKeyStore();
    setupEth1Signer();

    final Bytes digest = Bytes.wrap(Hash.sha3(DATA.toArray()));
    final Response response = signer.eth1Sign(PUBLIC_KEY_HEX_STRING, digest, false);
    final Bytes signature = verifyAndGetSignatureResponse(response);
    verifyDigestSignature(signature, digest, PUBLIC_KEY_HEX_STRING);
  }

  @Test
  public void rejectNonDigestWhenHashingIsDisabled() throws URISyntaxException {
    createFileBasedKeyStore();
    setupEth1Signer();

    assertThat(signer.eth1Sign(PUBLIC_KEY_HEX_STRING, DATA, false).statusCode()).isEqualTo(400);
  }

  @Test
  public void rejectNonBooleanApplyHash() throws URISyntaxException {
    createFileBasedKeyStore();
    setupEth1Signer();

    final JsonObject requestBody =
        new JsonObject().put("data", DATA.toHexString()).put("applyHash", "false");
    assertThat(signer.eth1Sign(PUBLIC_KEY_HEX_STRING, requestBody).statusCode()).isEqualTo(400);
  }

  @Test
  public void rejectNullApplyHash() throws URISyntaxException {
    createFileBasedKeyStore();
    setupEth1Signer();

    final JsonObject requestBody =
        new JsonObject().put("data", DATA.toHexString()).putNull("applyHash");
    assertThat(signer.eth1Sign(PUBLIC_KEY_HEX_STRING, requestBody).statusCode()).isEqualTo(400);
  }

  private void createFileBasedKeyStore() throws URISyntaxException {
    final String keyPath =
        new File(Resources.getResource("secp256k1/wallet.json").toURI()).getAbsolutePath();

    METADATA_FILE_HELPERS.createKeyStoreYamlFileAt(
        testDirectory.resolve(PUBLIC_KEY_HEX_STRING + ".yaml"),
        Path.of(keyPath),
        "pass",
        KeyType.SECP256K1);
  }

  @Test
  public void signDataWithKeyFromHashicorp() {
    final HashicorpNode hashicorpNode = HashicorpNode.createAndStartHashicorp(true);
    try {
      final String secretPath = "acceptanceTestSecretPath";
      final String secretName = "secretName";
      hashicorpNode.addSecretsToVault(singletonMap(secretName, PRIVATE_KEY), secretPath);

      final HashicorpSigningParams hashicorpSigningParams =
          new HashicorpSigningParams(hashicorpNode, secretPath, secretName, KeyType.SECP256K1);

      METADATA_FILE_HELPERS.createHashicorpYamlFileAt(
          testDirectory.resolve(PUBLIC_KEY_HEX_STRING + ".yaml"),
          hashicorpSigningParams,
          Optional.empty());

      signAndVerifySignature();
    } finally {
      hashicorpNode.shutdown();
    }
  }

  @Test
  public void signDataWithKeyInAzure() {
    final AzureKeyVaultEmulator emulator = AzureKeyVaultEmulator.getInstance();
    final AzureOverrides azureOverrides =
        new AzureOverrides(
            Optional.of(URI.create(emulator.getVaultUrl())),
            Optional.of(URI.create(MOCK_AUTHORITY.getAuthorityHostUrl())),
            Optional.of(emulator.getTrustCertificatePath()));
    final var azureKey =
        AzureKeyVaultAcceptanceTest.getSECPKeysFromEmulator(azureOverrides).stream()
            .findAny()
            .orElseThrow();

    METADATA_FILE_HELPERS.createAzureKeyYamlFileAt(
        testDirectory.resolve("azure_key.yaml"),
        "unused",
        "unused",
        "unused",
        AzureKeyVaultEmulator.TENANT_ID,
        azureKey.name(),
        azureOverrides);

    final SignerConfigurationBuilder builder =
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(testDirectory)
            .withMode("eth1")
            .withChainIdProvider(new ConfigurationChainId(DEFAULT_CHAIN_ID))
            .withOverriddenCA(emulator.getTlsCertificateDefinition());
    startSigner(builder.build());

    final Response response = signer.eth1Sign(azureKey.publicKeyHex(), DATA);
    final Bytes signature = verifyAndGetSignatureResponse(response);
    verifySignature(signature, azureKey.publicKeyHex());

    final Bytes digest = Bytes.wrap(Hash.sha3(DATA.toArray()));
    final Response digestResponse = signer.eth1Sign(azureKey.publicKeyHex(), digest, false);
    verifyDigestSignature(
        verifyAndGetSignatureResponse(digestResponse), digest, azureKey.publicKeyHex());
  }

  @Test
  @EnabledIfEnvironmentVariables({
    @EnabledIfEnvironmentVariable(
        named = "RW_AWS_ACCESS_KEY_ID",
        matches = ".+",
        disabledReason = "RW_AWS_ACCESS_KEY_ID env variable is required"),
    @EnabledIfEnvironmentVariable(
        named = "RW_AWS_SECRET_ACCESS_KEY",
        matches = ".+",
        disabledReason = "RW_AWS_SECRET_ACCESS_KEY env variable is required"),
    @EnabledIfEnvironmentVariable(
        named = "AWS_ACCESS_KEY_ID",
        matches = ".+",
        disabledReason = "AWS_ACCESS_KEY_ID env variable is required"),
    @EnabledIfEnvironmentVariable(
        named = "AWS_SECRET_ACCESS_KEY",
        matches = ".+",
        disabledReason = "AWS_SECRET_ACCESS_KEY env variable is required"),
  })
  public void remoteSignWithAwsKMS() {
    final String roAwsAccessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
    final String roAwsSecretAccessKey = System.getenv("AWS_SECRET_ACCESS_KEY");
    final Optional<String> awsSessionToken =
        Optional.ofNullable(System.getenv("AWS_SESSION_TOKEN"));
    // default region to us-east-2 if environment variable is not defined.
    final String region = Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-2");
    // can be pointed to localstack
    final Optional<URI> awsEndpointOverride =
        Optional.ofNullable(System.getenv("AWS_ENDPOINT_OVERRIDE")).map(URI::create);

    final AwsKmsUtil awsKmsUtil =
        new AwsKmsUtil(
            region,
            System.getenv("RW_AWS_ACCESS_KEY_ID"),
            System.getenv("RW_AWS_SECRET_ACCESS_KEY"),
            Optional.ofNullable(System.getenv("AWS_SESSION_TOKEN")),
            awsEndpointOverride);
    final Map.Entry<String, ECPublicKey> remoteAWSKMSKey = createRemoteAWSKMSKey(awsKmsUtil);
    final String awsKeyId = remoteAWSKMSKey.getKey();
    final ECPublicKey ecPublicKey = remoteAWSKMSKey.getValue();

    try {
      METADATA_FILE_HELPERS.createAwsKmsYamlFileAt(
          testDirectory.resolve("aws_kms_test.yaml"),
          region,
          roAwsAccessKeyId,
          roAwsSecretAccessKey,
          awsSessionToken,
          awsEndpointOverride,
          awsKeyId);

      final String publicKeyHex = EthPublicKeyUtils.toHexString(ecPublicKey);
      signAndVerifySignature(publicKeyHex);

      final Bytes digest = Bytes.wrap(Hash.sha3(DATA.toArray()));
      final Response digestResponse = signer.eth1Sign(publicKeyHex, digest, false);
      verifyDigestSignature(verifyAndGetSignatureResponse(digestResponse), digest, publicKeyHex);
    } finally {
      awsKmsUtil.deleteKey(awsKeyId);
    }
  }

  private void signAndVerifySignature() {
    signAndVerifySignature(PUBLIC_KEY_HEX_STRING);
  }

  private void signAndVerifySignature(final String publicKeyHex) {
    setupEth1Signer();

    // openapi
    final Response response = signer.eth1Sign(publicKeyHex, DATA);
    final Bytes signature = verifyAndGetSignatureResponse(response);
    verifySignature(signature, publicKeyHex);
  }

  void verifySignature(final Bytes signature, final String publicKeyHex) {
    final ECPublicKey expectedPublicKey =
        EthPublicKeyUtils.bytesToECPublicKey(Bytes.fromHexString(publicKeyHex));

    final byte[] r = signature.slice(0, 32).toArray();
    final byte[] s = signature.slice(32, 32).toArray();
    final byte[] v = signature.slice(64).toArray();
    final BigInteger messagePublicKey = recoverPublicKey(new SignatureData(v, r, s));
    assertThat(EthPublicKeyUtils.web3JPublicKeyToECPublicKey(messagePublicKey))
        .isEqualTo(expectedPublicKey);
  }

  void verifyDigestSignature(final Bytes signature, final Bytes digest, final String publicKeyHex) {
    final ECPublicKey expectedPublicKey =
        EthPublicKeyUtils.bytesToECPublicKey(Bytes.fromHexString(publicKeyHex));

    final byte[] r = signature.slice(0, 32).toArray();
    final byte[] s = signature.slice(32, 32).toArray();
    final byte[] v = signature.slice(64).toArray();
    try {
      final BigInteger messagePublicKey =
          Sign.signedMessageHashToKey(digest.toArray(), new SignatureData(v, r, s));
      assertThat(EthPublicKeyUtils.web3JPublicKeyToECPublicKey(messagePublicKey))
          .isEqualTo(expectedPublicKey);
    } catch (final SignatureException e) {
      throw new IllegalStateException("signature cannot be recovered", e);
    }
  }

  private BigInteger recoverPublicKey(final SignatureData signature) {
    try {
      return signedMessageToKey(DATA.toArray(), signature);
    } catch (final SignatureException e) {
      throw new IllegalStateException("signature cannot be recovered", e);
    }
  }

  private static Map.Entry<String, ECPublicKey> createRemoteAWSKMSKey(final AwsKmsUtil awsKmsUtil) {
    final String testKeyId = awsKmsUtil.createKey(Collections.emptyMap());

    final ECPublicKey ecPublicKey = awsKmsUtil.publicKey(testKeyId);
    return Maps.immutableEntry(testKeyId, ecPublicKey);
  }
}
