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
package tech.pegasys.web3signer.tests.signing;

import static io.restassured.http.ContentType.ANY;
import static io.restassured.http.ContentType.JSON;
import static io.restassured.http.ContentType.TEXT;
import static java.util.Collections.singletonMap;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.networks.Eth2Network;
import tech.pegasys.web3signer.AwsSecretsManagerUtil;
import tech.pegasys.web3signer.bls.keystore.model.KdfFunction;
import tech.pegasys.web3signer.core.service.http.ArtifactType;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.Eth2SigningRequestBody;
import tech.pegasys.web3signer.dsl.HashicorpSigningParams;
import tech.pegasys.web3signer.dsl.azure.AzureKeyVaultEmulator;
import tech.pegasys.web3signer.dsl.azure.MockAzureAuthorityExtension;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.utils.Eth2RequestUtils;
import tech.pegasys.web3signer.dsl.utils.MetadataFileHelpers;
import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;
import tech.pegasys.web3signer.keystore.hashicorp.dsl.HashicorpNode;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.tests.bulkloading.AzureKeyVaultAcceptanceTest;

import java.net.URI;
import java.nio.file.Path;
import java.util.Collections;
import java.util.Optional;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.core.json.JsonObject;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariables;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;

public class BlsSigningAcceptanceTest extends SigningAcceptanceTestBase {

  private static final String PRIVATE_KEY =
      "3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35";
  private static final MetadataFileHelpers METADATA_FILE_HELPERS = new MetadataFileHelpers();

  @RegisterExtension
  static final MockAzureAuthorityExtension MOCK_AUTHORITY = new MockAzureAuthorityExtension();

  private static final BLSSecretKey KEY =
      BLSSecretKey.fromBytes(Bytes32.fromHexString(PRIVATE_KEY));
  private static final BLSKeyPair KEY_PAIR = new BLSKeyPair(KEY);
  private static final BLSPublicKey PUBLIC_KEY = KEY_PAIR.getPublicKey();

  @ParameterizedTest(name = "{index} - {0} Signing")
  @EnumSource
  public void signDataWithKeyLoadedFromUnencryptedFile(final ArtifactType artifactType)
      throws JsonProcessingException {
    final String configFilename = PUBLIC_KEY.toString().substring(2);
    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createUnencryptedYamlFileAt(keyConfigFile, PRIVATE_KEY, KeyType.BLS);

    signAndVerifySignature(artifactType, TEXT);
  }

  @ParameterizedTest
  @EnumSource
  public void signDataWithJsonAcceptTypeWithKeyLoadedFromUnencryptedFile(
      final ArtifactType artifactType) throws JsonProcessingException {
    final String configFilename = PUBLIC_KEY.toString().substring(2);
    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createUnencryptedYamlFileAt(keyConfigFile, PRIVATE_KEY, KeyType.BLS);

    signAndVerifySignature(artifactType, JSON);
  }

  @ParameterizedTest
  @EnumSource
  public void signDataWithDefaultAcceptTypeWithKeyLoadedFromUnencryptedFile(
      final ArtifactType artifactType) throws JsonProcessingException {
    final String configFilename = PUBLIC_KEY.toString().substring(2);
    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createUnencryptedYamlFileAt(keyConfigFile, PRIVATE_KEY, KeyType.BLS);
    // this is same as not setting accept type at all - the client defaults to */* aka ANY
    signAndVerifySignature(artifactType, ANY);
  }

  @ParameterizedTest
  @EnumSource(KdfFunction.class)
  public void signDataWithKeyLoadedFromKeyStoreFile(final KdfFunction kdfFunction)
      throws JsonProcessingException {
    final String configFilename = PUBLIC_KEY.toString().substring(2);

    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createKeyStoreYamlFileAt(keyConfigFile, KEY_PAIR, kdfFunction);

    signAndVerifySignature(ArtifactType.BLOCK);
  }

  @Test
  public void ableToSignUsingHashicorp() throws JsonProcessingException {
    final String configFilename = KEY_PAIR.getPublicKey().toString().substring(2);
    final HashicorpNode hashicorpNode = HashicorpNode.createAndStartHashicorp(true);
    try {
      final String secretPath = "acceptanceTestSecretPath";
      final String secretName = "secretName";

      hashicorpNode.addSecretsToVault(singletonMap(secretName, PRIVATE_KEY), secretPath);

      final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
      METADATA_FILE_HELPERS.createHashicorpYamlFileAt(
          keyConfigFile,
          new HashicorpSigningParams(hashicorpNode, secretPath, secretName, KeyType.BLS),
          Optional.empty());

      signAndVerifySignature(ArtifactType.BLOCK);
    } finally {
      hashicorpNode.shutdown();
    }
  }

  @ParameterizedTest(name = "{index} - Using http protocol version: {0}, with TLS: {1}")
  @CsvSource({"HTTP_1_1, true", "HTTP_2, true", "HTTP_1_1, false", "HTTP_2, false"})
  public void ableToSignUsingHashicorpWithHttpProtocolOverride(
      final String httpProtocolVersion, boolean withTLS) throws JsonProcessingException {
    final String configFilename = KEY_PAIR.getPublicKey().toString().substring(2);
    final HashicorpNode hashicorpNode = HashicorpNode.createAndStartHashicorp(withTLS);
    try {
      final String secretPath = "acceptanceTestSecretPath";
      final String secretName = "secretName";

      hashicorpNode.addSecretsToVault(singletonMap(secretName, PRIVATE_KEY), secretPath);

      final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
      METADATA_FILE_HELPERS.createHashicorpYamlFileAt(
          keyConfigFile,
          new HashicorpSigningParams(hashicorpNode, secretPath, secretName, KeyType.BLS),
          Optional.ofNullable(httpProtocolVersion));

      signAndVerifySignature(ArtifactType.BLOCK);
    } finally {
      hashicorpNode.shutdown();
    }
  }

  @Test
  public void ableToSignUsingAzure() throws JsonProcessingException {
    final AzureKeyVaultEmulator emulator = AzureKeyVaultEmulator.getInstance();

    // fetch secret which only has single value containing the private key. The metadata file
    // approach is not able to cater for multiple values in azure secret at present.
    final AzureKeyVault.AzureSecret azureSecret =
        AzureKeyVaultAcceptanceTest.getBLSSecretsFromEmulator(
                new AzureOverrides(
                    Optional.of(URI.create(emulator.getVaultUrl())),
                    Optional.of(URI.create(MOCK_AUTHORITY.getAuthorityHostUrl())),
                    Optional.of(emulator.getTrustCertificatePath())))
            .stream()
            .filter(entry -> entry.values().size() == 1)
            .findFirst()
            .orElseThrow();

    final Path keyConfigFile = testDirectory.resolve("azure_key.yaml");
    METADATA_FILE_HELPERS.createAzureYamlFileAt(
        keyConfigFile,
        "unused",
        "unused",
        AzureKeyVaultEmulator.TENANT_ID,
        "unused",
        azureSecret.name(),
        new AzureOverrides(
            Optional.of(URI.create(emulator.getVaultUrl())),
            Optional.of(URI.create(MOCK_AUTHORITY.getAuthorityHostUrl())),
            Optional.of(emulator.getTrustCertificatePath())));

    final BLSSecretKey azurePrivateKey =
        BLSSecretKey.fromBytes(
            Bytes32.fromHexString(azureSecret.values().stream().findFirst().orElseThrow()));
    final BLSKeyPair blsKeyPair = new BLSKeyPair(azurePrivateKey);

    final SignerConfigurationBuilder builder =
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(testDirectory)
            .withMode("eth2")
            .withNetwork(Eth2Network.MINIMAL.configName())
            .withOverriddenCA(emulator.getTlsCertificateDefinition());
    setForkEpochsAndStartSigner(builder, SpecMilestone.PHASE0);

    final Eth2SigningRequestBody request = Eth2RequestUtils.createCannedRequest(ArtifactType.BLOCK);
    final Response response = signer.eth2Sign(blsKeyPair.getPublicKey().toString(), request, TEXT);
    final Bytes signature = verifyAndGetSignatureResponse(response, TEXT);
    final BLSSignature expectedSignature =
        BLS.sign(blsKeyPair.getSecretKey(), request.signingRoot());
    assertThat(signature).isEqualTo(expectedSignature.toBytesCompressed());
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
    @EnabledIfEnvironmentVariable(
        named = "AWS_REGION",
        matches = ".+",
        disabledReason = "AWS_REGION env variable is required")
  })
  public void ableToSignUsingAws() throws JsonProcessingException {
    final String rwAwsAccessKeyId = System.getenv("RW_AWS_ACCESS_KEY_ID");
    final String rwAwsSecretAccessKey = System.getenv("RW_AWS_SECRET_ACCESS_KEY");
    final String roAwsAccessKeyId = System.getenv("AWS_ACCESS_KEY_ID");
    final String roAwsSecretAccessKey = System.getenv("AWS_SECRET_ACCESS_KEY");
    final String region = Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-2");
    // can be pointed to localstack
    final Optional<URI> awsEndpointOverride =
        System.getenv("AWS_ENDPOINT_OVERRIDE") != null
            ? Optional.of(URI.create(System.getenv("AWS_ENDPOINT_OVERRIDE")))
            : Optional.empty();
    final String publicKey = KEY_PAIR.getPublicKey().toString();

    final AwsSecretsManagerUtil awsSecretsManagerUtil =
        new AwsSecretsManagerUtil(
            region, rwAwsAccessKeyId, rwAwsSecretAccessKey, awsEndpointOverride);

    awsSecretsManagerUtil.createSecret(publicKey, PRIVATE_KEY, Collections.emptyMap());
    final String fullyPrefixKeyName = awsSecretsManagerUtil.getSecretsManagerPrefix() + publicKey;

    final String configFilename = publicKey.substring(2);
    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    try {
      METADATA_FILE_HELPERS.createAwsYamlFileAt(
          keyConfigFile,
          region,
          roAwsAccessKeyId,
          roAwsSecretAccessKey,
          fullyPrefixKeyName,
          awsEndpointOverride);

      signAndVerifySignature(ArtifactType.BLOCK);
    } finally {
      awsSecretsManagerUtil.deleteSecret(publicKey);
      awsSecretsManagerUtil.close();
    }
  }

  @ParameterizedTest
  @EnumSource
  public void failsIfSigningRootDoesNotMatchSigningData(final ArtifactType artifactType)
      throws JsonProcessingException {
    final String configFilename = PUBLIC_KEY.toString().substring(2);

    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createKeyStoreYamlFileAt(keyConfigFile, KEY_PAIR, KdfFunction.SCRYPT);

    setupMinimalWeb3Signer(artifactType);

    final Eth2SigningRequestBody request = Eth2RequestUtils.createCannedRequest(artifactType);
    final Eth2SigningRequestBody requestWithMismatchedSigningRoot =
        new Eth2SigningRequestBody(
            request.type(),
            Bytes32.ZERO,
            request.forkInfo(),
            request.block(),
            request.blockRequest(),
            request.attestation(),
            request.aggregationSlot(),
            request.aggregateAndProofV2(),
            request.voluntaryExit(),
            request.randaoReveal(),
            request.deposit(),
            request.syncCommitteeMessage(),
            request.syncAggregatorSelectionData(),
            request.contributionAndProof(),
            request.validatorRegistration(),
            request.executionPayloadBid(),
            request.executionPayloadEnvelope(),
            request.payloadAttestationMessage(),
            request.proposerPreferences(),
            request.builderRequestAuth());

    final Response response =
        signer.eth2Sign(KEY_PAIR.getPublicKey().toString(), requestWithMismatchedSigningRoot);
    assertThat(response.getStatusCode()).isEqualTo(500);
  }

  @ParameterizedTest
  @EnumSource(
      value = ContentType.class,
      names = {"TEXT", "JSON", "ANY"})
  public void ableToSignWithoutSigningRootField(final ContentType acceptableContentType)
      throws JsonProcessingException {
    final String configFilename = PUBLIC_KEY.toString().substring(2);

    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createKeyStoreYamlFileAt(keyConfigFile, KEY_PAIR, KdfFunction.SCRYPT);

    setupMinimalWeb3Signer(ArtifactType.BLOCK);

    final Eth2SigningRequestBody request = Eth2RequestUtils.createBlockRequest();

    final Eth2SigningRequestBody requestWithMismatchedSigningRoot =
        new Eth2SigningRequestBody(
            request.type(),
            null,
            request.forkInfo(),
            request.block(),
            request.blockRequest(),
            request.attestation(),
            request.aggregationSlot(),
            request.aggregateAndProofV2(),
            request.voluntaryExit(),
            request.randaoReveal(),
            request.deposit(),
            request.syncCommitteeMessage(),
            request.syncAggregatorSelectionData(),
            request.contributionAndProof(),
            request.validatorRegistration(),
            request.executionPayloadBid(),
            request.executionPayloadEnvelope(),
            request.payloadAttestationMessage(),
            request.proposerPreferences(),
            request.builderRequestAuth());

    final Response response =
        signer.eth2Sign(
            KEY_PAIR.getPublicKey().toString(),
            requestWithMismatchedSigningRoot,
            acceptableContentType);

    assertThat(response.statusCode()).isEqualTo(200);

    // validate that for ANY and JSON we get application/json content type, and we are able to parse
    // JSON as well.
    if (acceptableContentType == ANY || acceptableContentType == JSON) {
      assertThat(response.contentType()).startsWith("application/json");
      final JsonObject jsonObject = new JsonObject(response.body().print());
      assertThat(jsonObject.containsKey("signature")).isTrue();
    } else {
      assertThat(response.contentType()).startsWith("text/plain");
    }
  }

  private void signAndVerifySignature(final ArtifactType artifactType)
      throws JsonProcessingException {
    signAndVerifySignature(artifactType, TEXT);
  }

  private void signAndVerifySignature(
      final ArtifactType artifactType, final ContentType acceptMediaType)
      throws JsonProcessingException {
    signAndVerifySignature(artifactType, KEY_PAIR, acceptMediaType);
  }

  private void signAndVerifySignature(
      final ArtifactType artifactType,
      final BLSKeyPair blsKeyPair,
      final ContentType acceptMediaType)
      throws JsonProcessingException {
    setupMinimalWeb3Signer(artifactType);

    // openapi
    final Eth2SigningRequestBody request = Eth2RequestUtils.createCannedRequest(artifactType);
    final Response response =
        signer.eth2Sign(blsKeyPair.getPublicKey().toString(), request, acceptMediaType);
    final Bytes signature =
        verifyAndGetSignatureResponse(response, expectedContentType(acceptMediaType));
    final BLSSignature expectedSignature =
        BLS.sign(blsKeyPair.getSecretKey(), request.signingRoot());
    assertThat(signature).isEqualTo(expectedSignature.toBytesCompressed());
  }

  private void setupMinimalWeb3Signer(final ArtifactType artifactType) {
    switch (artifactType) {
      case BLOCK_V2,
          SYNC_COMMITTEE_MESSAGE,
          SYNC_COMMITTEE_SELECTION_PROOF,
          SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF ->
          setupEth2Signer(Eth2Network.MINIMAL, SpecMilestone.ALTAIR);
      case EXECUTION_PAYLOAD_BID,
          EXECUTION_PAYLOAD_ENVELOPE,
          PAYLOAD_ATTESTATION_MESSAGE,
          PROPOSER_PREFERENCES,
          BUILDER_REQUEST_AUTH ->
          setupEth2Signer(Eth2Network.MINIMAL, SpecMilestone.GLOAS);
      default -> setupEth2Signer(Eth2Network.MINIMAL, SpecMilestone.PHASE0);
    }
  }

  private ContentType expectedContentType(final ContentType acceptMediaType) {
    return acceptMediaType == ANY || acceptMediaType == JSON ? JSON : TEXT;
  }
}
