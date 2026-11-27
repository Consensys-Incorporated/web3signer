/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.enclave.host.aws;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import tech.pegasys.web3signer.enclave.host.KeyBundle;
import tech.pegasys.web3signer.enclave.host.KeyReleaseBroker;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.util.Arrays;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.CreateGrantRequest;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DryRunOperationException;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.GrantOperation;
import software.amazon.awssdk.services.kms.model.KeyEncryptionMechanism;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.ReEncryptRequest;

class AwsKmsKeyReleaseBrokerTest {
  private static final String KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/test";
  private static final Map<String, String> CONTEXT =
      Map.of("purpose", "web3signer-enclave-bls-keys");
  private static final KeyBundle.Dek DEK =
      new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_AWS_KMS, KEY_ARN, CONTEXT, new byte[] {1, 2, 3});

  private final KmsClient kms = mock(KmsClient.class);
  private final AwsKmsKeyReleaseBroker broker = new AwsKmsKeyReleaseBroker(kms, "alias/test");

  private static Evidence evidence(final byte[] document) {
    return new Evidence(Protocol.EVIDENCE_AWS_NITRO, new byte[] {9, 9}, document);
  }

  private static byte[] filled32() {
    final byte[] bytes = new byte[32];
    Arrays.fill(bytes, (byte) 5);
    return bytes;
  }

  private static KmsException kmsError(final String code) {
    return (KmsException)
        KmsException.builder()
            .statusCode(400)
            .awsErrorDetails(AwsErrorDetails.builder().errorCode(code).errorMessage(code).build())
            .build();
  }

  private void denyAllDryRuns() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("AccessDeniedException"));
    when(kms.reEncrypt(any(ReEncryptRequest.class))).thenThrow(kmsError("AccessDeniedException"));
    when(kms.createGrant(any(CreateGrantRequest.class)))
        .thenThrow(kmsError("AccessDeniedException"));
  }

  @Test
  void newDataKeyAsksForAnAes256KeyWithTheEncryptionContext() {
    when(kms.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenReturn(
            GenerateDataKeyResponse.builder()
                .keyId(KEY_ARN)
                .plaintext(SdkBytes.fromByteArray(filled32()))
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[] {9, 9}))
                .build());
    try (KeyReleaseBroker.DataKey dataKey = broker.newDataKey()) {
      assertThat(dataKey.plaintext()).isEqualTo(filled32());
      assertThat(dataKey.dek().provider()).isEqualTo("aws-kms");
      assertThat(dataKey.dek().keyId()).isEqualTo(KEY_ARN);
      assertThat(dataKey.dek().wrapped()).containsExactly(9, 9);
      assertThat(dataKey.dek().encryptionContext()).isEqualTo(CONTEXT);
    }
    final ArgumentCaptor<GenerateDataKeyRequest> request =
        ArgumentCaptor.forClass(GenerateDataKeyRequest.class);
    verify(kms).generateDataKey(request.capture());
    assertThat(request.getValue().keyId()).isEqualTo("alias/test");
    assertThat(request.getValue().keySpec()).isEqualTo(DataKeySpec.AES_256);
    assertThat(request.getValue().encryptionContext()).isEqualTo(CONTEXT);
  }

  @Test
  void newDataKeyRefusesAKeyOfTheWrongSize() {
    final byte[] shortKey = new byte[16];
    Arrays.fill(shortKey, (byte) 5);
    final SdkBytes plaintext = SdkBytes.fromByteArray(shortKey);
    when(kms.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenReturn(
            GenerateDataKeyResponse.builder()
                .keyId(KEY_ARN)
                .plaintext(plaintext)
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[] {9}))
                .build());
    assertThatThrownBy(broker::newDataKey)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("KMS returned a data key of 16 bytes");
    assertThat(plaintext.asByteArrayUnsafe()).containsOnly(0);
  }

  @Test
  void newDataKeyWipesThePlaintextWhenTheResponseIsIncomplete() {
    final SdkBytes plaintext = SdkBytes.fromByteArray(filled32());
    when(kms.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenReturn(
            GenerateDataKeyResponse.builder()
                .plaintext(plaintext)
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[] {9}))
                .build());
    assertThatThrownBy(broker::newDataKey)
        .isInstanceOf(NullPointerException.class)
        .hasMessage("keyId");
    assertThat(plaintext.asByteArrayUnsafe()).containsOnly(0);
  }

  @Test
  void newDataKeyNeedsAKeyId() {
    final AwsKmsKeyReleaseBroker releaseOnly = new AwsKmsKeyReleaseBroker(kms, null);
    assertThatThrownBy(releaseOnly::newDataKey)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("A KMS key id is required to create a data key");
    verifyNoInteractions(kms);
  }

  @Test
  void closingTheDataKeyWipesTheKmsResponse() {
    final SdkBytes plaintext = SdkBytes.fromByteArray(filled32());
    when(kms.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenReturn(
            GenerateDataKeyResponse.builder()
                .keyId(KEY_ARN)
                .plaintext(plaintext)
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[] {9}))
                .build());
    broker.newDataKey().close();
    assertThat(plaintext.asByteArrayUnsafe()).containsOnly(0);
  }

  @Test
  void releaseSendsTheAttestationDocumentAsRecipient() {
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenReturn(
            DecryptResponse.builder()
                .keyId(KEY_ARN)
                .ciphertextForRecipient(SdkBytes.fromByteArray(new byte[] {0x30, (byte) 0x80}))
                .build());
    assertThat(broker.release(DEK, evidence(new byte[] {7, 7, 7}))).containsExactly(0x30, 0x80);
    final ArgumentCaptor<DecryptRequest> request = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(kms).decrypt(request.capture());
    final DecryptRequest sent = request.getValue();
    assertThat(sent.ciphertextBlob().asByteArray()).containsExactly(1, 2, 3);
    assertThat(sent.encryptionContext()).isEqualTo(CONTEXT);
    assertThat(sent.keyId()).isEqualTo(KEY_ARN);
    assertThat(sent.recipient().attestationDocument().asByteArray()).containsExactly(7, 7, 7);
    assertThat(sent.recipient().keyEncryptionAlgorithm())
        .isEqualTo(KeyEncryptionMechanism.RSAES_OAEP_SHA_256);
    assertThat(sent.dryRun()).isNull();
  }

  @Test
  void releaseAcceptsAnEmptyPlaintextBesideTheCiphertextForRecipient() {
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenReturn(
            DecryptResponse.builder()
                .plaintext(SdkBytes.fromByteArray(new byte[0]))
                .ciphertextForRecipient(SdkBytes.fromByteArray(new byte[] {0x30}))
                .build());
    assertThat(broker.release(DEK, evidence(new byte[] {7}))).containsExactly(0x30);
  }

  @Test
  void releaseFailsWhenKmsReturnsAPlaintext() {
    final SdkBytes plaintext = SdkBytes.fromByteArray(filled32());
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenReturn(
            DecryptResponse.builder()
                .plaintext(plaintext)
                .ciphertextForRecipient(SdkBytes.fromByteArray(new byte[] {0x30}))
                .build());
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7})))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage(
            "KMS returned the data key in plaintext although a recipient was given; aborting");
    assertThat(plaintext.asByteArrayUnsafe()).containsOnly(0);
  }

  @ParameterizedTest
  @NullAndEmptySource
  void releaseFailsWhenKmsReturnsNoCiphertextForRecipient(final byte[] ciphertext) {
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenReturn(
            DecryptResponse.builder()
                .keyId(KEY_ARN)
                .ciphertextForRecipient(
                    ciphertext == null ? null : SdkBytes.fromByteArray(ciphertext))
                .build());
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7})))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("KMS returned no CiphertextForRecipient");
  }

  @Test
  void releaseExplainsAnAccessDeniedAndKeepsTheKmsMessage() {
    final KmsException denied = kmsError("AccessDeniedException");
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(denied);
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7})))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("KMS refused to release the data key to the enclave")
        .hasMessageContaining("--debug-mode")
        .hasMessageContaining("PCR0")
        .hasMessageContaining("names this instance's role")
        .hasMessageContaining("KMS said: " + denied.getMessage())
        .hasCause(denied);
  }

  @Test
  void releasePassesOtherKmsErrorsThrough() {
    final KmsException notFound = kmsError("NotFoundException");
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(notFound);
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7}))).isSameAs(notFound);
  }

  @Test
  void policyCheckDryRunsEachOperationWithoutAttestation() {
    denyAllDryRuns();
    broker.assertEvidenceRequired(DEK);

    final ArgumentCaptor<DecryptRequest> decrypt = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(kms).decrypt(decrypt.capture());
    assertThat(decrypt.getValue().dryRun()).isTrue();
    assertThat(decrypt.getValue().recipient()).isNull();
    assertThat(decrypt.getValue().encryptionContext()).isEqualTo(CONTEXT);
    assertThat(decrypt.getValue().keyId()).isEqualTo(KEY_ARN);

    final ArgumentCaptor<ReEncryptRequest> reEncrypt =
        ArgumentCaptor.forClass(ReEncryptRequest.class);
    verify(kms).reEncrypt(reEncrypt.capture());
    assertThat(reEncrypt.getValue().dryRun()).isTrue();
    assertThat(reEncrypt.getValue().ciphertextBlob().asByteArray()).containsExactly(1, 2, 3);
    assertThat(reEncrypt.getValue().sourceKeyId()).isEqualTo(KEY_ARN);
    assertThat(reEncrypt.getValue().sourceEncryptionContext()).isEqualTo(CONTEXT);
    assertThat(reEncrypt.getValue().destinationKeyId()).isEqualTo(KEY_ARN);

    final ArgumentCaptor<CreateGrantRequest> grant =
        ArgumentCaptor.forClass(CreateGrantRequest.class);
    verify(kms).createGrant(grant.capture());
    assertThat(grant.getValue().dryRun()).isTrue();
    assertThat(grant.getValue().keyId()).isEqualTo(KEY_ARN);
    assertThat(grant.getValue().granteePrincipal()).isEqualTo("arn:aws:iam::111122223333:root");
    assertThat(grant.getValue().operations()).containsExactly(GrantOperation.DECRYPT);
  }

  @Test
  void policyCheckAsksForWhatTheReleaseAsksFor() {
    when(kms.reEncrypt(any(ReEncryptRequest.class))).thenThrow(kmsError("AccessDeniedException"));
    when(kms.createGrant(any(CreateGrantRequest.class)))
        .thenThrow(kmsError("AccessDeniedException"));
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenThrow(kmsError("AccessDeniedException"))
        .thenReturn(
            DecryptResponse.builder()
                .ciphertextForRecipient(SdkBytes.fromByteArray(new byte[] {0x30}))
                .build());
    broker.assertEvidenceRequired(DEK);
    broker.release(DEK, evidence(new byte[] {7}));
    final ArgumentCaptor<DecryptRequest> requests = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(kms, times(2)).decrypt(requests.capture());
    final DecryptRequest dryRun = requests.getAllValues().get(0);
    final DecryptRequest release = requests.getAllValues().get(1);
    assertThat(dryRun.toBuilder().dryRun(null).recipient(release.recipient()).build())
        .isEqualTo(release);
  }

  @ParameterizedTest
  @ValueSource(strings = {"Decrypt", "ReEncrypt", "CreateGrant"})
  void policyCheckFailsWhenADryRunWouldSucceed(final String operation) {
    denyAllDryRuns();
    final DryRunOperationException wouldSucceed =
        DryRunOperationException.builder().message("would succeed").build();
    switch (operation) {
      case "Decrypt" -> doThrow(wouldSucceed).when(kms).decrypt(any(DecryptRequest.class));
      case "ReEncrypt" -> doThrow(wouldSucceed).when(kms).reEncrypt(any(ReEncryptRequest.class));
      default -> doThrow(wouldSucceed).when(kms).createGrant(any(CreateGrantRequest.class));
    }
    assertThatThrownBy(() -> broker.assertEvidenceRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage(
            "This principal can obtain the data key with "
                + operation
                + " without attestation; fix the KMS key policy");
  }

  @Test
  void policyCheckFailsWhenADryRunReturnsWithoutError() {
    when(kms.decrypt(any(DecryptRequest.class))).thenReturn(DecryptResponse.builder().build());
    assertThatThrownBy(() -> broker.assertEvidenceRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage(
            "This principal can obtain the data key with Decrypt without attestation; fix the"
                + " KMS key policy");
  }

  @Test
  void policyCheckFailsOnAnyOtherError() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("NotFoundException"));
    assertThatThrownBy(() -> broker.assertEvidenceRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("NotFoundException");
  }

  @Test
  void policyCheckRefusesAKeyIdThatIsNotAnArnBeforeCallingKms() {
    final KeyBundle.Dek aliasDek =
        new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_AWS_KMS, "alias/test", CONTEXT, new byte[] {1});
    assertThatThrownBy(() -> broker.assertEvidenceRequired(aliasDek))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Not a KMS key ARN: alias/test");
    verifyNoInteractions(kms);
  }

  @Test
  void refusesADataKeyFromAnotherProvider() {
    final KeyBundle.Dek devDek =
        new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_DEV, "dev", Map.of(), new byte[60]);
    assertThatThrownBy(() -> broker.release(devDek, evidence(new byte[] {7})))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The bundle was sealed with provider dev, but the aws-kms broker was given");
    assertThatThrownBy(() -> broker.assertEvidenceRequired(devDek))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("provider dev");
    verifyNoInteractions(kms);
  }

  @Test
  void refusesEvidenceOfAnotherType() {
    final Evidence dev = new Evidence(Protocol.EVIDENCE_DEV, new byte[] {9}, new byte[] {9});
    assertThatThrownBy(() -> broker.release(DEK, dev))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The aws-kms broker accepts evidence type 1, but the enclave produced type 0");
    verifyNoInteractions(kms);
  }

  @Test
  void acceptsOnlyTheAwsNitroPlatform() {
    broker.checkPlatform(Protocol.PLATFORM_AWS_NITRO);
    assertThatThrownBy(() -> broker.checkPlatform(Protocol.PLATFORM_DEV))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(
            "The aws-kms broker releases data keys only to an enclave on platform aws-nitro, but"
                + " the enclave runs dev");
    assertThatThrownBy(() -> broker.checkPlatform(7))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageEndingWith("but the enclave runs platform-7");
    verifyNoInteractions(kms);
  }

  @Test
  void closeClosesTheKmsClient() {
    broker.close();
    verify(kms).close();
  }

  @Test
  void regionComesFromTheKeyArn() {
    assertThat(AwsKmsKeyReleaseBroker.regionOf(KEY_ARN)).isEqualTo("us-east-1");
    assertThat(AwsKmsKeyReleaseBroker.regionOf("arn:aws-cn:kms:cn-north-1:111122223333:key/x"))
        .isEqualTo("cn-north-1");
    assertThatThrownBy(() -> AwsKmsKeyReleaseBroker.regionOf("alias/test"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Not a KMS key ARN: alias/test");
    assertThat(AwsKmsKeyReleaseBroker.regionOf("arn:aws:kms:eu-west-1:111122223333:alias/test"))
        .isEqualTo("eu-west-1");
    assertThatThrownBy(() -> AwsKmsKeyReleaseBroker.regionOf("arn:aws:s3:us-east-1:111:bucket/x"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void accountRootComesFromTheKeyArn() {
    assertThat(AwsKmsKeyReleaseBroker.accountRootOf(KEY_ARN))
        .isEqualTo("arn:aws:iam::111122223333:root");
    assertThat(AwsKmsKeyReleaseBroker.accountRootOf("arn:aws-cn:kms:cn-north-1:444455556666:key/x"))
        .isEqualTo("arn:aws-cn:iam::444455556666:root");
    assertThatThrownBy(() -> AwsKmsKeyReleaseBroker.accountRootOf("arn:aws:kms:us-east-1::key/x"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
