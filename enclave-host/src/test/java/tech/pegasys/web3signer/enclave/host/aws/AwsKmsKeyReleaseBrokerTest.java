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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import tech.pegasys.web3signer.enclave.host.KeyBundle;
import tech.pegasys.web3signer.enclave.host.KeyReleaseBroker;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DryRunOperationException;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyEncryptionMechanism;
import software.amazon.awssdk.services.kms.model.KmsException;

class AwsKmsKeyReleaseBrokerTest {
  private static final String KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/test";
  private static final Map<String, String> CONTEXT =
      Map.of("purpose", "web3signer-enclave-bls-keys");
  private static final KeyBundle.Dek DEK =
      new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_AWS_KMS, KEY_ARN, CONTEXT, new byte[] {1, 2, 3});

  private static Evidence evidence(final byte[] document) {
    return new Evidence(Protocol.EVIDENCE_AWS_NITRO, new byte[] {9, 9}, document);
  }

  private final KmsClient kms = mock(KmsClient.class);
  private final AwsKmsKeyReleaseBroker broker = new AwsKmsKeyReleaseBroker(kms, "alias/test");

  private static KmsException kmsError(final String code) {
    return (KmsException)
        KmsException.builder()
            .statusCode(400)
            .awsErrorDetails(AwsErrorDetails.builder().errorCode(code).errorMessage(code).build())
            .build();
  }

  @Test
  void newDataKeyAsksForAnAes256KeyWithTheEncryptionContext() {
    when(kms.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenReturn(
            GenerateDataKeyResponse.builder()
                .keyId(KEY_ARN)
                .plaintext(SdkBytes.fromByteArray(new byte[32]))
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[] {9, 9}))
                .build());
    try (KeyReleaseBroker.DataKey dataKey = broker.newDataKey()) {
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
  void releaseFailsWhenKmsReturnsAPlaintext() {
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenReturn(
            DecryptResponse.builder()
                .plaintext(SdkBytes.fromByteArray(new byte[32]))
                .ciphertextForRecipient(SdkBytes.fromByteArray(new byte[] {0x30}))
                .build());
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7})))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("plaintext");
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
  void policyCheckIsADryRunWithoutRecipient() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("AccessDeniedException"));
    broker.assertEvidenceRequired(DEK);
    final ArgumentCaptor<DecryptRequest> request = ArgumentCaptor.forClass(DecryptRequest.class);
    verify(kms).decrypt(request.capture());
    assertThat(request.getValue().dryRun()).isTrue();
    assertThat(request.getValue().recipient()).isNull();
    assertThat(request.getValue().encryptionContext()).isEqualTo(CONTEXT);
    assertThat(request.getValue().keyId()).isEqualTo(KEY_ARN);
  }

  @Test
  void policyCheckFailsWhenTheDryRunWouldSucceed() {
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenThrow(DryRunOperationException.builder().message("would succeed").build());
    assertThatThrownBy(() -> broker.assertEvidenceRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("without attestation");
  }

  @Test
  void policyCheckFailsOnAnyOtherError() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("NotFoundException"));
    assertThatThrownBy(() -> broker.assertEvidenceRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("NotFoundException");
  }

  @Test
  void releaseFailsWhenKmsReturnsNoCiphertextForRecipient() {
    when(kms.decrypt(any(DecryptRequest.class)))
        .thenReturn(DecryptResponse.builder().keyId(KEY_ARN).build());
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7})))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("KMS returned no CiphertextForRecipient");
  }

  @Test
  void releaseHintNamesTheParentRoleAsACause() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("AccessDeniedException"));
    assertThatThrownBy(() -> broker.release(DEK, evidence(new byte[] {7})))
        .hasMessageContaining("names this instance's role");
  }

  @Test
  void policyCheckAsksForWhatTheReleaseAsksFor() {
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

  @Test
  void newDataKeyRefusesAKeyOfTheWrongSize() {
    when(kms.generateDataKey(any(GenerateDataKeyRequest.class)))
        .thenReturn(
            GenerateDataKeyResponse.builder()
                .keyId(KEY_ARN)
                .plaintext(SdkBytes.fromByteArray(new byte[16]))
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[] {9}))
                .build());
    assertThatThrownBy(broker::newDataKey)
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("KMS returned a data key of 16 bytes");
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
  void regionComesFromTheKeyArn() {
    assertThat(AwsKmsKeyReleaseBroker.regionOf(KEY_ARN)).isEqualTo("us-east-1");
    assertThat(AwsKmsKeyReleaseBroker.regionOf("arn:aws-cn:kms:cn-north-1:111122223333:key/x"))
        .isEqualTo("cn-north-1");
    assertThatThrownBy(() -> AwsKmsKeyReleaseBroker.regionOf("alias/test"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Not a KMS key ARN: alias/test");
  }

  private static byte[] filled32() {
    final byte[] bytes = new byte[32];
    java.util.Arrays.fill(bytes, (byte) 5);
    return bytes;
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
}
