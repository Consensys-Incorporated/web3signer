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
package tech.pegasys.web3signer.enclave.host;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
      new KeyBundle.Dek("aws-kms", KEY_ARN, CONTEXT, new byte[] {1, 2, 3});

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
    assertThat(broker.release(DEK, new byte[] {7, 7, 7})).containsExactly(0x30, 0x80);
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
    assertThatThrownBy(() -> broker.release(DEK, new byte[] {7}))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("plaintext");
  }

  @Test
  void policyCheckIsADryRunWithoutRecipient() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("AccessDeniedException"));
    broker.assertAttestationRequired(DEK);
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
    assertThatThrownBy(() -> broker.assertAttestationRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("without attestation");
  }

  @Test
  void policyCheckFailsOnAnyOtherError() {
    when(kms.decrypt(any(DecryptRequest.class))).thenThrow(kmsError("NotFoundException"));
    assertThatThrownBy(() -> broker.assertAttestationRequired(DEK))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("NotFoundException");
  }
}
