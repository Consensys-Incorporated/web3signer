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

import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.util.Map;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptRequest;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.DryRunOperationException;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyRequest;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyResponse;
import software.amazon.awssdk.services.kms.model.KeyEncryptionMechanism;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.RecipientInfo;

/**
 * AWS KMS: {@code GenerateDataKey} for sealing, {@code Decrypt} with a Nitro Enclaves attestation
 * document as {@code Recipient} for the release. KMS answers with the data key encrypted to the RSA
 * key in the document, so the caller never sees it.
 */
public final class AwsKmsKeyReleaseBroker implements KeyReleaseBroker {
  public static final Map<String, String> ENCRYPTION_CONTEXT =
      Map.of("purpose", "web3signer-enclave-bls-keys");

  private final KmsClient kms;
  private final String keyId;

  /**
   * @param kms the client; closed with this broker
   * @param keyId key id, ARN or alias for {@link #newDataKey()}; may be null when only releasing
   */
  public AwsKmsKeyReleaseBroker(final KmsClient kms, final String keyId) {
    this.kms = kms;
    this.keyId = keyId;
  }

  /** A broker with a KMS client for {@code region} and the default credentials chain. */
  public static AwsKmsKeyReleaseBroker create(final String region, final String keyId) {
    return new AwsKmsKeyReleaseBroker(KmsClient.builder().region(Region.of(region)).build(), keyId);
  }

  @Override
  public String provider() {
    return KeyBundle.Dek.PROVIDER_AWS_KMS;
  }

  @Override
  public int expectedPlatform() {
    return Protocol.PLATFORM_AWS_NITRO;
  }

  @Override
  public DataKey newDataKey() {
    if (keyId == null) {
      throw new IllegalStateException("A KMS key id is required to create a data key");
    }
    final GenerateDataKeyResponse response =
        kms.generateDataKey(
            GenerateDataKeyRequest.builder()
                .keyId(keyId)
                .keySpec(DataKeySpec.AES_256)
                .encryptionContext(ENCRYPTION_CONTEXT)
                .build());
    final byte[] plaintext = response.plaintext().asByteArray();
    if (plaintext.length != Protocol.DEK_SIZE) {
      throw new IllegalStateException("KMS returned a data key of " + plaintext.length + " bytes");
    }
    return new DataKey(
        plaintext,
        new KeyBundle.Dek(
            KeyBundle.Dek.PROVIDER_AWS_KMS,
            response.keyId(),
            ENCRYPTION_CONTEXT,
            response.ciphertextBlob().asByteArray()));
  }

  @Override
  public byte[] release(final KeyBundle.Dek dek, final byte[] attestationDocument) {
    final DecryptResponse response;
    try {
      response =
          kms.decrypt(
              DecryptRequest.builder()
                  .ciphertextBlob(SdkBytes.fromByteArray(dek.wrapped()))
                  .encryptionContext(dek.encryptionContext())
                  .keyId(dek.keyId())
                  .recipient(
                      RecipientInfo.builder()
                          .attestationDocument(SdkBytes.fromByteArray(attestationDocument))
                          .keyEncryptionAlgorithm(KeyEncryptionMechanism.RSAES_OAEP_SHA_256)
                          .build())
                  .build());
    } catch (final KmsException e) {
      if (isAccessDenied(e)) {
        throw new IllegalStateException(
            "KMS refused to release the data key to the enclave: the key policy does not accept"
                + " this enclave's attestation. Check that the enclave runs without --debug-mode"
                + " and that the PCR0 in the key policy matches the image (nitro-cli describe-eif)."
                + " KMS said: "
                + e.getMessage(),
            e);
      }
      throw e;
    }
    if (response.plaintext() != null && response.plaintext().asByteArray().length > 0) {
      throw new IllegalStateException(
          "KMS returned the data key in plaintext although a recipient was given; aborting");
    }
    if (response.ciphertextForRecipient() == null) {
      throw new IllegalStateException("KMS returned no CiphertextForRecipient");
    }
    return response.ciphertextForRecipient().asByteArray();
  }

  @Override
  public void assertAttestationRequired(final KeyBundle.Dek dek) {
    try {
      kms.decrypt(
          DecryptRequest.builder()
              .ciphertextBlob(SdkBytes.fromByteArray(dek.wrapped()))
              .encryptionContext(dek.encryptionContext())
              .keyId(dek.keyId())
              .dryRun(true)
              .build());
    } catch (final DryRunOperationException e) {
      throw new IllegalStateException(
          "This principal can decrypt the data key without attestation; fix the KMS key policy");
    } catch (final KmsException e) {
      if (isAccessDenied(e)) {
        return;
      }
      throw new IllegalStateException("KMS key policy check failed: " + e.getMessage(), e);
    }
    throw new IllegalStateException(
        "KMS accepted a dry-run Decrypt without attestation; fix the KMS key policy");
  }

  private static boolean isAccessDenied(final KmsException e) {
    return e.awsErrorDetails() != null
        && "AccessDeniedException".equals(e.awsErrorDetails().errorCode());
  }

  @Override
  public void close() {
    kms.close();
  }
}
