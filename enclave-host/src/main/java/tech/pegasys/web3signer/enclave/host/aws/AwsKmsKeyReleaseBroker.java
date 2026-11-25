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

import tech.pegasys.web3signer.enclave.host.KeyBundle;
import tech.pegasys.web3signer.enclave.host.KeyReleaseBroker;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
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

  /**
   * A broker that releases {@code dek}, with a KMS client in the region of the bundle's key ARN and
   * the default credentials chain.
   */
  public static AwsKmsKeyReleaseBroker forRelease(final KeyBundle.Dek dek) {
    return create(regionOf(dek.keyId()), null);
  }

  /** The region of a KMS key ARN, {@code arn:<partition>:kms:<region>:<account>:key/<id>}. */
  static String regionOf(final String keyArn) {
    final String[] parts = keyArn.split(":", 6);
    if (parts.length != 6
        || !parts[0].equals("arn")
        || !parts[2].equals("kms")
        || parts[3].isEmpty()) {
      throw new IllegalArgumentException("Not a KMS key ARN: " + keyArn);
    }
    return parts[3];
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
  public int expectedEvidenceType() {
    return Protocol.EVIDENCE_AWS_NITRO;
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
    // the SDK's own array, so that closing the data key also wipes it
    final byte[] plaintext = response.plaintext().asByteArrayUnsafe();
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

  /**
   * KMS verifies the attestation document and encrypts to the public key inside it, so the release
   * key that travels beside the evidence is not used here.
   */
  @Override
  public byte[] release(final KeyBundle.Dek dek, final Evidence evidence) {
    final DecryptResponse response;
    try {
      response =
          kms.decrypt(
              decryptRequest(dek)
                  .recipient(
                      RecipientInfo.builder()
                          .attestationDocument(SdkBytes.fromByteArray(evidence.evidence()))
                          .keyEncryptionAlgorithm(KeyEncryptionMechanism.RSAES_OAEP_SHA_256)
                          .build())
                  .build());
    } catch (final KmsException e) {
      if (isAccessDenied(e)) {
        throw new IllegalStateException(
            "KMS refused to release the data key to the enclave: the key policy does not accept"
                + " this request. Check that the enclave runs without --debug-mode, that the PCR0"
                + " in the key policy matches the image (nitro-cli describe-eif), and that the key"
                + " policy names this instance's role. KMS said: "
                + e.getMessage(),
            e);
      }
      throw e;
    }
    if (response.plaintext() != null) {
      throw new IllegalStateException(
          "KMS returned the data key in plaintext although a recipient was given; aborting");
    }
    if (response.ciphertextForRecipient() == null) {
      throw new IllegalStateException("KMS returned no CiphertextForRecipient");
    }
    return response.ciphertextForRecipient().asByteArray();
  }

  @Override
  public void assertEvidenceRequired(final KeyBundle.Dek dek) {
    try {
      kms.decrypt(decryptRequest(dek).dryRun(true).build());
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

  /** The part of the release request the dry run must share, so it checks the same thing. */
  private static DecryptRequest.Builder decryptRequest(final KeyBundle.Dek dek) {
    return DecryptRequest.builder()
        .ciphertextBlob(SdkBytes.fromByteArray(dek.wrapped()))
        .encryptionContext(dek.encryptionContext())
        .keyId(dek.keyId());
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
