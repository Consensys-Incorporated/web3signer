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

import java.util.Arrays;
import java.util.Map;

import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
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
import software.amazon.awssdk.services.kms.model.RecipientInfo;

/**
 * AWS KMS: {@code GenerateDataKey} for sealing, {@code Decrypt} with a Nitro Enclaves attestation
 * document as {@code Recipient} for the release. KMS answers the release with the data key
 * encrypted to the RSA key in the document, so the host never sees it.
 */
public final class AwsKmsKeyReleaseBroker implements KeyReleaseBroker {
  private static final Map<String, String> ENCRYPTION_CONTEXT =
      Map.of("purpose", "web3signer-enclave-bls-keys");

  private final KmsClient kms;
  private final String keyId;

  /**
   * @param kms the client; closed with this broker
   * @param keyId key id, ARN or alias for {@link #newDataKey()}; may be null when only releasing
   */
  AwsKmsKeyReleaseBroker(final KmsClient kms, final String keyId) {
    this.kms = kms;
    this.keyId = keyId;
  }

  /**
   * A broker with a KMS client for {@code region} and the default credentials chain, for sealing.
   * To release, use {@link #forRelease}, which takes the region from the bundle's key ARN.
   */
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
    return arnParts(keyArn)[3];
  }

  /** The root principal of the account that owns a KMS key ARN. */
  static String accountRootOf(final String keyArn) {
    final String[] parts = arnParts(keyArn);
    return "arn:" + parts[1] + ":iam::" + parts[4] + ":root";
  }

  private static String[] arnParts(final String keyArn) {
    final String[] parts = keyArn.split(":", 6);
    if (parts.length != 6
        || !parts[0].equals("arn")
        || !parts[2].equals("kms")
        || parts[3].isEmpty()
        || parts[4].isEmpty()) {
      throw new IllegalArgumentException("Not a KMS key ARN: " + keyArn);
    }
    return parts;
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
    try {
      if (plaintext.length != Protocol.DEK_SIZE) {
        throw new IllegalStateException(
            "KMS returned a data key of " + plaintext.length + " bytes");
      }
      return new DataKey(
          plaintext,
          new KeyBundle.Dek(
              KeyBundle.Dek.PROVIDER_AWS_KMS,
              response.keyId(),
              ENCRYPTION_CONTEXT,
              response.ciphertextBlob().asByteArray()));
    } catch (final RuntimeException e) {
      Arrays.fill(plaintext, (byte) 0);
      throw e;
    }
  }

  /**
   * KMS verifies the attestation document and encrypts to the public key inside it, so the release
   * key that travels beside the evidence is not used here.
   */
  @Override
  public byte[] release(final KeyBundle.Dek dek, final Evidence evidence) {
    checkProvider(dek);
    checkEvidenceType(evidence);
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
    // with a recipient, KMS documents Plaintext as null or empty
    if (!isEmpty(response.plaintext())) {
      Arrays.fill(response.plaintext().asByteArrayUnsafe(), (byte) 0);
      throw new IllegalStateException(
          "KMS returned the data key in plaintext although a recipient was given; aborting");
    }
    if (isEmpty(response.ciphertextForRecipient())) {
      throw new IllegalStateException("KMS returned no CiphertextForRecipient");
    }
    return response.ciphertextForRecipient().asByteArray();
  }

  private static boolean isEmpty(final SdkBytes bytes) {
    return bytes == null || bytes.asByteArrayUnsafe().length == 0;
  }

  /**
   * Dry runs {@code Decrypt}, {@code ReEncrypt} and {@code CreateGrant} as this principal, without
   * attestation, and fails unless KMS refuses each one. Other principals, and a principal that can
   * change the key policy, are not checked.
   */
  @Override
  public void assertEvidenceRequired(final KeyBundle.Dek dek) {
    checkProvider(dek);
    // before any KMS call, so a key id that is not an ARN fails first
    final String grantee = accountRootOf(dek.keyId());
    assertDenied("Decrypt", () -> kms.decrypt(decryptRequest(dek).dryRun(true).build()));
    assertDenied("ReEncrypt", () -> kms.reEncrypt(reEncryptDryRun(dek)));
    assertDenied("CreateGrant", () -> kms.createGrant(createGrantDryRun(dek, grantee)));
  }

  /** Only an access denied passes: a dry run that would succeed, or any other error, fails. */
  private static void assertDenied(final String operation, final Runnable dryRun) {
    try {
      dryRun.run();
    } catch (final DryRunOperationException e) {
      // how KMS says the call would succeed
    } catch (final KmsException e) {
      if (isAccessDenied(e)) {
        return;
      }
      throw new IllegalStateException(
          "KMS key policy check of " + operation + " failed: " + e.getMessage(), e);
    }
    throw new IllegalStateException(
        "This principal can obtain the data key with "
            + operation
            + " without attestation; fix the KMS key policy");
  }

  /**
   * Re-encrypts to the same key, which catches {@code kms:ReEncrypt*}. A {@code kms:ReEncryptFrom}
   * granted on its own, used towards another key, is not caught.
   */
  private static ReEncryptRequest reEncryptDryRun(final KeyBundle.Dek dek) {
    return ReEncryptRequest.builder()
        .ciphertextBlob(SdkBytes.fromByteArray(dek.wrapped()))
        .sourceKeyId(dek.keyId())
        .sourceEncryptionContext(dek.encryptionContext())
        .destinationKeyId(dek.keyId())
        .dryRun(true)
        .build();
  }

  /**
   * A grant of {@code Decrypt} to the key's account, since grants carry no attestation condition. A
   * policy that only allows grants to some other grantee is not caught.
   */
  private static CreateGrantRequest createGrantDryRun(
      final KeyBundle.Dek dek, final String grantee) {
    return CreateGrantRequest.builder()
        .keyId(dek.keyId())
        .granteePrincipal(grantee)
        .operations(GrantOperation.DECRYPT)
        .dryRun(true)
        .build();
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
