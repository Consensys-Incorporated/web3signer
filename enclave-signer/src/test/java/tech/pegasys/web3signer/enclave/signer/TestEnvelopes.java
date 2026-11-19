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
package tech.pegasys.web3signer.enclave.signer;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

/** Test helpers: KMS-style CMS envelopes made with BouncyCastle, and sealed key entries. */
final class TestEnvelopes {
  static final HexFormat HEX = HexFormat.of();
  private static final SecureRandom RANDOM = new SecureRandom();

  private TestEnvelopes() {}

  static PublicKey rsaPublicKey(final byte[] spki) {
    try {
      return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(spki));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * CMS EnvelopedData: RSA-OAEP SHA-256/MGF1 SHA-256, subject key identifier recipient, AES-256-CBC
   * content. {@code stream} gives BER with indefinite lengths, otherwise DER.
   */
  static byte[] envelope(final PublicKey recipient, final byte[] plaintext, final boolean stream) {
    try {
      final byte[] subjectKeyId =
          MessageDigest.getInstance("SHA-256").digest(recipient.getEncoded());
      final AlgorithmIdentifier oaep =
          new JcaAlgorithmParametersConverter()
              .getAlgorithmIdentifier(
                  PKCSObjectIdentifiers.id_RSAES_OAEP,
                  new OAEPParameterSpec(
                      "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
      final JceKeyTransRecipientInfoGenerator recipientInfo =
          new JceKeyTransRecipientInfoGenerator(subjectKeyId, oaep, recipient);
      final OutputEncryptor encryptor =
          new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).build();
      if (stream) {
        final CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
        generator.addRecipientInfoGenerator(recipientInfo);
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (OutputStream content = generator.open(out, encryptor)) {
          content.write(plaintext);
        }
        return out.toByteArray();
      }
      final CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
      generator.addRecipientInfoGenerator(recipientInfo);
      return generator
          .generate(new CMSProcessableByteArray(plaintext), encryptor)
          .toASN1Structure()
          .getEncoded("DER");
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    } catch (final GeneralSecurityException | CMSException e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] randomBytes(final int size) {
    final byte[] bytes = new byte[size];
    RANDOM.nextBytes(bytes);
    return bytes;
  }

  /** One LOAD_KEYS entry: AES-256-GCM of {@code secret} under {@code dek}, AAD = public key. */
  static tech.pegasys.web3signer.enclave.protocol.SealedKey seal(
      final byte[] dek, final byte[] publicKey, final byte[] secret) {
    try {
      final byte[] nonce = randomBytes(12);
      final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      gcm.init(
          Cipher.ENCRYPT_MODE, new SecretKeySpec(dek, "AES"), new GCMParameterSpec(128, nonce));
      gcm.updateAAD(publicKey);
      return new tech.pegasys.web3signer.enclave.protocol.SealedKey(
          publicKey.clone(), nonce, gcm.doFinal(secret));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}
