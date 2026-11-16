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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

/**
 * <b>Insecure, for tests and local runs only.</b> Wraps the data key with a local master key, and
 * releases it to whatever RSA key the dev enclave presents: its "attestation document" is the SPKI
 * of that key. The release blob has the same CMS form as the one AWS KMS returns, so the enclave
 * runs one code path everywhere.
 */
public final class DevKeyReleaseBroker implements KeyReleaseBroker {
  private static final byte[] WRAP_AAD =
      "web3signer-enclave-dev-dek".getBytes(StandardCharsets.US_ASCII);
  private static final int NONCE_SIZE = 12;

  private final byte[] masterKey;
  private final SecureRandom random = new SecureRandom();

  public DevKeyReleaseBroker(final byte[] masterKey) {
    if (masterKey.length != 32) {
      throw new IllegalArgumentException("The dev master key must be 32 bytes");
    }
    this.masterKey = masterKey.clone();
  }

  /** Reads a master key file: 64 hex characters, surrounding whitespace ignored. */
  public static DevKeyReleaseBroker fromFile(final Path file) throws IOException {
    final String hex = Files.readString(file).trim();
    if (hex.length() != 64) {
      throw new IllegalArgumentException("The dev master key file must hold 64 hex characters");
    }
    return new DevKeyReleaseBroker(HexFormat.of().parseHex(hex));
  }

  @Override
  public int expectedPlatform() {
    return Protocol.PLATFORM_DEV;
  }

  @Override
  public DataKey newDataKey() {
    final byte[] dek = new byte[Protocol.DEK_SIZE];
    random.nextBytes(dek);
    final byte[] nonce = new byte[NONCE_SIZE];
    random.nextBytes(nonce);
    try {
      final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      gcm.init(
          Cipher.ENCRYPT_MODE,
          new SecretKeySpec(masterKey, "AES"),
          new GCMParameterSpec(128, nonce));
      gcm.updateAAD(WRAP_AAD);
      final byte[] sealed = gcm.doFinal(dek);
      final byte[] wrapped = new byte[NONCE_SIZE + sealed.length];
      System.arraycopy(nonce, 0, wrapped, 0, NONCE_SIZE);
      System.arraycopy(sealed, 0, wrapped, NONCE_SIZE, sealed.length);
      return new DataKey(
          dek, new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_DEV, "dev", Map.of(), wrapped));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("Cannot wrap the data key", e);
    }
  }

  private byte[] unwrap(final KeyBundle.Dek dek) {
    final byte[] wrapped = dek.wrapped();
    if (wrapped.length <= NONCE_SIZE) {
      throw new IllegalArgumentException("The wrapped data key is too short");
    }
    try {
      final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      gcm.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(masterKey, "AES"),
          new GCMParameterSpec(128, wrapped, 0, NONCE_SIZE));
      gcm.updateAAD(WRAP_AAD);
      return gcm.doFinal(wrapped, NONCE_SIZE, wrapped.length - NONCE_SIZE);
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("The dev master key does not open this bundle's data key");
    }
  }

  @Override
  public byte[] release(final KeyBundle.Dek dek, final byte[] attestationDocument) {
    final byte[] plaintext = unwrap(dek);
    try {
      final PublicKey recipient =
          KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(attestationDocument));
      final byte[] subjectKeyId = MessageDigest.getInstance("SHA-256").digest(attestationDocument);
      final JceKeyTransRecipientInfoGenerator recipientInfo =
          new JceKeyTransRecipientInfoGenerator(
              subjectKeyId,
              new JcaAlgorithmParametersConverter()
                  .getAlgorithmIdentifier(
                      PKCSObjectIdentifiers.id_RSAES_OAEP,
                      new OAEPParameterSpec(
                          "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT)),
              recipient);
      final CMSEnvelopedDataStreamGenerator generator = new CMSEnvelopedDataStreamGenerator();
      generator.addRecipientInfoGenerator(recipientInfo);
      final ByteArrayOutputStream out = new ByteArrayOutputStream();
      try (OutputStream content =
          generator.open(out, new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).build())) {
        content.write(plaintext);
      }
      return out.toByteArray();
    } catch (final GeneralSecurityException | CMSException | IOException e) {
      throw new IllegalStateException("Cannot build the release envelope", e);
    } finally {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  /** The dev provider has no policy: anyone with the master key can open the data key. */
  @Override
  public void assertAttestationRequired(final KeyBundle.Dek dek) {}

  @Override
  public void close() {
    Arrays.fill(masterKey, (byte) 0);
  }
}
