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

import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
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
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.apache.tuweni.bytes.Bytes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter;

/**
 * <b>Insecure, for tests and local runs only.</b> Wraps the data key with a local master key, and
 * releases it to whatever release key the dev enclave presents: dev evidence proves nothing. The
 * release blob has the same CMS form as the one AWS KMS returns, so the enclave runs one code path
 * everywhere.
 */
public final class DevKeyReleaseBroker implements KeyReleaseBroker {
  private static final byte[] WRAP_AAD =
      "web3signer-enclave-dev-dek".getBytes(StandardCharsets.US_ASCII);

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
  public String provider() {
    return KeyBundle.Dek.PROVIDER_DEV;
  }

  @Override
  public int expectedPlatform() {
    return Protocol.PLATFORM_DEV;
  }

  @Override
  public int expectedEvidenceType() {
    return Protocol.EVIDENCE_DEV;
  }

  @Override
  public DataKey newDataKey() {
    final byte[] dek = new byte[Protocol.DEK_SIZE];
    random.nextBytes(dek);
    final AesGcm.Sealed sealed = AesGcm.seal(masterKey, WRAP_AAD, dek);
    final byte[] wrapped =
        Bytes.concatenate(Bytes.wrap(sealed.nonce()), Bytes.wrap(sealed.ciphertext())).toArray();
    return new DataKey(
        dek, new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_DEV, "dev", Map.of(), wrapped));
  }

  private byte[] unwrap(final KeyBundle.Dek dek) {
    final byte[] wrapped = dek.wrapped();
    if (wrapped.length <= AesGcm.NONCE_SIZE) {
      throw new IllegalArgumentException("The wrapped data key is too short");
    }
    final AesGcm.Sealed sealed =
        new AesGcm.Sealed(
            Arrays.copyOfRange(wrapped, 0, AesGcm.NONCE_SIZE),
            Arrays.copyOfRange(wrapped, AesGcm.NONCE_SIZE, wrapped.length));
    try {
      return AesGcm.open(masterKey, WRAP_AAD, sealed);
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("The dev master key does not open this bundle's data key");
    }
  }

  @Override
  public byte[] release(final KeyBundle.Dek dek, final Evidence evidence) {
    final byte[] plaintext = unwrap(dek);
    try {
      final byte[] releaseKey = evidence.releaseKey();
      final PublicKey recipient =
          KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(releaseKey));
      final byte[] subjectKeyId = MessageDigest.getInstance("SHA-256").digest(releaseKey);
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
  public void assertEvidenceRequired(final KeyBundle.Dek dek) {}

  @Override
  public void close() {
    Arrays.fill(masterKey, (byte) 0);
  }
}
