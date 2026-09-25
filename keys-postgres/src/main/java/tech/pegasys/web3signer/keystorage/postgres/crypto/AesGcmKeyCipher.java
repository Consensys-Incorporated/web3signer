/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM encrypt/decrypt for the postgres keystore's on-disk format: a 12-byte random IV
 * prepended to the ciphertext, followed by the 16-byte GCM tag (the tag is appended automatically
 * by {@link Cipher#doFinal}).
 *
 * <p>Not thread-safe - holds a single {@link Cipher} instance so it can be reused across many calls
 * (avoiding repeated {@code Cipher.getInstance} provider lookups and, since the JDK caches the
 * expanded AES key schedule across {@code init()} calls for an unchanged key, repeated calls with
 * the same key are cheaper than the first). Callers running parallel decryption should hold one
 * instance per worker thread (e.g. via {@link ThreadLocal}), scoped to a single load cycle.
 *
 * <p>{@code encrypt} is provided so that test fixtures (and any provisioning-side tooling written
 * against this class) produce ciphertext using the exact same code path this class uses to decrypt,
 * rather than a second, independently-written implementation that could silently drift from the
 * real contract.
 */
public final class AesGcmKeyCipher {

  private static final String TRANSFORMATION = "AES/GCM/NoPadding";
  private static final int GCM_TAG_BITS = 128;
  public static final int IV_LENGTH_BYTES = 12;

  private final Cipher cipher;

  public AesGcmKeyCipher() {
    try {
      this.cipher = Cipher.getInstance(TRANSFORMATION);
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("AES/GCM/NoPadding is not available on this JVM", e);
    }
  }

  /**
   * Returns the decrypted plaintext.
   *
   * @param key the AES-256 key
   * @param ivCiphertextAndTag {@code IV(12) || ciphertext || tag(16)}
   * @param aad the additional authenticated data expected for this ciphertext
   */
  public byte[] decrypt(final byte[] key, final byte[] ivCiphertextAndTag, final byte[] aad)
      throws GeneralSecurityException {
    final GCMParameterSpec spec =
        new GCMParameterSpec(GCM_TAG_BITS, ivCiphertextAndTag, 0, IV_LENGTH_BYTES);
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
    cipher.updateAAD(aad);
    return cipher.doFinal(
        ivCiphertextAndTag, IV_LENGTH_BYTES, ivCiphertextAndTag.length - IV_LENGTH_BYTES);
  }

  /**
   * Returns {@code IV(12) || ciphertext || tag(16)}.
   *
   * @param key the AES-256 key
   * @param plaintext the plaintext to encrypt
   * @param aad the additional authenticated data to bind this ciphertext to
   */
  public byte[] encrypt(final byte[] key, final byte[] plaintext, final byte[] aad)
      throws GeneralSecurityException {
    final byte[] iv = new byte[IV_LENGTH_BYTES];
    SecureRandom.getInstanceStrong().nextBytes(iv);
    cipher.init(
        Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
    cipher.updateAAD(aad);
    final byte[] ciphertextAndTag = cipher.doFinal(plaintext);
    final byte[] result = new byte[IV_LENGTH_BYTES + ciphertextAndTag.length];
    System.arraycopy(iv, 0, result, 0, IV_LENGTH_BYTES);
    System.arraycopy(ciphertextAndTag, 0, result, IV_LENGTH_BYTES, ciphertextAndTag.length);
    return result;
  }
}
