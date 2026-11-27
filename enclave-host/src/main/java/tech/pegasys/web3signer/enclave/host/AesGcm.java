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

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** AES-256-GCM with a fresh random nonce, as used for sealed keys and the dev data key. */
final class AesGcm {
  static final int NONCE_SIZE = Protocol.SEALED_NONCE_SIZE;
  private static final int KEY_SIZE = 32;
  private static final int TAG_BITS = 128;
  private static final SecureRandom RANDOM = new SecureRandom();

  /** A nonce and the ciphertext with its tag. */
  @SuppressWarnings("ArrayRecordComponent")
  record Sealed(byte[] nonce, byte[] ciphertext) {}

  private AesGcm() {}

  static Sealed seal(final byte[] key, final byte[] aad, final byte[] plaintext) {
    final byte[] nonce = new byte[NONCE_SIZE];
    RANDOM.nextBytes(nonce);
    try {
      return new Sealed(nonce, cipher(Cipher.ENCRYPT_MODE, key, aad, nonce).doFinal(plaintext));
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException("AES-GCM encryption failed", e);
    }
  }

  /** Fails when the key, nonce or additional data don't match the ciphertext. */
  static byte[] open(final byte[] key, final byte[] aad, final Sealed sealed)
      throws GeneralSecurityException {
    return cipher(Cipher.DECRYPT_MODE, key, aad, sealed.nonce()).doFinal(sealed.ciphertext());
  }

  private static Cipher cipher(
      final int mode, final byte[] key, final byte[] aad, final byte[] nonce)
      throws GeneralSecurityException {
    // the JCE would quietly use AES-128 or AES-192 for a shorter key
    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("AES-256 needs a 32-byte key, not " + key.length);
    }
    // GCM accepts any nonce length, and would decrypt a malformed one differently
    if (nonce.length != NONCE_SIZE) {
      throw new IllegalArgumentException("AES-GCM nonce must be 12 bytes, not " + nonce.length);
    }
    final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
    gcm.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, nonce));
    gcm.updateAAD(aad);
    return gcm;
  }
}
