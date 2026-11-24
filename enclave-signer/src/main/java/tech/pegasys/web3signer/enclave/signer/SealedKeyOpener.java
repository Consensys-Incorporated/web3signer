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

import static tech.pegasys.web3signer.enclave.protocol.Protocol.PUBLIC_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SEALED_CIPHERTEXT_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SECRET_KEY_SIZE;

import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.lang.foreign.MemorySegment;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Opens one sealed key: AES-256-GCM under the data key with the public key as additional data, then
 * {@code blst_sk_check}, then the derived public key must equal the entry's.
 */
final class SealedKeyOpener {
  private final Blst blst;
  private final Blst.Scratch scratch;
  private final SecretKeySpec dek;
  private final byte[] secret = new byte[SECRET_KEY_SIZE];
  private final byte[] derived = new byte[PUBLIC_KEY_SIZE];

  SealedKeyOpener(final Blst blst, final Blst.Scratch scratch, final byte[] dek) {
    this.blst = blst;
    this.scratch = scratch;
    this.dek = new SecretKeySpec(dek, "AES");
  }

  /**
   * Opens {@code key} into {@code scalar}.
   *
   * @return false when the entry is rejected; {@code scalar} is zeroed then
   */
  boolean open(final SealedKey key, final MemorySegment scalar) {
    try {
      final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      gcm.init(Cipher.DECRYPT_MODE, dek, new GCMParameterSpec(128, key.nonce()));
      gcm.updateAAD(key.publicKey());
      if (gcm.doFinal(key.ciphertext(), 0, SEALED_CIPHERTEXT_SIZE, secret, 0) != SECRET_KEY_SIZE) {
        return false;
      }
      blst.scalarFromBigEndian(scratch, secret, 0, scalar);
      if (!blst.isValidSecretKey(scalar)) {
        scalar.fill((byte) 0);
        return false;
      }
      blst.publicKey(scratch, scalar, derived, 0);
      if (!Arrays.equals(derived, key.publicKey())) {
        scalar.fill((byte) 0);
        return false;
      }
      return true;
    } catch (final GeneralSecurityException | RuntimeException e) {
      scalar.fill((byte) 0);
      return false;
    } finally {
      Arrays.fill(secret, (byte) 0);
    }
  }
}
