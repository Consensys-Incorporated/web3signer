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
package tech.pegasys.web3signer.enclave.protocol;

import java.util.Arrays;
import java.util.HexFormat;

/**
 * One entry of {@code LOAD_KEYS}: a BLS secret encrypted with AES-256-GCM under the data key.
 *
 * @param publicKey compressed BLS public key, 48 bytes; also the GCM additional data
 * @param nonce GCM nonce, 12 bytes
 * @param ciphertext 32 bytes of ciphertext followed by the 16-byte tag
 */
@SuppressWarnings("ArrayRecordComponent")
public record SealedKey(byte[] publicKey, byte[] nonce, byte[] ciphertext) {

  public SealedKey {
    if (publicKey.length != Protocol.PUBLIC_KEY_SIZE
        || nonce.length != Protocol.SEALED_NONCE_SIZE
        || ciphertext.length != Protocol.SEALED_CIPHERTEXT_SIZE) {
      throw new IllegalArgumentException("Sealed key has wrong field sizes");
    }
  }

  @Override
  public boolean equals(final Object o) {
    return o instanceof SealedKey other
        && Arrays.equals(publicKey, other.publicKey)
        && Arrays.equals(nonce, other.nonce)
        && Arrays.equals(ciphertext, other.ciphertext);
  }

  @Override
  public int hashCode() {
    return 31 * (31 * Arrays.hashCode(publicKey) + Arrays.hashCode(nonce))
        + Arrays.hashCode(ciphertext);
  }

  @Override
  public String toString() {
    return "SealedKey[publicKey=0x" + HexFormat.of().formatHex(publicKey) + "]";
  }
}
