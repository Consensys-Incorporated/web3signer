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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.GeneralSecurityException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class AesGcmTest {
  private static final byte[] KEY = new byte[32];
  private static final byte[] AAD = {1, 2, 3};
  private static final byte[] PLAINTEXT = {4, 5, 6, 7};

  @Test
  void opensWhatItSeals() throws Exception {
    final AesGcm.Sealed sealed = AesGcm.seal(KEY, AAD, PLAINTEXT);
    assertThat(sealed.nonce()).hasSize(AesGcm.NONCE_SIZE);
    assertThat(AesGcm.open(KEY, AAD, sealed)).isEqualTo(PLAINTEXT);
  }

  @Test
  void refusesOtherAdditionalData() {
    final AesGcm.Sealed sealed = AesGcm.seal(KEY, AAD, PLAINTEXT);
    assertThatThrownBy(() -> AesGcm.open(KEY, new byte[] {9}, sealed))
        .isInstanceOf(GeneralSecurityException.class);
  }

  @Test
  void refusesATamperedCiphertext() {
    final AesGcm.Sealed sealed = AesGcm.seal(KEY, AAD, PLAINTEXT);
    final byte[] tampered = sealed.ciphertext().clone();
    tampered[0] ^= 1;
    assertThatThrownBy(() -> AesGcm.open(KEY, AAD, new AesGcm.Sealed(sealed.nonce(), tampered)))
        .isInstanceOf(GeneralSecurityException.class);
  }

  @Test
  void refusesAnotherKey() {
    final AesGcm.Sealed sealed = AesGcm.seal(KEY, AAD, PLAINTEXT);
    final byte[] other = new byte[32];
    other[0] = 1;
    assertThatThrownBy(() -> AesGcm.open(other, AAD, sealed))
        .isInstanceOf(GeneralSecurityException.class);
  }

  @Test
  void usesAFreshNonceForEachSeal() {
    assertThat(AesGcm.seal(KEY, AAD, PLAINTEXT).nonce())
        .isNotEqualTo(AesGcm.seal(KEY, AAD, PLAINTEXT).nonce());
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 11, 13, 16})
  void needsA12ByteNonce(final int size) {
    final AesGcm.Sealed sealed = AesGcm.seal(KEY, AAD, PLAINTEXT);
    assertThatThrownBy(
            () -> AesGcm.open(KEY, AAD, new AesGcm.Sealed(new byte[size], sealed.ciphertext())))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("AES-GCM nonce must be 12 bytes, not " + size);
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 24, 31, 33})
  void needsA32ByteKey(final int size) {
    final byte[] key = new byte[size];
    final AesGcm.Sealed sealed = AesGcm.seal(KEY, AAD, PLAINTEXT);
    assertThatThrownBy(() -> AesGcm.seal(key, AAD, PLAINTEXT))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("AES-256 needs a 32-byte key, not " + size);
    assertThatThrownBy(() -> AesGcm.open(key, AAD, sealed))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
