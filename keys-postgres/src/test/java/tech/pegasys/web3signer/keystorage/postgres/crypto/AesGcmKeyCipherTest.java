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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import javax.crypto.AEADBadTagException;

import org.junit.jupiter.api.Test;

class AesGcmKeyCipherTest {

  private static SecureRandom secureRandom = new SecureRandom();
  private final AesGcmKeyCipher cipher = new AesGcmKeyCipher();
  private final byte[] key = randomKey();
  private final byte[] aad = AadCodec.forRow("tenant-a", "0xabc", 1);

  @Test
  void decryptsWhatWasEncrypted() throws GeneralSecurityException {
    final byte[] plaintext = "a 32 byte long secret key......".getBytes(UTF_8);
    final byte[] ciphertext = cipher.encrypt(key, plaintext, aad);

    assertThat(ciphertext).hasSize(AesGcmKeyCipher.IV_LENGTH_BYTES + plaintext.length + 16);
    assertThat(cipher.decrypt(key, ciphertext, aad)).isEqualTo(plaintext);
  }

  @Test
  void producesDifferentCiphertextEachTimeDueToRandomIv() throws GeneralSecurityException {
    final byte[] plaintext = "some plaintext".getBytes(UTF_8);
    final byte[] first = cipher.encrypt(key, plaintext, aad);
    final byte[] second = cipher.encrypt(key, plaintext, aad);
    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void rejectsTamperedCiphertext() throws GeneralSecurityException {
    final byte[] ciphertext = cipher.encrypt(key, "plaintext".getBytes(UTF_8), aad);
    ciphertext[ciphertext.length - 1] ^= 0x01;

    assertThatThrownBy(() -> cipher.decrypt(key, ciphertext, aad))
        .isInstanceOf(AEADBadTagException.class);
  }

  @Test
  void rejectsMismatchedAad() throws GeneralSecurityException {
    final byte[] ciphertext = cipher.encrypt(key, "plaintext".getBytes(UTF_8), aad);
    final byte[] wrongAad = AadCodec.forRow("tenant-b", "0xabc", 1);

    assertThatThrownBy(() -> cipher.decrypt(key, ciphertext, wrongAad))
        .isInstanceOf(AEADBadTagException.class);
  }

  @Test
  void rejectsWrongKey() throws GeneralSecurityException {
    final byte[] ciphertext = cipher.encrypt(key, "plaintext".getBytes(UTF_8), aad);

    assertThatThrownBy(() -> cipher.decrypt(randomKey(), ciphertext, aad))
        .isInstanceOf(AEADBadTagException.class);
  }

  private static byte[] randomKey() {
    final byte[] key = new byte[32];
    secureRandom.nextBytes(key);
    return key;
  }
}
