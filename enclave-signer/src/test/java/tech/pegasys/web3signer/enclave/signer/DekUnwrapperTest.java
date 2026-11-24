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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.pegasys.web3signer.enclave.signer.TestEnvelopes.HEX;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DekUnwrapperTest {
  private static KeyPair rsa;
  private static byte[] dek;
  private static byte[] ber;

  @BeforeAll
  static void createKey() throws Exception {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    rsa = generator.generateKeyPair();
    dek = TestEnvelopes.randomBytes(32);
    ber = TestEnvelopes.envelope(rsa.getPublic(), dek, true);
  }

  private static byte[] resource(final String name) throws IOException {
    try (InputStream in = DekUnwrapperTest.class.getResourceAsStream("/" + name)) {
      return HEX.parseHex(new String(in.readAllBytes(), StandardCharsets.US_ASCII).trim());
    }
  }

  private static int indexOf(final byte[] haystack, final byte[] needle) {
    for (int i = 0; i <= haystack.length - needle.length; i++) {
      if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
        return i;
      }
    }
    throw new IllegalStateException("not found");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "_w_ctx"})
  void parsesTheAwsSamples(final String suffix) throws Exception {
    final CmsEnvelopedData envelope =
        CmsEnvelopedData.parse(resource("kms-cms-vectors/input_ber" + suffix + ".hex"));
    assertThat(envelope.encryptedKey())
        .isEqualTo(resource("kms-cms-vectors/encrypted_key_out" + suffix + ".hex"));
    assertThat(envelope.iv()).isEqualTo(resource("kms-cms-vectors/iv_out" + suffix + ".hex"));
    assertThat(envelope.encryptedContent())
        .isEqualTo(resource("kms-cms-vectors/ciphertext_out" + suffix + ".hex"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"debug", "production"})
  void unwrapsRealKmsAnswers(final String mode) throws Exception {
    final byte[] cms = resource("kms-release-vectors/" + mode + ".cms.hex");
    final PrivateKey key =
        KeyFactory.getInstance("RSA")
            .generatePrivate(
                new PKCS8EncodedKeySpec(resource("kms-release-vectors/" + mode + ".pkcs8.hex")));
    final byte[] expectedContent = resource("kms-release-vectors/" + mode + ".content.hex");
    assertThat(cms).hasSize(493);
    assertThat(expectedContent).hasSize(48);

    final CmsEnvelopedData envelope = CmsEnvelopedData.parse(cms);
    final Cipher oaep = Cipher.getInstance("RSA/ECB/OAEPPadding");
    oaep.init(
        Cipher.DECRYPT_MODE,
        key,
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    final Cipher aes = Cipher.getInstance("AES/CBC/NoPadding");
    aes.init(
        Cipher.DECRYPT_MODE,
        new SecretKeySpec(oaep.doFinal(envelope.encryptedKey()), "AES"),
        new IvParameterSpec(envelope.iv()));
    assertThat(aes.doFinal(envelope.encryptedContent())).isEqualTo(expectedContent);

    assertThat(DekUnwrapper.unwrap(key, cms)).isEqualTo(Arrays.copyOf(expectedContent, 32));
  }

  @Test
  void roundTripsBerAndDerEnvelopes() throws Exception {
    assertThat(ber[1] & 0xff).isEqualTo(0x80);
    assertThat(DekUnwrapper.unwrap(rsa.getPrivate(), ber)).isEqualTo(dek);
    final byte[] der = TestEnvelopes.envelope(rsa.getPublic(), dek, false);
    assertThat(der[1] & 0xff).isNotEqualTo(0x80);
    assertThat(DekUnwrapper.unwrap(rsa.getPrivate(), der)).isEqualTo(dek);
  }

  @Test
  void paddingBlockIsNeverInspected() throws Exception {
    final byte[] content = CmsEnvelopedData.parse(ber).encryptedContent();
    final int lastBlock = indexOf(ber, Arrays.copyOfRange(content, 32, 48));
    for (int i = 0; i < 16; i++) {
      final byte[] tampered = ber.clone();
      tampered[lastBlock + i] ^= 0x01;
      assertThat(DekUnwrapper.unwrap(rsa.getPrivate(), tampered)).isEqualTo(dek);
    }
  }

  @Test
  void tamperedIvGivesAnotherKeyWithoutError() throws Exception {
    final byte[] tampered = ber.clone();
    tampered[indexOf(ber, CmsEnvelopedData.parse(ber).iv())] ^= 0x01;
    final byte[] other = DekUnwrapper.unwrap(rsa.getPrivate(), tampered);
    assertThat(other).hasSize(32).isNotEqualTo(dek);
  }

  @Test
  void corruptedEncryptedKeyFails() throws Exception {
    final byte[] tampered = ber.clone();
    tampered[indexOf(ber, CmsEnvelopedData.parse(ber).encryptedKey()) + 5] ^= 0x01;
    assertUnwrapFails(tampered);
  }

  @ParameterizedTest
  @ValueSource(ints = {16, 48})
  void contentOtherThan48BytesFails(final int plaintextSize) throws Exception {
    final byte[] envelope =
        TestEnvelopes.envelope(rsa.getPublic(), TestEnvelopes.randomBytes(plaintextSize), true);
    assertThat(CmsEnvelopedData.parse(envelope).encryptedContent())
        .hasSize(plaintextSize == 16 ? 32 : 64);
    assertUnwrapFails(envelope);
  }

  @Test
  void wrongContentTypeFails() {
    final byte[] tampered = ber.clone();
    final int at = indexOf(ber, HEX.parseHex("2a864886f70d010701"));
    tampered[at + 8] = 0x02;
    assertUnwrapFails(tampered);
  }

  @Test
  void truncatedInputFails() {
    for (int length = 0; length < ber.length; length++) {
      assertUnwrapFails(Arrays.copyOf(ber, length));
    }
    final byte[] trailing = Arrays.copyOf(ber, ber.length + 1);
    assertUnwrapFails(trailing);
  }

  @Test
  void randomMutationsOnlyEverFailAsUnwrapFailed() {
    final Random random = new Random(7);
    for (int i = 0; i < 10_000; i++) {
      final byte[] mutated = mutate(ber, random);
      try {
        final byte[] result = DekUnwrapper.unwrap(rsa.getPrivate(), mutated);
        assertThat(result).hasSize(32);
      } catch (final DekUnwrapper.UnwrapException e) {
        assertThat(e).hasMessage("unwrap failed").hasNoCause();
      }
    }
  }

  private static byte[] mutate(final byte[] original, final Random random) {
    final byte[] copy = original.clone();
    final int kind = random.nextInt(4);
    if (kind == 0) {
      for (int flips = 1 + random.nextInt(3); flips > 0; flips--) {
        copy[random.nextInt(copy.length)] ^= (byte) (1 << random.nextInt(8));
      }
      return copy;
    }
    if (kind == 1) {
      copy[random.nextInt(copy.length)] = (byte) random.nextInt(256);
      return copy;
    }
    if (kind == 2) {
      return Arrays.copyOf(copy, random.nextInt(copy.length));
    }
    final int at = random.nextInt(copy.length);
    final byte[] longer = new byte[copy.length + 1];
    System.arraycopy(copy, 0, longer, 0, at);
    longer[at] = (byte) random.nextInt(256);
    System.arraycopy(copy, at, longer, at + 1, copy.length - at);
    return longer;
  }

  private static void assertUnwrapFails(final byte[] blob) {
    assertThatThrownBy(() -> DekUnwrapper.unwrap(rsa.getPrivate(), blob))
        .isExactlyInstanceOf(DekUnwrapper.UnwrapException.class)
        .hasNoCause();
  }
}
