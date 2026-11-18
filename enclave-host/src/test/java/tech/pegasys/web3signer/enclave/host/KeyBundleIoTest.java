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

import tech.pegasys.web3signer.enclave.protocol.SealedKey;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeyBundleIoTest {

  private static byte[] filled(final int size, final int value) {
    final byte[] bytes = new byte[size];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static final KeyBundle BUNDLE =
      new KeyBundle(
          1,
          new KeyBundle.Dek(
              "aws-kms",
              "arn:aws:kms:us-east-1:111122223333:key/0b9c",
              Map.of("purpose", "web3signer-enclave-bls-keys"),
              filled(20, 7)),
          List.of(
              new SealedKey(filled(48, 1), filled(12, 2), filled(48, 3)),
              new SealedKey(filled(48, 4), filled(12, 5), filled(48, 6))));

  @Test
  void roundTripsThroughJsonAndFiles(@TempDir final Path dir) throws Exception {
    final String json = KeyBundleIo.toJson(BUNDLE);
    assertThat(json)
        .contains("\"provider\" : \"aws-kms\"")
        .contains("\"wrapped\" : \"BwcHBwcHBwcHBwcHBwcHBwcHBwc=\"")
        .contains("\"pubkey\" : \"0x" + "01".repeat(48) + "\"")
        .contains("\"nonce\" : \"0x" + "02".repeat(12) + "\"");
    final KeyBundle parsed = KeyBundleIo.fromJson(json);
    assertThat(parsed.keys()).isEqualTo(BUNDLE.keys());
    assertThat(parsed.dek().wrapped()).isEqualTo(BUNDLE.dek().wrapped());
    assertThat(parsed.dek().encryptionContext()).isEqualTo(BUNDLE.dek().encryptionContext());
    assertThat(parsed.dek().keyId()).isEqualTo(BUNDLE.dek().keyId());

    final Path file = dir.resolve("keys.bundle.json");
    KeyBundleIo.write(BUNDLE, file);
    assertThat(KeyBundleIo.read(file).keys()).isEqualTo(BUNDLE.keys());
    assertThat(dir.toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void unknownVersionIsRefused() {
    final String json = KeyBundleIo.toJson(BUNDLE).replace("\"version\" : 1", "\"version\" : 2");
    assertThatThrownBy(() -> KeyBundleIo.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("version");
  }

  @Test
  void malformedEntriesAreRefused() {
    final String json = KeyBundleIo.toJson(BUNDLE).replace("0x" + "02".repeat(12), "0x0202");
    assertThatThrownBy(() -> KeyBundleIo.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("nonce");
  }
}
