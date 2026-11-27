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

import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class KeyBundleTest {
  private static final KeyBundle.Dek DEK =
      new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_DEV, "dev", Map.of("a", "b"), filled(20, 7));

  private static byte[] filled(final int size, final int value) {
    final byte[] bytes = new byte[size];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static SealedKey sealedKey(final int pubKeyFill) {
    return new SealedKey(filled(48, pubKeyFill), filled(12, 2), filled(48, 3));
  }

  @Test
  void needsADek() {
    assertThatThrownBy(() -> new KeyBundle(null, List.of()))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("dek");
  }

  @Test
  void refusesTheSamePublicKeyTwice() {
    assertThatThrownBy(() -> new KeyBundle(DEK, List.of(sealedKey(1), sealedKey(4), sealedKey(1))))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle holds public key 0x" + "01".repeat(48) + " more than once");
  }

  @Test
  void allowsNoKeys() {
    assertThat(new KeyBundle(DEK, List.of()).keys()).isEmpty();
  }

  @Test
  void dekNeedsAProviderAndKeyId() {
    assertThatThrownBy(() -> new KeyBundle.Dek(null, "dev", Map.of(), new byte[] {1}))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("provider");
    assertThatThrownBy(() -> new KeyBundle.Dek("dev", null, Map.of(), new byte[] {1}))
        .isInstanceOf(NullPointerException.class)
        .hasMessage("keyId");
  }

  @Test
  void dekRefusesAnUnknownProvider() {
    assertThatThrownBy(() -> new KeyBundle.Dek("bogus", "dev", Map.of(), new byte[] {1}))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unknown key bundle provider: bogus");
  }

  @Test
  void dekRefusesAnEmptyWrappedKey() {
    assertThatThrownBy(() -> new KeyBundle.Dek("dev", "dev", Map.of(), new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The wrapped data key is empty");
  }

  @Test
  void dekEqualityComparesTheWrappedKeyByContent() {
    final KeyBundle.Dek same =
        new KeyBundle.Dek(DEK.provider(), DEK.keyId(), DEK.encryptionContext(), DEK.wrapped());
    assertThat(same).isEqualTo(DEK).hasSameHashCodeAs(DEK);
    assertThat(
            new KeyBundle.Dek(DEK.provider(), DEK.keyId(), DEK.encryptionContext(), filled(20, 8)))
        .isNotEqualTo(DEK);
    assertThat(new KeyBundle.Dek(DEK.provider(), DEK.keyId(), Map.of(), DEK.wrapped()))
        .isNotEqualTo(DEK);
  }

  @Test
  void wrappedKeyCannotBeChangedThroughTheRecord() {
    DEK.wrapped()[0] = 0;
    assertThat(DEK.wrapped()).containsOnly(7);
  }

  @Test
  void changingTheArgumentsLeavesTheRecordUnchanged() {
    final byte[] wrapped = filled(20, 7);
    final Map<String, String> context = new HashMap<>(Map.of("a", "b"));
    final List<SealedKey> keys = new ArrayList<>(List.of(sealedKey(1)));
    final KeyBundle bundle =
        new KeyBundle(new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_DEV, "dev", context, wrapped), keys);

    wrapped[0] = 0;
    context.put("c", "d");
    keys.add(sealedKey(4));

    assertThat(bundle.dek()).isEqualTo(DEK);
    assertThat(bundle.keys()).hasSize(1);
  }
}
