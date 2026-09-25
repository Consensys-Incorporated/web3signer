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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AadCodecTest {

  @Test
  void isDeterministic() {
    assertThat(AadCodec.forRow("tenant-a", "0xabc", 1))
        .isEqualTo(AadCodec.forRow("tenant-a", "0xabc", 1));
    assertThat(AadCodec.forTenant("tenant-a", 1)).isEqualTo(AadCodec.forTenant("tenant-a", 1));
  }

  @Test
  void lengthPrefixingPreventsFieldBoundaryCollisions() {
    // "A" + "BC" must not encode the same as "AB" + "C"
    final byte[] first = AadCodec.forRow("A", "BC", 1);
    final byte[] second = AadCodec.forRow("AB", "C", 1);
    assertThat(first).isNotEqualTo(second);
  }

  @Test
  void differentDekVersionsProduceDifferentAad() {
    assertThat(AadCodec.forRow("tenant-a", "0xabc", 1))
        .isNotEqualTo(AadCodec.forRow("tenant-a", "0xabc", 2));
    assertThat(AadCodec.forTenant("tenant-a", 1)).isNotEqualTo(AadCodec.forTenant("tenant-a", 2));
  }

  @Test
  void rowAadDiffersFromTenantAad() {
    assertThat(AadCodec.forRow("tenant-a", "tenant-a", 1))
        .isNotEqualTo(AadCodec.forTenant("tenant-a", 1));
  }
}
