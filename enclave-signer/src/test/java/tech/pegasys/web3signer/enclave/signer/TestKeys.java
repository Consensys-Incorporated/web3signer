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

import tech.pegasys.teku.bls.BLSKeyPair;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/** Loads keys straight into a {@link KeyTable}, bypassing provisioning. */
final class TestKeys {
  private static final SecureRandom RANDOM = new SecureRandom();

  private TestKeys() {}

  static List<BLSKeyPair> random(final int count) {
    final List<BLSKeyPair> keys = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      keys.add(BLSKeyPair.random(RANDOM));
    }
    return keys;
  }

  static int load(final KeyTable table, final Blst blst, final List<BLSKeyPair> keys) {
    try (Arena arena = Arena.ofConfined()) {
      final Blst.Scratch scratch = new Blst.Scratch(arena);
      final byte[] publicKeys = new byte[keys.size() * 48];
      final MemorySegment scalars = arena.allocate(keys.size() * 32L, 8);
      for (int i = 0; i < keys.size(); i++) {
        final BLSKeyPair key = keys.get(i);
        System.arraycopy(
            key.getPublicKey().toBytesCompressed().toArrayUnsafe(), 0, publicKeys, i * 48, 48);
        blst.scalarFromBigEndian(
            scratch, key.getSecretKey().toBytes().toArrayUnsafe(), 0, scalars.asSlice(i * 32L, 32));
      }
      return table.addAll(publicKeys, scalars, keys.size());
    }
  }
}
