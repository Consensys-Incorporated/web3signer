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

import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.enclave.protocol.Messages.PublicKeysPage;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class KeyTableTest {
  private final Random random = new Random(42);

  /**
   * A public key whose bytes derive from {@code id} (SplitMix64 of id and position); the scalar
   * holds {@code id}.
   */
  private static byte[] publicKey(final int id) {
    final byte[] key = new byte[48];
    for (int i = 0; i < key.length; i += 8) {
      long z = (((long) id << 8) | i) + 0x9E3779B97F4A7C15L;
      z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
      z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
      z ^= z >>> 31;
      for (int b = 0; b < 8; b++) {
        key[i + b] = (byte) (z >>> (8 * b));
      }
    }
    key[0] = (byte) 0x80; // compression flag, as in real keys
    return key;
  }

  private static int add(final KeyTable table, final int from, final int count) {
    return add(table, ids(from, count));
  }

  private static int[] ids(final int from, final int count) {
    final int[] ids = new int[count];
    for (int i = 0; i < count; i++) {
      ids[i] = from + i;
    }
    return ids;
  }

  private static int add(final KeyTable table, final int[] ids) {
    try (Arena arena = Arena.ofConfined()) {
      final byte[] keys = new byte[ids.length * 48];
      final MemorySegment scalars = arena.allocate(ids.length * 32L, 8);
      for (int i = 0; i < ids.length; i++) {
        System.arraycopy(publicKey(ids[i]), 0, keys, i * 48, 48);
        scalars.set(JAVA_INT, i * 32L, ids[i]);
      }
      return table.addAll(keys, scalars, ids.length);
    }
  }

  private static int scalarId(final MemorySegment scalar) {
    return scalar.get(JAVA_INT, 0);
  }

  @Test
  void lookupHitAndMiss() {
    final KeyTable table = new KeyTable();
    assertThat(table.lookup(publicKey(1), 0)).isNull();
    assertThat(add(table, 0, 100)).isEqualTo(100);
    for (int i = 0; i < 100; i++) {
      assertThat(scalarId(table.lookup(publicKey(i), 0))).isEqualTo(i);
    }
    assertThat(table.lookup(publicKey(100), 0)).isNull();
    final byte[] almost = publicKey(5);
    almost[47] ^= 1;
    assertThat(table.lookup(almost, 0)).isNull();
    final byte[] shifted = new byte[60];
    System.arraycopy(publicKey(7), 0, shifted, 12, 48);
    assertThat(scalarId(table.lookup(shifted, 12))).isEqualTo(7);
  }

  @Test
  void duplicatesAreSkipped() {
    final KeyTable table = new KeyTable();
    assertThat(add(table, 0, 10)).isEqualTo(10);
    assertThat(add(table, 5, 10)).isEqualTo(5);
    assertThat(add(table, new int[] {20, 20, 21})).isEqualTo(2);
    assertThat(table.size()).isEqualTo(17);
    assertThat(table.contains(publicKey(20))).isTrue();
  }

  @Test
  void pagesAcrossSeveralAddsInLoadOrder() {
    final KeyTable table = new KeyTable();
    add(table, 0, 7);
    add(table, 7, 1);
    add(table, 8, 12);
    final List<byte[]> seen = new ArrayList<>();
    for (int offset = 0; ; ) {
      final PublicKeysPage page = table.page(offset, 3);
      assertThat(page.total()).isEqualTo(20);
      if (page.publicKeys().isEmpty()) {
        break;
      }
      seen.addAll(page.publicKeys());
      offset += page.publicKeys().size();
    }
    assertThat(seen).hasSize(20);
    for (int i = 0; i < 20; i++) {
      assertThat(seen.get(i)).isEqualTo(publicKey(i));
    }
    assertThat(table.page(25, 3).publicKeys()).isEmpty();
    assertThat(table.page(0xFFFF_FFFFL, 3).publicKeys()).isEmpty();
  }

  @Test
  void lookupsFromEightThreadsDuringAdds() throws Exception {
    final KeyTable table = new KeyTable();
    final AtomicInteger published = new AtomicInteger();
    final AtomicBoolean done = new AtomicBoolean();
    try (ExecutorService readers = Executors.newFixedThreadPool(8)) {
      final List<Future<Long>> results = new ArrayList<>();
      for (int t = 0; t < 8; t++) {
        final Random threadRandom = new Random(random.nextLong());
        results.add(
            readers.submit(
                () -> {
                  long lookups = 0;
                  while (!done.get()) {
                    final int count = published.get();
                    if (count == 0) {
                      continue;
                    }
                    final int id = threadRandom.nextInt(count);
                    final MemorySegment scalar = table.lookup(publicKey(id), 0);
                    assertThat(scalar).isNotNull();
                    assertThat(scalarId(scalar)).isEqualTo(id);
                    assertThat(table.lookup(publicKey(1_000_000 + id), 0)).isNull();
                    lookups++;
                  }
                  return lookups;
                }));
      }
      for (int batch = 0; batch < 20; batch++) {
        add(table, batch * 500, 500);
        published.set((batch + 1) * 500);
        Thread.sleep(2);
      }
      done.set(true);
      for (final Future<Long> result : results) {
        assertThat(result.get()).isPositive();
      }
    }
    assertThat(table.size()).isEqualTo(10_000);
  }
}
