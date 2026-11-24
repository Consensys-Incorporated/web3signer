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

import tech.pegasys.web3signer.enclave.protocol.Messages.PublicKeysPage;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Append-only key set shared by all connections.
 *
 * <ul>
 *   <li>Secret scalars live in native memory from {@link Arena#global()}, allocated in chunks. They
 *       are never moved or freed.
 *   <li>The index is an open-addressing table over an {@code int[]} whose size is a power of two of
 *       at least twice the key count. A hit is confirmed by comparing all 48 bytes.
 *   <li>Readers take one immutable snapshot from a volatile field; writers are synchronized and
 *       publish a new snapshot.
 * </ul>
 */
public final class KeyTable {
  private static final int CHUNK_KEYS = 1024;
  private static final long HASH_MULTIPLIER = 0x9E37_79B9_7F4A_7C15L;

  /** Immutable view of the key set. {@code slots} hold key index + 1, 0 when empty. */
  @SuppressWarnings("ArrayRecordComponent")
  private record Snapshot(
      int count, byte[] publicKeys, MemorySegment[] secrets, int[] slots, int shift) {}

  private volatile Snapshot snapshot =
      new Snapshot(0, new byte[0], new MemorySegment[0], new int[2], 63);

  private MemorySegment chunk = MemorySegment.NULL;
  private int chunkUsed = CHUNK_KEYS;

  public int size() {
    return snapshot.count;
  }

  /** The secret scalar for the public key at {@code buffer[offset..offset + 48)}, or null. */
  public MemorySegment lookup(final byte[] buffer, final int offset) {
    final Snapshot s = snapshot;
    final int index = find(s, buffer, offset);
    return index >= 0 ? s.secrets[index] : null;
  }

  public boolean contains(final byte[] publicKey) {
    return find(snapshot, publicKey, 0) >= 0;
  }

  private static int find(final Snapshot s, final byte[] buffer, final int offset) {
    final int mask = s.slots.length - 1;
    int slot = hash(buffer, offset, s.shift);
    while (true) {
      final int entry = s.slots[slot];
      if (entry == 0) {
        return -1;
      }
      final int index = entry - 1;
      final int at = index * PUBLIC_KEY_SIZE;
      if (Arrays.equals(
          s.publicKeys, at, at + PUBLIC_KEY_SIZE, buffer, offset, offset + PUBLIC_KEY_SIZE)) {
        return index;
      }
      slot = (slot + 1) & mask;
    }
  }

  /** The 8 bytes at offset 8 (the first byte carries compression flags), multiplied, top bits. */
  private static int hash(final byte[] buffer, final int offset, final int shift) {
    long bits = 0;
    for (int i = 8; i < 16; i++) {
      bits = (bits << 8) | (buffer[offset + i] & 0xff);
    }
    return (int) ((bits * HASH_MULTIPLIER) >>> shift);
  }

  /**
   * Copies {@code count} public keys from {@code publicKeys} (48 bytes each) and their scalars from
   * {@code scalars} (32 bytes each) into the table. Keys already present are skipped.
   *
   * @return the number of keys added
   */
  public synchronized int addAll(
      final byte[] publicKeys, final MemorySegment scalars, final int count) {
    final Snapshot old = snapshot;
    final int capacity = old.count + count;
    final byte[] keys = Arrays.copyOf(old.publicKeys, capacity * PUBLIC_KEY_SIZE);
    final MemorySegment[] secrets = Arrays.copyOf(old.secrets, capacity);
    int size = old.count;
    final int bits = 64 - Long.numberOfLeadingZeros(Math.max(1, capacity * 2L - 1));
    final int[] slots = new int[1 << bits];
    final int shift = 64 - bits;
    for (int i = 0; i < size; i++) {
      insert(slots, shift, keys, i);
    }
    // shares the arrays being filled, so keys added by this call are found too
    final Snapshot building = new Snapshot(size, keys, secrets, slots, shift);
    for (int i = 0; i < count; i++) {
      final int from = i * PUBLIC_KEY_SIZE;
      if (find(building, publicKeys, from) >= 0) {
        continue;
      }
      System.arraycopy(publicKeys, from, keys, size * PUBLIC_KEY_SIZE, PUBLIC_KEY_SIZE);
      final MemorySegment secret = allocateSecret();
      MemorySegment.copy(scalars, i * (long) Blst.SCALAR_SIZE, secret, 0, Blst.SCALAR_SIZE);
      secrets[size] = secret;
      insert(slots, shift, keys, size);
      size++;
    }
    snapshot =
        new Snapshot(
            size,
            Arrays.copyOf(keys, size * PUBLIC_KEY_SIZE),
            Arrays.copyOf(secrets, size),
            slots,
            shift);
    return size - old.count;
  }

  private static void insert(
      final int[] slots, final int shift, final byte[] keys, final int index) {
    final int mask = slots.length - 1;
    int slot = hash(keys, index * PUBLIC_KEY_SIZE, shift);
    while (slots[slot] != 0) {
      slot = (slot + 1) & mask;
    }
    slots[slot] = index + 1;
  }

  private MemorySegment allocateSecret() {
    if (chunkUsed == CHUNK_KEYS) {
      chunk = Arena.global().allocate((long) CHUNK_KEYS * Blst.SCALAR_SIZE, 8);
      chunkUsed = 0;
    }
    return chunk.asSlice((long) chunkUsed++ * Blst.SCALAR_SIZE, Blst.SCALAR_SIZE);
  }

  /**
   * Up to {@code limit} public keys starting at {@code offset}, in load order, from one snapshot.
   */
  public PublicKeysPage page(final long offset, final int limit) {
    final Snapshot s = snapshot;
    final int count = offset >= s.count ? 0 : (int) Math.min(limit, s.count - offset);
    final List<byte[]> keys = new ArrayList<>(count);
    for (int i = 0, at = (int) offset * PUBLIC_KEY_SIZE; i < count; i++, at += PUBLIC_KEY_SIZE) {
      keys.add(Arrays.copyOfRange(s.publicKeys, at, at + PUBLIC_KEY_SIZE));
    }
    return new PublicKeysPage(s.count, keys);
  }
}
