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

import static java.nio.ByteOrder.LITTLE_ENDIAN;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * The part of <a href="https://github.com/ethereum/ssz-specs">SSZ</a> that the protocol uses:
 * containers of {@code Uint8}, {@code Uint16}, {@code Uint32}, byte vectors and byte lists, with
 * the byte lists after the fixed fields, and lists of fixed-size containers as a whole body.
 */
final class Ssz {
  static final int BYTES_PER_LENGTH_OFFSET = 4;

  private Ssz() {}

  static Writer writeContainer() {
    return new Writer();
  }

  /** Decodes a whole body as one container; the body must be used up. */
  static <T> T readContainer(final byte[] body, final String what, final Decoder<T> decoder)
      throws IOException {
    final Reader reader = new Reader(body, what);
    final T value = decoder.decode(reader);
    reader.checkNothingLeft();
    return value;
  }

  /** Encodes a whole body as a list of fixed-size containers: their fields one after another. */
  static <T> byte[] writeList(final List<T> items, final int maxCount, final Encoder<T> encoder) {
    checkArgument(
        items.size() <= maxCount,
        "List of " + items.size() + " items, at most " + maxCount + " allowed");
    final Writer out = new Writer();
    for (final T item : items) {
      encoder.encode(out, item);
    }
    checkArgument(out.byteLists.isEmpty(), "List items must be of fixed size");
    return out.toBytes();
  }

  /** Decodes a whole body as a list of fixed-size containers, until the body runs out. */
  static <T> List<T> readList(
      final byte[] body, final int maxCount, final String what, final Decoder<T> decoder)
      throws IOException {
    final Reader reader = new Reader(body, what);
    final List<T> items = new ArrayList<>();
    while (reader.in.hasRemaining()) {
      reader.checkBody(items.size() < maxCount, "list longer than " + maxCount);
      items.add(decoder.decode(reader));
    }
    return items;
  }

  /** Encodes a whole body as a byte list of at most {@code maxSize} bytes. */
  static byte[] writeByteList(final byte[] value, final int maxSize) {
    checkArgument(
        value.length <= maxSize,
        "Byte list of " + value.length + " bytes, at most " + maxSize + " allowed");
    return value.clone();
  }

  /** Decodes a whole body as a byte list of at most {@code maxSize} bytes. */
  static byte[] readByteList(final byte[] body, final int maxSize, final String what)
      throws IOException {
    checkBody(body.length <= maxSize, what, "byte list longer than " + maxSize);
    return body;
  }

  /** Writes the fields of a container or of one list item. */
  @FunctionalInterface
  interface Encoder<T> {
    void encode(Writer out, T value);
  }

  /** Reads the fields of a container or of one list item. */
  @FunctionalInterface
  interface Decoder<T> {
    T decode(Reader in) throws IOException;
  }

  /** Throws {@link IllegalArgumentException}: a value the message cannot carry. */
  private static void checkArgument(final boolean valid, final String message) {
    if (!valid) {
      throw new IllegalArgumentException(message);
    }
  }

  /** Throws the {@link IOException} of a malformed body. */
  private static void checkBody(final boolean valid, final String what, final String reason)
      throws IOException {
    if (!valid) {
      throw new IOException("Malformed " + what + ": " + reason);
    }
  }

  /** Encodes one container. {@link #toBytes()} places the offsets at the end of the fixed part. */
  static final class Writer {
    private final ByteArrayOutputStream fixed = new ByteArrayOutputStream();
    private final List<byte[]> byteLists = new ArrayList<>(2);

    private Writer() {}

    Writer uint8(final int value) {
      return uint(value, 1);
    }

    Writer uint16(final int value) {
      return uint(value, 2);
    }

    Writer uint32(final long value) {
      return uint(value, 4);
    }

    /** A byte vector of exactly {@code size} bytes. */
    Writer vector(final byte[] value, final int size) {
      checkArgument(
          value.length == size, "Byte vector of " + value.length + " bytes, expected " + size);
      fixed().writeBytes(value);
      return this;
    }

    Writer byteList(final byte[] value, final int maxSize) {
      checkArgument(
          value.length <= maxSize,
          "Byte list of " + value.length + " bytes, at most " + maxSize + " allowed");
      byteLists.add(value);
      return this;
    }

    private Writer uint(final long value, final int size) {
      checkArgument(
          value >= 0 && value < 1L << (8 * size), "uint" + 8 * size + " out of range: " + value);
      final ByteArrayOutputStream out = fixed();
      for (int i = 0; i < size; i++) {
        out.write((int) (value >>> (8 * i)));
      }
      return this;
    }

    private ByteArrayOutputStream fixed() {
      if (!byteLists.isEmpty()) {
        throw new IllegalStateException("Fixed fields must come before byte lists");
      }
      return fixed;
    }

    byte[] toBytes() {
      final int fixedSize = fixed.size() + BYTES_PER_LENGTH_OFFSET * byteLists.size();
      int size = fixedSize;
      for (final byte[] byteList : byteLists) {
        size += byteList.length;
      }
      final ByteBuffer out = ByteBuffer.allocate(size).order(LITTLE_ENDIAN);
      out.put(fixed.toByteArray());
      int offset = fixedSize;
      for (final byte[] byteList : byteLists) {
        out.putInt(offset);
        offset += byteList.length;
      }
      for (final byte[] byteList : byteLists) {
        out.put(byteList);
      }
      return out.array();
    }
  }

  /**
   * Decodes one container, or the items of a list, field by field. At the first byte list it reads
   * all the offsets: the first one is the size of the fixed part, so it gives their number.
   */
  static final class Reader {
    private final ByteBuffer in;
    private final String what;

    /** Start of each byte list, then the end of the body; null before the first byte list. */
    private int[] bounds;

    private int nextByteList;

    private Reader(final byte[] body, final String what) {
      this.in = ByteBuffer.wrap(body).order(LITTLE_ENDIAN);
      this.what = what;
    }

    int uint8() throws IOException {
      return fixed(1).get() & 0xff;
    }

    int uint16() throws IOException {
      return fixed(2).getShort() & 0xffff;
    }

    long uint32() throws IOException {
      return Integer.toUnsignedLong(fixed(4).getInt());
    }

    byte[] vector(final int size) throws IOException {
      final byte[] value = new byte[size];
      fixed(size).get(value);
      return value;
    }

    byte[] byteList(final int maxSize) throws IOException {
      if (bounds == null) {
        readOffsets();
      }
      final int count = bounds.length - 1;
      checkBody(
          nextByteList < count,
          "has " + count + " byte lists, expected at least " + (nextByteList + 1));
      final int from = bounds[nextByteList];
      final int to = bounds[++nextByteList];
      checkBody(to - from <= maxSize, "byte list longer than " + maxSize);
      final byte[] value = new byte[to - from];
      in.get(from, value);
      return value;
    }

    private ByteBuffer fixed(final int size) throws IOException {
      if (bounds != null) {
        throw new IllegalStateException(what + ": fixed fields must come before byte lists");
      }
      checkBody(in.remaining() >= size, "shorter than its fixed part");
      return in;
    }

    /** The rest of the fixed part is offsets, and the end of the body closes the last byte list. */
    private void readOffsets() throws IOException {
      final int start = in.position();
      checkBody(in.remaining() >= BYTES_PER_LENGTH_OFFSET, "shorter than its fixed part");
      final long fixedSize = Integer.toUnsignedLong(in.getInt());
      checkBody(
          fixedSize >= start + BYTES_PER_LENGTH_OFFSET
              && fixedSize <= in.limit()
              && (fixedSize - start) % BYTES_PER_LENGTH_OFFSET == 0,
          "first offset is not the size of the fixed part");
      final int count = (int) (fixedSize - start) / BYTES_PER_LENGTH_OFFSET;
      bounds = new int[count + 1];
      bounds[0] = (int) fixedSize;
      for (int i = 1; i < count; i++) {
        // read signed: an offset of 2^31 or more is negative, so the order check refuses it
        bounds[i] = in.getInt();
      }
      bounds[count] = in.limit();
      for (int i = 1; i <= count; i++) {
        checkBody(bounds[i] >= bounds[i - 1], "offsets decrease or point past the end");
      }
    }

    private void checkNothingLeft() throws IOException {
      if (bounds == null) {
        checkBody(!in.hasRemaining(), "trailing bytes");
      } else {
        final int count = bounds.length - 1;
        checkBody(nextByteList == count, "has " + count + " byte lists, expected " + nextByteList);
      }
    }

    void checkBody(final boolean valid, final String reason) throws IOException {
      Ssz.checkBody(valid, what, reason);
    }
  }
}
