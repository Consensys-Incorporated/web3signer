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
 * containers of {@code uint8}, {@code uint64}, byte vectors, byte lists and lists of fixed-size
 * items, with the variable fields after the fixed ones.
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
    final Reader reader = new Reader(ByteBuffer.wrap(body).order(LITTLE_ENDIAN), what, false);
    final T value = decoder.decode(reader);
    reader.checkNothingLeft();
    return value;
  }

  /** Writes the fields of one list item. */
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
  static void require(final boolean valid, final String message) {
    if (!valid) {
      throw new IllegalArgumentException(message);
    }
  }

  /** Throws the {@link IOException} of a malformed body. */
  static void check(final boolean valid, final String what, final String reason)
      throws IOException {
    if (!valid) {
      throw new IOException("Malformed " + what + ": " + reason);
    }
  }

  /** Encodes one container. {@link #toBytes()} places the offsets at the end of the fixed part. */
  static final class Writer {
    private final ByteArrayOutputStream fixed = new ByteArrayOutputStream();
    private final List<byte[]> variables = new ArrayList<>(2);

    private Writer() {}

    Writer uint8(final int value) {
      require(value >= 0 && value <= 0xff, "uint8 out of range: " + value);
      fixed().write(value);
      return this;
    }

    Writer uint64(final long value) {
      require(value >= 0, "uint64 out of range: " + value);
      fixed().writeBytes(ByteBuffer.allocate(8).order(LITTLE_ENDIAN).putLong(value).array());
      return this;
    }

    /** A byte vector of exactly {@code size} bytes. */
    Writer vector(final byte[] value, final int size) {
      require(value.length == size, "Byte vector of " + value.length + " bytes, expected " + size);
      fixed().writeBytes(value);
      return this;
    }

    Writer byteList(final byte[] value, final int maxSize) {
      require(
          value.length <= maxSize,
          "Byte list of " + value.length + " bytes, at most " + maxSize + " allowed");
      variables.add(value);
      return this;
    }

    /** A list of fixed-size items, each written by {@code encoder}. */
    <T> Writer list(final List<T> items, final int maxCount, final Encoder<T> encoder) {
      require(
          items.size() <= maxCount,
          "List of " + items.size() + " items, at most " + maxCount + " allowed");
      final Writer item = new Writer();
      for (final T value : items) {
        encoder.encode(item, value);
      }
      if (!item.variables.isEmpty()) {
        throw new IllegalStateException("List items must be of fixed size");
      }
      variables.add(item.fixed.toByteArray());
      return this;
    }

    private ByteArrayOutputStream fixed() {
      if (!variables.isEmpty()) {
        throw new IllegalStateException("Fixed fields must come before variable fields");
      }
      return fixed;
    }

    byte[] toBytes() {
      final int fixedSize = fixed.size() + BYTES_PER_LENGTH_OFFSET * variables.size();
      int size = fixedSize;
      for (final byte[] variable : variables) {
        size += variable.length;
      }
      final ByteBuffer out = ByteBuffer.allocate(size).order(LITTLE_ENDIAN);
      out.put(fixed.toByteArray());
      int offset = fixedSize;
      for (final byte[] variable : variables) {
        out.putInt(offset);
        offset += variable.length;
      }
      for (final byte[] variable : variables) {
        out.put(variable);
      }
      return out.array();
    }
  }

  /**
   * Decodes one container, or the items of a list, field by field. At the first variable field it
   * reads all the offsets: the first one is the size of the fixed part, so it gives their number.
   */
  static final class Reader {
    private final ByteBuffer in;
    private final String what;
    private final boolean items;

    /** Start of each variable field, and the end of the container; null before the first. */
    private int[] bounds;

    private int nextVariable;

    private Reader(final ByteBuffer in, final String what, final boolean items) {
      this.in = in;
      this.what = what;
      this.items = items;
    }

    int uint8() throws IOException {
      return fixed(1).get() & 0xff;
    }

    long uint64() throws IOException {
      final long value = fixed(8).getLong();
      check(value >= 0, what, "uint64 above 2^63 - 1");
      return value;
    }

    byte[] vector(final int size) throws IOException {
      final byte[] value = new byte[size];
      fixed(size).get(value);
      return value;
    }

    byte[] byteList(final int maxSize) throws IOException {
      final ByteBuffer field = variable();
      check(field.remaining() <= maxSize, what, "byte list longer than " + maxSize);
      final byte[] value = new byte[field.remaining()];
      field.get(value);
      return value;
    }

    /** A list of at most {@code maxCount} fixed-size items, each read by {@code decoder}. */
    <T> List<T> list(final int maxCount, final Decoder<T> decoder) throws IOException {
      final ByteBuffer field = variable();
      final Reader reader = new Reader(field, what, true);
      final List<T> values = new ArrayList<>();
      while (field.hasRemaining()) {
        final int before = field.position();
        values.add(decoder.decode(reader));
        if (field.position() == before) {
          throw new IllegalStateException(what + ": list item without fields");
        }
        check(values.size() <= maxCount, what, "list longer than " + maxCount);
      }
      return values;
    }

    private ByteBuffer fixed(final int size) throws IOException {
      if (bounds != null) {
        throw new IllegalStateException(what + ": fixed fields must come before variable fields");
      }
      check(in.remaining() >= size, what, "shorter than its fixed part");
      return in;
    }

    private ByteBuffer variable() throws IOException {
      if (items) {
        throw new IllegalStateException(what + ": list items must be of fixed size");
      }
      if (bounds == null) {
        readOffsets();
      }
      final int count = bounds.length - 1;
      check(
          nextVariable < count,
          what,
          "has " + count + " variable fields, expected at least " + (nextVariable + 1));
      final int from = bounds[nextVariable];
      final int to = bounds[++nextVariable];
      return in.slice(from, to - from).order(LITTLE_ENDIAN);
    }

    private void readOffsets() throws IOException {
      final int start = in.position();
      check(in.remaining() >= BYTES_PER_LENGTH_OFFSET, what, "shorter than its fixed part");
      final long fixedSize = Integer.toUnsignedLong(in.getInt());
      check(
          fixedSize >= start + BYTES_PER_LENGTH_OFFSET
              && fixedSize <= in.limit()
              && (fixedSize - start) % BYTES_PER_LENGTH_OFFSET == 0,
          what,
          "first offset is not the size of the fixed part");
      final int count = (int) (fixedSize - start) / BYTES_PER_LENGTH_OFFSET;
      bounds = new int[count + 1];
      bounds[0] = (int) fixedSize;
      for (int i = 1; i < count; i++) {
        final long offset = Integer.toUnsignedLong(in.getInt());
        check(offset >= bounds[i - 1], what, "decreasing offsets");
        check(offset <= in.limit(), what, "offset past the end");
        bounds[i] = (int) offset;
      }
      bounds[count] = in.limit();
    }

    private void checkNothingLeft() throws IOException {
      if (bounds == null) {
        check(!in.hasRemaining(), what, "trailing bytes");
      } else {
        final int count = bounds.length - 1;
        check(
            nextVariable == count,
            what,
            "has " + count + " variable fields, expected " + nextVariable);
      }
    }
  }
}
