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

import static tech.pegasys.web3signer.enclave.protocol.Protocol.FRAME_HEADER_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.LENGTH_PREFIX_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_FRAME_LENGTH;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MIN_FRAME_LENGTH;

import java.io.IOException;
import java.util.List;

/**
 * Frame codec: {@code length u32 | type u8 | request_id u32 | payload}. Several frames can go out
 * in one write.
 */
public final class Frames {
  /** Bytes in front of the payload: the length prefix, the type and the request id. */
  public static final int OVERHEAD = LENGTH_PREFIX_SIZE + FRAME_HEADER_SIZE;

  private Frames() {}

  /** A decoded frame. The payload of a response starts with the status byte. */
  @SuppressWarnings("ArrayRecordComponent")
  public record Frame(int type, int requestId, byte[] payload) {
    /** The status byte of a response, or {@link Protocol#BAD_REQUEST} for an empty payload. */
    public int status() {
      return payload.length == 0 ? Protocol.BAD_REQUEST : payload[0] & 0xff;
    }
  }

  /** Thrown when a frame announces a length outside the protocol range. Closes the connection. */
  public static final class FrameLengthException extends IOException {
    private static final long serialVersionUID = 1L;

    public FrameLengthException(final long length) {
      super("Frame length out of range: " + length);
    }
  }

  public static boolean isValidLength(final long length) {
    return length >= MIN_FRAME_LENGTH && length <= MAX_FRAME_LENGTH;
  }

  /** Total encoded size of a frame with this payload size. */
  public static int encodedSize(final int payloadSize) {
    return OVERHEAD + payloadSize;
  }

  /**
   * Writes the frame header for a payload of {@code payloadSize} bytes at {@code offset}.
   *
   * @return the offset of the payload
   */
  public static int putHeader(
      final byte[] buffer,
      final int offset,
      final int type,
      final int requestId,
      final int payloadSize) {
    final int length = FRAME_HEADER_SIZE + payloadSize;
    if (!isValidLength(length)) {
      throw new IllegalArgumentException("Frame length out of range: " + length);
    }
    putInt(buffer, offset, length);
    buffer[offset + 4] = (byte) type;
    putInt(buffer, offset + 5, requestId);
    return offset + OVERHEAD;
  }

  public static byte[] encode(final int type, final int requestId, final byte[] payload) {
    final byte[] frame = new byte[encodedSize(payload.length)];
    final int at = putHeader(frame, 0, type, requestId, payload.length);
    System.arraycopy(payload, 0, frame, at, payload.length);
    return frame;
  }

  /** Writes all frames with one write. */
  public static void writeAll(final Connection connection, final List<byte[]> frames)
      throws IOException {
    int size = 0;
    for (final byte[] frame : frames) {
      size += frame.length;
    }
    final byte[] buffer = new byte[size];
    int at = 0;
    for (final byte[] frame : frames) {
      System.arraycopy(frame, 0, buffer, at, frame.length);
      at += frame.length;
    }
    connection.write(buffer, 0, size);
  }

  /** Reads one frame. A length outside the protocol range throws {@link FrameLengthException}. */
  public static Frame read(final Connection connection) throws IOException {
    final byte[] header = new byte[OVERHEAD];
    connection.readFully(header, 0, LENGTH_PREFIX_SIZE);
    final long length = getUnsignedInt(header, 0);
    if (!isValidLength(length)) {
      throw new FrameLengthException(length);
    }
    connection.readFully(header, LENGTH_PREFIX_SIZE, FRAME_HEADER_SIZE);
    final byte[] payload = new byte[(int) length - FRAME_HEADER_SIZE];
    connection.readFully(payload, 0, payload.length);
    return new Frame(header[4] & 0xff, getInt(header, 5), payload);
  }

  public static void putInt(final byte[] buffer, final int offset, final int value) {
    buffer[offset] = (byte) (value >>> 24);
    buffer[offset + 1] = (byte) (value >>> 16);
    buffer[offset + 2] = (byte) (value >>> 8);
    buffer[offset + 3] = (byte) value;
  }

  public static void putShort(final byte[] buffer, final int offset, final int value) {
    buffer[offset] = (byte) (value >>> 8);
    buffer[offset + 1] = (byte) value;
  }

  public static int getInt(final byte[] buffer, final int offset) {
    return ((buffer[offset] & 0xff) << 24)
        | ((buffer[offset + 1] & 0xff) << 16)
        | ((buffer[offset + 2] & 0xff) << 8)
        | (buffer[offset + 3] & 0xff);
  }

  public static long getUnsignedInt(final byte[] buffer, final int offset) {
    return Integer.toUnsignedLong(getInt(buffer, offset));
  }

  public static int getUnsignedShort(final byte[] buffer, final int offset) {
    return ((buffer[offset] & 0xff) << 8) | (buffer[offset + 1] & 0xff);
  }
}
