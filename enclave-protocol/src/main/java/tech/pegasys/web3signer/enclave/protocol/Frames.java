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
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_BODY_SIZE;

import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Frame codec. A frame is the SSZ container {@code FrameHeader{length: Uint32, request_id: Uint32,
 * kind: Uint8}} followed by an SSZ body of {@code length} bytes. The kind of a request is its
 * opcode, the kind of a response its result code.
 */
public final class Frames {
  public static final int HEADER_SIZE = 9;
  private static final int DISCARD_BUFFER_SIZE = 4096;

  private Frames() {}

  /** A whole frame. */
  @SuppressWarnings("ArrayRecordComponent")
  public record Frame(int requestId, int kind, byte[] body) {}

  /**
   * Writes one frame: the header, then the body as it is, so that a body is never copied while a
   * slow peer holds up the write.
   *
   * @throws IllegalArgumentException when the kind does not fit a {@code Uint8} or the body is
   *     above {@link Protocol#MAX_BODY_SIZE}
   */
  public static void write(final Connection connection, final Frame frame) throws IOException {
    final byte[] body = frame.body();
    if (body.length > MAX_BODY_SIZE) {
      throw new IllegalArgumentException("Frame length out of range: " + body.length);
    }
    if (frame.kind() < 0 || frame.kind() > 0xff) {
      throw new IllegalArgumentException("Frame kind out of range: " + frame.kind());
    }
    final byte[] header =
        ByteBuffer.allocate(HEADER_SIZE)
            .order(LITTLE_ENDIAN)
            .putInt(body.length)
            .putInt(frame.requestId())
            .put((byte) frame.kind())
            .array();
    connection.write(header, 0, HEADER_SIZE);
    connection.write(body, 0, body.length);
  }

  /** Reads one response. A length above {@link Protocol#MAX_BODY_SIZE} throws before the body. */
  public static Frame readResponse(final Connection connection) throws IOException {
    final Header header = readHeader(connection);
    return new Frame(header.requestId(), header.kind(), readBody(connection, header.length()));
  }

  /**
   * Reads one request. A length above {@link Protocol#maxRequestBodySize} for its opcode throws
   * before the body. The body of an unknown opcode is discarded unread, so that the request can
   * still be answered with {@code UNSUPPORTED}, and comes back empty.
   */
  public static Frame readRequest(final Connection connection) throws IOException {
    final Header header = readHeader(connection);
    final int maxSize = Protocol.maxRequestBodySize(header.kind());
    if (maxSize < 0) {
      discard(connection, header.length());
      return new Frame(header.requestId(), header.kind(), new byte[0]);
    }
    if (header.length() > maxSize) {
      throw new IOException(
          "Frame length out of range for "
              + Protocol.opcodeName(header.kind())
              + ": "
              + header.length());
    }
    return new Frame(header.requestId(), header.kind(), readBody(connection, header.length()));
  }

  private record Header(int length, int requestId, int kind) {}

  private static Header readHeader(final Connection connection) throws IOException {
    final byte[] header = new byte[HEADER_SIZE];
    connection.readFully(header, 0, HEADER_SIZE);
    final ByteBuffer in = ByteBuffer.wrap(header).order(LITTLE_ENDIAN);
    final long length = Integer.toUnsignedLong(in.getInt());
    if (length > MAX_BODY_SIZE) {
      throw new IOException("Frame length out of range: " + length);
    }
    return new Header((int) length, in.getInt(), in.get() & 0xff);
  }

  private static byte[] readBody(final Connection connection, final int length) throws IOException {
    final byte[] body = new byte[length];
    connection.readFully(body, 0, length);
    return body;
  }

  private static void discard(final Connection connection, final int length) throws IOException {
    final byte[] scratch = new byte[Math.min(length, DISCARD_BUFFER_SIZE)];
    for (int left = length; left > 0; ) {
      final int n = Math.min(left, scratch.length);
      connection.readFully(scratch, 0, n);
      left -= n;
    }
  }
}
