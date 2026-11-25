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

  private Frames() {}

  /** A whole frame. */
  @SuppressWarnings("ArrayRecordComponent")
  public record Frame(int requestId, int kind, byte[] body) {}

  /**
   * Writes one frame with one write.
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
    final ByteBuffer out = ByteBuffer.allocate(HEADER_SIZE + body.length).order(LITTLE_ENDIAN);
    out.putInt(body.length).putInt(frame.requestId()).put((byte) frame.kind()).put(body);
    connection.write(out.array(), 0, out.capacity());
  }

  /** Reads one frame. A length above {@link Protocol#MAX_BODY_SIZE} throws before the body. */
  public static Frame read(final Connection connection) throws IOException {
    final byte[] header = new byte[HEADER_SIZE];
    connection.readFully(header, 0, HEADER_SIZE);
    final ByteBuffer in = ByteBuffer.wrap(header).order(LITTLE_ENDIAN);
    final long length = Integer.toUnsignedLong(in.getInt());
    if (length > MAX_BODY_SIZE) {
      throw new IOException("Frame length out of range: " + length);
    }
    final int requestId = in.getInt();
    final int kind = in.get() & 0xff;
    final byte[] body = new byte[(int) length];
    connection.readFully(body, 0, body.length);
    return new Frame(requestId, kind, body);
  }
}
