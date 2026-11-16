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

import static tech.pegasys.web3signer.enclave.protocol.Frames.OVERHEAD;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getUnsignedInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getUnsignedShort;
import static tech.pegasys.web3signer.enclave.protocol.Frames.putInt;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.BAD_REQUEST;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.INTERNAL_ERROR;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.LENGTH_PREFIX_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_FRAME_LENGTH;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_PUBLIC_KEYS_PAGE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.OK;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.PUBLIC_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.RESPONSE_FLAG;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SIGNATURE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.UNKNOWN_KEY;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.UNSUPPORTED;

import tech.pegasys.web3signer.enclave.protocol.Connection;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Payloads;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;

/**
 * Serves one connection on its own thread. Handles every complete frame in its input buffer and
 * writes the responses together, once no complete request is left or the output buffer is full.
 */
final class ConnectionHandler {
  private static final int BUFFER_SIZE = 64 * 1024;
  private static final int SIGN_RESPONSE_SIZE = OVERHEAD + 1 + SIGNATURE_SIZE;

  private final Connection connection;
  private final SignerServer server;
  private final Blst.Scratch scratch;

  private byte[] in = new byte[BUFFER_SIZE];
  private int inStart;
  private int inEnd;
  private byte[] out = new byte[BUFFER_SIZE];
  private int outLength;

  ConnectionHandler(final Connection connection, final SignerServer server, final Arena arena) {
    this.connection = connection;
    this.server = server;
    this.scratch = new Blst.Scratch(arena);
  }

  /** Runs until the peer closes, an I/O error, or a frame with an impossible length. */
  void run() throws IOException {
    while (true) {
      while (inEnd - inStart >= LENGTH_PREFIX_SIZE) {
        final long length = getUnsignedInt(in, inStart);
        if (!Frames.isValidLength(length)) {
          Log.warn("closing connection: frame length out of range");
          return;
        }
        final int total = LENGTH_PREFIX_SIZE + (int) length;
        if (inEnd - inStart < total) {
          makeRoom(total);
          break;
        }
        handle(inStart + LENGTH_PREFIX_SIZE, (int) length);
        inStart += total;
      }
      flush();
      if (inStart == inEnd) {
        inStart = 0;
        inEnd = 0;
      }
      if (inEnd == in.length) {
        makeRoom(in.length - inStart + 1);
      }
      final int n = connection.read(in, inEnd, in.length - inEnd);
      if (n < 0) {
        return;
      }
      inEnd += n;
    }
  }

  /** Makes sure a frame of {@code total} bytes starting at {@code inStart} fits the buffer. */
  private void makeRoom(final int total) {
    if (in.length - inStart >= total) {
      return;
    }
    final int pending = inEnd - inStart;
    final byte[] target =
        total > in.length
            ? new byte
                [Math.min(Math.max(total, in.length * 2), LENGTH_PREFIX_SIZE + MAX_FRAME_LENGTH)]
            : in;
    System.arraycopy(in, inStart, target, 0, pending);
    in = target;
    inStart = 0;
    inEnd = pending;
  }

  private void flush() throws IOException {
    if (outLength > 0) {
      connection.write(out, 0, outLength);
      outLength = 0;
    }
  }

  /** Reserves {@code size} bytes in the output buffer, writing what it holds first if needed. */
  private int reserve(final int size) throws IOException {
    if (outLength + size > out.length) {
      flush();
      if (size > out.length) {
        out = new byte[size];
      }
    }
    final int at = outLength;
    outLength += size;
    return at;
  }

  /** Handles the frame whose type byte is at {@code at} and whose length is {@code length}. */
  private void handle(final int at, final int length) throws IOException {
    final int type = in[at] & 0xff;
    final int requestId = getInt(in, at + 1);
    final int payload = at + Protocol.FRAME_HEADER_SIZE;
    final int payloadLength = length - Protocol.FRAME_HEADER_SIZE;
    try {
      switch (type) {
        case Protocol.SIGN -> sign(requestId, payload, payloadLength);
        case Protocol.STATUS -> status(requestId, payloadLength);
        case Protocol.GET_PUBLIC_KEYS -> publicKeys(requestId, payload, payloadLength);
        default -> respond(type, requestId, Payloads.errorResponse(UNSUPPORTED));
      }
    } catch (final RuntimeException e) {
      Log.error("request failed", e);
      respond(type, requestId, Payloads.errorResponse(INTERNAL_ERROR));
    }
  }

  private void respond(final int type, final int requestId, final byte[] payload)
      throws IOException {
    final int at = reserve(OVERHEAD + payload.length);
    Frames.putHeader(out, at, type | RESPONSE_FLAG, requestId, payload.length);
    System.arraycopy(payload, 0, out, at + OVERHEAD, payload.length);
  }

  private void sign(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (payloadLength < PUBLIC_KEY_SIZE + 2
        || payloadLength != PUBLIC_KEY_SIZE + 2 + getUnsignedShort(in, payload + PUBLIC_KEY_SIZE)) {
      respond(Protocol.SIGN, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    final MemorySegment secret = server.keys().lookup(in, payload);
    if (secret == null) {
      respond(Protocol.SIGN, requestId, Payloads.errorResponse(UNKNOWN_KEY));
      return;
    }
    final int at = reserve(SIGN_RESPONSE_SIZE);
    Frames.putHeader(out, at, Protocol.SIGN | RESPONSE_FLAG, requestId, 1 + SIGNATURE_SIZE);
    out[at + OVERHEAD] = OK;
    server
        .blst()
        .sign(
            scratch,
            secret,
            in,
            payload + PUBLIC_KEY_SIZE + 2,
            payloadLength - PUBLIC_KEY_SIZE - 2,
            out,
            at + OVERHEAD + 1);
  }

  private void status(final int requestId, final int payloadLength) throws IOException {
    if (payloadLength != 0) {
      respond(Protocol.STATUS, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    respond(
        Protocol.STATUS,
        requestId,
        Payloads.statusResponse(
            server.platform(),
            Runtime.getRuntime().availableProcessors(),
            server.keys().size(),
            server.bootId(),
            server.version()));
  }

  private void publicKeys(final int requestId, final int payload, final int payloadLength)
      throws IOException {
    if (payloadLength != 8
        || getInt(in, payload + 4) < 1
        || getInt(in, payload + 4) > MAX_PUBLIC_KEYS_PAGE) {
      respond(Protocol.GET_PUBLIC_KEYS, requestId, Payloads.errorResponse(BAD_REQUEST));
      return;
    }
    final KeyTable.Page page =
        server.keys().page(getUnsignedInt(in, payload), getInt(in, payload + 4));
    final byte[] response = new byte[9 + page.publicKeys().length];
    response[0] = OK;
    putInt(response, 1, page.total());
    putInt(response, 5, page.count());
    System.arraycopy(page.publicKeys(), 0, response, 9, page.publicKeys().length);
    respond(Protocol.GET_PUBLIC_KEYS, requestId, response);
  }
}
