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

import static java.lang.foreign.ValueLayout.JAVA_BYTE;

import tech.pegasys.web3signer.enclave.protocol.VsockNative.ErrnoException;
import tech.pegasys.web3signer.enclave.protocol.VsockNative.Handles;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.SocketTimeoutException;

/**
 * {@link Connection} on a vsock stream socket: blocking fd I/O through native bounce buffers.
 * {@code ECONNRESET}, {@code ENOTCONN} and a read of 0 bytes all mean the peer is gone. Another
 * thread may close it while a call runs: the descriptor and the buffers are freed when that call
 * returns ({@link SharedFd}).
 */
public final class VsockConnection implements Connection {
  private static final int BUFFER_SIZE = 64 * 1024;

  private final Arena arena = Arena.ofShared();
  private final MemorySegment readCapture = VsockNative.allocateCapture(arena);
  private final MemorySegment writeCapture = VsockNative.allocateCapture(arena);
  private final MemorySegment in = arena.allocate(BUFFER_SIZE, 8);
  private final MemorySegment out = arena.allocate(BUFFER_SIZE, 8);
  private final SharedFd shared;
  private int inPosition;
  private int inLimit;

  VsockConnection(final int fd) {
    this.shared = new SharedFd(fd, arena);
  }

  /**
   * Connects to {@code cid:port}. Without an enclave at that CID the kernel gives up with {@code
   * ETIMEDOUT} after about 2 s.
   *
   * @param timeoutMillis read and write timeout; 0 waits forever
   */
  public static VsockConnection connect(final int cid, final int port, final int timeoutMillis)
      throws IOException {
    final int fd = VsockNative.socket();
    try (Arena call = Arena.ofConfined()) {
      final MemorySegment capture = VsockNative.allocateCapture(call);
      final MemorySegment address = VsockNative.sockaddrVm(call, cid, port);
      while (true) {
        final int rc =
            (int) Handles.CONNECT.invokeExact(capture, fd, address, VsockNative.SOCKADDR_VM_SIZE);
        if (rc == 0) {
          break;
        }
        final int errno = VsockNative.errno(capture);
        if (errno != VsockNative.EINTR) {
          throw new ErrnoException("connect(vsock:" + Integer.toUnsignedString(cid) + ")", errno);
        }
      }
      VsockNative.setTimeouts(fd, timeoutMillis);
      return new VsockConnection(fd);
    } catch (final IOException | RuntimeException e) {
      VsockNative.closeQuietly(fd);
      throw e;
    } catch (final Throwable t) {
      VsockNative.closeQuietly(fd);
      throw new IOException(t);
    }
  }

  @Override
  public int read(final byte[] buffer, final int offset, final int length) throws IOException {
    if (length == 0) {
      return 0;
    }
    final int fd = shared.acquire();
    try {
      if (inPosition == inLimit && !fill(fd)) {
        return -1;
      }
      final int n = Math.min(length, inLimit - inPosition);
      MemorySegment.copy(in, JAVA_BYTE, inPosition, buffer, offset, n);
      inPosition += n;
      return n;
    } finally {
      shared.release();
    }
  }

  /** Reads into the native buffer. Returns false at the end of the stream. */
  private boolean fill(final int fd) throws IOException {
    while (true) {
      final long n;
      try {
        n = (long) Handles.READ.invokeExact(readCapture, fd, in, (long) BUFFER_SIZE);
      } catch (final Throwable t) {
        throw new IOException(t);
      }
      if (n > 0) {
        inPosition = 0;
        inLimit = (int) n;
        return true;
      }
      if (n == 0) {
        return false;
      }
      final int errno = VsockNative.errno(readCapture);
      switch (errno) {
        case VsockNative.EINTR -> {}
        case VsockNative.EAGAIN -> throw new SocketTimeoutException("vsock read timed out");
        case VsockNative.ECONNRESET, VsockNative.ENOTCONN -> {
          return false;
        }
        default -> throw new ErrnoException("read", errno);
      }
    }
  }

  @Override
  public void write(final byte[] buffer, final int offset, final int length) throws IOException {
    final int fd = shared.acquire();
    try {
      writeAll(fd, buffer, offset, length);
    } finally {
      shared.release();
    }
  }

  private void writeAll(final int fd, final byte[] buffer, final int offset, final int length)
      throws IOException {
    int done = 0;
    while (done < length) {
      final int chunk = Math.min(length - done, BUFFER_SIZE);
      MemorySegment.copy(buffer, offset + done, out, JAVA_BYTE, 0, chunk);
      long sent = 0;
      while (sent < chunk) {
        final long n;
        try {
          n = (long) Handles.WRITE.invokeExact(writeCapture, fd, out.asSlice(sent), chunk - sent);
        } catch (final Throwable t) {
          throw new IOException(t);
        }
        if (n >= 0) {
          sent += n;
          continue;
        }
        final int errno = VsockNative.errno(writeCapture);
        if (errno == VsockNative.EAGAIN) {
          throw new SocketTimeoutException("vsock write timed out");
        }
        if (errno != VsockNative.EINTR) {
          throw new ErrnoException("write", errno);
        }
      }
      done += chunk;
    }
  }

  @Override
  public void close() {
    shared.close();
  }
}
