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

import tech.pegasys.web3signer.enclave.protocol.VsockNative.ErrnoException;
import tech.pegasys.web3signer.enclave.protocol.VsockNative.Handles;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.net.SocketException;

/** {@link Listener} on a vsock socket bound to any CID. */
public final class VsockListener implements Listener {
  private static final int BACKLOG = 128;

  /**
   * How often a blocked {@link #accept()} wakes to see whether the listener was closed. shutdown(2)
   * on a listening vsock socket fails with ENOTCONN and does not wake accept(2), and {@link
   * SharedFd} closes the descriptor only after accept returns, so accept runs with this receive
   * timeout instead.
   */
  private static final int ACCEPT_WAKE_MILLIS = 200;

  private final Arena arena = Arena.ofShared();
  private final MemorySegment capture = VsockNative.allocateCapture(arena);
  private final SharedFd shared;
  private final EnclaveAddress address;

  private VsockListener(final int fd, final int port) {
    this.shared = new SharedFd(fd, arena);
    this.address =
        EnclaveAddress.vsock(EnclaveAddress.VMADDR_CID_ANY, Integer.toUnsignedLong(port));
  }

  public static VsockListener bind(final int port) throws IOException {
    final int fd = VsockNative.socket();
    try (Arena call = Arena.ofConfined()) {
      final MemorySegment capture = VsockNative.allocateCapture(call);
      final MemorySegment address =
          VsockNative.sockaddrVm(call, (int) EnclaveAddress.VMADDR_CID_ANY, port);
      int rc = (int) Handles.BIND.invokeExact(capture, fd, address, VsockNative.SOCKADDR_VM_SIZE);
      if (rc != 0) {
        throw new ErrnoException(
            "bind(vsock:" + Integer.toUnsignedString(port) + ")", VsockNative.errno(capture));
      }
      rc = (int) Handles.LISTEN.invokeExact(capture, fd, BACKLOG);
      if (rc != 0) {
        throw new ErrnoException("listen", VsockNative.errno(capture));
      }
      VsockNative.setTimeouts(fd, ACCEPT_WAKE_MILLIS);
      return new VsockListener(fd, port);
    } catch (final IOException | RuntimeException e) {
      VsockNative.closeQuietly(fd);
      throw e;
    } catch (final Throwable t) {
      VsockNative.closeQuietly(fd);
      throw new IOException(t);
    }
  }

  @Override
  public Connection accept() throws IOException {
    while (true) {
      final int fd = shared.acquire(); // throws once the listener is closed
      try {
        final int connection;
        try {
          connection =
              (int) Handles.ACCEPT.invokeExact(capture, fd, MemorySegment.NULL, MemorySegment.NULL);
        } catch (final Throwable t) {
          throw new IOException(t);
        }
        if (connection >= 0) {
          return accepted(connection);
        }
        final int errno = VsockNative.errno(capture);
        if (shared.isClosed()) {
          throw new SocketException("Listener closed");
        }
        if (errno != VsockNative.EINTR && errno != VsockNative.EAGAIN) {
          throw new ErrnoException("accept", errno);
        }
      } finally {
        shared.release();
      }
    }
  }

  /** Clears the listener's wake-up timeout in case the accepted socket inherited it. */
  private static Connection accepted(final int fd) throws IOException {
    try {
      VsockNative.setTimeouts(fd, 0);
    } catch (final IOException | RuntimeException e) {
      VsockNative.closeQuietly(fd);
      throw e;
    }
    return new VsockConnection(fd);
  }

  @Override
  public EnclaveAddress address() {
    return address;
  }

  @Override
  public void close() {
    shared.close();
  }
}
