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
import java.util.concurrent.atomic.AtomicBoolean;

/** {@link Listener} on a vsock socket bound to any CID. */
public final class VsockListener implements Listener {
  private static final int BACKLOG = 128;

  private final int fd;
  private final EnclaveAddress address;
  private final MemorySegment capture = VsockNative.allocateCapture(Arena.ofAuto());
  private final AtomicBoolean closed = new AtomicBoolean();

  private VsockListener(final int fd, final int port) {
    this.fd = fd;
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
      if (closed.get()) {
        throw new SocketException("Listener closed");
      }
      final int connection;
      try {
        connection =
            (int) Handles.ACCEPT.invokeExact(capture, fd, MemorySegment.NULL, MemorySegment.NULL);
      } catch (final Throwable t) {
        throw new IOException(t);
      }
      if (connection >= 0) {
        return new VsockConnection(connection);
      }
      final int errno = VsockNative.errno(capture);
      if (closed.get()) {
        throw new SocketException("Listener closed");
      }
      if (errno != VsockNative.EINTR) {
        throw new ErrnoException("accept", errno);
      }
    }
  }

  @Override
  public EnclaveAddress address() {
    return address;
  }

  @Override
  public void close() {
    if (closed.compareAndSet(false, true)) {
      VsockNative.shutdownQuietly(fd);
      VsockNative.closeQuietly(fd);
    }
  }
}
