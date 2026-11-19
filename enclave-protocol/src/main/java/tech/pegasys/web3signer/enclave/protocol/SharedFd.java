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

import java.lang.foreign.Arena;
import java.net.SocketException;

/**
 * A socket descriptor that some threads use while another closes it. {@link #close()} shuts the
 * socket down at once, which wakes a thread blocked in it, but closes the descriptor and its arena
 * only when no call is inside {@link #acquire()}/{@link #release()} any more. Closing it earlier
 * would let the kernel give the same number to the next socket while a late call still uses it.
 */
final class SharedFd {
  private final int fd;
  private final Arena arena;
  private int users;
  private boolean closed;

  /**
   * @param fd the descriptor
   * @param arena memory used with the descriptor; closed together with it
   */
  SharedFd(final int fd, final Arena arena) {
    this.fd = fd;
    this.arena = arena;
  }

  /** Marks the start of a call on the descriptor. Pair with {@link #release()} in a finally. */
  synchronized int acquire() throws SocketException {
    if (closed) {
      throw new SocketException("Socket closed");
    }
    users++;
    return fd;
  }

  /** Marks the end of a call on the descriptor. */
  synchronized void release() {
    users--;
    if (closed && users == 0) {
      free();
    }
  }

  synchronized boolean isClosed() {
    return closed;
  }

  synchronized void close() {
    if (closed) {
      return;
    }
    closed = true;
    VsockNative.shutdownQuietly(fd);
    if (users == 0) {
      free();
    }
  }

  private void free() {
    VsockNative.closeQuietly(fd);
    arena.close();
  }
}
