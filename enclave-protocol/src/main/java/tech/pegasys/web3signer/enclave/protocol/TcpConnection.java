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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** {@link Connection} over a TCP socket with {@code TCP_NODELAY} and buffered input. */
public final class TcpConnection implements Connection {
  private static final int BUFFER_SIZE = 64 * 1024;

  private final Socket socket;
  private final InputStream in;
  private final OutputStream out;
  private final int writeTimeoutMillis;
  private volatile boolean writeTimedOut;

  /**
   * @param writeTimeoutMillis limit of one {@link #write}; 0 waits forever
   */
  TcpConnection(final Socket socket, final int writeTimeoutMillis) throws IOException {
    this.socket = socket;
    this.writeTimeoutMillis = writeTimeoutMillis;
    socket.setTcpNoDelay(true);
    this.in = new BufferedInputStream(socket.getInputStream(), BUFFER_SIZE);
    this.out = socket.getOutputStream();
  }

  /**
   * Connects to {@code host:port}.
   *
   * @param timeoutMillis connect, read and write timeout; 0 waits forever
   */
  public static TcpConnection connect(final String host, final int port, final int timeoutMillis)
      throws IOException {
    final Socket socket = new Socket();
    try {
      socket.connect(new InetSocketAddress(host, port), timeoutMillis);
      socket.setSoTimeout(timeoutMillis);
      return new TcpConnection(socket, timeoutMillis);
    } catch (final IOException | RuntimeException e) {
      socket.close();
      throw e;
    }
  }

  @Override
  public int read(final byte[] buffer, final int offset, final int length) throws IOException {
    return in.read(buffer, offset, length);
  }

  /**
   * Java sockets have no send timeout, so a write that outlasts the limit is ended by closing the
   * socket, which wakes the blocked writer. The connection is unusable afterwards.
   */
  @Override
  public void write(final byte[] buffer, final int offset, final int length) throws IOException {
    if (writeTimeoutMillis == 0) {
      out.write(buffer, offset, length);
      return;
    }
    final ScheduledFuture<?> watchdog =
        WriteWatchdog.EXECUTOR.schedule(
            this::expireWrite, writeTimeoutMillis, TimeUnit.MILLISECONDS);
    try {
      out.write(buffer, offset, length);
    } catch (final IOException e) {
      if (writeTimedOut) {
        throw new SocketTimeoutException("Write timed out after " + writeTimeoutMillis + " ms");
      }
      throw e;
    } finally {
      watchdog.cancel(false);
    }
  }

  private void expireWrite() {
    writeTimedOut = true;
    close();
  }

  /** One daemon thread for all connections, started on the first timed write. */
  private static final class WriteWatchdog {
    static final ScheduledThreadPoolExecutor EXECUTOR =
        new ScheduledThreadPoolExecutor(
            1,
            runnable ->
                Thread.ofPlatform().name("tcp-write-watchdog").daemon(true).unstarted(runnable));

    static {
      EXECUTOR.setRemoveOnCancelPolicy(true);
    }

    private WriteWatchdog() {}
  }

  @Override
  public void close() {
    try {
      socket.close();
    } catch (final IOException e) {
      // nothing left to release
    }
  }
}
