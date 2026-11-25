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
package tech.pegasys.web3signer.enclave.transport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

class TcpTest {

  private static Connection connect(final ServerSocket server, final int timeoutMillis)
      throws IOException {
    return Tcp.connect(
        server.getInetAddress().getHostAddress(),
        server.getLocalPort(),
        timeoutMillis,
        timeoutMillis);
  }

  private static ServerSocket loopbackServer() throws IOException {
    return new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
  }

  @Test
  void writeToAPeerThatNeverReadsTimesOut() throws Exception {
    try (ServerSocket server = loopbackServer();
        Connection connection = connect(server, 300);
        Socket stalled = server.accept()) {
      final byte[] chunk = new byte[1 << 20];
      assertTimeoutPreemptively(
          Duration.ofSeconds(10),
          () ->
              assertThatThrownBy(
                      () -> {
                        // fills both socket buffers, then blocks: the peer never reads
                        while (true) {
                          connection.write(chunk, 0, chunk.length);
                        }
                      })
                  .isInstanceOf(SocketTimeoutException.class));
    }
  }

  @Test
  void readFromAPeerThatNeverWritesTimesOut() throws Exception {
    try (ServerSocket server = loopbackServer();
        Connection connection = connect(server, 300);
        Socket silent = server.accept()) {
      final long start = System.nanoTime();
      assertThatThrownBy(() -> connection.read(new byte[1], 0, 1))
          .isInstanceOf(SocketTimeoutException.class);
      assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isBetween(250L, 2000L);
    }
  }

  @Test
  void aQuickWriteLeavesTheConnectionOpenOnceTheWatchdogTimeHasPassed() throws Exception {
    try (ServerSocket server = loopbackServer();
        Connection connection = connect(server, 200);
        Socket peer = server.accept()) {
      connection.write(new byte[] {1}, 0, 1);
      Thread.sleep(500); // past the write timeout: a watchdog left running would close the socket
      connection.write(new byte[] {2}, 0, 1);
      peer.getOutputStream().write(3);
      final byte[] read = new byte[1];
      connection.readFully(read, 0, 1);
      assertThat(read[0]).isEqualTo((byte) 3);
      assertThat(peer.getInputStream().readNBytes(2)).containsExactly(1, 2);
    }
  }

  @Test
  void closeWakesABlockedAccept() throws Exception {
    final Listener listener = EnclaveAddress.tcp("127.0.0.1", 0).listen();
    final CompletableFuture<Connection> accepted =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return listener.accept();
              } catch (final IOException e) {
                throw new CompletionException(e);
              }
            });
    Thread.sleep(200); // let accept block
    listener.close();
    assertThatThrownBy(() -> accepted.get(5, TimeUnit.SECONDS))
        .hasCauseInstanceOf(SocketException.class);
  }
}
