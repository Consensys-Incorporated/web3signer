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

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * Round trip over vsock on the loopback CID. Skipped where the kernel has no vsock loopback
 * transport ({@code sudo modprobe vsock_loopback} enables it).
 */
@EnabledOnOs(OS.LINUX)
class VsockTest {
  private static final int LOOPBACK_CID = 1;
  private static final int EAFNOSUPPORT = 97;

  private final Random random = new Random();

  /** Listens on a random port, or skips the test without AF_VSOCK support. */
  private Listener listen() throws IOException {
    try {
      return Vsock.listen(20_000 + random.nextInt(20_000));
    } catch (final Vsock.ErrnoException e) {
      Assumptions.assumeTrue(e.errno() != EAFNOSUPPORT, "no AF_VSOCK support");
      throw e;
    }
  }

  /** Connects over the loopback CID, or skips the test without the loopback transport. */
  private static Connection connectLoopback(final Listener listener) throws IOException {
    try {
      return EnclaveAddress.vsock(
              LOOPBACK_CID, ((EnclaveAddress.VsockAddress) listener.address()).port())
          .connect(5000, 5000);
    } catch (final Vsock.ErrnoException e) {
      Assumptions.assumeTrue(e.errno() != Vsock.ENETUNREACH, "vsock loopback transport not loaded");
      throw e;
    }
  }

  @Test
  void framesRoundTripOverVsockLoopback() throws Exception {
    try (Listener listener = listen()) {
      assertThat(listener.address().toString()).matches("vsock:\\d+");
      final CompletableFuture<Void> server =
          CompletableFuture.runAsync(
              () -> {
                try (Connection connection = listener.accept()) {
                  for (int i = 0; i < 3; i++) {
                    final Frame request = Frames.read(connection);
                    Frames.write(
                        connection, new Frame(request.requestId(), Protocol.OK, request.body()));
                  }
                } catch (final IOException e) {
                  throw new IllegalStateException(e);
                }
              });

      try (Connection client = connectLoopback(listener)) {
        final byte[] big = new byte[200_000];
        random.nextBytes(big);
        for (final byte[] body : new byte[][] {new byte[0], new byte[] {1, 2, 3}, big}) {
          Frames.write(client, new Frame(body.length, Protocol.SIGN, body));
          final Frame echoed = Frames.read(client);
          assertThat(echoed.requestId()).isEqualTo(body.length);
          assertThat(echoed.body()).isEqualTo(body);
        }
        server.get(10, TimeUnit.SECONDS);
        // the server closed its end: the next read reports the end of the stream
        assertThat(client.read(new byte[1], 0, 1)).isEqualTo(-1);
      }
    }
  }

  /**
   * The listener wakes every 200 ms to notice a close; the accepted socket must not keep that
   * timeout, or the enclave would drop every host connection that sits idle for 200 ms.
   */
  @Test
  void anAcceptedConnectionKeepsNoneOfTheListenersWakeUpTimeout() throws Exception {
    try (Listener listener = listen()) {
      final CompletableFuture<Connection> accepted =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  return listener.accept();
                } catch (final IOException e) {
                  throw new CompletionException(e);
                }
              });
      try (Connection client = connectLoopback(listener);
          Connection server = accepted.get(5, TimeUnit.SECONDS)) {
        final CompletableFuture<Integer> read =
            CompletableFuture.supplyAsync(
                () -> {
                  try {
                    return server.read(new byte[1], 0, 1);
                  } catch (final IOException e) {
                    throw new CompletionException(e);
                  }
                });
        Thread.sleep(600);
        assertThat(read).isNotDone();
        client.write(new byte[] {5}, 0, 1);
        assertThat(read.get(5, TimeUnit.SECONDS)).isEqualTo(1);
      }
    }
  }

  @Test
  void closeWakesABlockedAccept() throws Exception {
    final Listener listener = listen();
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

  @Test
  void connectFailuresNameTheirErrno() {
    assertThat(new Vsock.ErrnoException("connect(vsock:16)", 110))
        .hasMessage(
            "connect(vsock:16) failed: ETIMEDOUT (connection timed out: is the enclave running?), errno 110");
    assertThat(new Vsock.ErrnoException("read", 4242)).hasMessage("read failed: errno 4242");
  }

  /**
   * The fd I/O of {@link Vsock} on a local stream socket pair: the same read, write, timeout and
   * end-of-stream paths as on vsock, runnable without a vsock transport.
   */
  @Test
  void fdIoOnALocalSocketPair() throws Throwable {
    final int[] fds = socketPair();
    final Connection left = Vsock.wrap(fds[0]);
    final Connection right = Vsock.wrap(fds[1]);
    try (left;
        right) {
      Vsock.setTimeouts(fds[0], 200);
      final byte[] big = new byte[300_000];
      random.nextBytes(big);
      final CompletableFuture<Void> writer =
          CompletableFuture.runAsync(
              () -> {
                try {
                  right.write(big, 0, big.length);
                } catch (final IOException e) {
                  throw new IllegalStateException(e);
                }
              });
      final byte[] received = new byte[big.length];
      left.readFully(received, 0, received.length);
      writer.get(10, TimeUnit.SECONDS);
      assertThat(received).isEqualTo(big);

      final long start = System.nanoTime();
      assertThatThrownBy(() -> left.read(new byte[1], 0, 1))
          .isInstanceOf(SocketTimeoutException.class);
      assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isBetween(150L, 2000L);

      right.close();
      assertThat(left.read(new byte[1], 0, 1)).isEqualTo(-1);
    }
  }

  @Test
  void writeToAPeerThatNeverReadsTimesOut() throws Throwable {
    final int[] fds = socketPair();
    try (Connection left = Vsock.wrap(fds[0]);
        Connection right = Vsock.wrap(fds[1])) {
      Vsock.setTimeouts(fds[0], 200);
      final byte[] chunk = new byte[1 << 20];
      assertTimeoutPreemptively(
          Duration.ofSeconds(10),
          () ->
              assertThatThrownBy(
                      () -> {
                        // fills the socket buffers, then blocks: the peer never reads
                        while (true) {
                          left.write(chunk, 0, chunk.length);
                        }
                      })
                  .isInstanceOf(SocketTimeoutException.class));
    }
  }

  @Test
  void closeWakesABlockedWriter() throws Throwable {
    final int[] fds = socketPair();
    final Connection left = Vsock.wrap(fds[0]);
    try (Connection right = Vsock.wrap(fds[1])) {
      final byte[] chunk = new byte[1 << 20];
      final CompletableFuture<Void> writer =
          CompletableFuture.runAsync(
              () -> {
                try {
                  while (true) {
                    left.write(chunk, 0, chunk.length); // blocks once the buffers are full
                  }
                } catch (final IOException e) {
                  throw new CompletionException(e);
                }
              });
      Thread.sleep(300); // let the writer block in write(2)
      assertThat(writer).isNotDone();
      left.close();
      assertThatThrownBy(() -> writer.get(5, TimeUnit.SECONDS))
          .hasCauseInstanceOf(IOException.class);
    }
  }

  /**
   * Closing wakes a blocked reader, and the closed connection never reaches the socket that gets
   * its descriptor number next.
   */
  @Test
  void closeWakesAReaderAndNeverTouchesAReusedDescriptor() throws Throwable {
    final int[] fds = socketPair();
    final Connection left = Vsock.wrap(fds[0]);
    final Connection right = Vsock.wrap(fds[1]);
    final CompletableFuture<Integer> reader =
        CompletableFuture.supplyAsync(
            () -> {
              try {
                return left.read(new byte[1], 0, 1);
              } catch (final IOException e) {
                throw new IllegalStateException(e);
              }
            });
    Thread.sleep(200); // let the reader block in read(2)
    left.close();
    assertThat(reader.get(5, TimeUnit.SECONDS)).isEqualTo(-1);
    right.close();

    // the kernel hands out the lowest free numbers: the new pair normally gets the old ones
    final int[] reused = socketPair();
    final Connection newLeft = Vsock.wrap(reused[0]);
    final Connection newRight = Vsock.wrap(reused[1]);
    try (newLeft;
        newRight) {
      Assumptions.assumeTrue(reused[0] == fds[0] || reused[1] == fds[0], "number not reused");
      final Connection peerOfReused = reused[0] == fds[0] ? newRight : newLeft;
      Vsock.setTimeouts(reused[0] == fds[0] ? reused[1] : reused[0], 200);

      assertThatThrownBy(() -> left.write(new byte[] {42}, 0, 1))
          .isInstanceOf(SocketException.class);
      assertThatThrownBy(() -> peerOfReused.read(new byte[1], 0, 1))
          .isInstanceOf(SocketTimeoutException.class);
    }
  }

  private static int[] socketPair() throws Throwable {
    final Linker linker = Linker.nativeLinker();
    final MethodHandle socketpair =
        linker.downcallHandle(
            linker.defaultLookup().find("socketpair").orElseThrow(),
            FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_INT, JAVA_INT, ADDRESS));
    try (Arena arena = Arena.ofConfined()) {
      final MemorySegment fds = arena.allocate(JAVA_INT, 2);
      final int rc = (int) socketpair.invokeExact(1 /* AF_UNIX */, 1 /* SOCK_STREAM */, 0, fds);
      assertThat(rc).isZero();
      return new int[] {fds.getAtIndex(JAVA_INT, 0), fds.getAtIndex(JAVA_INT, 1)};
    }
  }
}
