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

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.net.SocketTimeoutException;
import java.util.Random;
import java.util.concurrent.CompletableFuture;
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
class VsockTransportTest {
  private static final int LOOPBACK_CID = 1;
  private static final int EAFNOSUPPORT = 97;

  @Test
  void framesRoundTripOverVsockLoopback() throws Exception {
    final int port = 20_000 + new Random().nextInt(20_000);
    final VsockListener listener;
    try {
      listener = VsockListener.bind(port);
    } catch (final VsockNative.ErrnoException e) {
      Assumptions.assumeTrue(e.errno() != EAFNOSUPPORT, "no AF_VSOCK support");
      throw e;
    }
    try (listener) {
      assertThat(listener.address()).hasToString("vsock:" + port);
      final CompletableFuture<Void> server =
          CompletableFuture.runAsync(
              () -> {
                try (Connection connection = listener.accept()) {
                  for (int i = 0; i < 3; i++) {
                    final Frame request = Frames.read(connection);
                    final byte[] response =
                        Frames.encode(
                            request.type() | Protocol.RESPONSE_FLAG,
                            request.requestId(),
                            request.payload());
                    connection.write(response, 0, response.length);
                  }
                } catch (final IOException e) {
                  throw new IllegalStateException(e);
                }
              });

      final Connection client;
      try {
        client = Transports.connect(EnclaveAddress.vsock(LOOPBACK_CID, port), 5000);
      } catch (final VsockNative.ErrnoException e) {
        Assumptions.assumeTrue(
            e.errno() != VsockNative.ENETUNREACH, "vsock loopback transport not loaded");
        throw e;
      }
      try (client) {
        final byte[] big = new byte[200_000];
        new Random(1).nextBytes(big);
        for (final byte[] payload : new byte[][] {new byte[0], new byte[] {1, 2, 3}, big}) {
          final byte[] frame = Frames.encode(Protocol.SIGN, payload.length, payload);
          client.write(frame, 0, frame.length);
          final Frame echoed = Frames.read(client);
          assertThat(echoed.requestId()).isEqualTo(payload.length);
          assertThat(echoed.payload()).isEqualTo(payload);
        }
        server.get(10, TimeUnit.SECONDS);
        // the server closed its end: the next read reports the end of the stream
        assertThat(client.read(new byte[1], 0, 1)).isEqualTo(-1);
      }
    }
  }

  /**
   * The fd I/O of {@link VsockConnection} on a local stream socket pair: the same read, write,
   * timeout and end-of-stream paths as on vsock, runnable without a vsock transport.
   */
  @Test
  void fdIoOnALocalSocketPair() throws Throwable {
    final int[] fds = socketPair();
    final VsockConnection left = new VsockConnection(fds[0]);
    final VsockConnection right = new VsockConnection(fds[1]);
    try (left;
        right) {
      VsockNative.setTimeouts(fds[0], 200);
      final byte[] big = new byte[300_000];
      new Random(2).nextBytes(big);
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
