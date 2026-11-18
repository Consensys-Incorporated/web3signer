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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EnclaveClientTest {
  private static final byte[] PUBLIC_KEY = new byte[48];

  /** Number of frames in each write the client made. */
  private final List<Integer> framesPerWrite = new CopyOnWriteArrayList<>();

  private final List<AutoCloseable> resources = new ArrayList<>();

  @AfterEach
  void tearDown() throws Exception {
    for (final AutoCloseable resource : resources.reversed()) {
      resource.close();
    }
  }

  private ScriptedServer server(final ScriptedServer.Script script) throws IOException {
    final ScriptedServer server = new ScriptedServer(script);
    resources.add(server);
    return server;
  }

  private EnclaveClient client(final ScriptedServer server, final EnclaveClient.Options options) {
    final EnclaveAddress address = server.address();
    final EnclaveClient client =
        new EnclaveClient(
            timeout -> new CountingConnection(Transports.connect(address, timeout)),
            address.toString(),
            options);
    resources.add(client);
    return client;
  }

  private static byte[] message(final int i) {
    final byte[] message = new byte[32];
    Arrays.fill(message, (byte) i);
    message[0] = (byte) (i >> 8);
    return message;
  }

  /** Answers every SIGN, optionally slowly. */
  private static ScriptedServer.Script answering(final ScriptedServer[] self, final long delayMs) {
    return (connection, index) -> {
      while (true) {
        final Frame request = self[0].read(connection);
        sleep(delayMs);
        final byte[] response = ScriptedServer.signResponse(request);
        connection.write(response, 0, response.length);
      }
    };
  }

  private ScriptedServer answeringServer(final long delayMs) throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] = server(answering(self, delayMs));
    return self[0];
  }

  private static void sleep(final long millis) {
    try {
      Thread.sleep(millis);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  @Test
  void concurrentCallsAreBatchedAndEachCallerGetsItsOwnAnswer() throws Exception {
    final ScriptedServer server = answeringServer(2);
    final EnclaveClient client = client(server, new EnclaveClient.Options(1, 8, 10_000));

    final int calls = 50;
    final CountDownLatch start = new CountDownLatch(1);
    try (ExecutorService callers = Executors.newFixedThreadPool(calls)) {
      final List<Future<byte[]>> results = new ArrayList<>();
      for (int i = 0; i < calls; i++) {
        final byte[] message = message(i);
        results.add(
            callers.submit(
                () -> {
                  start.await();
                  return client.sign(PUBLIC_KEY, message);
                }));
      }
      start.countDown();
      for (int i = 0; i < calls; i++) {
        assertThat(results.get(i).get(30, TimeUnit.SECONDS))
            .isEqualTo(ScriptedServer.fakeSignature(message(i)));
      }
    }
    assertThat(framesPerWrite.stream().mapToInt(Integer::intValue).sum()).isEqualTo(calls);
    assertThat(framesPerWrite).hasSizeLessThan(calls);
    assertThat(framesPerWrite).allSatisfy(frames -> assertThat(frames).isBetween(1, 8));
    assertThat(client.batchStats())
        .isEqualTo(new EnclaveClient.BatchStats(framesPerWrite.size(), calls));
  }

  @Test
  void sequentialCallsGoOutOnePerWrite() throws IOException {
    final EnclaveClient client = client(answeringServer(0), new EnclaveClient.Options(1, 8, 5000));
    for (int i = 0; i < 5; i++) {
      assertThat(client.sign(PUBLIC_KEY, message(i)))
          .isEqualTo(ScriptedServer.fakeSignature(message(i)));
    }
    assertThat(framesPerWrite).containsExactly(1, 1, 1, 1, 1);
  }

  @Test
  void connectionCountDefaultsToTheEnclaveCpus() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              while (true) {
                final Frame request = self[0].read(connection);
                final byte[] response =
                    request.type() == Protocol.STATUS
                        ? ScriptedServer.statusResponse(request, 3)
                        : ScriptedServer.signResponse(request);
                connection.write(response, 0, response.length);
              }
            });
    final EnclaveClient client = client(self[0], EnclaveClient.Options.DEFAULT);
    assertThat(client.sign(PUBLIC_KEY, message(1)))
        .isEqualTo(ScriptedServer.fakeSignature(message(1)));
    assertThat(client.dispatcherCount()).isEqualTo(3);
  }

  @Test
  void unansweredCallsAreResentOnceAfterADrop() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              final Frame request = self[0].read(connection);
              if (index == 0) {
                return; // drop without an answer
              }
              final byte[] response = ScriptedServer.signResponse(request);
              connection.write(response, 0, response.length);
              while (true) {
                self[0].read(connection);
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    assertThat(client.sign(PUBLIC_KEY, message(7)))
        .isEqualTo(ScriptedServer.fakeSignature(message(7)));
    assertThat(self[0].connectionCount()).isEqualTo(2);
    assertThat(self[0].received).hasSize(2);
    assertThat(self[0].received.get(1).payload()).isEqualTo(self[0].received.get(0).payload());
  }

  @Test
  void callsFailAfterASecondDrop() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] = server((connection, index) -> self[0].read(connection));
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, message(1)))
        .isInstanceOf(EnclaveUnavailableException.class);
    sleep(300);
    assertThat(self[0].received).hasSize(2);
    assertThat(self[0].connectionCount()).isEqualTo(2);
  }

  @Test
  void unwrapDekIsNeverResent() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] = server((connection, index) -> self[0].read(connection));
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    try (ProvisioningSession session = client.openProvisioningSession()) {
      assertThatThrownBy(() -> session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]))
          .isInstanceOf(EnclaveUnavailableException.class);
    }
    sleep(300);
    assertThat(self[0].received).hasSize(1);
    assertThat(self[0].received.get(0).type()).isEqualTo(Protocol.UNWRAP_DEK);
    assertThat(self[0].connectionCount()).isEqualTo(1);
  }

  @Test
  void silentServerTimesOutWithinTheConfiguredTime() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              while (true) {
                self[0].read(connection);
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 300));
    final long start = System.nanoTime();
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, message(1)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessageContaining("300 ms");
    assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isBetween(250L, 1000L);
  }

  @Test
  void firstCallersDoNotQueueBehindAnUnreachableEnclave() throws Exception {
    // connections = 0: the first sign asks the enclave for its cpus, two attempts of 300 ms
    final EnclaveClient client =
        new EnclaveClient(
            timeout -> {
              sleep(300);
              throw new IOException("unreachable");
            },
            "unreachable",
            new EnclaveClient.Options(0, 8, 1000));
    resources.add(client);

    final int calls = 8;
    final CountDownLatch start = new CountDownLatch(1);
    final long started;
    try (ExecutorService callers = Executors.newFixedThreadPool(calls)) {
      final List<Future<byte[]>> results = new ArrayList<>();
      for (int i = 0; i < calls; i++) {
        final byte[] message = message(i);
        results.add(
            callers.submit(
                () -> {
                  start.await();
                  return client.sign(PUBLIC_KEY, message);
                }));
      }
      started = System.nanoTime();
      start.countDown();
      for (final Future<byte[]> result : results) {
        assertThatThrownBy(() -> result.get(30, TimeUnit.SECONDS))
            .hasCauseInstanceOf(EnclaveUnavailableException.class);
      }
    }
    // in parallel about 600 ms; one after the other under a lock 8 x 600 ms
    assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)).isLessThan(2500L);
  }

  @Test
  void closeFailsAnInFlightCallWithoutReconnecting() throws Exception {
    final CountDownLatch received = new CountDownLatch(1);
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              self[0].read(connection);
              received.countDown();
              while (true) {
                self[0].read(connection); // never answers
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 10_000));
    try (ExecutorService caller = Executors.newSingleThreadExecutor()) {
      final Future<byte[]> result = caller.submit(() -> client.sign(PUBLIC_KEY, message(1)));
      assertThat(received.await(5, TimeUnit.SECONDS)).isTrue();
      client.close();
      assertThatThrownBy(() -> result.get(5, TimeUnit.SECONDS))
          .hasCauseInstanceOf(EnclaveUnavailableException.class)
          .hasRootCauseMessage("Enclave client is closed");
    }
    assertThat(self[0].connectionCount()).isEqualTo(1);
  }

  @Test
  void fullQueueFailsTheCallAtOnce() throws Exception {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              while (true) {
                self[0].read(connection);
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 60_000));
    final CountDownLatch queueFull = new CountDownLatch(1);
    try (ExecutorService callers = Executors.newVirtualThreadPerTaskExecutor()) {
      for (int i = 0; i < EnclaveClient.QUEUE_CAPACITY + 100; i++) {
        callers.submit(
            () -> {
              try {
                client.sign(PUBLIC_KEY, message(1));
              } catch (final EnclaveUnavailableException e) {
                if (e.getMessage().contains("queue is full")) {
                  queueFull.countDown();
                }
              }
            });
      }
      assertThat(queueFull.await(10, TimeUnit.SECONDS)).isTrue();
      final long start = System.nanoTime();
      assertThatThrownBy(() -> client.sign(PUBLIC_KEY, message(2)))
          .hasMessageContaining("queue is full");
      assertThat(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)).isLessThan(100);
      client.close();
    }
  }

  @Test
  void wrongRequestIdDropsTheConnection() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              while (true) {
                final Frame request = self[0].read(connection);
                final byte[] response = ScriptedServer.signResponse(request);
                if (index == 0) {
                  Frames.putInt(response, 5, request.requestId() + 1);
                }
                connection.write(response, 0, response.length);
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    assertThat(client.sign(PUBLIC_KEY, message(3)))
        .isEqualTo(ScriptedServer.fakeSignature(message(3)));
    assertThat(self[0].connectionCount()).isEqualTo(2);
  }

  @Test
  void wrongResponseTypeDropsTheConnectionAndRetries() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              final Frame request = self[0].read(connection);
              final byte[] response = ScriptedServer.statusResponse(request, 2);
              if (index == 0) {
                response[4] = (byte) (Protocol.SIGN | Protocol.RESPONSE_FLAG);
              }
              connection.write(response, 0, response.length);
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    assertThat(client.status().cpus()).isEqualTo(2);
    assertThat(self[0].connectionCount()).isEqualTo(2);
  }

  @Test
  void refusalIsReportedWithItsStatus() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              while (true) {
                final Frame request = self[0].read(connection);
                final byte[] response =
                    ScriptedServer.response(request, Payloads.errorResponse(Protocol.UNKNOWN_KEY));
                connection.write(response, 0, response.length);
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, message(3)))
        .isInstanceOfSatisfying(
            EnclaveException.class, e -> assertThat(e.status()).isEqualTo(Protocol.UNKNOWN_KEY));
    assertThat(self[0].connectionCount()).isEqualTo(1);
  }

  @Test
  void publicKeysPagesThroughTheKeySet() throws IOException {
    final ScriptedServer[] self = new ScriptedServer[1];
    self[0] =
        server(
            (connection, index) -> {
              while (true) {
                final Frame request = self[0].read(connection);
                final int offset = Frames.getInt(request.payload(), 0);
                final int count = Math.min(2, 5 - offset); // the server pages by 2
                final byte[] payload = new byte[9 + count * 48];
                Frames.putInt(payload, 1, 5);
                Frames.putInt(payload, 5, count);
                for (int i = 0; i < count; i++) {
                  Arrays.fill(payload, 9 + i * 48, 9 + (i + 1) * 48, (byte) (offset + i));
                }
                final byte[] response = ScriptedServer.response(request, payload);
                connection.write(response, 0, response.length);
              }
            });
    final EnclaveClient client = client(self[0], new EnclaveClient.Options(1, 8, 5000));
    final List<byte[]> keys = client.publicKeys();
    assertThat(keys).hasSize(5);
    for (int i = 0; i < 5; i++) {
      assertThat(keys.get(i)[0]).isEqualTo((byte) i);
    }
  }

  /** Counts the frames in every write the client makes. */
  private final class CountingConnection implements Connection {
    private final Connection delegate;

    CountingConnection(final Connection delegate) {
      this.delegate = delegate;
    }

    @Override
    public int read(final byte[] buffer, final int offset, final int length) throws IOException {
      return delegate.read(buffer, offset, length);
    }

    @Override
    public void write(final byte[] buffer, final int offset, final int length) throws IOException {
      int frames = 0;
      for (int at = offset; at < offset + length; at += 4 + Frames.getInt(buffer, at)) {
        if (buffer[at + 4] == Protocol.SIGN) {
          frames++;
        }
      }
      if (frames > 0) {
        framesPerWrite.add(frames);
      }
      delegate.write(buffer, offset, length);
    }

    @Override
    public void close() {
      delegate.close();
    }
  }
}
