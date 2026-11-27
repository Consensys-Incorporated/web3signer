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
package tech.pegasys.web3signer.enclave.client;

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.KeyLoadCounts;
import tech.pegasys.web3signer.enclave.protocol.Messages.PublicKeysRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.protocol.UnsupportedProtocolVersionException;
import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EnclaveClientTest {
  private static final byte[] PUBLIC_KEY = new byte[48];
  private static final Duration PROVISIONING_TIMEOUT = Duration.ofSeconds(5);

  private final List<AutoCloseable> resources = new ArrayList<>();

  @AfterEach
  void tearDown() throws Exception {
    for (final AutoCloseable resource : resources.reversed()) {
      resource.close();
    }
  }

  private ScriptedTcpServer server(final ScriptedTcpServer.Script script) throws IOException {
    final ScriptedTcpServer server = new ScriptedTcpServer(script);
    resources.add(server);
    return server;
  }

  /** Connects to the server, counting the connects: a resend needs a new connection. */
  private static EnclaveClient.Connector countingConnector(
      final ScriptedTcpServer server, final AtomicInteger connects) {
    return (connectTimeout, ioTimeout) -> {
      connects.incrementAndGet();
      return server.address().connect(connectTimeout, ioTimeout);
    };
  }

  private EnclaveClient client(
      final ScriptedTcpServer server, final EnclaveClient.Options options) {
    return client(server.address()::connect, options);
  }

  private EnclaveClient client(
      final EnclaveClient.Connector connector, final EnclaveClient.Options options) {
    final EnclaveClient client = new EnclaveClient(connector, options);
    resources.add(client);
    return client;
  }

  private static byte[] root(final int i) {
    final byte[] root = new byte[32];
    Arrays.fill(root, (byte) i);
    root[0] = (byte) (i >> 8);
    return root;
  }

  private static byte[] signature(final int i) {
    return ScriptedTcpServer.fakeSignature(root(i));
  }

  /** Answers every SIGN after {@code delayMillis}. */
  private ScriptedTcpServer answeringServer(final long delayMillis) throws IOException {
    return server(
        (server, connection, index) -> {
          while (true) {
            final Frame request = server.read(connection);
            sleep(delayMillis);
            ScriptedTcpServer.respondToSign(connection, request);
          }
        });
  }

  /** Reads requests and never answers. */
  private ScriptedTcpServer silentServer() throws IOException {
    return server(
        (server, connection, index) -> {
          while (true) {
            server.read(connection);
          }
        });
  }

  /** A connector that blocks until the test ends, ignoring its timeouts, then fails. */
  private EnclaveClient.Connector hungConnector(final CountDownLatch connecting) {
    final CountDownLatch release = new CountDownLatch(1);
    resources.add(release::countDown);
    return (connectTimeout, ioTimeout) -> {
      connecting.countDown();
      try {
        release.await();
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      throw new IOException("hung");
    };
  }

  private static void sleep(final long millis) {
    try {
      Thread.sleep(millis);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private static long millisSince(final long startNanos) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startNanos);
  }

  // ------------------------------------------------------------------ pool

  @Test
  void concurrentCallersEachGetTheirOwnAnswerOverAtMostThePoolSize() throws Exception {
    final ScriptedTcpServer server = answeringServer(2);
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(4, Duration.ofSeconds(10)));
    final int calls = 50;
    final CountDownLatch start = new CountDownLatch(1);
    try (ExecutorService callers = Executors.newFixedThreadPool(calls)) {
      final List<Future<byte[]>> results = new ArrayList<>();
      for (int i = 0; i < calls; i++) {
        final byte[] root = root(i);
        results.add(
            callers.submit(
                () -> {
                  start.await();
                  return client.sign(PUBLIC_KEY, root);
                }));
      }
      start.countDown();
      for (int i = 0; i < calls; i++) {
        assertThat(results.get(i).get(30, TimeUnit.SECONDS)).isEqualTo(signature(i));
      }
    }
    assertThat(server.received).hasSize(calls);
    assertThat(server.connectionCount()).isBetween(1, 4);
  }

  @Test
  void sequentialCallsReuseOneConnection() throws IOException {
    final ScriptedTcpServer server = answeringServer(0);
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(4, Duration.ofSeconds(5)));
    for (int i = 0; i < 5; i++) {
      assertThat(client.sign(PUBLIC_KEY, root(i))).isEqualTo(signature(i));
    }
    assertThat(server.connectionCount()).isEqualTo(1);
  }

  @Test
  void signRejectsAnythingButA48ByteKeyAndA32ByteRoot() throws IOException {
    final EnclaveClient client = client(answeringServer(0), EnclaveClient.Options.DEFAULT);
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, new byte[33]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> client.sign(new byte[47], new byte[32]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aCallerWaitsForAFreeConnectionNoLongerThanTheRequestTimeout() throws Exception {
    final CountDownLatch connecting = new CountDownLatch(1);
    final EnclaveClient client =
        client(hungConnector(connecting), new EnclaveClient.Options(1, Duration.ofMillis(300)));
    Thread.ofVirtual().start(() -> client.sign(PUBLIC_KEY, root(1))); // holds the only connection
    assertThat(connecting.await(5, TimeUnit.SECONDS)).isTrue();

    final long start = System.nanoTime();
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(2)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessageContaining("free within 300 ms");
    assertThat(millisSince(start)).isBetween(250L, 3000L);
  }

  @Test
  void optionsAndProvisioningTimeoutAreChecked() throws IOException {
    assertThatThrownBy(() -> new EnclaveClient.Options(0, Duration.ofSeconds(1)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new EnclaveClient.Options(1, Duration.ofMillis(0)))
        .isInstanceOf(IllegalArgumentException.class);
    final EnclaveClient client = client(answeringServer(0), EnclaveClient.Options.DEFAULT);
    for (final Duration timeout :
        new Duration[] {
          Duration.ZERO,
          Duration.ofMillis(Integer.MAX_VALUE + 1L),
          Duration.ofSeconds(Long.MAX_VALUE)
        }) {
      assertThatThrownBy(() -> client.openProvisioningSession(timeout))
          .isInstanceOf(IllegalArgumentException.class);
      assertThatThrownBy(() -> new EnclaveClient.Options(1, timeout))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  // ------------------------------------------------------------------ closing

  @Test
  void closeFailsAnInFlightCallOnAPooledConnectionWithoutReconnecting() throws Exception {
    final CountDownLatch received = new CountDownLatch(1);
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              ScriptedTcpServer.respondToSign(connection, self.read(connection));
              self.read(connection);
              received.countDown();
              while (true) {
                self.read(connection); // never answers
              }
            });
    final AtomicInteger connects = new AtomicInteger();
    final EnclaveClient client =
        client(
            countingConnector(server, connects),
            new EnclaveClient.Options(1, Duration.ofSeconds(10)));
    assertThat(client.sign(PUBLIC_KEY, root(1))).isEqualTo(signature(1)); // pools the connection
    try (ExecutorService caller = Executors.newSingleThreadExecutor()) {
      final Future<byte[]> result = caller.submit(() -> client.sign(PUBLIC_KEY, root(2)));
      assertThat(received.await(5, TimeUnit.SECONDS)).isTrue();
      client.close();
      assertThatThrownBy(() -> result.get(5, TimeUnit.SECONDS))
          .hasCauseInstanceOf(EnclaveUnavailableException.class)
          .cause()
          .hasMessage("Enclave client is closed");
    }
    assertThat(connects).hasValue(1);
  }

  @Test
  void closeFailsAProvisioningSessionWaitingForAnAnswer() throws Exception {
    final CountDownLatch received = new CountDownLatch(1);
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              self.read(connection);
              received.countDown();
              while (true) {
                self.read(connection); // never answers, like a release waiting for approval
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(2)));
    final ProvisioningSession session = client.openProvisioningSession(Duration.ofMinutes(1));
    resources.add(session);
    try (ExecutorService caller = Executors.newSingleThreadExecutor()) {
      final Future<?> result =
          caller.submit(() -> session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]));
      assertThat(received.await(5, TimeUnit.SECONDS)).isTrue();
      client.close();
      assertThatThrownBy(() -> result.get(5, TimeUnit.SECONDS))
          .hasCauseInstanceOf(EnclaveUnavailableException.class);
    }
  }

  @Test
  void aCallerInterruptedWhileWaitingForAConnectionFailsAndStaysInterrupted() throws Exception {
    final CountDownLatch connecting = new CountDownLatch(1);
    final EnclaveClient client =
        client(hungConnector(connecting), new EnclaveClient.Options(1, Duration.ofSeconds(60)));
    Thread.ofVirtual().start(() -> client.sign(PUBLIC_KEY, root(1))); // holds the only connection
    assertThat(connecting.await(5, TimeUnit.SECONDS)).isTrue();

    final FutureTask<Boolean> waiter =
        new FutureTask<>(
            () -> {
              assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(2)))
                  .isInstanceOf(EnclaveUnavailableException.class)
                  .hasMessage("Interrupted while waiting for the enclave signer");
              return Thread.currentThread().isInterrupted();
            });
    final Thread thread = Thread.ofVirtual().start(waiter);
    thread.interrupt();
    assertThat(waiter.get(5, TimeUnit.SECONDS)).isTrue();
  }

  @Test
  void aConnectionThatOpensAfterCloseIsClosedUnused() throws Exception {
    final CountDownLatch connecting = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);
    final AtomicInteger written = new AtomicInteger();
    final CountDownLatch connectionClosed = new CountDownLatch(1);
    final EnclaveClient client =
        client(
            (connectTimeout, ioTimeout) -> {
              connecting.countDown();
              try {
                release.await();
              } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
              }
              return new Connection() {
                @Override
                public int read(final byte[] buffer, final int offset, final int length) {
                  return -1;
                }

                @Override
                public void write(final byte[] buffer, final int offset, final int length) {
                  written.addAndGet(length);
                }

                @Override
                public void close() {
                  connectionClosed.countDown();
                }
              };
            },
            new EnclaveClient.Options(1, Duration.ofSeconds(60)));
    try (ExecutorService caller = Executors.newSingleThreadExecutor()) {
      final Future<byte[]> result = caller.submit(() -> client.sign(PUBLIC_KEY, root(1)));
      assertThat(connecting.await(5, TimeUnit.SECONDS)).isTrue();
      client.close();
      release.countDown();
      assertThatThrownBy(() -> result.get(5, TimeUnit.SECONDS))
          .hasCauseInstanceOf(EnclaveUnavailableException.class)
          .cause()
          .hasMessage("Enclave client is closed");
    }
    assertThat(connectionClosed.getCount()).isZero();
    assertThat(written).hasValue(0);
  }

  @Test
  void closeFailsTheCallersWaitingForAConnection() throws Exception {
    final CountDownLatch connecting = new CountDownLatch(1);
    final EnclaveClient client =
        client(hungConnector(connecting), new EnclaveClient.Options(1, Duration.ofSeconds(60)));
    Thread.ofVirtual().start(() -> client.sign(PUBLIC_KEY, root(1))); // holds the only connection
    assertThat(connecting.await(5, TimeUnit.SECONDS)).isTrue();

    final List<FutureTask<byte[]>> waiting = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      final byte[] root = root(i);
      final FutureTask<byte[]> caller = new FutureTask<>(() -> client.sign(PUBLIC_KEY, root));
      Thread.ofVirtual().start(caller);
      waiting.add(caller);
    }
    sleep(200); // let them block on the pool
    final long start = System.nanoTime();
    client.close();
    for (final FutureTask<byte[]> caller : waiting) {
      assertThatThrownBy(() -> caller.get(5, TimeUnit.SECONDS))
          .hasCauseInstanceOf(EnclaveUnavailableException.class)
          .cause()
          .hasMessage("Enclave client is closed");
    }
    assertThat(millisSince(start)).isLessThan(1000L);
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(9)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Enclave client is closed");
  }

  // ------------------------------------------------------------------ retries

  @Test
  void aRequestThatFailsOnAPooledConnectionIsSentOnceMoreOnANewOne() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              ScriptedTcpServer.respondToSign(connection, self.read(connection));
              if (index == 0) {
                self.read(connection);
                return; // the second request on the first connection gets no answer
              }
              while (true) {
                ScriptedTcpServer.respondToSign(connection, self.read(connection));
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThat(client.sign(PUBLIC_KEY, root(1))).isEqualTo(signature(1));
    assertThat(client.sign(PUBLIC_KEY, root(2))).isEqualTo(signature(2));
    assertThat(server.connectionCount()).isEqualTo(2);
    assertThat(server.received).hasSize(3);
    assertThat(server.received.get(2).body()).isEqualTo(server.received.get(1).body());
  }

  @Test
  void aFailureOnANewConnectionIsNotRetried() throws IOException {
    final ScriptedTcpServer server = server((self, connection, index) -> self.read(connection));
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(1)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessageContaining("unavailable");
    assertThat(server.received).hasSize(1);
    assertThat(server.connectionCount()).isEqualTo(1);
  }

  @Test
  void aTimeoutOnAPooledConnectionIsNotRetried() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              ScriptedTcpServer.respondToSign(connection, self.read(connection));
              while (true) {
                self.read(connection); // silent from the second request on
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofMillis(300)));
    assertThat(client.sign(PUBLIC_KEY, root(1))).isEqualTo(signature(1));

    final long start = System.nanoTime();
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(2)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessageContaining("did not answer within 300 ms");
    assertThat(millisSince(start)).isBetween(250L, 3000L);
    assertThat(server.connectionCount()).isEqualTo(1);
  }

  @Test
  void silentServerTimesOutWithinTheConfiguredTime() throws IOException {
    final EnclaveClient client =
        client(silentServer(), new EnclaveClient.Options(1, Duration.ofMillis(300)));
    final long start = System.nanoTime();
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(1)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessageContaining("300 ms");
    assertThat(millisSince(start)).isBetween(250L, 3000L);
  }

  @Test
  void anErrorDuringARequestClosesTheConnection() {
    final List<Boolean> closed = new CopyOnWriteArrayList<>();
    final EnclaveClient client =
        client(
            (connectTimeout, ioTimeout) -> {
              final int index = closed.size();
              closed.add(false);
              return new Connection() {
                @Override
                public int read(final byte[] buffer, final int offset, final int length) {
                  throw new OutOfMemoryError("test");
                }

                @Override
                public void write(final byte[] buffer, final int offset, final int length) {}

                @Override
                public void close() {
                  closed.set(index, true);
                }
              };
            },
            new EnclaveClient.Options(2, Duration.ofSeconds(1)));
    for (int i = 0; i < 3; i++) {
      assertThatThrownBy(client::status).isInstanceOf(OutOfMemoryError.class);
    }
    assertThat(closed).hasSize(3).containsOnly(true);
  }

  @Test
  void anErrorDuringProvisioningClosesTheSession() {
    final List<Boolean> closed = new CopyOnWriteArrayList<>();
    final EnclaveClient client =
        client(
            (connectTimeout, ioTimeout) -> {
              closed.add(false);
              return new Connection() {
                @Override
                public int read(final byte[] buffer, final int offset, final int length) {
                  throw new OutOfMemoryError("test");
                }

                @Override
                public void write(final byte[] buffer, final int offset, final int length) {}

                @Override
                public void close() {
                  closed.set(0, true);
                }
              };
            },
            new EnclaveClient.Options(1, Duration.ofSeconds(1)));
    final ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT);
    assertThatThrownBy(session::status).isInstanceOf(OutOfMemoryError.class);
    assertThat(closed).containsExactly(true);
  }

  @Test
  void anUnreachableEnclaveFailsWithTheConnectFailure() {
    final EnclaveClient client =
        client(
            (connectTimeout, ioTimeout) -> {
              throw new IOException("connection refused");
            },
            new EnclaveClient.Options(1, Duration.ofMillis(300)));
    assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(1)))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasRootCauseMessage("connection refused");
  }

  @Test
  void unwrapDekIsNeverResent() throws IOException {
    final ScriptedTcpServer server = server((self, connection, index) -> self.read(connection));
    final AtomicInteger connects = new AtomicInteger();
    final EnclaveClient client =
        client(countingConnector(server, connects), EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]))
          .isInstanceOf(EnclaveUnavailableException.class);
    }
    assertThat(connects).hasValue(1);
    assertThat(server.received).hasSize(1);
    assertThat(server.received.get(0).kind()).isEqualTo(Protocol.UNWRAP_DEK);
  }

  // ------------------------------------------------------------------ answers

  @Test
  void anAnswerToAnotherRequestDropsTheConnection() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              for (int answered = 0; ; answered++) {
                final Frame request = self.read(connection);
                // the first connection answers its second request under another request id
                final int requestId =
                    index == 0 && answered == 1 ? request.requestId() + 1 : request.requestId();
                final byte[] root = Messages.decodeSignRequest(request.body()).signingRoot();
                Frames.write(
                    connection,
                    new Frame(
                        requestId,
                        Protocol.OK,
                        Messages.encodeSignature(ScriptedTcpServer.fakeSignature(root))));
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThat(client.sign(PUBLIC_KEY, root(2))).isEqualTo(signature(2));
    assertThat(client.sign(PUBLIC_KEY, root(3))).isEqualTo(signature(3));
    assertThat(server.connectionCount()).isEqualTo(2);
  }

  @Test
  void aMalformedAnswerDropsTheConnection() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              final byte[] status = ScriptedTcpServer.status(2);
              ScriptedTcpServer.respond(connection, self.read(connection), Protocol.OK, status);
              // the first connection cuts its second answer short
              final byte[] second = index == 0 ? Arrays.copyOf(status, 20) : status;
              ScriptedTcpServer.respond(connection, self.read(connection), Protocol.OK, second);
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThat(client.status().cpus()).isEqualTo(2);
    assertThat(client.status().cpus()).isEqualTo(2);
    assertThat(server.connectionCount()).isEqualTo(2);
  }

  @Test
  void signerOfAnotherProtocolVersionIsRefusedWithoutRetry() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              ScriptedTcpServer.respond(
                  connection, self.read(connection), Protocol.OK, ScriptedTcpServer.status(1));
              // a v2 STATUS may have another layout: only the version must be readable
              final byte[] body =
                  ByteBuffer.allocate(60).order(ByteOrder.LITTLE_ENDIAN).putLong(0, 2).array();
              ScriptedTcpServer.respond(connection, self.read(connection), Protocol.OK, body);
              while (true) {
                self.read(connection);
              }
            });
    final AtomicInteger connects = new AtomicInteger();
    final EnclaveClient client =
        client(
            countingConnector(server, connects),
            new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    client.status(); // pools the connection, so the refused STATUS is one a failure could resend
    assertThatThrownBy(client::status)
        .isInstanceOfSatisfying(
            UnsupportedProtocolVersionException.class, e -> assertThat(e.version()).isEqualTo(2));
    assertThat(connects).hasValue(1);
  }

  @Test
  void provisioningWithASignerOfAnotherProtocolVersionFailsAndClosesTheSession()
      throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              final byte[] body = new byte[] {2};
              ScriptedTcpServer.respond(connection, self.read(connection), Protocol.OK, body);
              self.read(connection); // the session closes instead of sending more
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(session::status)
          .isInstanceOfSatisfying(
              UnsupportedProtocolVersionException.class, e -> assertThat(e.version()).isEqualTo(2));
      assertThatThrownBy(session::status).isInstanceOf(EnclaveUnavailableException.class);
    }
    assertThat(server.received).hasSize(1);
  }

  @Test
  void refusalIsReportedWithItsResultAndMessageAndKeepsTheConnection() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                ScriptedTcpServer.respond(
                    connection,
                    self.read(connection),
                    Protocol.RESOURCE_UNAVAILABLE,
                    "no such key\nX".getBytes(US_ASCII));
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    for (int i = 0; i < 2; i++) {
      assertThatThrownBy(() -> client.sign(PUBLIC_KEY, root(3)))
          .isInstanceOfSatisfying(
              EnclaveException.class,
              e -> {
                assertThat(e.result()).isEqualTo(Protocol.RESOURCE_UNAVAILABLE);
                assertThat(e.detail()).isEqualTo("no such key?X"); // control characters replaced
                assertThat(e)
                    .hasMessage(
                        "Enclave signer refused SIGN: RESOURCE_UNAVAILABLE (no such key?X)");
              });
    }
    assertThat(server.connectionCount()).isEqualTo(1);
  }

  /** A short page ends the listing, so a whole number of full pages ends with an empty one. */
  @ParameterizedTest
  @ValueSource(
      ints = {
        0,
        Protocol.MAX_PUBLIC_KEYS_PAGE,
        Protocol.MAX_PUBLIC_KEYS_PAGE + 3,
        2 * Protocol.MAX_PUBLIC_KEYS_PAGE,
        Protocol.MAX_KEYS
      })
  void publicKeysPagesThroughTheKeySet(final int keyCount) throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                final Frame request = self.read(connection);
                if (request.kind() == Protocol.STATUS) {
                  ScriptedTcpServer.respond(
                      connection, request, Protocol.OK, ScriptedTcpServer.status(1, keyCount));
                  continue;
                }
                final PublicKeysRequest page = Messages.decodePublicKeysRequest(request.body());
                final List<byte[]> keys = new ArrayList<>();
                for (long i = page.offset();
                    i < Math.min(keyCount, page.offset() + page.limit());
                    i++) {
                  keys.add(key((int) i));
                }
                ScriptedTcpServer.respond(
                    connection, request, Protocol.OK, Messages.encodePublicKeys(keys));
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    final List<byte[]> keys = client.publicKeys();
    assertThat(keys).hasSize(keyCount);
    for (int i = 0; i < keyCount; i++) {
      assertThat(keys.get(i)).isEqualTo(key(i));
    }
    // STATUS, the full pages, a short or empty page, STATUS
    assertThat(server.received).hasSize(keyCount / Protocol.MAX_PUBLIC_KEYS_PAGE + 3);
  }

  @Test
  void publicKeysFromASignerThatKeepsFillingPagesFail() throws IOException {
    final List<byte[]> fullPage = Collections.nCopies(Protocol.MAX_PUBLIC_KEYS_PAGE, key(0));
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                final Frame request = self.read(connection);
                // ignores the offset: every page is full
                final byte[] body =
                    request.kind() == Protocol.STATUS
                        ? ScriptedTcpServer.status(1)
                        : Messages.encodePublicKeys(fullPage);
                ScriptedTcpServer.respond(connection, request, Protocol.OK, body);
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThatThrownBy(client::publicKeys)
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Enclave signer listed more than " + Protocol.MAX_KEYS + " keys");
    // STATUS, then one full page past MAX_KEYS, and no second STATUS
    assertThat(server.received).hasSize(1 + Protocol.MAX_KEYS / Protocol.MAX_PUBLIC_KEYS_PAGE + 1);
  }

  /** A signer that holds 10 keys, but lists {@code listed} of them before a short page. */
  private ScriptedTcpServer miscountingServer(final int listed) throws IOException {
    return server(
        (self, connection, index) -> {
          while (true) {
            final Frame request = self.read(connection);
            if (request.kind() == Protocol.STATUS) {
              ScriptedTcpServer.respond(
                  connection, request, Protocol.OK, ScriptedTcpServer.status(1, 10));
              continue;
            }
            final List<byte[]> keys = new ArrayList<>();
            if (Messages.decodePublicKeysRequest(request.body()).offset() == 0) {
              for (int i = 0; i < listed; i++) {
                keys.add(key(i));
              }
            }
            ScriptedTcpServer.respond(
                connection, request, Protocol.OK, Messages.encodePublicKeys(keys));
          }
        });
  }

  @Test
  void publicKeysThatEndBeforeTheKeyCountAreRefused() throws IOException {
    final EnclaveClient client =
        client(miscountingServer(5), new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThatThrownBy(client::publicKeys)
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Enclave signer listed 5 keys, but holds 10 to 10");
  }

  @Test
  void publicKeysBeyondTheKeyCountAreRefused() throws IOException {
    final EnclaveClient client =
        client(miscountingServer(12), new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThatThrownBy(client::publicKeys)
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Enclave signer listed 12 keys, but holds 10 to 10");
  }

  @Test
  void publicKeysFromASignerWithNoKeysLoadedSinceItStartedAreRefused() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                final Frame request = self.read(connection);
                if (request.kind() == Protocol.STATUS) {
                  ScriptedTcpServer.respond(
                      connection, request, Protocol.OK, ScriptedTcpServer.status(1));
                } else {
                  ScriptedTcpServer.respond(
                      connection,
                      request,
                      Protocol.NOT_INITIALIZED,
                      Messages.encodeErrorMessage("no keys loaded since start"));
                }
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThatThrownBy(client::publicKeys)
        .isInstanceOfSatisfying(
            EnclaveException.class,
            e -> assertThat(e.result()).isEqualTo(Protocol.NOT_INITIALIZED));
  }

  @Test
  void publicKeysFromTwoRunsOfTheEnclaveAreRefused() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              int statuses = 0;
              while (true) {
                final Frame request = self.read(connection);
                if (request.kind() == Protocol.STATUS) {
                  // the enclave restarts between the first and the second STATUS
                  final byte[] bootId = new byte[16];
                  bootId[0] = (byte) statuses++;
                  ScriptedTcpServer.respond(
                      connection,
                      request,
                      Protocol.OK,
                      Messages.encodeStatus(Protocol.PLATFORM_DEV, 1, 0, bootId, "test"));
                } else {
                  ScriptedTcpServer.respond(
                      connection, request, Protocol.OK, Messages.encodePublicKeys(List.of()));
                }
              }
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    assertThatThrownBy(client::publicKeys)
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessageContaining("restarted");
  }

  private static byte[] key(final int i) {
    return ByteBuffer.allocate(48).putInt(i).array();
  }

  // ------------------------------------------------------------------ provisioning

  private static List<SealedKey> sealedKeys(final int count) {
    final List<SealedKey> keys = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      final byte[] publicKey = ByteBuffer.allocate(48).putInt(0, i).array();
      keys.add(new SealedKey(publicKey, new byte[12], new byte[48]));
    }
    return keys;
  }

  @Test
  void loadKeysSplitsALargeSetAndAddsUpTheCounts() throws IOException {
    final List<Integer> requestSizes = new CopyOnWriteArrayList<>();
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                final Frame request = self.read(connection);
                final List<SealedKey> keys = Messages.decodeSealedKeys(request.body());
                requestSizes.add(keys.size());
                // the first key of each request counts as a duplicate
                ScriptedTcpServer.respond(
                    connection,
                    request,
                    Protocol.OK,
                    Messages.encodeKeyLoadCounts(new KeyLoadCounts(keys.size() - 1, 1, 0)));
              }
            });
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThat(session.loadKeys(sealedKeys(Protocol.MAX_LOAD_KEYS + 1)))
          .isEqualTo(new KeyLoadCounts(Protocol.MAX_LOAD_KEYS - 1, 2, 0));
    }
    assertThat(requestSizes).containsExactly(Protocol.MAX_LOAD_KEYS, 1);
  }

  @Test
  void loadCountsThatDoNotAddUpToTheRequestCloseTheSession() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) ->
                ScriptedTcpServer.respond(
                    connection,
                    self.read(connection),
                    Protocol.OK,
                    Messages.encodeKeyLoadCounts(KeyLoadCounts.EMPTY)));
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.loadKeys(sealedKeys(1)))
          .isInstanceOf(EnclaveUnavailableException.class)
          .hasRootCauseMessage("Malformed LOAD_KEYS response: counts add up to 0, expected 1");
    }
  }

  @Test
  void aFailedLoadKeysRequestReportsTheCountsOfTheEarlierOnes() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              final Frame first = self.read(connection);
              ScriptedTcpServer.respond(
                  connection,
                  first,
                  Protocol.OK,
                  Messages.encodeKeyLoadCounts(
                      new KeyLoadCounts(Protocol.MAX_LOAD_KEYS - 2, 1, 1)));
              self.read(connection); // the second request gets no answer
            });
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.loadKeys(sealedKeys(Protocol.MAX_LOAD_KEYS + 1)))
          .isInstanceOfSatisfying(
              PartialLoadException.class,
              e -> {
                assertThat(e.loadedBefore())
                    .isEqualTo(new KeyLoadCounts(Protocol.MAX_LOAD_KEYS - 2, 1, 1));
                assertThat(e).hasCauseInstanceOf(EnclaveUnavailableException.class);
                assertThat(e).hasMessageStartingWith("Loading keys failed after 4094 loaded");
              });
    }
  }

  @Test
  void aRefusedFirstLoadKeysRequestIsReportedAsTheRefusal() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                ScriptedTcpServer.respond(
                    connection,
                    self.read(connection),
                    Protocol.INVALID_STATE,
                    Messages.encodeErrorMessage("no data key: UNWRAP_DEK first"));
              }
            });
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.loadKeys(sealedKeys(Protocol.MAX_LOAD_KEYS + 1)))
          .isExactlyInstanceOf(EnclaveException.class)
          .satisfies(
              e -> assertThat(((EnclaveException) e).result()).isEqualTo(Protocol.INVALID_STATE));
    }
    // the second request is never sent
    assertThat(server.received).hasSize(1);
  }

  @Test
  void aRefusedLaterLoadKeysRequestReportsTheEarlierCountsAndKeepsTheSession() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              int loadRequests = 0;
              while (true) {
                final Frame request = self.read(connection);
                if (request.kind() == Protocol.LOAD_KEYS && ++loadRequests == 2) {
                  ScriptedTcpServer.respond(
                      connection,
                      request,
                      Protocol.BAD_REQUEST,
                      Messages.encodeErrorMessage("refused"));
                } else if (request.kind() == Protocol.LOAD_KEYS) {
                  ScriptedTcpServer.respond(
                      connection,
                      request,
                      Protocol.OK,
                      Messages.encodeKeyLoadCounts(
                          new KeyLoadCounts(Protocol.MAX_LOAD_KEYS, 0, 0)));
                } else {
                  ScriptedTcpServer.respond(
                      connection, request, Protocol.OK, ScriptedTcpServer.status(1));
                }
              }
            });
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.loadKeys(sealedKeys(Protocol.MAX_LOAD_KEYS + 1)))
          .isInstanceOfSatisfying(
              PartialLoadException.class,
              e -> {
                assertThat(e.loadedBefore())
                    .isEqualTo(new KeyLoadCounts(Protocol.MAX_LOAD_KEYS, 0, 0));
                assertThat(e.getCause())
                    .isInstanceOfSatisfying(
                        EnclaveException.class,
                        cause -> assertThat(cause.result()).isEqualTo(Protocol.BAD_REQUEST));
              });
      // a refusal leaves the session usable
      session.status();
    }
    assertThat(server.connectionCount()).isEqualTo(1);
  }

  @Test
  void provisioningRefusalKeepsTheSession() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                final Frame request = self.read(connection);
                if (request.kind() == Protocol.UNWRAP_DEK) {
                  ScriptedTcpServer.respond(
                      connection,
                      request,
                      Protocol.UNWRAP_FAILED,
                      Messages.encodeErrorMessage("release blob did not open"));
                } else {
                  ScriptedTcpServer.respond(
                      connection,
                      request,
                      Protocol.OK,
                      Messages.encodeEvidence(
                          new Evidence(Protocol.EVIDENCE_DEV, new byte[] {1}, new byte[] {2, 3})));
                }
              }
            });
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]))
          .isInstanceOfSatisfying(
              EnclaveException.class,
              e -> {
                assertThat(e.result()).isEqualTo(Protocol.UNWRAP_FAILED);
                assertThat(e.detail()).isEqualTo("release blob did not open");
              });
      final Evidence evidence = session.evidence(new byte[32]);
      assertThat(evidence.evidenceType()).isEqualTo(Protocol.EVIDENCE_DEV);
      assertThat(evidence.releaseKey()).containsExactly(1);
      assertThat(evidence.evidence()).containsExactly(2, 3);
    }
    assertThat(server.connectionCount()).isEqualTo(1);
  }

  @Test
  void aNonEmptyUnwrapDekAnswerClosesTheSession() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              while (true) {
                ScriptedTcpServer.respond(
                    connection, self.read(connection), Protocol.OK, new byte[] {1});
              }
            });
    final EnclaveClient client = client(server, EnclaveClient.Options.DEFAULT);
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThatThrownBy(() -> session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]))
          .isInstanceOf(EnclaveUnavailableException.class)
          .hasRootCauseMessage("Malformed UNWRAP_DEK response: body not empty");
      assertThatThrownBy(() -> session.evidence(new byte[32]))
          .isInstanceOf(EnclaveUnavailableException.class);
    }
    assertThat(server.received).hasSize(1);
  }

  @Test
  void loadingNoKeysSendsNothing() throws IOException {
    final ScriptedTcpServer server = server((self, connection, index) -> self.read(connection));
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      assertThat(session.loadKeys(List.of())).isEqualTo(KeyLoadCounts.EMPTY);
    }
    assertThat(server.received).isEmpty();
  }

  @Test
  void aSessionUsedAfterCloseFailsWithoutSending() throws IOException {
    final ScriptedTcpServer server = server((self, connection, index) -> self.read(connection));
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    final ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT);
    session.close();
    assertThatThrownBy(session::status)
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Provisioning connection failed");
    assertThat(server.received).isEmpty();
  }

  @Test
  void provisioningResponsesMayTakeTheSessionTimeout() throws IOException {
    final ScriptedTcpServer server =
        server(
            (self, connection, index) -> {
              final Frame request = self.read(connection);
              sleep(500); // longer than the request timeout
              ScriptedTcpServer.respond(
                  connection, request, Protocol.OK, Messages.encodeUnwrapDekResponse());
            });
    final EnclaveClient client =
        client(server, new EnclaveClient.Options(1, Duration.ofMillis(200)));
    try (ProvisioningSession session = client.openProvisioningSession(PROVISIONING_TIMEOUT)) {
      session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]);
    }
  }

  @Test
  void aProvisioningSessionGivesUpAfterItsTimeout() throws IOException {
    final EnclaveClient client =
        client(silentServer(), new EnclaveClient.Options(1, Duration.ofSeconds(5)));
    try (ProvisioningSession session = client.openProvisioningSession(Duration.ofMillis(300))) {
      final long start = System.nanoTime();
      assertTimeoutPreemptively(
          Duration.ofSeconds(10),
          () ->
              assertThatThrownBy(() -> session.unwrapDek(Protocol.BLOB_FORMAT_CMS, new byte[10]))
                  .isInstanceOf(EnclaveUnavailableException.class)
                  .hasMessage("Provisioning connection failed")
                  .hasCauseInstanceOf(SocketTimeoutException.class));
      assertThat(millisSince(start)).isBetween(250L, 3000L);
    }
  }

  @Test
  void aProvisioningSessionCannotOpenOnAClosedClient() {
    final AtomicInteger connects = new AtomicInteger();
    final EnclaveClient client =
        client(
            (connectTimeout, ioTimeout) -> {
              connects.incrementAndGet();
              throw new IOException("not expected");
            },
            EnclaveClient.Options.DEFAULT);
    client.close();
    assertThatThrownBy(() -> client.openProvisioningSession(PROVISIONING_TIMEOUT))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Enclave client is closed");
    assertThat(connects).hasValue(0);
  }

  @Test
  void aProvisioningSessionThatCannotConnectReportsWhy() {
    final EnclaveClient client =
        client(
            (connectTimeout, ioTimeout) -> {
              throw new IOException("connection refused");
            },
            EnclaveClient.Options.DEFAULT);
    assertThatThrownBy(() -> client.openProvisioningSession(PROVISIONING_TIMEOUT))
        .isInstanceOf(EnclaveUnavailableException.class)
        .hasMessage("Enclave signer unavailable")
        .hasRootCauseMessage("connection refused");
  }
}
