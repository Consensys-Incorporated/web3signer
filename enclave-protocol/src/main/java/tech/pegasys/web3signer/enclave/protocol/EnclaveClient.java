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

import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Payloads.PublicKeysPage;

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

/**
 * Client of an enclave signer.
 *
 * <ul>
 *   <li>{@link #sign} goes through dispatcher threads. Each owns one connection, takes the calls
 *       already queued (up to {@code maxBatch}), sends their frames with one write and reads the
 *       answers in order. After an I/O error or a protocol mismatch it reconnects and resends the
 *       unanswered calls once.
 *   <li>{@link #status} and {@link #publicKeys} use a short-lived connection and retry once.
 *   <li>{@link #openProvisioningSession} pins one connection and never retries.
 * </ul>
 */
public final class EnclaveClient implements Closeable {
  public static final int QUEUE_CAPACITY = 4096;
  public static final int PROVISIONING_TIMEOUT_MILLIS = 30_000;
  static final long RECONNECT_DELAY_NANOS = TimeUnit.MILLISECONDS.toNanos(200);
  private static final long POLL_MILLIS = 100;

  /**
   * Client settings.
   *
   * @param connections dispatcher connections; 0 means the enclave's {@code cpus}
   * @param maxBatch largest number of {@code SIGN} requests in one write
   * @param requestTimeoutMillis timeout of one request, and of connect, read and write
   */
  public record Options(int connections, int maxBatch, int requestTimeoutMillis) {
    public static final Options DEFAULT = new Options(0, 8, 2000);

    public Options {
      if (connections < 0 || maxBatch < 1 || requestTimeoutMillis < 1) {
        throw new IllegalArgumentException("Invalid enclave client options");
      }
    }
  }

  /** Opens a connection to the enclave signer. */
  @FunctionalInterface
  public interface Connector {
    Connection connect(int timeoutMillis) throws IOException;
  }

  /**
   * Counters of the signing path.
   *
   * @param writes batches written
   * @param requests {@code SIGN} requests in those batches
   */
  public record BatchStats(long writes, long requests) {}

  private final Connector connector;
  private final String target;
  private final Options options;
  private final BlockingQueue<Call> queue = new ArrayBlockingQueue<>(QUEUE_CAPACITY);
  private final AtomicInteger requestIds = new AtomicInteger();
  private final List<Dispatcher> dispatchers = new ArrayList<>();
  private final LongAdder writes = new LongAdder();
  private final LongAdder requests = new LongAdder();
  private volatile boolean started;
  private volatile boolean closed;

  public EnclaveClient(final Connector connector, final String target, final Options options) {
    this.connector = connector;
    this.target = target;
    this.options = options;
  }

  public static EnclaveClient create(final EnclaveAddress address, final Options options) {
    return new EnclaveClient(
        timeout -> Transports.connect(address, timeout), address.toString(), options);
  }

  public String target() {
    return target;
  }

  public BatchStats batchStats() {
    return new BatchStats(writes.sum(), requests.sum());
  }

  // ------------------------------------------------------------------ control calls

  public EnclaveStatus status() {
    return control(
        connection ->
            Payloads.decodeStatus(
                exchange(connection, nextRequestId(), Protocol.STATUS, Payloads.statusRequest())
                    .payload()));
  }

  /** All public keys, in load order. */
  public List<byte[]> publicKeys() {
    return control(
        connection -> {
          final List<byte[]> keys = new ArrayList<>();
          while (true) {
            final Frame response =
                exchange(
                    connection,
                    nextRequestId(),
                    Protocol.GET_PUBLIC_KEYS,
                    Payloads.getPublicKeysRequest(keys.size(), Protocol.MAX_PUBLIC_KEYS_PAGE));
            final PublicKeysPage page = Payloads.decodePublicKeys(response.payload());
            keys.addAll(page.publicKeys());
            if (page.publicKeys().isEmpty() || keys.size() >= page.total()) {
              return keys;
            }
          }
        });
  }

  @FunctionalInterface
  private interface ControlCall<T> {
    T run(Connection connection) throws IOException;
  }

  private <T> T control(final ControlCall<T> call) {
    requireOpen();
    IOException failure = null;
    for (int attempt = 0; attempt < 2; attempt++) {
      try (Connection connection = connector.connect(options.requestTimeoutMillis())) {
        return call.run(connection);
      } catch (final IOException e) {
        failure = e;
      }
    }
    throw new EnclaveUnavailableException("Enclave signer at " + target + " unavailable", failure);
  }

  // ------------------------------------------------------------------ provisioning

  public ProvisioningSession openProvisioningSession() {
    requireOpen();
    try {
      return new ProvisioningSession(this, connector.connect(PROVISIONING_TIMEOUT_MILLIS));
    } catch (final IOException e) {
      throw new EnclaveUnavailableException("Enclave signer at " + target + " unavailable", e);
    }
  }

  int nextRequestId() {
    return requestIds.incrementAndGet();
  }

  /** Sends one request and reads its response. Checks request id, type and status. */
  static Frame exchange(
      final Connection connection, final int requestId, final int opcode, final byte[] payload)
      throws IOException {
    final byte[] frame = Frames.encode(opcode, requestId, payload);
    connection.write(frame, 0, frame.length);
    final Frame response = Frames.read(connection);
    if (response.requestId() != requestId) {
      throw new ProtocolMismatchException("Response for request " + response.requestId());
    }
    Payloads.requireOk(response, opcode);
    return response;
  }

  /** A response that does not match its request. The connection must be dropped. */
  static final class ProtocolMismatchException extends IOException {
    private static final long serialVersionUID = 1L;

    ProtocolMismatchException(final String message) {
      super(message);
    }
  }

  // ------------------------------------------------------------------ signing

  private static final class Call {
    final byte[] publicKey;
    final byte[] message;
    final CompletableFuture<byte[]> result = new CompletableFuture<>();

    Call(final byte[] publicKey, final byte[] message) {
      this.publicKey = publicKey;
      this.message = message;
    }
  }

  /**
   * Signs {@code message} with the key {@code publicKey} held by the enclave.
   *
   * @return the 96-byte compressed signature
   * @throws EnclaveException when the enclave refuses, for example {@link Protocol#UNKNOWN_KEY}
   * @throws EnclaveUnavailableException on timeout, a full queue or a connection failure
   */
  public byte[] sign(final byte[] publicKey, final byte[] message) {
    Payloads.checkSign(publicKey, message);
    requireOpen();
    startDispatchers();
    final Call call = new Call(publicKey, message);
    if (!queue.offer(call)) {
      throw new EnclaveUnavailableException("Enclave signer request queue is full");
    }
    try {
      return call.result.get(options.requestTimeoutMillis(), TimeUnit.MILLISECONDS);
    } catch (final TimeoutException e) {
      final EnclaveUnavailableException timeout =
          new EnclaveUnavailableException(
              "Enclave signer did not answer within " + options.requestTimeoutMillis() + " ms");
      call.result.completeExceptionally(timeout);
      throw timeout;
    } catch (final ExecutionException e) {
      if (e.getCause() instanceof EnclaveException refused) {
        throw new EnclaveException(refused.status(), "Enclave signer refused to sign");
      }
      throw new EnclaveUnavailableException("Signing through " + target + " failed", e.getCause());
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      call.result.completeExceptionally(e);
      throw new EnclaveUnavailableException("Interrupted while waiting for the enclave signer", e);
    }
  }

  private void startDispatchers() {
    if (started) {
      return;
    }
    synchronized (dispatchers) {
      if (started || closed) {
        return;
      }
      final int count =
          options.connections() > 0 ? options.connections() : Math.max(1, status().cpus());
      for (int i = 0; i < count; i++) {
        final Dispatcher dispatcher = new Dispatcher();
        dispatcher.thread =
            Thread.ofPlatform().name("enclave-dispatcher-" + i).daemon(true).start(dispatcher::run);
        dispatchers.add(dispatcher);
      }
      started = true;
    }
  }

  public int dispatcherCount() {
    synchronized (dispatchers) {
      return dispatchers.size();
    }
  }

  private final class Dispatcher {
    private Thread thread;
    private volatile Connection connection;
    private long nextConnectAt = System.nanoTime();
    private byte[] buffer = new byte[4096];

    void run() {
      final List<Call> batch = new ArrayList<>(options.maxBatch());
      try {
        while (!closed) {
          final Call first;
          try {
            first = queue.poll(POLL_MILLIS, TimeUnit.MILLISECONDS);
          } catch (final InterruptedException e) {
            break;
          }
          if (first == null) {
            continue;
          }
          batch.clear();
          batch.add(first);
          queue.drainTo(batch, options.maxBatch() - 1);
          batch.removeIf(call -> call.result.isDone());
          if (!batch.isEmpty()) {
            dispatch(batch);
          }
        }
      } finally {
        dropConnection();
      }
    }

    private void dispatch(final List<Call> batch) {
      List<Call> pending = batch;
      Exception failure = null;
      for (int attempt = 0; attempt < 2; attempt++) {
        if (connection == null) {
          if (attempt == 0 && System.nanoTime() < nextConnectAt) {
            fail(pending, new EnclaveUnavailableException("Enclave signer not connected"));
            return;
          }
          try {
            connection = connector.connect(options.requestTimeoutMillis());
          } catch (final IOException | RuntimeException e) {
            nextConnectAt = System.nanoTime() + RECONNECT_DELAY_NANOS;
            fail(pending, e);
            return;
          }
        }
        try {
          send(pending);
          return;
        } catch (final IOException | RuntimeException e) {
          failure = e;
          dropConnection();
          pending = new ArrayList<>(pending);
          pending.removeIf(call -> call.result.isDone());
          if (pending.isEmpty()) {
            return;
          }
        }
      }
      fail(pending, failure);
    }

    /** Writes all frames with one write, then reads the answers in order. */
    private void send(final List<Call> calls) throws IOException {
      int size = 0;
      for (final Call call : calls) {
        size += Frames.encodedSize(Payloads.signRequestSize(call.message.length));
      }
      if (buffer.length < size) {
        buffer = new byte[Math.max(size, buffer.length * 2)];
      }
      final int[] ids = new int[calls.size()];
      int at = 0;
      for (int i = 0; i < calls.size(); i++) {
        final Call call = calls.get(i);
        ids[i] = nextRequestId();
        final int payloadSize = Payloads.signRequestSize(call.message.length);
        final int payloadAt = Frames.putHeader(buffer, at, Protocol.SIGN, ids[i], payloadSize);
        Payloads.putSignRequest(buffer, payloadAt, call.publicKey, call.message);
        at = payloadAt + payloadSize;
      }
      connection.write(buffer, 0, at);
      writes.increment();
      requests.add(calls.size());

      for (int i = 0; i < calls.size(); i++) {
        final Frame response = Frames.read(connection);
        if (response.requestId() != ids[i]
            || response.type() != (Protocol.SIGN | Protocol.RESPONSE_FLAG)) {
          throw new ProtocolMismatchException(
              "Expected SIGN response " + ids[i] + ", got request " + response.requestId());
        }
        final Call call = calls.get(i);
        if (response.status() == Protocol.OK) {
          call.result.complete(Payloads.decodeSignature(response.payload()));
        } else {
          call.result.completeExceptionally(
              new EnclaveException(response.status(), "Enclave signer refused to sign"));
        }
      }
    }

    private void fail(final List<Call> calls, final Exception cause) {
      final EnclaveUnavailableException failure =
          cause instanceof EnclaveUnavailableException unavailable
              ? unavailable
              : new EnclaveUnavailableException(
                  "Enclave signer at " + target + " unavailable", cause);
      for (final Call call : calls) {
        call.result.completeExceptionally(failure);
      }
    }

    private void dropConnection() {
      final Connection current = connection;
      if (current != null) {
        current.close();
        connection = null;
      }
    }
  }

  private void requireOpen() {
    if (closed) {
      throw new EnclaveUnavailableException("Enclave client is closed");
    }
  }

  @Override
  public void close() {
    closed = true;
    final List<Dispatcher> stopping;
    synchronized (dispatchers) {
      stopping = List.copyOf(dispatchers);
    }
    for (final Dispatcher dispatcher : stopping) {
      dispatcher.thread.interrupt();
      // a thread blocked in a socket read wakes up only when its connection closes
      final Connection current = dispatcher.connection;
      if (current != null) {
        current.close();
      }
    }
    for (final Dispatcher dispatcher : stopping) {
      try {
        dispatcher.thread.join(1000);
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
        break;
      }
    }
    final EnclaveUnavailableException closedFailure =
        new EnclaveUnavailableException("Enclave client is closed");
    Call call;
    while ((call = queue.poll()) != null) {
      call.result.completeExceptionally(closedFailure);
    }
  }
}
