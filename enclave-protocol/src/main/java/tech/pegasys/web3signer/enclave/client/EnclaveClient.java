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

import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.PageRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.SignRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.Status;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.protocol.UnsupportedProtocolVersionException;
import tech.pegasys.web3signer.enclave.transport.Connection;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;

import java.io.Closeable;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Client of an enclave signer.
 *
 * <ul>
 *   <li>{@link #sign}, {@link #status} and {@link #publicKeys} borrow a connection from a pool of
 *       at most {@code connections}, send one request on the caller's thread and give the
 *       connection back. Connections are opened on demand and kept while they work.
 *   <li>A request that fails on a pooled connection, other than by a timeout, is sent once more on
 *       a new connection: after the enclave restarts, every pooled connection is stale.
 *   <li>{@link #openProvisioningSession} opens a connection of its own and never retries.
 * </ul>
 */
public final class EnclaveClient implements Closeable {
  public static final Duration DEFAULT_PROVISIONING_TIMEOUT = Duration.ofSeconds(30);

  /**
   * Client settings.
   *
   * @param connections largest number of pooled connections, and so of requests in flight; the
   *     signer accepts 64 connections, so the default of 32 leaves room for provisioning
   * @param requestTimeoutMillis how long a request waits for a free connection, and the timeout of
   *     connect, read and write; a vsock connect is bounded by the kernel instead (about 2 s)
   */
  public record Options(int connections, int requestTimeoutMillis) {
    public static final Options DEFAULT = new Options(32, 2000);

    public Options {
      if (connections < 1) {
        throw new IllegalArgumentException("connections must be at least 1: " + connections);
      }
      if (requestTimeoutMillis < 1) {
        throw new IllegalArgumentException(
            "requestTimeoutMillis must be at least 1: " + requestTimeoutMillis);
      }
    }
  }

  /** Opens a connection to the enclave signer. */
  @FunctionalInterface
  public interface Connector {
    Connection connect(int connectTimeoutMillis, int ioTimeoutMillis) throws IOException;
  }

  /** Decodes the body of an {@code OK} response. */
  @FunctionalInterface
  interface BodyDecoder<T> {
    T decode(byte[] body) throws IOException;
  }

  private final Connector connector;
  private final Options options;
  private final Semaphore permits;
  private final Deque<Connection> idle = new ConcurrentLinkedDeque<>();
  private final Set<Connection> open = ConcurrentHashMap.newKeySet();
  private final AtomicInteger requestIds = new AtomicInteger();
  private volatile boolean closed;

  public EnclaveClient(final Connector connector, final Options options) {
    this.connector = connector;
    this.options = options;
    this.permits = new Semaphore(options.connections(), true);
  }

  public static EnclaveClient create(final EnclaveAddress address, final Options options) {
    return new EnclaveClient(address::connect, options);
  }

  /**
   * Signs a 32-byte signing root with the key {@code publicKey} held by the enclave.
   *
   * @return the 96-byte compressed signature
   * @throws IllegalArgumentException when the key is not 48 bytes or the root not 32
   * @throws EnclaveException when the enclave refuses, for example {@link
   *     Protocol#RESOURCE_UNAVAILABLE} for a key it does not hold
   * @throws EnclaveUnavailableException on a timeout or a connection failure
   */
  public byte[] sign(final byte[] publicKey, final byte[] signingRoot) {
    final byte[] request = Messages.encodeSignRequest(new SignRequest(publicKey, signingRoot));
    return sendPooled(Protocol.SIGN, request, Messages::decodeSignature);
  }

  public Status status() {
    return sendPooled(Protocol.STATUS, Messages.encodeStatusRequest(), Messages::decodeStatus);
  }

  /** All public keys, in load order. */
  public List<byte[]> publicKeys() {
    final List<byte[]> keys = new ArrayList<>();
    while (true) {
      final byte[] request =
          Messages.encodePageRequest(new PageRequest(keys.size(), Protocol.MAX_PUBLIC_KEYS_PAGE));
      final List<byte[]> page =
          sendPooled(Protocol.GET_PUBLIC_KEYS, request, Messages::decodePublicKeys);
      keys.addAll(page);
      // keys are only ever added, so a short page is the last one
      if (page.size() < Protocol.MAX_PUBLIC_KEYS_PAGE) {
        return keys;
      }
    }
  }

  /**
   * Opens a provisioning session on a connection of its own.
   *
   * @param responseTimeout how long each provisioning response may take, for example while a key
   *     release waits for approval
   */
  public ProvisioningSession openProvisioningSession(final Duration responseTimeout) {
    final long millis = responseTimeout.toMillis();
    if (millis < 1 || millis > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("Invalid provisioning timeout: " + responseTimeout);
    }
    requireOpen();
    try {
      return new ProvisioningSession(
          this,
          registerConnection(connector.connect(options.requestTimeoutMillis(), (int) millis)));
    } catch (final IOException e) {
      throw new EnclaveUnavailableException("Enclave signer unavailable", e);
    }
  }

  // ------------------------------------------------------------------ requests

  /**
   * Sends one request and reads its response.
   *
   * @return the body of an {@code OK} response
   * @throws EnclaveException when the enclave refuses; the connection stays usable
   * @throws IOException on an I/O error or an answer to another request; close the connection
   */
  byte[] sendAndReceive(final Connection connection, final int opcode, final byte[] body)
      throws IOException {
    final int requestId = requestIds.incrementAndGet();
    Frames.write(connection, new Frame(requestId, opcode, body));
    final Frame response = Frames.read(connection);
    if (response.requestId() != requestId) {
      throw new IOException(
          "Response to request " + response.requestId() + ", expected " + requestId);
    }
    if (response.kind() != Protocol.OK) {
      throw new EnclaveException(
          response.kind(),
          Protocol.opcodeName(opcode),
          Messages.decodeErrorMessage(response.body()));
    }
    return response.body();
  }

  /** One request on a pooled connection, resent once on a new one if a pooled one failed. */
  private <T> T sendPooled(final int opcode, final byte[] body, final BodyDecoder<T> decoder) {
    waitForFreeConnection();
    try {
      requireOpen();
      final Connection pooled = idle.pollFirst();
      if (pooled != null) {
        try {
          return sendAndDecode(pooled, opcode, body, decoder);
        } catch (final IOException e) {
          if (closed || e instanceof SocketTimeoutException) {
            throw unavailable(e);
          }
          // most likely stale: try a new connection
        }
      }
      try {
        return sendAndDecode(connect(), opcode, body, decoder);
      } catch (final IOException e) {
        throw unavailable(e);
      }
    } finally {
      permits.release();
    }
  }

  /** Sends and decodes; keeps the connection unless it failed, closes it otherwise. */
  private <T> T sendAndDecode(
      final Connection connection,
      final int opcode,
      final byte[] body,
      final BodyDecoder<T> decoder)
      throws IOException {
    try {
      final T result = decoder.decode(sendAndReceive(connection, opcode, body));
      releaseConnection(connection);
      return result;
    } catch (final EnclaveException refused) {
      releaseConnection(connection); // a refusal leaves the connection usable
      throw refused;
    } catch (final UnsupportedProtocolVersionException e) {
      closeConnection(connection);
      throw new EnclaveUnavailableException(e.getMessage(), e);
    } catch (final IOException | RuntimeException e) {
      closeConnection(connection);
      throw e;
    }
  }

  private void waitForFreeConnection() {
    final boolean acquired;
    try {
      acquired = permits.tryAcquire(options.requestTimeoutMillis(), TimeUnit.MILLISECONDS);
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new EnclaveUnavailableException("Interrupted while waiting for the enclave signer", e);
    }
    if (!acquired) {
      throw new EnclaveUnavailableException(
          "No connection to the enclave signer free within "
              + options.requestTimeoutMillis()
              + " ms");
    }
  }

  private Connection connect() throws IOException {
    final int timeout = options.requestTimeoutMillis();
    return registerConnection(connector.connect(timeout, timeout));
  }

  /** Registers a new connection, pooled or provisioning, so that {@link #close()} reaches it. */
  private Connection registerConnection(final Connection connection) {
    open.add(connection);
    if (closed) {
      // close() may have looked before this connection existed
      closeConnection(connection);
      throw closedFailure();
    }
    return connection;
  }

  /** Puts a working connection back in the idle pool, or closes it if the client has closed. */
  private void releaseConnection(final Connection connection) {
    idle.offerFirst(connection);
    if (closed && idle.remove(connection)) {
      closeConnection(connection);
    }
  }

  void closeConnection(final Connection connection) {
    open.remove(connection);
    connection.close();
  }

  private EnclaveUnavailableException unavailable(final IOException cause) {
    if (closed) {
      return closedFailure();
    }
    if (cause instanceof SocketTimeoutException) {
      return new EnclaveUnavailableException(
          "Enclave signer did not answer within " + options.requestTimeoutMillis() + " ms", cause);
    }
    return new EnclaveUnavailableException("Enclave signer unavailable", cause);
  }

  private static EnclaveUnavailableException closedFailure() {
    return new EnclaveUnavailableException("Enclave client is closed");
  }

  private void requireOpen() {
    if (closed) {
      throw closedFailure();
    }
  }

  /**
   * Closes every connection, provisioning sessions included, which fails the requests in flight,
   * and fails the callers waiting for a connection.
   */
  @Override
  public void close() {
    closed = true;
    // wakes the waiting callers: each one sees closed and passes its permit on
    permits.release(options.connections());
    idle.clear();
    for (final Connection connection : open) {
      closeConnection(connection);
    }
  }
}
