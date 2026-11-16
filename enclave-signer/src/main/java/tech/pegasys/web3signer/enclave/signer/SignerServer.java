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
package tech.pegasys.web3signer.enclave.signer;

import tech.pegasys.web3signer.enclave.protocol.Connection;
import tech.pegasys.web3signer.enclave.protocol.EnclaveAddress;
import tech.pegasys.web3signer.enclave.protocol.Listener;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.security.SecureRandom;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/** Accept loop of the enclave signer. One platform thread per connection, up to a maximum. */
public final class SignerServer implements AutoCloseable {
  public static final int DEFAULT_MAX_CONNECTIONS = 64;

  private final Listener listener;
  private final KeyTable keys;
  private final Blst blst;
  private final Attestor attestor;
  private final int platform;
  private final int maxConnections;
  private final String version;
  private final byte[] bootId = new byte[Protocol.BOOT_ID_SIZE];
  private final Set<Connection> active = ConcurrentHashMap.newKeySet();
  private final AtomicLong accepted = new AtomicLong();
  private final AtomicLong refused = new AtomicLong();
  private volatile boolean closed;
  private Thread acceptThread;

  public SignerServer(
      final Listener listener,
      final Blst blst,
      final Attestor attestor,
      final int platform,
      final int maxConnections,
      final String version) {
    this.listener = listener;
    this.keys = new KeyTable();
    this.blst = blst;
    this.attestor = attestor;
    this.platform = platform;
    this.maxConnections = maxConnections;
    this.version = version;
    new SecureRandom().nextBytes(bootId);
  }

  public synchronized void start() {
    if (acceptThread == null) {
      acceptThread = Thread.ofPlatform().name("enclave-signer-accept").start(this::acceptLoop);
    }
  }

  public EnclaveAddress address() {
    return listener.address();
  }

  /** Blocks until the server is closed. */
  public void awaitTermination() throws InterruptedException {
    acceptThread.join();
  }

  private void acceptLoop() {
    while (!closed) {
      final Connection connection;
      try {
        connection = listener.accept();
      } catch (final IOException e) {
        if (!closed) {
          Log.error("accept failed", e);
        }
        continue;
      }
      if (active.size() >= maxConnections) {
        refused.incrementAndGet();
        Log.warn("refused connection: " + maxConnections + " connections open");
        connection.close();
        continue;
      }
      active.add(connection);
      final long number = accepted.incrementAndGet();
      Thread.ofPlatform()
          .name("enclave-signer-connection-" + number)
          .daemon(true)
          .start(() -> serve(connection));
    }
  }

  private void serve(final Connection connection) {
    try (Arena arena = Arena.ofConfined()) {
      new ConnectionHandler(connection, this, arena).run();
    } catch (final IOException e) {
      if (!closed) {
        Log.error("connection ended", e);
      }
    } catch (final RuntimeException | Error e) {
      Log.error("connection failed", e);
    } finally {
      active.remove(connection);
      connection.close();
    }
  }

  KeyTable keys() {
    return keys;
  }

  Blst blst() {
    return blst;
  }

  Attestor attestor() {
    return attestor;
  }

  int platform() {
    return platform;
  }

  String version() {
    return version;
  }

  byte[] bootId() {
    return bootId;
  }

  public int keyCount() {
    return keys.size();
  }

  public int activeConnections() {
    return active.size();
  }

  @Override
  public void close() {
    closed = true;
    listener.close();
    for (final Connection connection : active) {
      connection.close();
    }
  }
}
