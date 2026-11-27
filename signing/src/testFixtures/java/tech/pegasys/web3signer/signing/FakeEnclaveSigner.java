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
package tech.pegasys.web3signer.signing;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.enclave.protocol.Frames;
import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages;
import tech.pegasys.web3signer.enclave.protocol.Messages.PublicKeysRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.SignRequest;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.Connection;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;
import tech.pegasys.web3signer.enclave.transport.Listener;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.IntStream;

import org.apache.tuweni.bytes.Bytes;

/**
 * An enclave signer on {@code tcp:127.0.0.1:<free port>} that answers {@code STATUS}, {@code
 * GET_PUBLIC_KEYS} and {@code SIGN} with Teku BLS. Keys are added with {@link #load}, without
 * provisioning. Not initialized until the first load, like a signer that has just started.
 */
public final class FakeEnclaveSigner implements AutoCloseable {
  private static final SecureRandom RANDOM = new SecureRandom();

  private final Listener listener;
  private final Thread acceptThread;
  private final Set<Connection> connections = ConcurrentHashMap.newKeySet();
  private final Set<Thread> serveThreads = ConcurrentHashMap.newKeySet();
  private final List<BLSKeyPair> keys = new CopyOnWriteArrayList<>();
  private final Map<Bytes, BLSKeyPair> byPublicKey = new ConcurrentHashMap<>();
  private volatile byte[] bootId = newBootId();
  private volatile boolean initialized;
  private volatile int signRefusal = Protocol.OK;

  public FakeEnclaveSigner() {
    try {
      listener = EnclaveAddress.tcp("127.0.0.1", 0).listen();
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
    acceptThread = Thread.ofPlatform().daemon(true).start(this::acceptLoop);
  }

  private static byte[] newBootId() {
    final byte[] id = new byte[16];
    RANDOM.nextBytes(id);
    return id;
  }

  public static List<BLSKeyPair> randomKeys(final int count) {
    return IntStream.range(0, count).mapToObj(i -> BLSKeyPair.random(RANDOM)).toList();
  }

  public EnclaveAddress address() {
    return listener.address();
  }

  /** The boot id answered to {@code STATUS}, as hex. */
  public String bootId() {
    return HexFormat.of().formatHex(bootId);
  }

  /** Answers every later {@code SIGN} with {@code result}, or signs again for {@code OK}. */
  public void refuseSigning(final int result) {
    signRefusal = result;
  }

  /** Adds keys, as a successful {@code LOAD_KEYS} would; an empty list initializes the signer. */
  public synchronized void load(final List<BLSKeyPair> newKeys) {
    for (final BLSKeyPair key : newKeys) {
      if (byPublicKey.putIfAbsent(key.getPublicKey().toBytesCompressed(), key) == null) {
        keys.add(key);
      }
    }
    initialized = true;
  }

  /**
   * Forgets every key, picks a new boot id and drops open connections, like a signer that restarted
   * on the same address and is not provisioned yet.
   */
  public synchronized void restart() {
    keys.clear();
    byPublicKey.clear();
    initialized = false;
    bootId = newBootId();
    connections.forEach(Connection::close);
  }

  private void acceptLoop() {
    while (true) {
      final Connection connection;
      try {
        connection = listener.accept();
      } catch (final IOException e) {
        return;
      }
      connections.add(connection);
      serveThreads.add(Thread.ofPlatform().daemon(true).start(() -> serve(connection)));
    }
  }

  private void serve(final Connection connection) {
    try (connection) {
      while (true) {
        final Frame request = Frames.readRequest(connection);
        final Frame response = answer(request);
        Frames.write(connection, response);
      }
    } catch (final IOException e) {
      // peer gone, or closed by close()
    } finally {
      connections.remove(connection);
    }
  }

  private Frame answer(final Frame request) throws IOException {
    return switch (request.kind()) {
      case Protocol.STATUS ->
          ok(request, Messages.encodeStatus(Protocol.PLATFORM_DEV, 1, keys.size(), bootId, "fake"));
      case Protocol.GET_PUBLIC_KEYS -> {
        if (!initialized) {
          yield error(request, Protocol.NOT_INITIALIZED, "no keys loaded");
        }
        final PublicKeysRequest page = Messages.decodePublicKeysRequest(request.body());
        final List<BLSKeyPair> snapshot = List.copyOf(keys);
        final int from = (int) Math.min(page.offset(), snapshot.size());
        final int to = Math.min(from + page.limit(), snapshot.size());
        yield ok(
            request,
            Messages.encodePublicKeys(
                snapshot.subList(from, to).stream()
                    .map(key -> key.getPublicKey().toBytesCompressed().toArray())
                    .toList()));
      }
      case Protocol.SIGN -> {
        if (signRefusal != Protocol.OK) {
          yield error(request, signRefusal, "refused by the fake");
        }
        if (!initialized) {
          yield error(request, Protocol.NOT_INITIALIZED, "no keys loaded");
        }
        final SignRequest sign = Messages.decodeSignRequest(request.body());
        final BLSKeyPair key = byPublicKey.get(Bytes.wrap(sign.pubKey()));
        if (key == null) {
          yield error(request, Protocol.RESOURCE_UNAVAILABLE, "no key");
        }
        final Bytes signature =
            BLS.sign(key.getSecretKey(), Bytes.wrap(sign.signingRoot())).toBytesCompressed();
        yield ok(request, Messages.encodeSignature(signature.toArray()));
      }
      default -> error(request, Protocol.UNSUPPORTED, "not supported by the fake");
    };
  }

  private static Frame ok(final Frame request, final byte[] body) {
    return new Frame(request.requestId(), Protocol.OK, body);
  }

  private static Frame error(final Frame request, final int result, final String message) {
    return new Frame(request.requestId(), result, Messages.encodeErrorMessage(message));
  }

  /** Stops listening and drops every open connection, like a stopped enclave. */
  @Override
  public void close() {
    listener.close();
    // on Linux a socket is only closed once the thread blocked on it wakes, so wait for them
    join(acceptThread);
    connections.forEach(Connection::close);
    serveThreads.forEach(this::join);
  }

  private void join(final Thread thread) {
    try {
      thread.join(Duration.ofSeconds(5));
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
