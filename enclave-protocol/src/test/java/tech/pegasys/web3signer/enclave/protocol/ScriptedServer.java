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

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/** A TCP server whose behaviour per connection is a script. For client tests. */
final class ScriptedServer implements AutoCloseable {

  @FunctionalInterface
  interface Script {
    /**
     * Serves one connection.
     *
     * @param index 0 for the first connection, 1 for the second, ...
     */
    void serve(Connection connection, int index) throws IOException;
  }

  private final TcpListener listener;
  private final AtomicInteger connections = new AtomicInteger();
  final List<Frame> received = new CopyOnWriteArrayList<>();

  ScriptedServer(final Script script) throws IOException {
    listener = TcpListener.bind("127.0.0.1", 0);
    Thread.ofPlatform()
        .daemon(true)
        .start(
            () -> {
              while (true) {
                final Connection connection;
                try {
                  connection = listener.accept();
                } catch (final IOException e) {
                  return;
                }
                final int index = connections.getAndIncrement();
                Thread.ofPlatform()
                    .daemon(true)
                    .start(
                        () -> {
                          try (connection) {
                            script.serve(connection, index);
                          } catch (final IOException e) {
                            // peer gone
                          }
                        });
              }
            });
  }

  EnclaveAddress address() {
    return listener.address();
  }

  int connectionCount() {
    return connections.get();
  }

  /** Reads one request and records it. */
  Frame read(final Connection connection) throws IOException {
    final Frame frame = Frames.read(connection);
    received.add(frame);
    return frame;
  }

  static byte[] response(final Frame request, final byte[] payload) {
    return Frames.encode(request.type() | Protocol.RESPONSE_FLAG, request.requestId(), payload);
  }

  /** A fake signature: the message repeated to 96 bytes, so each caller can check its answer. */
  static byte[] fakeSignature(final byte[] message) {
    final byte[] signature = new byte[Protocol.SIGNATURE_SIZE];
    for (int i = 0; i < signature.length; i++) {
      signature[i] = message.length == 0 ? 0 : message[i % message.length];
    }
    return signature;
  }

  static byte[] signResponse(final Frame request) {
    final byte[] message = Arrays.copyOfRange(request.payload(), 50, request.payload().length);
    final byte[] payload = new byte[1 + Protocol.SIGNATURE_SIZE];
    System.arraycopy(fakeSignature(message), 0, payload, 1, Protocol.SIGNATURE_SIZE);
    return response(request, payload);
  }

  static byte[] statusResponse(final Frame request, final int cpus) {
    return response(
        request, Payloads.statusResponse(Protocol.PLATFORM_DEV, cpus, 0, new byte[16], "test"));
  }

  @Override
  public void close() {
    listener.close();
  }
}
