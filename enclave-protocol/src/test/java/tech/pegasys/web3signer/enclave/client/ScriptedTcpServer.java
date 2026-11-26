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
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.Connection;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;
import tech.pegasys.web3signer.enclave.transport.Listener;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/** A TCP server on the loopback address that runs a script on each connection. For client tests. */
final class ScriptedTcpServer implements AutoCloseable {

  @FunctionalInterface
  interface Script {
    /**
     * Serves one connection.
     *
     * @param server this server, to record what the script reads
     * @param index 0 for the first connection, 1 for the second, ...
     */
    void serve(ScriptedTcpServer server, Connection connection, int index) throws IOException;
  }

  private final Listener listener;
  private final AtomicInteger connections = new AtomicInteger();
  final List<Frame> received = new CopyOnWriteArrayList<>();

  ScriptedTcpServer(final Script script) throws IOException {
    listener = EnclaveAddress.tcp("127.0.0.1", 0).listen();
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
                            script.serve(this, connection, index);
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
    final Frame frame = Frames.readRequest(connection);
    received.add(frame);
    return frame;
  }

  static void respond(
      final Connection connection, final Frame request, final int result, final byte[] body)
      throws IOException {
    Frames.write(connection, new Frame(request.requestId(), result, body));
  }

  /** A fake signature: the signing root repeated to 96 bytes, so each caller can check it. */
  static byte[] fakeSignature(final byte[] signingRoot) {
    final byte[] signature = new byte[Protocol.SIGNATURE_SIZE];
    for (int i = 0; i < signature.length; i++) {
      signature[i] = signingRoot[i % signingRoot.length];
    }
    return signature;
  }

  static void respondToSign(final Connection connection, final Frame request) throws IOException {
    final byte[] signingRoot = Messages.decodeSignRequest(request.body()).signingRoot();
    respond(connection, request, Protocol.OK, Messages.encodeSignature(fakeSignature(signingRoot)));
  }

  static byte[] status(final int cpus) {
    return status(cpus, 0);
  }

  static byte[] status(final int cpus, final long keyCount) {
    return Messages.encodeStatus(Protocol.PLATFORM_DEV, cpus, keyCount, new byte[16], "test");
  }

  @Override
  public void close() {
    listener.close();
  }
}
