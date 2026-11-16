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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;

/** {@link Listener} on a TCP server socket. For development and tests. */
public final class TcpListener implements Listener {
  private final ServerSocket serverSocket;
  private final EnclaveAddress address;

  private TcpListener(final ServerSocket serverSocket, final String host) {
    this.serverSocket = serverSocket;
    this.address = EnclaveAddress.tcp(host, serverSocket.getLocalPort());
  }

  public static TcpListener bind(final String host, final int port) throws IOException {
    final ServerSocket serverSocket = new ServerSocket();
    try {
      serverSocket.setReuseAddress(true);
      serverSocket.bind(new InetSocketAddress(host, port), 128);
      return new TcpListener(serverSocket, host);
    } catch (final IOException | RuntimeException e) {
      serverSocket.close();
      throw e;
    }
  }

  @Override
  public Connection accept() throws IOException {
    final Socket socket = serverSocket.accept();
    try {
      return new TcpConnection(socket);
    } catch (final IOException | RuntimeException e) {
      socket.close();
      throw e;
    }
  }

  @Override
  public EnclaveAddress address() {
    return address;
  }

  @Override
  public void close() {
    try {
      serverSocket.close();
    } catch (final IOException e) {
      // nothing left to release
    }
  }
}
