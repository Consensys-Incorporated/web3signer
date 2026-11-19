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

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.time.Duration;

import org.junit.jupiter.api.Test;

class TcpConnectionTest {

  @Test
  void writeToAPeerThatNeverReadsTimesOut() throws Exception {
    try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        TcpConnection connection =
            TcpConnection.connect(
                server.getInetAddress().getHostAddress(), server.getLocalPort(), 300);
        Socket stalled = server.accept()) {
      final byte[] chunk = new byte[1 << 20];
      assertTimeoutPreemptively(
          Duration.ofSeconds(10),
          () ->
              assertThatThrownBy(
                      () -> {
                        // fills both socket buffers, then blocks: the peer never reads
                        while (true) {
                          connection.write(chunk, 0, chunk.length);
                        }
                      })
                  .isInstanceOf(SocketTimeoutException.class));
    }
  }
}
