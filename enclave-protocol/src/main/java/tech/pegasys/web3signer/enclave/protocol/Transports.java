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

/** Opens connections and listeners for an {@link EnclaveAddress}. */
public final class Transports {
  private Transports() {}

  /**
   * Connects to an enclave signer.
   *
   * @param timeoutMillis connect, read and write timeout; 0 waits forever
   */
  public static Connection connect(final EnclaveAddress address, final int timeoutMillis)
      throws IOException {
    return switch (address.kind()) {
      case TCP -> TcpConnection.connect(address.host(), (int) address.port(), timeoutMillis);
      case VSOCK ->
          VsockConnection.connect((int) address.cid(), (int) address.port(), timeoutMillis);
    };
  }

  public static Listener listen(final EnclaveAddress address) throws IOException {
    return switch (address.kind()) {
      case TCP -> TcpListener.bind(address.host(), (int) address.port());
      case VSOCK -> VsockListener.bind((int) address.port());
    };
  }
}
