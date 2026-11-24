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

import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;

import java.io.IOException;
import java.io.UncheckedIOException;

/** An enclave signer with the dev platform on {@code tcp:127.0.0.1:<free port>}, in this JVM. */
public final class InProcessEnclaveSigner implements AutoCloseable {
  private final SignerServer server;

  public InProcessEnclaveSigner() {
    this(SignerServer.DEFAULT_MAX_CONNECTIONS);
  }

  public InProcessEnclaveSigner(final int maxConnections) {
    try {
      server =
          new SignerServer(
              EnclaveAddress.parseListen("tcp:127.0.0.1:0").listen(),
              new Blst(BlstTestLibrary.path()),
              new DevEvidenceProvider(),
              Protocol.PLATFORM_DEV,
              maxConnections,
              "test");
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
    server.start();
  }

  public EnclaveAddress address() {
    return server.address();
  }

  public SignerServer server() {
    return server;
  }

  @Override
  public void close() {
    server.close();
  }
}
