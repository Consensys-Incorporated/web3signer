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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.web3signer.enclave.protocol.EnclaveAddress;
import tech.pegasys.web3signer.enclave.protocol.EnclaveClient;
import tech.pegasys.web3signer.enclave.protocol.EnclaveStatus;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.EnclaveBlsArtifactSigner;
import tech.pegasys.web3signer.signing.config.EnclaveSignerParameters;

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Loads one signer per key held by an enclave signer. Owns the {@link EnclaveClient} that every
 * returned signer shares; it is created on the first {@link #load()} and closed by {@link
 * #close()}.
 */
public class BlsEnclaveBulkLoader implements Closeable {
  private static final Logger LOG = LogManager.getLogger();

  private final EnclaveSignerParameters parameters;
  private EnclaveClient client;
  private boolean closed;

  public BlsEnclaveBulkLoader(final EnclaveSignerParameters parameters) {
    this.parameters = parameters;
  }

  private synchronized EnclaveClient client() {
    if (closed) {
      throw new IllegalStateException("Enclave bulk loader is closed");
    }
    if (client == null) {
      client =
          EnclaveClient.create(
              EnclaveAddress.parseConnect(parameters.getAddress()),
              new EnclaveClient.Options(
                  parameters.getConnections(),
                  parameters.getMaxBatch(),
                  parameters.getRequestTimeoutMillis()));
    }
    return client;
  }

  public MappedResults<ArtifactSigner> load() {
    try {
      final EnclaveClient enclave = client();
      final EnclaveStatus status = enclave.status();
      if (status.protocolVersion() != Protocol.VERSION) {
        LOG.error(
            "Enclave signer at {} speaks protocol version {}, expected {}",
            enclave.target(),
            status.protocolVersion(),
            Protocol.VERSION);
        return MappedResults.errorResult();
      }
      final List<ArtifactSigner> signers = new ArrayList<>();
      for (final byte[] publicKey : enclave.publicKeys()) {
        signers.add(new EnclaveBlsArtifactSigner(enclave, publicKey));
      }
      LOG.info(
          "Enclave signer at {}: platform {}, version {}, {} keys",
          enclave.target(),
          status.platformName(),
          status.version(),
          signers.size());
      return MappedResults.newInstance(signers, 0);
    } catch (final RuntimeException e) {
      LOG.error("Unable to load keys from the enclave signer: {}", e.getMessage());
      return MappedResults.errorResult();
    }
  }

  @Override
  public synchronized void close() {
    closed = true;
    if (client != null) {
      client.close();
      client = null;
    }
  }
}
