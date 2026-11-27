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

import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.client.EnclaveException;
import tech.pegasys.web3signer.enclave.client.EnclaveUnavailableException;
import tech.pegasys.web3signer.enclave.protocol.Messages.Status;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.EnclaveBlsArtifactSigner;
import tech.pegasys.web3signer.signing.SignerUnavailableException;
import tech.pegasys.web3signer.signing.config.EnclaveSignerParameters;

import java.io.Closeable;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import com.google.common.base.Throwables;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Loads one signer per key held by an enclave signer. Owns the {@link EnclaveClient} that every
 * returned signer shares, closed by {@link #close()}. Also answers {@link #status()} for the health
 * check, through a second client with a short timeout so that a hung enclave signer cannot hold the
 * check for long.
 *
 * <p>A failed {@link #load()} returns the signers of the last successful one, with an error, so
 * that a reload during an enclave signer outage keeps its keys known: signing them fails as
 * unavailable rather than as unknown keys.
 */
public class BlsEnclaveBulkLoader implements Closeable {
  private static final Logger LOG = LogManager.getLogger();
  private static final long STATUS_TIMEOUT_MILLIS = 500;

  /**
   * Answer of the enclave signer to {@code STATUS}.
   *
   * @param keyCount number of keys the enclave signer holds
   * @param bootId random id the enclave signer chose at start, as hex
   */
  public record EnclaveSignerStatus(long keyCount, String bootId) {}

  private final EnclaveSignerParameters parameters;
  private final EnclaveClient client;
  private final EnclaveClient statusClient;
  private volatile List<ArtifactSigner> lastLoaded = List.of();

  /**
   * Creates the clients without connecting; connections are opened on demand.
   *
   * @throws IllegalArgumentException when the enclave signer address is invalid
   */
  public BlsEnclaveBulkLoader(final EnclaveSignerParameters parameters) {
    this.parameters = parameters;
    final EnclaveAddress address = EnclaveAddress.parseConnect(parameters.getAddress());
    client =
        EnclaveClient.create(
            address,
            new EnclaveClient.Options(
                parameters.getConnections(),
                Duration.ofMillis(parameters.getRequestTimeoutMillis())));
    // a client of its own with a short timeout, so that status() never waits behind signing
    statusClient =
        EnclaveClient.create(
            address,
            new EnclaveClient.Options(
                1,
                Duration.ofMillis(
                    Math.min(STATUS_TIMEOUT_MILLIS, parameters.getRequestTimeoutMillis()))));
  }

  /**
   * Asks the enclave signer for its status. The wait for the connection, and connect, write and
   * read each, are bounded by {@value #STATUS_TIMEOUT_MILLIS} ms (or the configured request
   * timeout, if shorter); a stale connection is replaced once.
   *
   * @throws SignerUnavailableException on any failure, for example when the enclave signer does not
   *     answer, speaks another protocol version, or this loader is closed
   */
  public EnclaveSignerStatus status() {
    try {
      final Status status = statusClient.status();
      return new EnclaveSignerStatus(status.keyCount(), status.bootId());
    } catch (final RuntimeException e) {
      throw new SignerUnavailableException(e);
    }
  }

  public MappedResults<ArtifactSigner> load() {
    try {
      final List<ArtifactSigner> signers = new ArrayList<>();
      for (final byte[] publicKey : client.publicKeys()) {
        signers.add(new EnclaveBlsArtifactSigner(client, publicKey));
      }
      LOG.info("Enclave signer at {}: {} keys", parameters.getAddress(), signers.size());
      lastLoaded = List.copyOf(signers);
      return MappedResults.newInstance(signers, 0);
    } catch (final RuntimeException e) {
      if (isOutage(e)) {
        LOG.warn("Unable to load keys from the enclave signer: {}", reason(e));
      } else {
        LOG.error("Unable to load keys from the enclave signer", e);
      }
      return failedLoad();
    }
  }

  /** An enclave signer that is down or not yet provisioned, which needs no stack trace. */
  private boolean isOutage(final RuntimeException e) {
    return e instanceof EnclaveUnavailableException
        || (e instanceof EnclaveException refused && refused.result() == Protocol.NOT_INITIALIZED);
  }

  /** The message, with the root cause's (such as "Connection refused") when there is one. */
  private String reason(final RuntimeException e) {
    if (e.getCause() == null) {
      return e.getMessage();
    }
    final String rootMessage = Throwables.getRootCause(e).getMessage();
    return rootMessage == null ? e.getMessage() : e.getMessage() + ": " + rootMessage;
  }

  private MappedResults<ArtifactSigner> failedLoad() {
    final List<ArtifactSigner> previous = lastLoaded;
    if (!previous.isEmpty()) {
      LOG.warn("Keeping {} enclave signer keys from the last successful load", previous.size());
    }
    return MappedResults.newInstance(new ArrayList<>(previous), 1);
  }

  @Override
  public void close() {
    client.close();
    statusClient.close();
  }
}
