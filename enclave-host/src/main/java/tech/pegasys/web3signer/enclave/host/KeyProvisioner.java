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
package tech.pegasys.web3signer.enclave.host;

import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.client.EnclaveException;
import tech.pegasys.web3signer.enclave.client.EnclaveUnavailableException;
import tech.pegasys.web3signer.enclave.client.PartialLoadException;
import tech.pegasys.web3signer.enclave.client.ProvisioningSession;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Messages.Status;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Loads a bundle into a running enclave signer: get the enclave's evidence, have the broker release
 * the data key to the release key the evidence binds, unwrap it there, load the sealed keys.
 * Additive; never retried once the enclave answers.
 */
public final class KeyProvisioner {
  private static final long RETRY_MILLIS = 1000;

  /**
   * No nonce: KMS doesn't check one, and each GET_EVIDENCE binds a new release key, so an old
   * attestation document is of no use to anyone.
   */
  private static final byte[] NO_NONCE = new byte[0];

  private KeyProvisioner() {}

  /**
   * Provisioning options.
   *
   * @param waitSeconds how long to retry while the enclave is not reachable
   * @param responseTimeout how long each provisioning response may take
   * @param verifyKeyPolicy run the negative key policy check first
   * @param dumpReleaseBlob file for the release blob, for parser debugging; null for none
   */
  public record Options(
      int waitSeconds, Duration responseTimeout, boolean verifyKeyPolicy, Path dumpReleaseBlob) {}

  /**
   * Outcome of provisioning.
   *
   * @param load the counters added up over all LOAD_KEYS calls
   * @param bundleKeys number of keys in the bundle
   * @param enclaveKeyCount keys held by the enclave afterwards
   */
  public record Result(LoadResult load, int bundleKeys, long enclaveKeyCount) {}

  /** A provisioning session and the status the enclave answered with when it was opened. */
  private record Connected(ProvisioningSession session, Status status) implements AutoCloseable {
    @Override
    public void close() {
      session.close();
    }
  }

  public static Result provision(
      final KeyBundle bundle,
      final KeyReleaseBroker broker,
      final EnclaveClient client,
      final Options options) {
    checkBundle(bundle, broker);
    try (Connected connected = connect(client, options.waitSeconds(), options.responseTimeout())) {
      final ProvisioningSession session = connected.session();
      checkPlatform(connected.status(), broker);
      if (options.verifyKeyPolicy()) {
        broker.assertEvidenceRequired(bundle.dek());
      }
      final Evidence evidence = session.getEvidence(NO_NONCE);
      checkEvidenceType(evidence, broker);
      final byte[] blob = broker.release(bundle.dek(), evidence);
      dumpReleaseBlob(options.dumpReleaseBlob(), blob);
      session.unwrapDek(Protocol.BLOB_FORMAT_CMS, blob);
      final LoadResult load = session.loadKeys(bundle.keys());
      checkLoad(load, bundle.keys().size());
      return new Result(load, bundle.keys().size(), session.status().keyCount());
    } catch (final PartialLoadException e) {
      throw new EnclaveHostException("Provisioning incomplete: " + e.getMessage(), e);
    } catch (final EnclaveException e) {
      throw new EnclaveHostException(e.getMessage(), e);
    } catch (final EnclaveUnavailableException e) {
      throw new EnclaveHostException("Enclave connection failed: " + e.getMessage(), e);
    }
  }

  private static void checkBundle(final KeyBundle bundle, final KeyReleaseBroker broker) {
    if (bundle.keys().isEmpty()) {
      throw new EnclaveHostException("The key bundle contains no keys; nothing to provision");
    }
    if (!broker.provider().equals(bundle.dek().provider())) {
      throw new EnclaveHostException(
          String.format(
              "The bundle was sealed with provider %s, but the %s broker was given",
              bundle.dek().provider(), broker.provider()));
    }
  }

  private static void checkPlatform(final Status status, final KeyReleaseBroker broker) {
    if (status.platform() != broker.expectedPlatform()) {
      throw new EnclaveHostException(
          String.format(
              "The %s broker releases data keys only to an enclave on platform %s, but the enclave"
                  + " runs %s",
              broker.provider(),
              Protocol.platformName(broker.expectedPlatform()),
              status.platformName()));
    }
  }

  private static void checkEvidenceType(final Evidence evidence, final KeyReleaseBroker broker) {
    if (evidence.type() != broker.expectedEvidenceType()) {
      throw new EnclaveHostException(
          String.format(
              "The %s broker accepts evidence type %d, but the enclave produced type %d",
              broker.provider(), broker.expectedEvidenceType(), evidence.type()));
    }
  }

  private static void checkLoad(final LoadResult load, final int expected) {
    if (load.rejected() == expected) {
      throw new EnclaveHostException(
          "The enclave rejected every entry: the data key does not match this bundle ("
              + summary(load, expected)
              + ")");
    }
    if (load.rejected() > 0 || load.loaded() + load.duplicates() != expected) {
      throw new EnclaveHostException("Provisioning incomplete: " + summary(load, expected));
    }
  }

  private static void dumpReleaseBlob(final Path file, final byte[] blob) {
    if (file == null) {
      return;
    }
    try {
      Files.write(file, blob);
    } catch (final IOException e) {
      throw new EnclaveHostException("Cannot write " + file, e);
    }
  }

  static String summary(final LoadResult load, final int expected) {
    return load.loaded()
        + " loaded, "
        + load.duplicates()
        + " duplicates, "
        + load.rejected()
        + " rejected of "
        + expected;
  }

  /** Opens a provisioning session, retrying until the enclave answers or the wait expires. */
  private static Connected connect(
      final EnclaveClient client, final int waitSeconds, final Duration responseTimeout) {
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(waitSeconds);
    while (true) {
      try {
        return open(client, responseTimeout);
      } catch (final EnclaveUnavailableException e) {
        final long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
          throw e;
        }
        try {
          TimeUnit.NANOSECONDS.sleep(
              Math.min(remaining, TimeUnit.MILLISECONDS.toNanos(RETRY_MILLIS)));
        } catch (final InterruptedException ie) {
          Thread.currentThread().interrupt();
          throw new EnclaveHostException("Interrupted while waiting for the enclave", ie);
        }
      }
    }
  }

  /** Opens a session and asks for its status; closes the session if that fails. */
  private static Connected open(final EnclaveClient client, final Duration responseTimeout) {
    final ProvisioningSession session = client.openProvisioningSession(responseTimeout);
    try {
      return new Connected(session, session.status());
    } catch (final RuntimeException e) {
      session.close();
      throw e;
    }
  }
}
