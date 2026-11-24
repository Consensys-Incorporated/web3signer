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
import java.security.SecureRandom;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Loads a bundle into a running enclave signer: get the enclave's evidence, have the broker release
 * the data key to the release key the evidence binds, unwrap it there, load the sealed keys.
 * Additive; never retried once the enclave answers.
 */
public final class KeyProvisioner {
  private static final long RETRY_MILLIS = 1000;

  private static final SecureRandom RANDOM = new SecureRandom();

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

  public static Result provision(
      final KeyBundle bundle,
      final KeyReleaseBroker broker,
      final EnclaveClient client,
      final Options options) {
    if (bundle.keys().isEmpty()) {
      throw new EnclaveHostException("The key bundle contains no keys; nothing to provision");
    }
    if (!broker.provider().equals(bundle.dek().provider())) {
      throw new EnclaveHostException(
          "The bundle was sealed with provider "
              + bundle.dek().provider()
              + ", but the "
              + broker.provider()
              + " broker was given");
    }
    try (ProvisioningSession session =
        connect(client, options.waitSeconds(), options.responseTimeout())) {
      final Status status = session.status();
      if (status.platform() != broker.expectedPlatform()) {
        throw new EnclaveHostException(
            "The "
                + broker.provider()
                + " broker releases data keys only to an enclave on platform "
                + Protocol.platformName(broker.expectedPlatform())
                + ", but the enclave runs "
                + status.platformName());
      }
      if (options.verifyKeyPolicy()) {
        broker.assertEvidenceRequired(bundle.dek());
      }

      final byte[] nonce = new byte[32];
      RANDOM.nextBytes(nonce);
      final Evidence evidence = session.getEvidence(nonce);
      if (evidence.type() != broker.expectedEvidenceType()) {
        throw new EnclaveHostException(
            "The "
                + broker.provider()
                + " broker accepts evidence type "
                + broker.expectedEvidenceType()
                + ", but the enclave produced type "
                + evidence.type());
      }
      final byte[] blob = broker.release(bundle.dek(), evidence);
      if (options.dumpReleaseBlob() != null) {
        Files.write(options.dumpReleaseBlob(), blob);
      }
      session.unwrapDek(Protocol.BLOB_FORMAT_CMS, blob);

      final LoadResult load = session.loadKeys(bundle.keys());
      final long enclaveKeys = session.status().keyCount();
      final int expected = bundle.keys().size();
      if (load.rejected() == expected) {
        throw new EnclaveHostException(
            "The enclave rejected every entry: the data key does not match this bundle ("
                + summary(load, expected)
                + ")");
      }
      if (load.rejected() > 0 || load.loaded() + load.duplicates() != expected) {
        throw new EnclaveHostException("Provisioning incomplete: " + summary(load, expected));
      }
      return new Result(load, expected, enclaveKeys);
    } catch (final PartialLoadException e) {
      throw new EnclaveHostException("Provisioning incomplete: " + e.getMessage(), e);
    } catch (final EnclaveException e) {
      throw new EnclaveHostException(e.getMessage(), e);
    } catch (final EnclaveUnavailableException e) {
      throw new EnclaveHostException("Enclave connection failed: " + e.getMessage(), e);
    } catch (final IOException e) {
      throw new EnclaveHostException("Cannot write " + options.dumpReleaseBlob(), e);
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
  private static ProvisioningSession connect(
      final EnclaveClient client, final int waitSeconds, final Duration responseTimeout) {
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(waitSeconds);
    while (true) {
      ProvisioningSession session = null;
      try {
        session = client.openProvisioningSession(responseTimeout);
        session.status();
        return session;
      } catch (final EnclaveUnavailableException e) {
        closeQuietly(session, e);
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
      } catch (final RuntimeException e) {
        closeQuietly(session, e);
        throw e;
      }
    }
  }

  private static void closeQuietly(final ProvisioningSession session, final Exception cause) {
    if (session == null) {
      return;
    }
    try {
      session.close();
    } catch (final RuntimeException closeFailure) {
      cause.addSuppressed(closeFailure);
    }
  }
}
