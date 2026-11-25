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

import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;

import java.util.Arrays;

/**
 * Creates data keys and releases them to an enclave whose evidence the provider accepts. One
 * implementation per key release provider; the enclave only ever sees the release blob (format 1,
 * CMS EnvelopedData).
 */
public interface KeyReleaseBroker extends AutoCloseable {

  /**
   * A new data key: the plaintext for sealing, and its wrapped form for the bundle. The plaintext
   * is not copied, so that {@link #close()} zeroes the array the sealer used.
   */
  @SuppressWarnings("ArrayRecordComponent")
  record DataKey(byte[] plaintext, KeyBundle.Dek dek) implements AutoCloseable {

    /** Overwrites the plaintext data key with zeros. */
    @Override
    public void close() {
      Arrays.fill(plaintext, (byte) 0);
    }
  }

  /** The bundle {@code provider} this broker wraps and releases data keys for. */
  String provider();

  /** The {@code platform} the enclave must report for this provider. */
  int expectedPlatform();

  /** The evidence type this provider accepts, one of {@code Protocol.EVIDENCE_*}. */
  int expectedEvidenceType();

  DataKey newDataKey();

  /**
   * Asks the provider to release the data key to the release key that {@code evidence} binds.
   *
   * @return the release blob, format 1
   */
  byte[] release(KeyBundle.Dek dek, Evidence evidence);

  /** Fails when the caller could obtain the data key without presenting evidence. */
  void assertEvidenceRequired(KeyBundle.Dek dek);

  @Override
  void close();
}
