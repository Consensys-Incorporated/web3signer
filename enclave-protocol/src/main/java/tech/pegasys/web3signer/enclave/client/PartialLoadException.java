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

import tech.pegasys.web3signer.enclave.protocol.Messages.KeyLoadCounts;

/**
 * A {@code LOAD_KEYS} request failed after earlier requests of the same {@link
 * ProvisioningSession#loadKeys} call succeeded. The keys they loaded stay in the enclave.
 *
 * <p>The counts cover only the requests that succeeded. When the cause is an {@link
 * EnclaveUnavailableException}, the failed request may have loaded its keys too: the signer loads
 * them before it answers. Loading again is safe, since keys already held count as duplicates, and
 * {@code STATUS} reports how many keys the enclave holds.
 */
public final class PartialLoadException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final transient KeyLoadCounts loadedBefore;

  /**
   * @param loadedBefore the counts of the requests that succeeded
   * @param cause why the next request failed: an {@link EnclaveException} or an {@link
   *     EnclaveUnavailableException}
   */
  public PartialLoadException(final KeyLoadCounts loadedBefore, final RuntimeException cause) {
    super(
        "Loading keys failed after "
            + loadedBefore.loaded()
            + " loaded, "
            + loadedBefore.duplicates()
            + " duplicates and "
            + loadedBefore.rejected()
            + " rejected: "
            + cause.getMessage(),
        cause);
    this.loadedBefore = loadedBefore;
  }

  /** The counts of the requests that succeeded before the failure. */
  public KeyLoadCounts loadedBefore() {
    return loadedBefore;
  }
}
