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
package tech.pegasys.web3signer.signing.config;

/** Settings of the experimental enclave signer key source. */
public interface EnclaveSignerParameters {
  boolean isEnabled();

  /** {@code vsock:<cid>:<port>} or {@code tcp:<host>:<port>}. */
  String getAddress();

  /** Dispatcher connections; 0 means the enclave's vCPU count. */
  int getConnections();

  /** Largest number of {@code SIGN} requests sent in one write. */
  int getMaxBatch();

  int getRequestTimeoutMillis();
}
