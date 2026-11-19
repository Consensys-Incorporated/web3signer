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

/** The enclave signer answered with a status other than {@link Protocol#OK}. */
public class EnclaveException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final int status;

  public EnclaveException(final int status, final String message) {
    super(message + ": " + Protocol.statusName(status));
    this.status = status;
  }

  /** The status code of the response, one of the codes in {@link Protocol}. */
  public int status() {
    return status;
  }
}
