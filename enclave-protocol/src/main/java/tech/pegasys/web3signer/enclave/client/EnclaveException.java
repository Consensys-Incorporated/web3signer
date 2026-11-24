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

import tech.pegasys.web3signer.enclave.protocol.Protocol;

/**
 * The enclave signer refused a request: it answered with a result other than {@link Protocol#OK}.
 */
public class EnclaveException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final int result;
  private final String detail;

  /**
   * @param result the result code of the response
   * @param operation what was refused, for the message
   * @param detail the enclave's error message, printable ASCII, possibly empty
   */
  public EnclaveException(final int result, final String operation, final String detail) {
    super(
        "Enclave signer refused "
            + operation
            + ": "
            + Protocol.resultName(result)
            + (detail.isEmpty() ? "" : " (" + detail + ")"));
    this.result = result;
    this.detail = detail;
  }

  /** The result code of the response, one of the codes in {@link Protocol}. */
  public int result() {
    return result;
  }

  /** The enclave's error message, printable ASCII, possibly empty. */
  public String detail() {
    return detail;
  }
}
