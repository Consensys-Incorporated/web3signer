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
package tech.pegasys.web3signer.signing;

/**
 * A signer could not produce a signature because the service holding its key is unreachable or
 * cannot use the key right now, for example a stopped enclave signer. The condition is expected to
 * clear once that service is back. The message is meant for the API client and the log, and already
 * includes the cause's message.
 */
public class SignerUnavailableException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  public SignerUnavailableException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
