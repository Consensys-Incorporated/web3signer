/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres.kek;

/**
 * Thrown when a tenant's DEK cannot be resolved. Messages must never include key material - callers
 * should log only the tenant identifier and this exception's class name/message, which by contract
 * never embed key bytes.
 */
public class KekResolutionException extends RuntimeException {

  public KekResolutionException(final String message) {
    super(message);
  }

  public KekResolutionException(final String message, final Throwable cause) {
    super(message, cause);
  }
}
