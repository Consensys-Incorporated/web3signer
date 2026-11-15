/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.keystorage.hashicorp;

import java.util.EnumSet;
import java.util.Optional;

public enum TrustStoreType {
  JKS(true),
  PKCS12(true),
  /** Fingerprint allowlist; deprecated with Hashicorp metadata {@code tlsKnownServersPath}. */
  @Deprecated(forRemoval = true)
  WHITELIST(false),
  /** Fingerprint allowlist; deprecated with Hashicorp metadata {@code tlsKnownServersPath}. */
  @Deprecated(forRemoval = true)
  ALLOWLIST(false),
  PEM(false);

  private boolean passwordRequired;

  TrustStoreType(final boolean passwordRequired) {
    this.passwordRequired = passwordRequired;
  }

  public boolean isPasswordRequired() {
    return passwordRequired;
  }

  public static Optional<TrustStoreType> fromString(final String tsType) {
    return EnumSet.allOf(TrustStoreType.class).stream()
        .filter(t -> t.name().equals(tsType))
        .findAny();
  }
}
