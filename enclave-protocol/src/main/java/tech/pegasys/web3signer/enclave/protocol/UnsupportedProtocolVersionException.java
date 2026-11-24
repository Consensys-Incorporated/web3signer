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

import java.io.IOException;

/** A {@code STATUS} answer from a signer that speaks another protocol version. */
public final class UnsupportedProtocolVersionException extends IOException {
  private static final long serialVersionUID = 1L;
  private final long version;

  public UnsupportedProtocolVersionException(final long version) {
    super("Signer speaks protocol version " + version + ", expected " + Protocol.VERSION);
    this.version = version;
  }

  /** The protocol version the signer reported. */
  public long version() {
    return version;
  }
}
