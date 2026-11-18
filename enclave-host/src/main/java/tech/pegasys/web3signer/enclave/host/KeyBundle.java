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

import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.util.List;
import java.util.Map;

/**
 * A sealed key bundle: BLS secrets encrypted under one data key, and the data key wrapped by a key
 * release provider. Holds no plaintext secret.
 *
 * @param version bundle format version, {@link #VERSION}
 * @param dek the wrapped data key
 * @param keys the sealed keys
 */
public record KeyBundle(int version, Dek dek, List<SealedKey> keys) {
  public static final int VERSION = 1;

  public KeyBundle {
    keys = List.copyOf(keys);
  }

  /**
   * The wrapped data key.
   *
   * @param provider {@link #PROVIDER_AWS_KMS} or {@link #PROVIDER_DEV}
   * @param keyId the KMS key ARN, or {@code dev}
   * @param encryptionContext KMS encryption context; empty for dev
   * @param wrapped the wrapped data key
   */
  @SuppressWarnings("ArrayRecordComponent")
  public record Dek(
      String provider, String keyId, Map<String, String> encryptionContext, byte[] wrapped) {
    public static final String PROVIDER_AWS_KMS = "aws-kms";
    public static final String PROVIDER_DEV = "dev";

    public Dek {
      encryptionContext = Map.copyOf(encryptionContext);
      wrapped = wrapped.clone();
    }
  }
}
