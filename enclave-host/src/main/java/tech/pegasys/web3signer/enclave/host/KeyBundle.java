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

import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A sealed key bundle: BLS secrets encrypted under one data key, and the data key wrapped by a key
 * release provider. Holds no plaintext secret. Anything that can be built can be written and read
 * back by {@link KeyBundleFile}.
 *
 * @param dek the wrapped data key
 * @param keys the sealed keys
 */
public record KeyBundle(Dek dek, List<SealedKey> keys) {

  public KeyBundle {
    Objects.requireNonNull(dek, "dek");
    keys = List.copyOf(keys);
    final Set<String> pubKeys = new HashSet<>();
    for (final SealedKey key : keys) {
      final String pubKey = HexFormat.of().formatHex(key.pubKey());
      if (!pubKeys.add(pubKey)) {
        throw new IllegalArgumentException(
            "Key bundle holds public key 0x" + pubKey + " more than once");
      }
    }
  }

  /**
   * The wrapped data key.
   *
   * @param provider {@link #PROVIDER_AWS_KMS} or {@link #PROVIDER_DEV}
   * @param keyId the KMS key ARN, or {@code dev}
   * @param encryptionContext KMS encryption context; empty for dev
   * @param wrapped the wrapped data key; copied in and out
   */
  @SuppressWarnings("ArrayRecordComponent")
  public record Dek(
      String provider, String keyId, Map<String, String> encryptionContext, byte[] wrapped) {
    public static final String PROVIDER_AWS_KMS = "aws-kms";
    public static final String PROVIDER_DEV = "dev";

    public Dek {
      Objects.requireNonNull(provider, "provider");
      Objects.requireNonNull(keyId, "keyId");
      if (!provider.equals(PROVIDER_AWS_KMS) && !provider.equals(PROVIDER_DEV)) {
        throw new IllegalArgumentException("Unknown key bundle provider: " + provider);
      }
      if (wrapped.length == 0) {
        throw new IllegalArgumentException("The wrapped data key is empty");
      }
      encryptionContext = Map.copyOf(encryptionContext);
      wrapped = wrapped.clone();
    }

    @Override
    public byte[] wrapped() {
      return wrapped.clone();
    }

    // by content: the record default compares the array by identity
    @Override
    public boolean equals(final Object other) {
      return other instanceof Dek that
          && provider.equals(that.provider)
          && keyId.equals(that.keyId)
          && encryptionContext.equals(that.encryptionContext)
          && Arrays.equals(wrapped, that.wrapped);
    }

    @Override
    public int hashCode() {
      return Objects.hash(provider, keyId, encryptionContext, Arrays.hashCode(wrapped));
    }
  }
}
