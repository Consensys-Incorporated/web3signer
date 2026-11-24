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

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;

import java.security.SecureRandom;
import java.util.List;

/** Seals key pairs with the dev broker and provisions them into an enclave signer. */
public final class EnclaveTestKeys {
  private static final SecureRandom RANDOM = new SecureRandom();

  private EnclaveTestKeys() {}

  public static KeyProvisioner.Result provision(
      final EnclaveAddress address, final List<BLSKeyPair> keys) {
    final byte[] masterKey = new byte[32];
    RANDOM.nextBytes(masterKey);
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(masterKey);
        EnclaveClient client =
            EnclaveClient.create(address, new EnclaveClient.Options(1, 30_000))) {
      return KeyProvisioner.provision(
          KeySealer.seal(keys, broker),
          broker,
          client,
          new KeyProvisioner.Options(10, EnclaveClient.DEFAULT_PROVISIONING_TIMEOUT, true, null));
    }
  }

  public static List<BLSKeyPair> randomKeys(final int count) {
    return java.util.stream.IntStream.range(0, count)
        .mapToObj(i -> BLSKeyPair.random(RANDOM))
        .toList();
  }
}
