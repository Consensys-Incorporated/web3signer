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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.client.EnclaveException;
import tech.pegasys.web3signer.enclave.client.EnclaveUnavailableException;
import tech.pegasys.web3signer.enclave.host.EnclaveTestKeys;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.util.List;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class EnclaveBlsArtifactSignerTest {
  private final BLSKeyPair key = EnclaveTestKeys.randomKeys(1).get(0);
  private final byte[] publicKey = key.getPublicKey().toBytesCompressed().toArray();
  private final Bytes root = Bytes.random(32);

  @Test
  void signerIsUnavailableOnceTheEnclaveIsStopped() {
    final InProcessEnclaveSigner enclave = new InProcessEnclaveSigner();
    final EnclaveAddress address = enclave.address();
    EnclaveTestKeys.provision(address, List.of(key));
    try (EnclaveClient client = client(address, 2000)) {
      final EnclaveBlsArtifactSigner signer = new EnclaveBlsArtifactSigner(client, publicKey);
      assertThat(signer.sign(root).getSignatureData())
          .isEqualTo(BLS.sign(key.getSecretKey(), root));

      enclave.close();

      assertThatThrownBy(() -> signer.sign(root))
          .isInstanceOf(SignerUnavailableException.class)
          .hasMessageStartingWith("Signer unavailable: ")
          .hasCauseInstanceOf(EnclaveUnavailableException.class);
    }
  }

  @Test
  void signerIsUnavailableWhenTheEnclaveDoesNotAnswer() throws Exception {
    // accepts connections (backlog) but never reads or answers
    try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        EnclaveClient client =
            client(EnclaveAddress.parseConnect("tcp:127.0.0.1:" + silent.getLocalPort()), 200)) {
      final EnclaveBlsArtifactSigner signer = new EnclaveBlsArtifactSigner(client, publicKey);

      assertThatThrownBy(() -> signer.sign(root))
          .isInstanceOf(SignerUnavailableException.class)
          .hasMessageStartingWith("Signer unavailable: ")
          .hasCauseInstanceOf(EnclaveUnavailableException.class);
    }
  }

  @Test
  void signerIsUnavailableWhenTheEnclaveDoesNotHoldTheKey() {
    // e.g. an enclave signer restarted but not provisioned yet
    try (InProcessEnclaveSigner enclave = new InProcessEnclaveSigner();
        EnclaveClient client = client(enclave.address(), 2000)) {
      final EnclaveBlsArtifactSigner signer = new EnclaveBlsArtifactSigner(client, publicKey);

      assertThatThrownBy(() -> signer.sign(root))
          .isInstanceOf(SignerUnavailableException.class)
          .hasMessage(
              "Signer unavailable: Enclave signer refused SIGN: UNKNOWN_KEY"
                  + " (the enclave does not hold this key)")
          .hasCauseInstanceOf(EnclaveException.class);
    }
  }

  @Test
  void onlySigningRootsAreSigned() {
    try (InProcessEnclaveSigner enclave = new InProcessEnclaveSigner();
        EnclaveClient client = client(enclave.address(), 2000)) {
      final EnclaveBlsArtifactSigner signer = new EnclaveBlsArtifactSigner(client, publicKey);

      assertThatThrownBy(() -> signer.sign(Bytes.random(33)))
          .isInstanceOf(UnsupportedOperationException.class)
          .hasMessageContaining("32-byte signing roots only");
    }
  }

  private static EnclaveClient client(final EnclaveAddress address, final int timeoutMillis) {
    return EnclaveClient.create(address, new EnclaveClient.Options(1, timeoutMillis));
  }
}
