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
package tech.pegasys.web3signer.signing.bulkloading;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSignature;
import tech.pegasys.web3signer.signing.EnclaveBlsArtifactSigner;
import tech.pegasys.web3signer.signing.FakeEnclaveSigner;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.SignerUnavailableException;
import tech.pegasys.web3signer.signing.bulkloading.BlsEnclaveBulkLoader.EnclaveSignerStatus;
import tech.pegasys.web3signer.signing.config.EnclaveSignerParameters;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.Test;

class BlsEnclaveBulkLoaderTest {

  private record Parameters(String address) implements EnclaveSignerParameters {
    @Override
    public boolean isEnabled() {
      return true;
    }

    @Override
    public String getAddress() {
      return address;
    }

    @Override
    public int getConnections() {
      return 4;
    }

    @Override
    public int getRequestTimeoutMillis() {
      return 5000;
    }
  }

  @Test
  void loadsOneSignerPerEnclaveKeyAndSignsThroughTheEnclave() {
    final List<BLSKeyPair> keys = FakeEnclaveSigner.randomKeys(3);
    try (FakeEnclaveSigner enclave = new FakeEnclaveSigner();
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      enclave.load(keys);

      final MappedResults<ArtifactSigner> result = loader.load();
      assertThat(result.getErrorCount()).isZero();
      assertThat(result.getValues())
          .hasSize(3)
          .allMatch(EnclaveBlsArtifactSigner.class::isInstance);

      final Map<String, ArtifactSigner> byIdentifier =
          result.getValues().stream()
              .collect(Collectors.toMap(ArtifactSigner::getIdentifier, Function.identity()));
      final Bytes root = Bytes.random(32);
      for (final BLSKeyPair key : keys) {
        final ArtifactSigner signer = byIdentifier.get(key.getPublicKey().toString());
        assertThat(signer).isNotNull();
        assertThat(signer.getKeyType()).isEqualTo(KeyType.BLS);
        final BlsArtifactSignature signature = (BlsArtifactSignature) signer.sign(root);
        assertThat(signature.getSignatureData()).isEqualTo(BLS.sign(key.getSecretKey(), root));
        assertThat(signature.asHex())
            .isEqualTo(BLS.sign(key.getSecretKey(), root).toBytesCompressed().toHexString());
      }

      // a reload sees keys added since, through the same client
      enclave.load(FakeEnclaveSigner.randomKeys(2));
      assertThat(loader.load().getValues()).hasSize(5);
    }
  }

  @Test
  void keepsTheLastLoadedSignersWithAnErrorWhenTheEnclaveStopsAnswering() {
    final FakeEnclaveSigner enclave = new FakeEnclaveSigner();
    try (BlsEnclaveBulkLoader loader =
        new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      enclave.load(FakeEnclaveSigner.randomKeys(2));
      final MappedResults<ArtifactSigner> loaded = loader.load();
      assertThat(loaded.getErrorCount()).isZero();
      assertThat(loaded.getValues()).hasSize(2);

      enclave.close();

      final MappedResults<ArtifactSigner> reloaded = loader.load();
      assertThat(reloaded.getErrorCount()).isEqualTo(1);
      assertThat(reloaded.getValues()).containsExactlyElementsOf(loaded.getValues());
    } finally {
      enclave.close();
    }
  }

  @Test
  void replacesTheKeptSignersOnceARestartedEnclaveIsProvisionedAgain() {
    try (FakeEnclaveSigner enclave = new FakeEnclaveSigner();
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      enclave.load(FakeEnclaveSigner.randomKeys(2));
      final MappedResults<ArtifactSigner> loaded = loader.load();
      assertThat(loaded.getErrorCount()).isZero();

      enclave.restart();

      final MappedResults<ArtifactSigner> unprovisioned = loader.load();
      assertThat(unprovisioned.getErrorCount()).isEqualTo(1);
      assertThat(unprovisioned.getValues()).containsExactlyElementsOf(loaded.getValues());
      assertThatThrownBy(() -> loaded.getValues().iterator().next().sign(Bytes.random(32)))
          .isInstanceOf(SignerUnavailableException.class);

      final List<BLSKeyPair> newKeys = FakeEnclaveSigner.randomKeys(3);
      enclave.load(newKeys);

      final MappedResults<ArtifactSigner> reprovisioned = loader.load();
      assertThat(reprovisioned.getErrorCount()).isZero();
      assertThat(reprovisioned.getValues())
          .extracting(ArtifactSigner::getIdentifier)
          .containsExactlyInAnyOrderElementsOf(
              newKeys.stream().map(key -> key.getPublicKey().toString()).toList());

      // a later outage keeps the new signers, not the first ones
      enclave.restart();
      assertThat(loader.load().getValues()).containsExactlyElementsOf(reprovisioned.getValues());
    }
  }

  @Test
  void returnsAnErrorResultWhenTheEnclaveHoldsNoKeysYet() {
    try (FakeEnclaveSigner enclave = new FakeEnclaveSigner();
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      final MappedResults<ArtifactSigner> result = loader.load();
      assertThat(result.getErrorCount()).isEqualTo(1);
      assertThat(result.getValues()).isEmpty();
    }
  }

  @Test
  void loadsTheKeysOnceTheEnclaveIsProvisioned() {
    final List<BLSKeyPair> keys = FakeEnclaveSigner.randomKeys(2);
    try (FakeEnclaveSigner enclave = new FakeEnclaveSigner();
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      assertThat(loader.load().getErrorCount()).isEqualTo(1);

      enclave.load(keys);

      final MappedResults<ArtifactSigner> result = loader.load();
      assertThat(result.getErrorCount()).isZero();
      assertThat(result.getValues())
          .extracting(ArtifactSigner::getIdentifier)
          .containsExactlyInAnyOrderElementsOf(
              keys.stream().map(key -> key.getPublicKey().toString()).toList());
    }
  }

  @Test
  void signersAreUnavailableOnceTheLoaderIsClosed() {
    try (FakeEnclaveSigner enclave = new FakeEnclaveSigner()) {
      enclave.load(FakeEnclaveSigner.randomKeys(1));
      final BlsEnclaveBulkLoader loader =
          new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()));
      final MappedResults<ArtifactSigner> loaded = loader.load();
      final ArtifactSigner signer = loaded.getValues().iterator().next();

      loader.close();

      assertThatThrownBy(() -> signer.sign(Bytes.random(32)))
          .isInstanceOf(SignerUnavailableException.class);
      final MappedResults<ArtifactSigner> reloaded = loader.load();
      assertThat(reloaded.getErrorCount()).isEqualTo(1);
      assertThat(reloaded.getValues()).containsExactlyElementsOf(loaded.getValues());
      assertThatThrownBy(loader::status)
          .isInstanceOf(SignerUnavailableException.class)
          .hasMessage("Signer unavailable: Enclave client is closed");
    }
  }

  @Test
  void statusReportsTheKeysAndBootId() {
    try (FakeEnclaveSigner enclave = new FakeEnclaveSigner();
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      assertThat(loader.status()).isEqualTo(new EnclaveSignerStatus(0, enclave.bootId()));

      enclave.load(FakeEnclaveSigner.randomKeys(3));

      assertThat(loader.status()).isEqualTo(new EnclaveSignerStatus(3, enclave.bootId()));
    }
  }

  @Test
  void statusIsUnavailableOnceTheEnclaveIsStopped() {
    final FakeEnclaveSigner enclave = new FakeEnclaveSigner();
    try (BlsEnclaveBulkLoader loader =
        new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      loader.status();

      enclave.close();

      assertThatThrownBy(loader::status)
          .isInstanceOf(SignerUnavailableException.class)
          .hasMessageStartingWith("Signer unavailable: ");
    } finally {
      enclave.close();
    }
  }

  @Test
  void statusGivesUpWellBeforeTheRequestTimeout() throws Exception {
    // accepts connections (backlog) but never reads or answers
    try (ServerSocket silent = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters("tcp:127.0.0.1:" + silent.getLocalPort()))) {
      final long start = System.nanoTime();

      assertThatThrownBy(loader::status)
          .isInstanceOf(SignerUnavailableException.class)
          .hasMessageContaining("did not answer within 500 ms");
      // the 5 s request timeout of the parameters does not apply
      assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
    }
  }

  @Test
  void returnsAnErrorResultWhenNothingListens() {
    try (BlsEnclaveBulkLoader loader =
        new BlsEnclaveBulkLoader(new Parameters("tcp:127.0.0.1:1"))) {
      final MappedResults<ArtifactSigner> result = loader.load();
      assertThat(result.getErrorCount()).isEqualTo(1);
      assertThat(result.getValues()).isEmpty();
    }
  }

  @Test
  void rejectsAnInvalidAddress() {
    assertThatThrownBy(() -> new BlsEnclaveBulkLoader(new Parameters("udp:x:1")))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
