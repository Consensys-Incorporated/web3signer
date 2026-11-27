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

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSignature;
import tech.pegasys.web3signer.signing.EnclaveBlsArtifactSigner;
import tech.pegasys.web3signer.signing.FakeEnclaveSigner;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.EnclaveSignerParameters;

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
  void returnsAnErrorResultWhenNothingListens() {
    try (BlsEnclaveBulkLoader loader =
        new BlsEnclaveBulkLoader(new Parameters("tcp:127.0.0.1:1"))) {
      final MappedResults<ArtifactSigner> result = loader.load();
      assertThat(result.getErrorCount()).isEqualTo(1);
      assertThat(result.getValues()).isEmpty();
    }
  }

  @Test
  void returnsAnErrorResultForAnInvalidAddress() {
    try (BlsEnclaveBulkLoader loader = new BlsEnclaveBulkLoader(new Parameters("udp:x:1"))) {
      assertThat(loader.load().getErrorCount()).isEqualTo(1);
    }
  }
}
