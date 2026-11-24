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
package tech.pegasys.web3signer.tests.signing;

import static io.restassured.http.ContentType.JSON;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.networks.Eth2Network;
import tech.pegasys.web3signer.core.service.http.ArtifactType;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.Eth2SigningRequestBody;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.dsl.utils.Eth2RequestUtils;
import tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil;
import tech.pegasys.web3signer.enclave.host.EnclaveTestKeys;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;
import tech.pegasys.web3signer.signing.KeyType;

import java.util.List;

import io.restassured.response.Response;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class EnclaveSignerAcceptanceTest extends SigningAcceptanceTestBase {
  private static final String HEALTH_CHECK = "keys-check/enclave-bulk-loading";

  private final List<BLSKeyPair> keys = EnclaveTestKeys.randomKeys(3);
  private InProcessEnclaveSigner enclave;

  @BeforeEach
  void startEnclave() {
    enclave = new InProcessEnclaveSigner();
    EnclaveTestKeys.provision(enclave.address(), keys);
    final SignerConfigurationBuilder builder =
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(testDirectory)
            .withMode("eth2")
            .withNetwork(Eth2Network.MINIMAL.configName())
            .withEnclaveSignerAddress(enclave.address().toString());
    setForkEpochsAndStartSigner(builder, SpecMilestone.PHASE0);
  }

  @AfterEach
  void stopEnclave() {
    enclave.close();
  }

  @Test
  void publicKeysOfTheEnclaveAreListed() {
    signer
        .callApiPublicKeys(KeyType.BLS)
        .then()
        .statusCode(200)
        .body(
            "",
            containsInAnyOrder(keys.stream().map(key -> key.getPublicKey().toString()).toArray()));
  }

  @Test
  void signingReturnsTheBlsSignatureOfTheSigningRoot() throws Exception {
    final Eth2SigningRequestBody request = Eth2RequestUtils.createCannedRequest(ArtifactType.BLOCK);
    for (final BLSKeyPair key : keys) {
      final Response response = signer.eth2Sign(key.getPublicKey().toString(), request, JSON);
      final Bytes signature = verifyAndGetSignatureResponse(response, JSON);
      assertThat(signature)
          .isEqualTo(BLS.sign(key.getSecretKey(), request.signingRoot()).toBytesCompressed());
    }
  }

  @Test
  void healthcheckReportsTheEnclaveKeys() {
    final String body = signer.healthcheck().body().asString();
    assertThat(HealthCheckResultUtil.getHealthcheckStatusValue(body)).isEqualTo("UP");
    assertThat(HealthCheckResultUtil.getHealtcheckKeysLoaded(body, HEALTH_CHECK)).isEqualTo(3);
    assertThat(HealthCheckResultUtil.getHealthcheckErrorCount(body, HEALTH_CHECK)).isZero();
  }
}
