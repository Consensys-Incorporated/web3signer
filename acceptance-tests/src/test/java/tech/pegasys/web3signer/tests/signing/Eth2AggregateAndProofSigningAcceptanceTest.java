/*
 * Copyright 2021 ConsenSys AG.
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

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSPublicKey;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.networks.Eth2Network;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.Eth2SigningRequestBody;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.schema.Attestation;
import tech.pegasys.web3signer.dsl.utils.Eth2AggregateAndProofSigningRequestUtil;
import tech.pegasys.web3signer.dsl.utils.MetadataFileHelpers;
import tech.pegasys.web3signer.signing.KeyType;

import java.nio.file.Path;

import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

public class Eth2AggregateAndProofSigningAcceptanceTest extends SigningAcceptanceTestBase {
  private static final String PRIVATE_KEY =
      "3ee2224386c82ffea477e2adf28a2929f5c349165a4196158c7f3a2ecca40f35";

  private static final MetadataFileHelpers METADATA_FILE_HELPERS = new MetadataFileHelpers();
  private static final BLSSecretKey KEY =
      BLSSecretKey.fromBytes(Bytes32.fromHexString(PRIVATE_KEY));
  private static final BLSKeyPair KEY_PAIR = new BLSKeyPair(KEY);
  private static final BLSPublicKey PUBLIC_KEY = KEY_PAIR.getPublicKey();

  @BeforeEach
  void setup() {
    final String configFilename = PUBLIC_KEY.toString().substring(2);
    final Path keyConfigFile = testDirectory.resolve(configFilename + ".yaml");
    METADATA_FILE_HELPERS.createUnencryptedYamlFileAt(keyConfigFile, PRIVATE_KEY, KeyType.BLS);
  }

  @ParameterizedTest(name = "#{index} - {0}: Sign and verify AggregateAndProofV2 Signature")
  @EnumSource(
      value = SpecMilestone.class,
      names = {"PHASE0", "ALTAIR", "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU", "GLOAS"})
  void signAndVerifyAggregateAndProofV2Signature(final SpecMilestone specMilestone)
      throws Exception {
    final Eth2AggregateAndProofSigningRequestUtil util =
        new Eth2AggregateAndProofSigningRequestUtil(specMilestone);

    setupEth2Signer(Eth2Network.MINIMAL, specMilestone);

    final Eth2SigningRequestBody request = util.createAggregateAndProofV2Request();
    // assert that the Attestation in AggregateAndProofV2 is created correctly for the spec
    final Attestation aggregate = request.aggregateAndProofV2().data().aggregate;
    if (specMilestone.isGreaterThanOrEqualTo(SpecMilestone.ELECTRA)) {
      assertThat(aggregate.committee_bits).isNotNull();
    } else {
      assertThat(aggregate.committee_bits).isNull();
    }
    final Response response =
        signer.eth2Sign(KEY_PAIR.getPublicKey().toString(), request, ContentType.JSON);
    final Bytes signature = verifyAndGetSignatureResponse(response, ContentType.JSON);
    final BLSSignature expectedSignature = BLS.sign(KEY_PAIR.getSecretKey(), request.signingRoot());
    assertThat(signature).isEqualTo(expectedSignature.toBytesCompressed());
  }
}
