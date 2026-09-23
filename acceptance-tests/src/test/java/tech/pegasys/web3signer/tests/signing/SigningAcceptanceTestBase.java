/*
 * Copyright 2020 ConsenSys AG.
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

import tech.pegasys.teku.spec.SpecMilestone;
import tech.pegasys.teku.spec.networks.Eth2Network;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ConfigurationChainId;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.nio.file.Path;

import io.restassured.http.ContentType;
import io.restassured.response.Response;
import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.io.TempDir;

public class SigningAcceptanceTestBase extends AcceptanceTestBase {
  protected @TempDir Path testDirectory;

  protected void setupEth1Signer() {
    final SignerConfigurationBuilder builder = new SignerConfigurationBuilder();
    builder
        .withKeyStoreDirectory(testDirectory)
        .withMode("eth1")
        .withChainIdProvider(new ConfigurationChainId(DEFAULT_CHAIN_ID));
    startSigner(builder.build());
  }

  protected void setupEth2Signer(final Eth2Network eth2Network, final SpecMilestone specMilestone) {
    final SignerConfigurationBuilder builder = new SignerConfigurationBuilder();
    builder
        .withKeyStoreDirectory(testDirectory)
        .withMode("eth2")
        .withNetwork(eth2Network.configName());
    setForkEpochsAndStartSigner(builder, specMilestone);
  }

  protected void setupEth2Signer(final Path networkConfigFile, final SpecMilestone specMilestone) {
    final SignerConfigurationBuilder builder = new SignerConfigurationBuilder();
    builder.withKeyStoreDirectory(testDirectory).withMode("eth2").withNetwork(networkConfigFile);
    setForkEpochsAndStartSigner(builder, specMilestone);
  }

  protected void setupEth2SignerWithCustomNetworkConfig(final Path networkConfigFile) {
    final SignerConfigurationBuilder builder = new SignerConfigurationBuilder();
    builder.withKeyStoreDirectory(testDirectory).withMode("eth2").withNetwork(networkConfigFile);

    // no need to set custom fork epochs as they are meant to be provided in networkConfigFile

    startSigner(builder.build());
  }

  protected void setForkEpochsAndStartSigner(
      final SignerConfigurationBuilder builder, final SpecMilestone specMilestone) {
    setForkEpochs(specMilestone, builder);
    startSigner(builder.build());
  }

  private void setForkEpochs(
      final SpecMilestone specMilestone, final SignerConfigurationBuilder builder) {
    switch (specMilestone) {
      case PHASE0 -> {}
      case ALTAIR -> builder.withAltairForkEpoch(0L);
      case BELLATRIX -> {
        // As we are setting manual epoch, Teku libraries doesn't seem to work when Bellatrix epoch
        // is set to 0 while Altair is not set (as it attempts to calculate difference
        // between two forks). Hence, set both forks to 0.
        builder.withAltairForkEpoch(0L);
        builder.withBellatrixForkEpoch(0L);
      }
      case CAPELLA -> {
        builder.withAltairForkEpoch(0L);
        builder.withBellatrixForkEpoch(0L);
        builder.withCapellaForkEpoch(0L);
      }
      case DENEB -> {
        builder.withAltairForkEpoch(0L);
        builder.withBellatrixForkEpoch(0L);
        builder.withCapellaForkEpoch(0L);
        builder.withDenebForkEpoch(0L);
      }
      case ELECTRA -> {
        builder.withAltairForkEpoch(0L);
        builder.withBellatrixForkEpoch(0L);
        builder.withCapellaForkEpoch(0L);
        builder.withDenebForkEpoch(0L);
        builder.withElectraForkEpoch(0L);
      }
      case FULU -> {
        builder.withAltairForkEpoch(0L);
        builder.withBellatrixForkEpoch(0L);
        builder.withCapellaForkEpoch(0L);
        builder.withDenebForkEpoch(0L);
        builder.withElectraForkEpoch(0L);
        builder.withFuluForkEpoch(0L);
      }
      case GLOAS -> {
        builder.withAltairForkEpoch(0L);
        builder.withBellatrixForkEpoch(0L);
        builder.withCapellaForkEpoch(0L);
        builder.withDenebForkEpoch(0L);
        builder.withElectraForkEpoch(0L);
        builder.withFuluForkEpoch(0L);
        builder.withGloasForkEpoch(0L);
      }
      default ->
          throw new IllegalStateException(
              "Setting manual fork epoch is not yet implemented for " + specMilestone);
    }
  }

  protected Bytes verifyAndGetSignatureResponse(final Response response) {
    return verifyAndGetSignatureResponse(response, ContentType.TEXT);
  }

  protected Bytes verifyAndGetSignatureResponse(
      final Response response, final ContentType expectedContentType) {
    response.then().contentType(expectedContentType).statusCode(200);
    final String signature =
        expectedContentType == ContentType.JSON
            ? response.body().jsonPath().getString("signature")
            : response.body().print();
    return Bytes.fromHexString(signature);
  }
}
