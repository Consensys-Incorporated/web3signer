/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.tests.bulkloading;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static tech.pegasys.web3signer.core.config.HealthCheckNames.KEYS_CHECK_GCP_BULK_LOADING;
import static tech.pegasys.web3signer.dsl.utils.HealthCheckResultUtil.getHealtcheckKeysLoaded;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.GcpSecretManagerUtil;
import tech.pegasys.web3signer.dsl.gcp.GcpSecretManagerEmulator;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.GcpSecretManagerParameters;
import tech.pegasys.web3signer.signing.config.GcpSecretManagerParametersBuilder;
import tech.pegasys.web3signer.tests.AcceptanceTestBase;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.google.cloud.secretmanager.v1.SecretManagerServiceClient;
import io.restassured.http.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Runs against a local emulator, see {@link GcpSecretManagerEmulator}, or against real Google Cloud
 * using application default credentials when {@value #GCP_PROJECT_ID_ENV} is set.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // same instance is shared across test methods
public class GcpSecretManagerAcceptanceTest extends AcceptanceTestBase {
  private static final Logger LOG = LogManager.getLogger();
  private static final String GCP_PROJECT_ID_ENV = "GCP_PROJECT_ID";
  private static final String RUN_AS_PROCESS_PROPERTY = "acctests.runWeb3SignerAsProcess";
  private static final Optional<String> REAL_GCP_PROJECT_ID =
      Optional.ofNullable(System.getenv(GCP_PROJECT_ID_ENV)).filter(id -> !id.isBlank());
  private static final String GCP_PROJECT_ID =
      REAL_GCP_PROJECT_ID.orElse(GcpSecretManagerEmulator.PROJECT_ID);

  private GcpSecretManagerUtil gcpSecretManagerUtil;
  private final List<BLSKeyPair> blsKeyPairs = new ArrayList<>();
  private final List<String> secretNames = new ArrayList<>();

  @BeforeAll
  void setupGcpResources() throws IOException {
    // The emulator's throwaway credentials reach Web3Signer as an environment variable, which only
    // a Web3Signer subprocess receives. In-process, google-auth would use the developer's real ADC.
    assumeTrue(
        REAL_GCP_PROJECT_ID.isPresent() || Boolean.getBoolean(RUN_AS_PROCESS_PROPERTY),
        "Running against the emulator requires -D" + RUN_AS_PROCESS_PROPERTY + "=true");
    final SecretManagerServiceClient client =
        REAL_GCP_PROJECT_ID.isPresent()
            ? SecretManagerServiceClient.create()
            : GcpSecretManagerEmulator.getInstance().createClient();
    gcpSecretManagerUtil = new GcpSecretManagerUtil(GCP_PROJECT_ID, client);
    final SecureRandom secureRandom = new SecureRandom();

    for (int i = 0; i < 4; i++) {
      final BLSKeyPair blsKeyPair = BLSKeyPair.random(secureRandom);
      // Only the first two secrets match the filter used by the tests below.
      final String secretName =
          gcpSecretManagerUtil.createSecret(
              "%s%d-%s"
                  .formatted(i < 2 ? "Secret" : "Ignored", i, blsKeyPair.getPublicKey().toString()),
              blsKeyPair.getSecretKey().toBytes().toHexString());
      blsKeyPairs.add(blsKeyPair);
      secretNames.add(secretName);
    }
  }

  @ParameterizedTest(name = "{index} - Using config file: {0}")
  @ValueSource(booleans = {true, false})
  void secretsAreLoadedFromGCPSecretManagerAndReportedByPublicApi(final boolean useConfigFile) {
    final GcpSecretManagerParameters gcpSecretManagerParameters =
        gcpParametersBuilder()
            .withEnabled(true)
            .withProjectId(GCP_PROJECT_ID)
            // The filter has to select only this run's "Secret" secrets. Real GCP matches it as a
            // substring of the resource name, while the emulator matches it as a prefix of the
            // secret id, so scope it with the unique prefix of this run's secrets.
            .withFilter("name:" + gcpSecretManagerUtil.getSecretsManagerPrefix() + "Secret")
            .build();

    final SignerConfigurationBuilder configBuilder =
        signerConfigBuilder()
            .withUseConfigFile(useConfigFile)
            .withMode("eth2")
            .withGcpParameters(gcpSecretManagerParameters);

    startSigner(configBuilder.build());

    final String healthCheckJsonBody = signer.healthcheck().body().asString();
    int keysLoaded = getHealtcheckKeysLoaded(healthCheckJsonBody, KEYS_CHECK_GCP_BULK_LOADING);

    assertThat(keysLoaded).isEqualTo(2);

    signer
        .callApiPublicKeys(KeyType.BLS)
        .then()
        .statusCode(200)
        .contentType(ContentType.JSON)
        .body(
            "",
            containsInAnyOrder(
                blsKeyPairs.get(0).getPublicKey().toString(),
                blsKeyPairs.get(1).getPublicKey().toString()),
            "",
            hasSize(2));
  }

  private static GcpSecretManagerParametersBuilder gcpParametersBuilder() {
    return GcpSecretManagerParametersBuilder.aGcpParameters()
        .withEndpointOverride(
            REAL_GCP_PROJECT_ID.isPresent()
                ? Optional.empty()
                : Optional.of(GcpSecretManagerEmulator.getInstance().getTlsEndpoint()));
  }

  private static SignerConfigurationBuilder signerConfigBuilder() {
    final SignerConfigurationBuilder builder = new SignerConfigurationBuilder();
    if (REAL_GCP_PROJECT_ID.isEmpty()) {
      final GcpSecretManagerEmulator emulator = GcpSecretManagerEmulator.getInstance();
      builder
          .withOverriddenCA(emulator.getTlsCertificateDefinition())
          .withEnvironment(emulator.web3SignerEnvironment());
    }
    return builder;
  }

  @AfterAll
  void cleanUpAwsResources() {
    if (gcpSecretManagerUtil != null) {
      secretNames.forEach(
          secretName -> {
            try {
              gcpSecretManagerUtil.deleteSecret(secretName);
            } catch (final RuntimeException e) {
              LOG.warn(
                  "Unexpected error while deleting key {}{}: {}",
                  gcpSecretManagerUtil.getSecretsManagerPrefix(),
                  secretName,
                  e.getMessage());
            }
          });
      gcpSecretManagerUtil.close();
    }
  }
}
