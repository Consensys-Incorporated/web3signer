/*
 * Copyright 2022 ConsenSys AG.
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
package tech.pegasys.web3signer.tests.publickeys;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static tech.pegasys.web3signer.signing.KeyType.BLS;

import tech.pegasys.web3signer.AwsSecretsManagerUtil;

import java.net.URI;
import java.util.Collections;
import java.util.Optional;

import io.restassured.response.Response;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@EnabledIfEnvironmentVariable(
    named = "RW_AWS_ACCESS_KEY_ID",
    matches = ".+",
    disabledReason = "RW_AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "RW_AWS_SECRET_ACCESS_KEY",
    matches = ".+",
    disabledReason = "RW_AWS_SECRET_ACCESS_KEY env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_ACCESS_KEY_ID",
    matches = ".+",
    disabledReason = "AWS_ACCESS_KEY_ID env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_SECRET_ACCESS_KEY",
    matches = ".+",
    disabledReason = "AWS_SECRET_ACCESS_KEY env variable is required")
@EnabledIfEnvironmentVariable(
    named = "AWS_REGION",
    matches = ".+",
    disabledReason = "AWS_REGION env variable is required")
public class AwsKeyIdentifiersAcceptanceTest extends KeyIdentifiersAcceptanceTestBase {

  private static final String RW_AWS_ACCESS_KEY_ID = System.getenv("RW_AWS_ACCESS_KEY_ID");
  private static final String RW_AWS_SECRET_ACCESS_KEY = System.getenv("RW_AWS_SECRET_ACCESS_KEY");

  private static final String RO_AWS_ACCESS_KEY_ID = System.getenv("AWS_ACCESS_KEY_ID");
  private static final String RO_AWS_SECRET_ACCESS_KEY = System.getenv("AWS_SECRET_ACCESS_KEY");

  private static final String AWS_REGION =
      Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-2");

  // can be pointed to an AWS emulator
  private final Optional<URI> awsEndpointOverride =
      System.getenv("AWS_ENDPOINT_OVERRIDE") != null
          ? Optional.of(URI.create(System.getenv("AWS_ENDPOINT_OVERRIDE")))
          : Optional.empty();

  private final String privateKey = privateKeys(BLS)[0]; // secret value
  private final String publicKey = BLS_PUBLIC_KEY_1;

  private AwsSecretsManagerUtil awsSecretsManagerUtil;

  @BeforeAll
  void setup() {
    awsSecretsManagerUtil =
        new AwsSecretsManagerUtil(
            AWS_REGION, RW_AWS_ACCESS_KEY_ID, RW_AWS_SECRET_ACCESS_KEY, awsEndpointOverride);
    awsSecretsManagerUtil.createSecret(publicKey, privateKey, Collections.emptyMap());
  }

  @AfterAll
  void teardown() {
    if (awsSecretsManagerUtil != null) {
      awsSecretsManagerUtil.deleteSecret(publicKey);
      awsSecretsManagerUtil.close();
    }
  }

  @Test
  public void specifiedAwsKeysReturnAppropriatePublicKey() {
    METADATA_FILE_HELPERS.createAwsYamlFileAt(
        testDirectory.resolve(publicKey + ".yaml"),
        AWS_REGION,
        RO_AWS_ACCESS_KEY_ID,
        RO_AWS_SECRET_ACCESS_KEY,
        awsSecretsManagerUtil.getSecretsManagerPrefix() + publicKey,
        awsEndpointOverride);
    initAndStartSigner("eth2");
    final Response response = callApiPublicKeysWithoutOpenApiClientSideFilter(BLS);
    validateApiResponse(response, containsInAnyOrder(publicKey));
  }

  @Test
  public void environmentAwsKeysReturnAppropriatePublicKey() {
    METADATA_FILE_HELPERS.createAwsYamlFileWithEnvironmentAt(
        testDirectory.resolve(publicKey + ".yaml"),
        AWS_REGION,
        awsSecretsManagerUtil.getSecretsManagerPrefix() + publicKey,
        awsEndpointOverride);
    initAndStartSigner("eth2");
    final Response response = callApiPublicKeysWithoutOpenApiClientSideFilter(BLS);
    validateApiResponse(response, containsInAnyOrder(publicKey));
  }
}
