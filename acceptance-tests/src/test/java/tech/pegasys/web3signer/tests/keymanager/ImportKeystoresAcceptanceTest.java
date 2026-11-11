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
package tech.pegasys.web3signer.tests.keymanager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static tech.pegasys.web3signer.dsl.utils.Eth2RequestUtils.createAttestationRequest;

import tech.pegasys.teku.infrastructure.unsigned.UInt64;
import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.core.service.http.handlers.keymanager.imports.ImportKeystoresRequestBody;
import tech.pegasys.web3signer.core.service.http.handlers.signing.eth2.Eth2SigningRequestBody;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;
import tech.pegasys.web3signer.signing.KeyType;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.apache.tuweni.bytes.Bytes;
import org.awaitility.Awaitility;
import org.jdbi.v3.core.Jdbi;
import org.junit.jupiter.api.Test;

public class ImportKeystoresAcceptanceTest extends KeyManagerTestBase {

  private static final String PUBLIC_KEY =
      "0x98d083489b3b06b8740da2dfec5cc3c01b2086363fe023a9d7dc1f907633b1ff11f7b99b19e0533e969862270061d884";

  @Test
  public void invalidRequestBodyReturnsError() throws URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores("{\"invalid\": \"json body\"}");
    response.then().assertThat().statusCode(400);
  }

  @Test
  public void mismatchKeysAndPasswordsReturnsError() throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores(composeMismatchedRequestBody());
    response.then().assertThat().statusCode(400);
  }

  @Test
  public void emptyKeystoresReturnSuccess() throws URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores("{\"keystores\": [], \"passwords\": [] }");
    response.then().assertThat().statusCode(200);
  }

  @Test
  public void validRequestBodyWithSlashingdataReturnsSuccess()
      throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores(composeRequestBody());
    response
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("imported"));
  }

  @Test
  public void validRequestBodyWithWrongPasswordReturnsErrorResult()
      throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores(composeRequestBodyWrongPassword());
    response
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("error"));
  }

  @Test
  public void validRequestBodyNoSlashingdataReturnsImported()
      throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores(composeRequestBodyNoSlashingData());
    response
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("imported"));
  }

  @Test
  public void oneValidKeyOneInvalidKeyReturnsImportedAndError()
      throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Response response = callImportKeystores(composeRequestBodyTwoKeysOneInvalid());
    response
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data[0].status", is("imported"))
        .and()
        .body("data[1].status", is("error"));
  }

  @Test
  public void existingKeyReturnsDuplicate() throws IOException, URISyntaxException {
    createBlsKey("eth2/bls_keystore.json", "somepassword");
    setupSignerWithKeyManagerApi();

    assertThat(signer.listPublicKeys(KeyType.BLS).size()).isEqualTo(1);

    final Response response = callImportKeystores(composeRequestBody());
    response
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("duplicate"));

    assertThat(signer.listPublicKeys(KeyType.BLS).size()).isEqualTo(1);
  }

  @Test
  public void importLoadsNewKeys() throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    assertThat(signer.listPublicKeys(KeyType.BLS).size()).isEqualTo(0);

    callImportKeystores(composeRequestBody())
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("imported"));

    validateApiResponse(callListKeys(), "data.validating_pubkey", hasItem(PUBLIC_KEY));
    assertThat(signer.listPublicKeys(KeyType.BLS).size()).isEqualTo(1);
    assertThat(signer.listPublicKeys(KeyType.BLS).get(0)).isEqualTo(PUBLIC_KEY);
  }

  @Test
  public void canSignAfterImportingNewKey() throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    // import keystore
    callImportKeystores(composeRequestBody())
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("imported"));
    // Sign with it
    final Eth2SigningRequestBody request = createAttestationRequest(7, 8, UInt64.ZERO);
    signer.eth2Sign(PUBLIC_KEY, request).then().assertThat().statusCode(200);
  }

  @Test
  public void canSignPreviouslyDeletedKeyAfterImporting() throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    // import keystore
    callImportKeystores(composeRequestBody())
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("imported"));

    // delete keystore. this will disable the validator in the slashing protection db
    final JsonObject requestBody = new JsonObject().put("pubkeys", new JsonArray().add(PUBLIC_KEY));
    callDeleteKeystores(requestBody.toString());
    validateApiResponse(callListKeys(), "data.validating_pubkey", empty());

    // import again
    callImportKeystores(composeRequestBody())
        .then()
        .contentType(ContentType.JSON)
        .assertThat()
        .statusCode(200)
        .body("data.status", hasItem("imported"));
    validateApiResponse(callListKeys(), "data.validating_pubkey", hasItem(PUBLIC_KEY));

    // Sign with it
    final Eth2SigningRequestBody request = createAttestationRequest(7, 8, UInt64.ZERO);
    signer.eth2Sign(PUBLIC_KEY, request).then().assertThat().statusCode(200);
  }

  @Test
  public void reloadKeepsImportedKeyWhileItsKeystoreFailsAndRemovesItOnceDeleted()
      throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    callImportKeystores(composeRequestBody())
        .then()
        .statusCode(200)
        .body("data.status", hasItem("imported"));
    final Path keyConfigFile = testDirectory.resolve(PUBLIC_KEY + ".yaml");
    assertThat(keyConfigFile).exists();

    // the imported keystore can no longer be loaded: the key stays, enabled for signing
    Files.writeString(testDirectory.resolve(PUBLIC_KEY + ".json"), "not a keystore");
    reloadAndAwaitStatus("completed_with_errors");
    validateApiResponse(callListKeys(), "data.validating_pubkey", hasItem(PUBLIC_KEY));
    signer
        .eth2Sign(PUBLIC_KEY, createAttestationRequest(7, 8, UInt64.ZERO))
        .then()
        .assertThat()
        .statusCode(200);

    // its key config file is deleted while an unrelated key config file is corrupt: the key goes
    // away, the unrelated failure does not keep it
    Files.delete(keyConfigFile);
    Files.writeString(testDirectory.resolve("unrelated.yaml"), "not: [valid");
    signer.callReload().then().statusCode(202);
    Awaitility.await()
        .atMost(10, TimeUnit.SECONDS)
        .pollInterval(500, TimeUnit.MILLISECONDS)
        .untilAsserted(
            () -> {
              validateApiResponse(callListKeys(), "data.validating_pubkey", empty());
              signer
                  .getReloadStatus()
                  .then()
                  .statusCode(200)
                  .body("status", equalTo("completed_with_errors"));
            });
  }

  @Test
  public void reloadKeepsKeyImportedWithoutKeystoreStorageUntilDeleted()
      throws IOException, URISyntaxException {
    startSigner(
        new SignerConfigurationBuilder()
            .withKeyStoreDirectory(testDirectory)
            .withNetwork("minimal")
            .withMode("eth2")
            .withAltairForkEpoch(MINIMAL_ALTAIR_FORK)
            .withSlashingEnabled(true)
            .withSlashingProtectionDbUsername(DB_USERNAME)
            .withSlashingProtectionDbPassword(DB_PASSWORD)
            .withKeyManagerApiEnabled(true)
            .withKeyManagerSkipKeystoreStorage(true)
            .build());
    callImportKeystores(composeRequestBody())
        .then()
        .statusCode(200)
        .body("data.status", hasItem("imported"));
    try (final Stream<Path> files = Files.list(testDirectory)) {
      assertThat(files).isEmpty();
    }

    // a reload neither removes the in-memory key nor disables it for signing
    reloadAndAwaitStatus("completed");
    validateApiResponse(callListKeys(), "data.validating_pubkey", hasItem(PUBLIC_KEY));
    signer
        .eth2Sign(PUBLIC_KEY, createAttestationRequest(7, 8, UInt64.ZERO))
        .then()
        .assertThat()
        .statusCode(200);

    // deleted through the API: a later reload does not bring it back
    callDeleteKeystores(new JsonObject().put("pubkeys", new JsonArray().add(PUBLIC_KEY)).toString())
        .then()
        .statusCode(200);
    signer.callReload().then().statusCode(202);
    Awaitility.await()
        .atMost(10, TimeUnit.SECONDS)
        .pollInterval(500, TimeUnit.MILLISECONDS)
        .untilAsserted(
            () -> {
              signer.getReloadStatus().then().statusCode(200).body("status", equalTo("completed"));
              validateApiResponse(callListKeys(), "data.validating_pubkey", empty());
            });
  }

  private void reloadAndAwaitStatus(final String status) {
    signer.callReload().then().statusCode(202);
    Awaitility.await()
        .atMost(10, TimeUnit.SECONDS)
        .pollInterval(500, TimeUnit.MILLISECONDS)
        .untilAsserted(
            () -> signer.getReloadStatus().then().statusCode(200).body("status", equalTo(status)));
  }

  @Test
  public void importLoadsSlashingData() throws IOException, URISyntaxException {
    setupSignerWithKeyManagerApi();
    final Jdbi jdbi = Jdbi.create(signer.getSlashingDbUrl(), DB_USERNAME, DB_PASSWORD);
    final List<Map<String, Object>> validatorsBefore =
        jdbi.withHandle(h -> h.select("SELECT * from validators").mapToMap().list());
    assertThat(validatorsBefore).hasSize(0);

    // call import with one keystore but 2 pubkeys in the slashing data
    callImportKeystores(composeRequestBody()).then().statusCode(200);
    final List<Map<String, Object>> validatorsAfter =
        jdbi.withHandle(h -> h.select("SELECT * from validators").mapToMap().list());

    // assert that only one pubkey got inserted
    assertThat(validatorsAfter).hasSize(1);
    assertThat(validatorsAfter.get(0).get("public_key"))
        .isEqualTo(Bytes.fromHexString(PUBLIC_KEY).toArray());
  }

  @Test
  public void testRequestBodyParsing() throws IOException, URISyntaxException {
    final ObjectMapper objectMapper = SigningObjectMapperFactory.createObjectMapper();
    final ImportKeystoresRequestBody parsedBody =
        objectMapper.readValue(composeRequestBody(), ImportKeystoresRequestBody.class);
    assertThat(new JsonObject(parsedBody.getKeystores().get(0)).getInteger("version")).isEqualTo(4);
    assertThat(new JsonObject(parsedBody.getKeystores().get(0)).getString("pubkey"))
        .isEqualTo(
            "98d083489b3b06b8740da2dfec5cc3c01b2086363fe023a9d7dc1f907633b1ff11f7b99b19e0533e969862270061d884");
    assertThat(parsedBody.getPasswords().get(0)).isEqualTo("somepassword");
    assertThat(
            new JsonObject(parsedBody.getSlashingProtection())
                .getJsonArray("data")
                .getJsonObject(0)
                .getString("pubkey"))
        .isEqualTo(
            "0x8f3f44b74d316c3293cced0c48c72e021ef8d145d136f2908931090e7181c3b777498128a348d07b0b9cd3921b5ca537");
  }

  private String composeRequestBody() throws IOException, URISyntaxException {
    String keystoreData = readFile("eth2/bls_keystore.json");
    String password = "somepassword";
    String slashingProtectionData = readFile("slashing/slashingImport_two_entries.json");
    final JsonObject requestBody =
        new JsonObject()
            .put("keystores", new JsonArray().add(keystoreData))
            .put("passwords", new JsonArray().add(password))
            .put("slashing_protection", slashingProtectionData);
    return requestBody.toString();
  }

  private String composeRequestBodyNoSlashingData() throws IOException, URISyntaxException {
    String keystoreData = readFile("eth2/bls_keystore.json");
    String password = "somepassword";
    final JsonObject requestBody =
        new JsonObject()
            .put("keystores", new JsonArray().add(keystoreData))
            .put("passwords", new JsonArray().add(password));
    return requestBody.toString();
  }

  private String composeRequestBodyTwoKeysOneInvalid() throws IOException, URISyntaxException {
    String keystoreData = readFile("eth2/bls_keystore.json");
    String keystoreData2 = readFile("eth2/bls_keystore_2.json");
    String password = "somepassword";
    String password2 = "wrongpassord";
    final JsonObject requestBody =
        new JsonObject()
            .put("keystores", new JsonArray().add(keystoreData).add(keystoreData2))
            .put("passwords", new JsonArray().add(password).add(password2));
    return requestBody.toString();
  }

  private String composeMismatchedRequestBody() throws IOException, URISyntaxException {
    String keystoreData = readFile("eth2/bls_keystore.json");
    String password = "somepassword";
    String otherPassword = "someOtherPassword";
    final JsonObject requestBody =
        new JsonObject()
            .put("keystores", new JsonArray().add(keystoreData))
            .put("passwords", new JsonArray().add(password).add(otherPassword));
    return requestBody.toString();
  }

  private String composeRequestBodyWrongPassword() throws IOException, URISyntaxException {
    String keystoreData = readFile("eth2/bls_keystore.json");
    String password = "wrongpassword";
    final JsonObject requestBody =
        new JsonObject()
            .put("keystores", new JsonArray().add(keystoreData))
            .put("passwords", new JsonArray().add(password));
    return requestBody.toString();
  }
}
