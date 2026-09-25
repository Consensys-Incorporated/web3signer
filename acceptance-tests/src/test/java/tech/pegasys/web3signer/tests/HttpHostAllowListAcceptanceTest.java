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
package tech.pegasys.web3signer.tests;

import static io.restassured.RestAssured.given;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.hamcrest.Matchers.equalTo;

import tech.pegasys.web3signer.dsl.signer.SignerConfiguration;
import tech.pegasys.web3signer.dsl.signer.SignerConfigurationBuilder;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.util.Collections;
import java.util.stream.Collectors;

import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

public class HttpHostAllowListAcceptanceTest extends AcceptanceTestBase {
  private static final String UPCHECK_ENDPOINT = "/upcheck";

  @Test
  void httpEndpointWithDefaultAllowHostsRespondsWithOkResponse() {
    final SignerConfiguration signerConfiguration =
        new SignerConfigurationBuilder().withMode("eth2").build();
    startSigner(signerConfiguration);

    given()
        .baseUri(signer.getUrl())
        .contentType(ContentType.JSON)
        .when()
        .get(UPCHECK_ENDPOINT)
        .then()
        .assertThat()
        .statusCode(200);
  }

  @Test
  void httpEndpointForAllowedHostRespondsWithOkResponse() {
    final SignerConfiguration signerConfiguration =
        new SignerConfigurationBuilder()
            .withHttpAllowHostList(Collections.singletonList("127.0.0.1, foo"))
            .withMode("eth2")
            .build();
    startSigner(signerConfiguration);

    given()
        .baseUri(signer.getUrl())
        .contentType(ContentType.JSON)
        .when()
        .header("Host", "foo")
        .get(UPCHECK_ENDPOINT)
        .then()
        .assertThat()
        .statusCode(200);
  }

  @Test
  void httpEndpointForNonAllowedHostRespondsWithForbiddenResponse() {
    final SignerConfiguration signerConfiguration =
        new SignerConfigurationBuilder()
            .withHttpAllowHostList(Collections.singletonList("127.0.0.1"))
            .withMode("eth2")
            .build();
    startSigner(signerConfiguration);

    given()
        .baseUri(signer.getUrl())
        .contentType(ContentType.JSON)
        .when()
        .header("Host", "bar")
        .get(UPCHECK_ENDPOINT)
        .then()
        .assertThat()
        .statusCode(403)
        .contentType(ContentType.JSON)
        .body("code", equalTo(403))
        .body("message", equalTo("Host not authorized."));
  }

  @Test
  void jsonRpcEndpointForNonAllowedHostRespondsWithForbiddenResponse() {
    final SignerConfiguration signerConfiguration =
        new SignerConfigurationBuilder()
            .withHttpAllowHostList(Collections.singletonList("127.0.0.1"))
            .withMode("eth1")
            .build();
    startSigner(signerConfiguration);

    given()
        .baseUri(signer.getUrl())
        .contentType(ContentType.JSON)
        .body("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_accounts\",\"params\":[]}")
        .when()
        .header("Host", "bar")
        .post("/")
        .then()
        .assertThat()
        .statusCode(403)
        .contentType(ContentType.JSON)
        .body("code", equalTo(403))
        .body("message", equalTo("Host not authorized."));
  }

  @Test
  void upcheckWithoutValueInHostHeaderRespondsWithForbiddenResponse() throws Exception {
    final SignerConfiguration signerConfiguration =
        new SignerConfigurationBuilder()
            .withHttpAllowHostList(Collections.singletonList("127.0.0.1"))
            .withMode("eth2")
            .build();
    startSigner(signerConfiguration);

    // raw request without Host header
    final URI uri = URI.create(signer.getUrl());
    try (final Socket s = new Socket(InetAddress.getLoopbackAddress(), uri.getPort());
        final PrintWriter writer =
            new PrintWriter(new OutputStreamWriter(s.getOutputStream(), UTF_8), true);
        final BufferedReader reader =
            new BufferedReader(new InputStreamReader(s.getInputStream(), UTF_8))) {
      final String req =
          "GET "
              + UPCHECK_ENDPOINT
              + " HTTP/1.1\r\n"
              + "Connection: close\r\n" // signals server to close the connection
              + "Host: \r\n"
              + "\r\n"; // end of headers section
      writer.write(req);
      writer.flush();

      final String response = reader.lines().collect(Collectors.joining("\n"));

      assertThat(response).startsWith("HTTP/1.1 403 Forbidden");
      assertThat(response).contains("{\"code\":403,\"message\":\"Host not authorized.\"}");
    }
  }

  @Test
  void upcheckWithoutHostHeaderRespondsWithBadRequest() throws Exception {
    final SignerConfiguration signerConfiguration =
        new SignerConfigurationBuilder()
            .withHttpAllowHostList(Collections.singletonList("127.0.0.1"))
            .withMode("eth2")
            .build();
    startSigner(signerConfiguration);

    // raw request without Host header
    final URI uri = URI.create(signer.getUrl());
    try (final Socket s = new Socket(InetAddress.getLoopbackAddress(), uri.getPort());
        final PrintWriter writer =
            new PrintWriter(new OutputStreamWriter(s.getOutputStream(), UTF_8), true);
        final BufferedReader reader =
            new BufferedReader(new InputStreamReader(s.getInputStream(), UTF_8))) {
      final String req =
          "GET "
              + UPCHECK_ENDPOINT
              + " HTTP/1.1\r\n"
              + "Connection: close\r\n" // signals server to close the connection
              + "\r\n"; // end of headers section
      writer.write(req);
      writer.flush();

      final String response = reader.lines().collect(Collectors.joining("\n"));

      assertThat(response).startsWith("HTTP/1.1 400 Bad Request");
      assertThat(response).contains("Bad Request");
    }
  }
}
