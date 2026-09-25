/*
 * Copyright 2019 ConsenSys AG.
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
package tech.pegasys.web3signer.core.jsonrpcproxy;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockserver.model.HttpRequest.request;

import tech.pegasys.web3signer.core.jsonrpcproxy.model.HttpMethod;

import java.util.List;
import java.util.Map.Entry;

import com.google.common.collect.Lists;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.json.Json;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockserver.model.Header;

public class ProxyIntegrationTest extends IntegrationTestBase {

  private static final String NON_RPC_REQUEST =
      "{\"username\":\"username1\",\"password\":\"pegasys\"}";
  private static final String NON_RPC_RESPONSE = "{\"token\":\"eyJ0\"}";
  private static final String RPC_REQUEST =
      "{\"jsonrpc\":\"2.0\",\"method\":\"net_version\",\"params\":[],\"id\":0}";
  private static final String RPC_RESPONSE =
      "{\"id\":0,\"jsonrpc\":2.0,\"result\":\"4\",\"error\":null,\"rawResponse\":null,\"netVersion\":\"4\"}";
  private static final Iterable<Entry<String, String>> REQUEST_HEADERS =
      singletonList(ImmutablePair.of("Accept", "*/*"));
  private static final Iterable<Entry<String, String>> RESPONSE_HEADERS =
      singletonList(ImmutablePair.of("Content-Type", "Application/Json"));

  private static final String ROOT_PATH = "/arbitraryRootPath";
  private static final String NOT_FOUND_BODY = "{\"code\":404,\"message\":\"Not Found\"}";
  private static final String FORBIDDEN_BODY = "{\"code\":403,\"message\":\"Forbidden\"}";

  @BeforeAll
  public static void localSetup() {
    try {
      setupWeb3Signer(DEFAULT_CHAIN_ID, ROOT_PATH);
    } catch (final Exception e) {
      throw new RuntimeException("Failed to setup web3signer", e);
    }
  }

  @Test
  void rpcRequestWithHeadersIsProxied() {
    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST), response.ethNode(RESPONSE_HEADERS, RPC_RESPONSE));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(REQUEST_HEADERS, RPC_REQUEST),
        response.web3Signer(RESPONSE_HEADERS, RPC_RESPONSE));

    verifyEthNodeReceived(REQUEST_HEADERS, RPC_REQUEST);
  }

  @Test
  void requestWithHostHeaderIsRenamedToXForwardedHost() {
    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST), response.ethNode(RESPONSE_HEADERS, RPC_RESPONSE));

    final Iterable<Entry<String, String>> requestHeaders =
        List.of(ImmutablePair.of("Accept", "*.*"), ImmutablePair.of("Host", "localhost"));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(requestHeaders, RPC_REQUEST),
        response.web3Signer(RESPONSE_HEADERS, RPC_RESPONSE));

    final Iterable<Entry<String, String>> expectedForwardedHeaders =
        List.of(
            ImmutablePair.of("Accept", "*.*"), ImmutablePair.of("X-Forwarded-Host", "localhost"));

    verifyEthNodeReceived(expectedForwardedHeaders, RPC_REQUEST);
  }

  @Test
  void requestWithHostHeaderOverwritesExistingXForwardedHost() {
    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST), response.ethNode(RESPONSE_HEADERS, RPC_RESPONSE));

    final Iterable<Entry<String, String>> requestHeaders =
        List.of(
            ImmutablePair.of("Accept", "*.*"),
            ImmutablePair.of("Host", "localhost"),
            ImmutablePair.of("X-Forwarded-Host", "nowhere"));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(requestHeaders, RPC_REQUEST),
        response.web3Signer(RESPONSE_HEADERS, RPC_RESPONSE));

    final Iterable<Entry<String, String>> expectedForwardedHeaders =
        List.of(
            ImmutablePair.of("Accept", "*.*"), ImmutablePair.of("X-Forwarded-Host", "localhost"));

    verifyEthNodeReceived(expectedForwardedHeaders, RPC_REQUEST);
  }

  @Test
  void requestReturningErrorIsProxied() {
    final String ethProtocolVersionRequest = Json.encode(jsonRpc().ethProtocolVersion());

    setUpEthNodeResponse(
        request.ethNode(ethProtocolVersionRequest),
        response.ethNode("Not Found", HttpResponseStatus.NOT_FOUND));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(ethProtocolVersionRequest),
        response.web3Signer("Not Found", HttpResponseStatus.NOT_FOUND));

    verifyEthNodeReceived(ethProtocolVersionRequest);
  }

  @Test
  void postRequestToNonRootPathIsProxied() {
    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST),
        response.ethNode(RESPONSE_HEADERS, RPC_RESPONSE, HttpResponseStatus.OK));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(REQUEST_HEADERS, RPC_REQUEST),
        response.web3Signer(RESPONSE_HEADERS, RPC_RESPONSE),
        "/login");

    verifyEthNodeReceived(REQUEST_HEADERS, RPC_REQUEST, ROOT_PATH + "/login");
  }

  @ParameterizedTest
  @EnumSource(value = HttpMethod.class, names = "POST", mode = EnumSource.Mode.EXCLUDE)
  void rpcNonPostRequestsAreNotProxied(final HttpMethod httpMethod) {
    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST),
        response.ethNode(RESPONSE_HEADERS, RPC_RESPONSE, HttpResponseStatus.OK));

    sendRequestAndVerifyResponse(
        httpMethod,
        request.web3Signer(REQUEST_HEADERS, RPC_REQUEST),
        response.web3Signer(NOT_FOUND_BODY, HttpResponseStatus.NOT_FOUND),
        "/login");

    clientAndServer.verifyZeroInteractions();
  }

  @ParameterizedTest
  @EnumSource(HttpMethod.class)
  void nonRpcRequestsAreNotProxied(final HttpMethod httpMethod) {
    setUpEthNodeResponse(
        request.ethNode(NON_RPC_REQUEST),
        response.ethNode(RESPONSE_HEADERS, NON_RPC_RESPONSE, HttpResponseStatus.OK));

    sendRequestAndVerifyResponse(
        httpMethod,
        request.web3Signer(REQUEST_HEADERS, NON_RPC_REQUEST),
        response.web3Signer(NOT_FOUND_BODY, HttpResponseStatus.NOT_FOUND),
        "/login");

    clientAndServer.verifyZeroInteractions();
  }

  @Test
  void requestWithOriginHeaderProducesResponseWithCorsHeader() {
    final String originDomain = "sample.com";

    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST), response.ethNode(RESPONSE_HEADERS, RPC_RESPONSE));

    final List<Entry<String, String>> expectedResponseHeaders =
        Lists.newArrayList(RESPONSE_HEADERS);
    expectedResponseHeaders.add(
        ImmutablePair.of(HttpHeaderNames.ACCESS_CONTROL_ALLOW_ORIGIN.toString(), "sample.com"));

    final Iterable<Entry<String, String>> requestHeaders =
        List.of(
            ImmutablePair.of("Accept", "*/*"),
            ImmutablePair.of("Host", "localhost"),
            ImmutablePair.of("Origin", originDomain));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(requestHeaders, RPC_REQUEST),
        response.web3Signer(expectedResponseHeaders, RPC_RESPONSE));

    // Cors headers should not be forwarded to the downstream web3 provider (CORS is handled
    // entirely within Web3Signer.
    assertThat(clientAndServer.retrieveRecordedRequests(request().withHeader(new Header("origin"))))
        .isEmpty();
  }

  @Test
  void requestWithMisMatchedDomainReceives403() {
    final String originDomain = "notSample.com";
    final Iterable<Entry<String, String>> requestHeaders =
        List.of(
            ImmutablePair.of("Accept", "*/*"),
            ImmutablePair.of("Host", "localhost"),
            ImmutablePair.of("Origin", originDomain));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(requestHeaders, RPC_REQUEST),
        response.web3Signer(FORBIDDEN_BODY, HttpResponseStatus.FORBIDDEN));
  }

  @Test
  void multiValueHeadersFromDownstreamArePassedBackToCallingApplication() {

    final List<Entry<String, String>> multiValueResponseHeader =
        Lists.newArrayList(RESPONSE_HEADERS);
    multiValueResponseHeader.add(ImmutablePair.of("Random", "firstValue"));
    multiValueResponseHeader.add(ImmutablePair.of("Random", "secondValue"));

    final Iterable<Entry<String, String>> requestHeaders =
        List.of(ImmutablePair.of("Accept", "*/*"), ImmutablePair.of("Host", "localhost"));

    setUpEthNodeResponse(
        request.ethNode(RPC_REQUEST),
        response.ethNode(multiValueResponseHeader, RPC_RESPONSE, HttpResponseStatus.OK));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(requestHeaders, RPC_REQUEST),
        response.web3Signer(multiValueResponseHeader, RPC_RESPONSE),
        "/login");
  }
}
