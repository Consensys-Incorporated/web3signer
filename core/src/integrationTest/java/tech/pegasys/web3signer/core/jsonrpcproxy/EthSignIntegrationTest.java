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
package tech.pegasys.web3signer.core.jsonrpcproxy;

import static java.util.Collections.singletonList;
import static org.web3j.crypto.Keys.getAddress;
import static tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError.SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT;

import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcErrorResponse;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcSuccessResponse;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Map;

import io.netty.handler.codec.http.HttpHeaderValues;
import io.vertx.core.json.Json;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.jupiter.api.Test;
import org.web3j.crypto.Keys;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthSign;

public class EthSignIntegrationTest extends IntegrationTestBase {

  @Test
  void ethSignSignsMessageWhenAnUnlockedAccountIsPassed() {
    final Request<?, EthSign> requestBody =
        jsonRpc().ethSign(unlockedAccount, "some random data to be signed");

    final Iterable<Map.Entry<String, String>> expectedHeaders =
        singletonList(
            ImmutablePair.of("Content-Type", HttpHeaderValues.APPLICATION_JSON.toString()));

    final JsonRpcSuccessResponse responseBody =
        new JsonRpcSuccessResponse(
            requestBody.getId(),
            "0x22cf811d54835be906e45d728dfc8a7a32bb65ce146a4ccb6b689b8d8182a30f19fdb947229991b9dfd63b67fe4ebb59a3d3f8d9ed95b27e0c3d34e1800afbd81b");

    sendPostRequestAndVerifyResponse(
        request.web3Signer(Json.encode(requestBody)),
        response.web3Signer(expectedHeaders, Json.encode(responseBody)));
  }

  @Test
  void ethSignExpectsFirstParameterToBeEth1Address() {
    final String PUBLIC_KEY_OF_UNLOCKED_ACCOUNT =
        "0x6ac54201372d797a07ab0fa46c38acca97dec3af5ab19847f69b9c7ddca1b54c8e3c25bd9a3830f84fa06b03f60b7ddac41ad32d3a89ee5c488a4b116d9e8339";
    final Request<?, EthSign> requestBody =
        jsonRpc().ethSign(PUBLIC_KEY_OF_UNLOCKED_ACCOUNT, "some random data to be signed");

    final Iterable<Map.Entry<String, String>> expectedHeaders =
        singletonList(
            ImmutablePair.of("Content-Type", HttpHeaderValues.APPLICATION_JSON.toString()));

    final JsonRpcErrorResponse responseBody =
        new JsonRpcErrorResponse(requestBody.getId(), SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT);

    sendPostRequestAndVerifyResponse(
        request.web3Signer(Json.encode(requestBody)),
        response.web3Signer(expectedHeaders, Json.encode(responseBody)));
  }

  @Test
  void ethSignDoNotSignMessageWhenSignerAccountIsNotLoaded()
      throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
    final String A_RANDOM_ADDRESS = getAddress(Keys.createEcKeyPair().getPublicKey());
    final Request<?, EthSign> requestBody =
        jsonRpc().ethSign(A_RANDOM_ADDRESS, "some random data to be signed");

    final Iterable<Map.Entry<String, String>> expectedHeaders =
        singletonList(
            ImmutablePair.of("Content-Type", HttpHeaderValues.APPLICATION_JSON.toString()));

    final JsonRpcErrorResponse responseBody =
        new JsonRpcErrorResponse(requestBody.getId(), SIGNING_FROM_IS_NOT_AN_UNLOCKED_ACCOUNT);

    sendPostRequestAndVerifyResponse(
        request.web3Signer(Json.encode(requestBody)),
        response.web3Signer(expectedHeaders, Json.encode(responseBody)));
  }
}
