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

import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcSuccessResponse;

import java.util.Map.Entry;

import io.netty.handler.codec.http.HttpHeaderValues;
import io.vertx.core.json.Json;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.jupiter.api.Test;
import org.web3j.protocol.core.Request;
import org.web3j.protocol.core.methods.response.EthAccounts;

class EthAccountsIntegrationTest extends IntegrationTestBase {

  @Test
  void ethAccountsRequestFromWeb3jRespondsWithNodesAddress() {

    final Request<?, EthAccounts> requestBody = jsonRpc().ethAccounts();
    final Iterable<Entry<String, String>> expectedHeaders =
        singletonList(
            ImmutablePair.of("Content-Type", HttpHeaderValues.APPLICATION_JSON.toString()));

    final JsonRpcSuccessResponse responseBody =
        new JsonRpcSuccessResponse(requestBody.getId(), singletonList(unlockedAccount));

    sendPostRequestAndVerifyResponse(
        request.web3Signer(Json.encode(requestBody)),
        response.web3Signer(expectedHeaders, Json.encode(responseBody)));
  }
}
