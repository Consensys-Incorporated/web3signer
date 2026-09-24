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
package tech.pegasys.web3signer.core.service.jsonrpc.handlers;

import tech.pegasys.web3signer.core.service.jsonrpc.JsonRpcRequestId;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcErrorResponse;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcResponse;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcSuccessResponse;

import io.netty.handler.codec.http.HttpHeaderValues;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.Json;

public class HttpResponseFactory {

  private static final String JSON = HttpHeaderValues.APPLICATION_JSON.toString();

  public void response(
      final HttpServerResponse response, final int statusCode, final JsonRpcResponse body) {
    response.putHeader(HttpHeaders.CONTENT_TYPE, JSON);
    response.setStatusCode(statusCode);
    response.setChunked(false);
    response.end(Json.encodeToBuffer(body));
  }

  public void successResponse(
      final HttpServerResponse response, final JsonRpcRequestId id, final Object result) {
    response(response, 200, new JsonRpcSuccessResponse(id, result));
  }

  public void failureResponse(
      final HttpServerResponse response,
      final JsonRpcRequestId id,
      final int statusCode,
      final JsonRpcError error) {
    response(response, statusCode, new JsonRpcErrorResponse(id, error));
  }
}
