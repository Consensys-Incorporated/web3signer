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

import static io.netty.handler.codec.http.HttpResponseStatus.INTERNAL_SERVER_ERROR;

import tech.pegasys.web3signer.core.service.http.handlers.ErrorResponseException;
import tech.pegasys.web3signer.core.service.http.handlers.JsonErrorHandler;
import tech.pegasys.web3signer.core.service.jsonrpc.JsonRpcRequestId;
import tech.pegasys.web3signer.core.service.jsonrpc.exceptions.JsonRpcException;
import tech.pegasys.web3signer.core.service.jsonrpc.response.JsonRpcError;

import java.net.ConnectException;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLException;

import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.Handler;
import io.vertx.core.VertxException;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JsonRpcErrorHandler implements Handler<RoutingContext> {

  private static final Logger LOG = LogManager.getLogger();

  private final HttpResponseFactory httpResponseFactory;
  private final JsonErrorHandler jsonErrorHandler = new JsonErrorHandler();

  public JsonRpcErrorHandler(final HttpResponseFactory httpResponseFactory) {
    this.httpResponseFactory = httpResponseFactory;
  }

  @Override
  public void handle(final RoutingContext context) {
    final JsonRpcRequestId requestId = context.get(JsonRpcHandler.ID_ELEMENT_NAME);
    final int statusCode =
        context.statusCode() == -1 ? INTERNAL_SERVER_ERROR.code() : context.statusCode();

    final Throwable failure = context.failure();
    if (failure == null || failure instanceof ErrorResponseException) {
      // Not a JSON-RPC level failure: a platform rejection (e.g. CORS) or a handler that supplied
      // a client-facing message (e.g. host allow-list) which merely matched this route. Render it
      // like every other HTTP API failure instead of an id-less JSON-RPC envelope.
      jsonErrorHandler.handle(context);
      return;
    }

    if (failure instanceof JsonRpcException jsonRpcException) {
      httpResponseFactory.failureResponse(
          context.response(), requestId, statusCode, jsonRpcException.getJsonRpcError());
    } else if (failure instanceof ConnectException || failure instanceof SSLException) {
      httpResponseFactory.failureResponse(
          context.response(),
          requestId,
          statusCode,
          JsonRpcError.FAILED_TO_CONNECT_TO_DOWNSTREAM_NODE);
    } else if (failure instanceof TimeoutException) {
      httpResponseFactory.failureResponse(
          context.response(),
          requestId,
          statusCode,
          JsonRpcError.CONNECTION_TO_DOWNSTREAM_NODE_TIMED_OUT);
    } else if ((failure instanceof IllegalStateException || failure instanceof VertxException)
        && statusCode == HttpResponseStatus.FORBIDDEN.code()) {
      // send status code and empty body
      context.response().setStatusCode(statusCode);
      context.response().end();
    } else {
      LOG.error("Unhandled exception handling request", failure);
      httpResponseFactory.failureResponse(
          context.response(), requestId, statusCode, JsonRpcError.INTERNAL_ERROR);
    }
  }
}
