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
package tech.pegasys.web3signer.core.service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpClientResponse;
import io.vertx.core.http.HttpMethod;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class VertxRequestTransmitter implements RequestTransmitter {

  private static final Logger LOG = LogManager.getLogger();

  private final Vertx vertx;
  private final Duration httpRequestTimeout;
  private final DownstreamResponseHandler bodyHandler;
  private final HttpClient downStreamConnection;
  private final DownstreamPathCalculator downstreamPathCalculator;
  private final AtomicBoolean responseHandled = new AtomicBoolean(false);

  public VertxRequestTransmitter(
      final Vertx vertx,
      final HttpClient downStreamConnection,
      final Duration httpRequestTimeout,
      final DownstreamPathCalculator downstreamPathCalculator,
      final DownstreamResponseHandler bodyHandler) {
    this.vertx = vertx;
    this.httpRequestTimeout = httpRequestTimeout;
    this.bodyHandler = bodyHandler;
    this.downStreamConnection = downStreamConnection;
    this.downstreamPathCalculator = downstreamPathCalculator;
  }

  @Override
  public void sendRequest(
      final HttpMethod method,
      final Iterable<Entry<String, String>> headers,
      final String path,
      final String body) {
    LOG.debug(
        "Sending headers {} and request {} to {} ",
        () ->
            StreamSupport.stream(headers.spliterator(), false)
                .map(Objects::toString)
                .collect(Collectors.joining(", ")),
        () -> body,
        () -> path);

    final String fullPath = downstreamPathCalculator.calculateDownstreamPath(path);
    downStreamConnection
        .request(method, fullPath)
        .onSuccess(
            request -> {
              request.response().onSuccess(this::handleResponse).onFailure(this::handleException);
              request.idleTimeout(httpRequestTimeout.toMillis());
              request.exceptionHandler(this::handleException);
              headers.forEach(entry -> request.headers().add(entry.getKey(), entry.getValue()));
              request.setChunked(false);
              request.end(body);
            })
        .onFailure(this::handleException);
  }

  private void handleException(final Throwable thrown) {
    LOG.error("Transmission failed", thrown);
    if (!responseHandled.getAndSet(true)) {
      vertx
          .executeBlocking(
              () -> {
                bodyHandler.handleFailure(thrown);
                return null;
              },
              false)
          .onComplete(
              res -> {
                if (res.failed()) {
                  LOG.error("Reporting failure, failed", res.cause());
                }
              });
    }
  }

  private void handleResponse(final HttpClientResponse response) {
    responseHandled.set(true);
    logResponse(response);
    response.bodyHandler(
        body ->
            vertx
                .executeBlocking(
                    () -> {
                      bodyHandler.handleResponse(
                          response.headers(),
                          response.statusCode(),
                          body.toString(StandardCharsets.UTF_8));
                      return null;
                    },
                    false)
                .onComplete(
                    res -> {
                      if (res.failed()) {
                        final Throwable t = res.cause();
                        LOG.error("An unhandled error occurred while processing a response", t);
                        bodyHandler.handleFailure(t);
                      }
                    }));
  }

  private void logResponse(final HttpClientResponse response) {
    LOG.debug("Response status: {}", response.statusCode());
  }
}
