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
package tech.pegasys.web3signer.core.service.http.handlers;

import static io.vertx.core.http.HttpHeaders.CONTENT_TYPE;
import static java.net.HttpURLConnection.HTTP_ACCEPTED;
import static java.net.HttpURLConnection.HTTP_CONFLICT;
import static tech.pegasys.web3signer.core.service.http.handlers.ContentTypes.JSON_UTF_8;

import tech.pegasys.web3signer.signing.ArtifactSignerProvider;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import io.vertx.core.Handler;
import io.vertx.core.WorkerExecutor;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ReloadHandler implements Handler<RoutingContext> {
  private static final Logger LOG = LogManager.getLogger();

  public enum ReloadStatus {
    IDLE,
    RUNNING,
    COMPLETED,
    COMPLETED_WITH_ERRORS,
    FAILED
  }

  private final List<ArtifactSignerProvider> orderedArtifactSignerProviders;
  private final WorkerExecutor workerExecutor;
  private final AtomicBoolean reloadInProgress = new AtomicBoolean(false);
  private final AtomicReference<ReloadStatus> currentStatus =
      new AtomicReference<>(ReloadStatus.IDLE);
  private final AtomicReference<String> lastErrorMessage = new AtomicReference<>();
  private final AtomicReference<Instant> lastOperationTime = new AtomicReference<>();

  public ReloadHandler(
      final List<ArtifactSignerProvider> orderedArtifactSignerProviders,
      final WorkerExecutor workerExecutor) {
    this.orderedArtifactSignerProviders = orderedArtifactSignerProviders;
    this.workerExecutor = workerExecutor;
  }

  @Override
  public void handle(final RoutingContext routingContext) {
    // ReloadRoute binds only GET and POST
    if (routingContext.request().method().equals(HttpMethod.GET)) {
      handleStatusRequest(routingContext);
    } else {
      handleReloadRequest(routingContext);
    }
  }

  private void handleStatusRequest(final RoutingContext routingContext) {
    final Map<String, Object> statusResponse = new HashMap<>();
    statusResponse.put("status", currentStatus.get().name().toLowerCase(Locale.ENGLISH));

    final Instant lastOpTime = lastOperationTime.get();
    if (lastOpTime != null) {
      statusResponse.put("lastOperationTime", lastOpTime.toString());
    }

    final String errorMsg = lastErrorMessage.get();
    if (errorMsg != null) {
      statusResponse.put("lastError", errorMsg);
    }

    routingContext
        .response()
        .setStatusCode(200)
        .putHeader("Content-Type", "application/json")
        .end(Json.encode(statusResponse));
  }

  private void handleReloadRequest(final RoutingContext routingContext) {
    // Check if reload is already in progress
    if (!reloadInProgress.compareAndSet(false, true)) {
      routingContext.fail(
          HTTP_CONFLICT,
          new ErrorResponseException(
              "A reload operation is already in progress. Please try again later."));
      return;
    }

    LOG.debug("Reload operation initiated");
    currentStatus.set(ReloadStatus.RUNNING);
    lastOperationTime.set(Instant.now());
    lastErrorMessage.set(null); // Clear previous error

    try {
      workerExecutor
          .executeBlocking(
              () -> {
                long totalErrors = 0L;
                for (ArtifactSignerProvider signerProvider : orderedArtifactSignerProviders) {
                  try {
                    Long errorCount = signerProvider.load().get();
                    totalErrors += errorCount;
                  } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    LOG.error("Interrupted while reloading signer", e);
                    throw new RuntimeException("Reload interrupted", e);
                  } catch (final ExecutionException e) {
                    LOG.error("Error reloading signer", e);
                    throw new RuntimeException("Reload failed", e);
                  }
                }
                return totalErrors;
              },
              false) // unordered is fine since we have pool size 1
          .onSuccess(
              totalErrors -> {
                lastOperationTime.set(Instant.now());

                if (totalErrors > 0) {
                  // Completed with errors
                  currentStatus.set(ReloadStatus.COMPLETED_WITH_ERRORS);
                  lastErrorMessage.set(
                      String.format(
                          "Reload completed with %d signer loading error(s)", totalErrors));
                  LOG.warn("Reload operation completed with {} errors", totalErrors);
                } else {
                  // Completed successfully
                  currentStatus.set(ReloadStatus.COMPLETED);
                  LOG.info("Reload operation completed successfully");
                }
                reloadInProgress.set(false);
              })
          .onFailure(
              err -> {
                currentStatus.set(ReloadStatus.FAILED);
                lastErrorMessage.set(err.getMessage());
                lastOperationTime.set(Instant.now());
                LOG.error("Reload operation failed", err);
                reloadInProgress.set(false);
              });

      // Respond immediately - reload happens in background
      routingContext
          .response()
          .setStatusCode(HTTP_ACCEPTED)
          .putHeader(CONTENT_TYPE, JSON_UTF_8)
          .end(
              new JsonObject()
                  .put("code", HTTP_ACCEPTED)
                  .put(
                      "message",
                      "Reload operation accepted and is running in the background. Use GET /reload to check status.")
                  .encode());
    } catch (final RuntimeException e) {
      // Reset flag and state if executeBlocking throws synchronously
      currentStatus.set(ReloadStatus.FAILED);
      lastErrorMessage.set(e.getMessage());
      lastOperationTime.set(Instant.now());
      LOG.error("Failed to submit reload operation", e);
      reloadInProgress.set(false);
      throw e;
    }
  }
}
