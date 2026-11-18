/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.core;

import tech.pegasys.web3signer.signing.bulkloading.BlsEnclaveBulkLoader;
import tech.pegasys.web3signer.signing.bulkloading.BlsEnclaveBulkLoader.EnclaveSignerStatus;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicReference;

import io.vertx.core.Context;
import io.vertx.core.Handler;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.healthchecks.Status;

/**
 * Live health check of the enclave signer: asks it for {@code STATUS} on every check. UP with
 * {@code {"keys": <count>, "boot-id": <hex>}} when it answers and holds keys, DOWN otherwise, with
 * {@code {"error": <message>}} when the check itself fails.
 *
 * <p>The blocking {@code STATUS} call runs on {@code executor}, never on the event loop, and checks
 * that arrive while one is running share its result, so a hung enclave signer occupies one thread
 * at most. Register it with {@link #TIMEOUT_MILLIS}, which bounds how long a request waits.
 */
public class EnclaveSignerHealthCheck implements Handler<Promise<Status>> {
  /**
   * Health check procedure timeout. {@link BlsEnclaveBulkLoader#status()} tries twice; each try is
   * bounded by about 1 s (500 ms write and read) against a hung enclave signer and by about 2 s
   * (the kernel's vsock connect timeout) against a missing one, so a DOWN answer arrives within 4
   * s.
   */
  public static final long TIMEOUT_MILLIS = 5_000;

  private final BlsEnclaveBulkLoader enclave;
  private final Executor executor;
  private final AtomicReference<CompletableFuture<Status>> running = new AtomicReference<>();

  public EnclaveSignerHealthCheck(final BlsEnclaveBulkLoader enclave, final Executor executor) {
    this.enclave = enclave;
    this.executor = executor;
  }

  @Override
  public void handle(final Promise<Status> promise) {
    final Context context = Vertx.currentContext();
    check()
        .whenComplete(
            (result, failure) -> {
              final Status status = failure == null ? result : down(failure);
              if (context == null) {
                promise.tryComplete(status);
              } else {
                context.runOnContext(ignored -> promise.tryComplete(status));
              }
            });
  }

  private CompletableFuture<Status> check() {
    final CompletableFuture<Status> next = new CompletableFuture<>();
    final CompletableFuture<Status> current = running.compareAndExchange(null, next);
    if (current != null) {
      return current;
    }
    try {
      executor.execute(
          () -> {
            try {
              finish(next, probe());
            } catch (final Throwable e) {
              finish(next, down(e));
              throw e;
            }
          });
    } catch (final RejectedExecutionException e) {
      finish(next, Status.KO(new JsonObject().put("error", "Health check is shut down")));
    }
    return next;
  }

  private void finish(final CompletableFuture<Status> probe, final Status status) {
    running.compareAndSet(probe, null);
    probe.complete(status);
  }

  private Status probe() {
    try {
      final EnclaveSignerStatus status = enclave.status();
      final JsonObject data =
          new JsonObject().put("keys", status.keyCount()).put("boot-id", status.bootId());
      return status.keyCount() > 0 ? Status.OK(data) : Status.KO(data);
    } catch (final RuntimeException e) {
      return down(e);
    }
  }

  private static Status down(final Throwable failure) {
    final String message = failure.getMessage();
    return Status.KO(new JsonObject().put("error", message != null ? message : failure.toString()));
  }
}
