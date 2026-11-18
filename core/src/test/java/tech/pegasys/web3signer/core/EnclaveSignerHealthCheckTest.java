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

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.web3signer.enclave.host.EnclaveTestKeys;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;
import tech.pegasys.web3signer.signing.bulkloading.BlsEnclaveBulkLoader;
import tech.pegasys.web3signer.signing.config.EnclaveSignerParameters;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import io.vertx.core.Promise;
import io.vertx.ext.healthchecks.Status;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class EnclaveSignerHealthCheckTest {
  private final ExecutorService executor = Executors.newSingleThreadExecutor();

  private record Parameters(String address) implements EnclaveSignerParameters {
    @Override
    public boolean isEnabled() {
      return true;
    }

    @Override
    public String getAddress() {
      return address;
    }

    @Override
    public int getConnections() {
      return 1;
    }

    @Override
    public int getMaxBatch() {
      return 8;
    }

    @Override
    public int getRequestTimeoutMillis() {
      return 2000;
    }
  }

  @AfterEach
  void tearDown() {
    executor.shutdownNow();
  }

  @Test
  void upWithKeysAndBootIdWhileTheEnclaveAnswersThenDownOnceItIsStopped() throws Exception {
    final InProcessEnclaveSigner enclave = new InProcessEnclaveSigner();
    try (BlsEnclaveBulkLoader loader =
        new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      EnclaveTestKeys.provision(enclave.address(), EnclaveTestKeys.randomKeys(2));
      final EnclaveSignerHealthCheck check = new EnclaveSignerHealthCheck(loader, executor);

      final Status up = run(check);
      assertThat(up.isOk()).isTrue();
      assertThat(up.getData().getLong("keys")).isEqualTo(2);
      assertThat(up.getData().getString("boot-id")).matches("[0-9a-f]{32}");

      enclave.close();

      final Status down = run(check);
      assertThat(down.isOk()).isFalse();
      assertThat(down.getData().getString("error")).startsWith("Signer unavailable: ");
    } finally {
      enclave.close();
    }
  }

  @Test
  void downWhileTheEnclaveHoldsNoKeys() throws Exception {
    try (InProcessEnclaveSigner enclave = new InProcessEnclaveSigner();
        BlsEnclaveBulkLoader loader =
            new BlsEnclaveBulkLoader(new Parameters(enclave.address().toString()))) {
      final Status status = run(new EnclaveSignerHealthCheck(loader, executor));

      assertThat(status.isOk()).isFalse();
      assertThat(status.getData().getLong("keys")).isZero();
    }
  }

  private static Status run(final EnclaveSignerHealthCheck check) throws Exception {
    final Promise<Status> promise = Promise.promise();
    check.handle(promise);
    return promise.future().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
  }
}
