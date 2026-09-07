/*
 * Copyright 2026 ConsenSys AG.
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

import tech.pegasys.web3signer.common.config.SignerLoaderConfig;
import tech.pegasys.web3signer.core.config.BaseConfig;
import tech.pegasys.web3signer.core.config.MetricsPushOptions;
import tech.pegasys.web3signer.core.config.TlsOptions;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;

import java.io.FileInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

import io.vertx.core.Vertx;
import org.hyperledger.besu.plugin.services.MetricsSystem;
import org.hyperledger.besu.plugin.services.metrics.MetricCategory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RunnerGracefulShutdownTest {

  @TempDir Path dataPath;

  private static class StubBaseConfig implements BaseConfig {
    private final Path dataPath;

    StubBaseConfig(final Path dataPath) {
      this.dataPath = dataPath;
    }

    @Override
    public String getHttpListenHost() {
      return "127.0.0.1";
    }

    @Override
    public Integer getHttpListenPort() {
      return 0;
    }

    @Override
    public List<String> getHttpHostAllowList() {
      return List.of("*");
    }

    @Override
    public Collection<String> getCorsAllowedOrigins() {
      return List.of();
    }

    @Override
    public Path getDataPath() {
      return dataPath;
    }

    @Override
    public Path getKeyConfigPath() {
      return dataPath;
    }

    @Override
    public int getKeyStoreConfigFileMaxSize() {
      return 104_857_600;
    }

    @Override
    public Boolean isMetricsEnabled() {
      return false;
    }

    @Override
    public Integer getMetricsPort() {
      return 0;
    }

    @Override
    public String getMetricsNetworkInterface() {
      return "127.0.0.1";
    }

    @Override
    public Set<MetricCategory> getMetricCategories() {
      return Set.of();
    }

    @Override
    public List<String> getMetricsHostAllowList() {
      return List.of();
    }

    @Override
    public Optional<MetricsPushOptions> getMetricsPushOptions() {
      return Optional.empty();
    }

    @Override
    public Optional<TlsOptions> getTlsOptions() {
      return Optional.empty();
    }

    @Override
    public int getIdleConnectionTimeoutSeconds() {
      return 30;
    }

    @Override
    public void validateArgs() {}

    @Override
    public Boolean isAccessLogsEnabled() {
      return false;
    }

    @Override
    public int getVertxWorkerPoolSize() {
      return 5;
    }

    @Override
    public SignerLoaderConfig getSignerLoaderConfig() {
      return SignerLoaderConfig.withDefaults(dataPath);
    }

    @Override
    public long getReloadTimeoutMinutes() {
      return 30L;
    }
  }

  private static class TestRunner extends Runner {
    private final Consumer<Context> routePopulator;

    TestRunner(final BaseConfig config, final Consumer<Context> routePopulator) {
      super(config);
      this.routePopulator = routePopulator;
    }

    @Override
    protected List<ArtifactSignerProvider> createArtifactSignerProvider(
        final Vertx vertx, final MetricsSystem metricsSystem) {
      return List.of();
    }

    @Override
    protected void populateRouter(final Context context) {
      routePopulator.accept(context);
    }
  }

  private int readHttpPort() throws Exception {
    final Path portsFile = dataPath.resolve("web3signer.ports");
    final Properties props = new Properties();
    try (final FileInputStream fis = new FileInputStream(portsFile.toFile())) {
      props.load(fis);
    }
    return Integer.parseInt(props.getProperty("http-port"));
  }

  @Test
  void closeWaitsForInFlightRequestBeforeShuttingDown() throws Exception {
    final CountDownLatch requestStarted = new CountDownLatch(1);
    final CountDownLatch requestCanComplete = new CountDownLatch(1);
    final AtomicBoolean requestHandlerCompleted = new AtomicBoolean(false);

    final TestRunner runner =
        new TestRunner(
            new StubBaseConfig(dataPath),
            context ->
                context
                    .getRouter()
                    .route("/slow")
                    .blockingHandler(
                        rc -> {
                          requestStarted.countDown();
                          try {
                            requestCanComplete.await(10, TimeUnit.SECONDS);
                          } catch (final InterruptedException e) {
                            Thread.currentThread().interrupt();
                          }
                          requestHandlerCompleted.set(true);
                          rc.response().setStatusCode(200).end("ok");
                        }));

    runner.run();
    final int port = readHttpPort();

    // Send a slow request that blocks in the handler until signalled
    CompletableFuture.runAsync(
        () -> {
          try {
            HttpClient.newHttpClient()
                .send(
                    HttpRequest.newBuilder()
                        .uri(URI.create("http://127.0.0.1:" + port + "/slow"))
                        .build(),
                    HttpResponse.BodyHandlers.discarding());
          } catch (final Exception ignored) {
            // Connection may close during shutdown — expected
          }
        });

    assertThat(requestStarted.await(5, TimeUnit.SECONDS))
        .as("request handler should start within 5 seconds")
        .isTrue();

    // Trigger close in a separate thread — it should block until the in-flight request finishes
    final CompletableFuture<Void> closeFuture =
        CompletableFuture.runAsync(
            () -> {
              try {
                runner.close();
              } catch (final Exception e) {
                throw new RuntimeException(e);
              }
            });

    // Verify close() is actually blocking — it must not return while the request is in-flight
    try {
      closeFuture.get(200, TimeUnit.MILLISECONDS);
      throw new AssertionError("close() returned immediately — it should have waited for the in-flight request");
    } catch (final TimeoutException expected) {
      // correct: close() is blocked waiting for the in-flight request
    }

    // Release the in-flight request
    requestCanComplete.countDown();

    closeFuture.get(15, TimeUnit.SECONDS);

    assertThat(requestHandlerCompleted.get())
        .as("request handler must complete before close() returns")
        .isTrue();
  }

  @Test
  void closeCompletesNormallyWithNoInFlightRequests() throws Exception {
    final TestRunner runner = new TestRunner(new StubBaseConfig(dataPath), context -> {});
    runner.run();
    runner.close();
  }

  @Test
  void closeBeforeRunDoesNotThrow() throws Exception {
    final TestRunner runner = new TestRunner(new StubBaseConfig(dataPath), context -> {});
    runner.close();
  }
}
