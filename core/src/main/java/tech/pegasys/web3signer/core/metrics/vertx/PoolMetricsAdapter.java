/*
 * Copyright 2021 ConsenSys AG.
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
package tech.pegasys.web3signer.core.metrics.vertx;

import tech.pegasys.web3signer.common.Web3SignerMetricCategory;

import io.vertx.core.spi.metrics.PoolMetrics;
import org.hyperledger.besu.plugin.services.MetricsSystem;
import org.hyperledger.besu.plugin.services.metrics.Counter;
import org.hyperledger.besu.plugin.services.metrics.OperationTimer;
import org.hyperledger.besu.plugin.services.metrics.OperationTimer.TimingContext;

/**
 * Vert.x 5's pool metrics SPI replaced {@code submitted}/{@code rejected} with {@code
 * enqueue}/{@code dequeue}, and no longer distinguishes a rejected task: {@code dequeue} is invoked
 * both when a queued task starts executing and when it is rejected. The worker-pool rejected-task
 * counter was dropped accordingly, matching Vert.x's own metrics implementation.
 */
public final class PoolMetricsAdapter implements PoolMetrics<TimingContext, TimingContext> {

  private final Counter submittedCounter;
  private final Counter completedCounter;
  private final OperationTimer queueDelay;
  private final OperationTimer poolUsage;

  public PoolMetricsAdapter(
      final MetricsSystem metricsSystem, final String poolType, final String poolName) {
    submittedCounter =
        metricsSystem
            .createLabelledCounter(
                Web3SignerMetricCategory.HTTP,
                "vertx_worker_pool_submitted_total",
                "Total number of tasks submitted to the Vertx worker pool",
                "poolType",
                "poolName")
            .labels(poolType, poolName);

    completedCounter =
        metricsSystem
            .createLabelledCounter(
                Web3SignerMetricCategory.HTTP,
                "vertx_worker_pool_completed_total",
                "Total number of tasks completed by the Vertx worker pool",
                "poolType",
                "poolName")
            .labels(poolType, poolName);

    queueDelay =
        metricsSystem
            .createLabelledTimer(
                Web3SignerMetricCategory.HTTP,
                "vertx_worker_queue_delay",
                "Time spent in queue before being processed by the Vertx worker pool",
                "poolType",
                "poolName")
            .labels(poolType, poolName);

    poolUsage =
        metricsSystem
            .createLabelledTimer(
                Web3SignerMetricCategory.HTTP,
                "vertx_worker_pool_usage",
                "Time spent in the Vertx worker pool",
                "poolType",
                "poolName")
            .labels(poolType, poolName);
  }

  @Override
  public TimingContext enqueue() {
    submittedCounter.inc();
    return queueDelay.startTimer();
  }

  @Override
  public void dequeue(final TimingContext queueTimerContext) {
    queueTimerContext.stopTimer();
  }

  @Override
  public TimingContext begin() {
    return poolUsage.startTimer();
  }

  @Override
  public void end(final TimingContext usageTimerContext) {
    completedCounter.inc();
    usageTimerContext.stopTimer();
  }
}
