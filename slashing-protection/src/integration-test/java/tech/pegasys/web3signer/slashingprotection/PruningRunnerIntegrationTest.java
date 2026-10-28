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
package tech.pegasys.web3signer.slashingprotection;

import static db.DatabaseUtil.PASSWORD;
import static db.DatabaseUtil.USERNAME;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.common.util.concurrent.ThreadFactoryBuilder;
import dsl.TestSlashingProtectionParameters;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class PruningRunnerIntegrationTest extends IntegrationTestBase {

  public static final String PRUNING_THREAD_NAME = "slashing-db-pruner-0";
  private ScheduledExecutorService scheduledExecutorService;
  private TestSlashingProtectionParameters slashingProtectionParameters;
  private SlashingProtectionContext pruningSlashingProtectionContext;

  @BeforeEach
  void setupSlashingProtection() {
    slashingProtectionParameters =
        new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 5, 1);
    scheduledExecutorService =
        new ScheduledThreadPoolExecutor(
            1, new ThreadFactoryBuilder().setNameFormat("slashing-db-pruner" + "-%d").build());
    pruningSlashingProtectionContext =
        SlashingProtectionContextFactory.create(slashingProtectionParameters);
    insertValidatorAndCreateSlashingData(
        pruningSlashingProtectionContext.getRegisteredValidators(), 10, 10, 1);
  }

  @AfterEach
  void tearDownSlashingProtection() {
    scheduledExecutorService.shutdownNow();
  }

  @Test
  void prunesValidatorsForExecuteOnOwnThread() {
    final TestSlashingProtectionPruner testSlashingProtectionPruner =
        new TestSlashingProtectionPruner(pruningSlashingProtectionContext.getPruner());
    final DbPrunerRunner dbPrunerRunner =
        new DbPrunerRunner(
            slashingProtectionParameters, testSlashingProtectionPruner, scheduledExecutorService);

    dbPrunerRunner.execute();

    final List<PruningStat> pruningStats = testSlashingProtectionPruner.getPruningStats();
    waitForPruningToFinish(pruningStats, 1);
    assertThat(pruningStats.get(0).getThread().getName()).isEqualTo(PRUNING_THREAD_NAME);
    assertThat(fetchAttestations(1)).hasSize(5);
    assertThat(fetchBlocks(1)).hasSize(5);
  }

  @Test
  void prunesValidatorsForExecuteHandlesErrors() {
    final TestSlashingProtectionPruner testSlashingProtectionPruner =
        new TestSlashingProtectionPruner(createPrunerRunnerThatFailsOnFirstRun());
    final DbPrunerRunner dbPrunerRunner =
        new DbPrunerRunner(
            slashingProtectionParameters, testSlashingProtectionPruner, scheduledExecutorService);

    // run expecting error to occur and no pruning to happen
    dbPrunerRunner.execute();

    final List<PruningStat> pruningStats = testSlashingProtectionPruner.getPruningStats();
    waitForPruningToFinish(pruningStats, 1);
    final Set<Thread> currentThreads = Thread.getAllStackTraces().keySet();
    assertThat(currentThreads.stream().anyMatch(t -> t.getName().equals(PRUNING_THREAD_NAME)))
        .isTrue();
    assertThat(fetchAttestations(1)).hasSize(10);
    assertThat(fetchBlocks(1)).hasSize(10);

    // ensure that pruning still works after the failed execution
    dbPrunerRunner.execute();

    waitForPruningToFinish(pruningStats, 2);
    assertThat(pruningStats.get(1).getThread().getName()).isEqualTo(PRUNING_THREAD_NAME);
    assertThat(fetchAttestations(1)).hasSize(5);
    assertThat(fetchBlocks(1)).hasSize(5);
  }

  private Runnable createPrunerRunnerThatFailsOnFirstRun() {
    final AtomicInteger pruningCount = new AtomicInteger(0);
    return () -> {
      if (pruningCount.addAndGet(1) == 1) {
        throw new IllegalStateException("Pruning failed");
      } else {
        pruningSlashingProtectionContext.getPruner().prune();
      }
    };
  }

  @Test
  void prunesValidatorsForScheduledRunAreRunPeriodically() {
    final SlashingProtectionParameters slashingProtectionParameters =
        new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 5, 1, 1);
    final TestSlashingProtectionPruner testSlashingProtectionPruner =
        new TestSlashingProtectionPruner(createPrunerRunnerThatFailsOnFirstRun());
    final DbPrunerRunner dbPrunerRunner =
        new DbPrunerRunner(
            slashingProtectionParameters, testSlashingProtectionPruner, scheduledExecutorService);

    dbPrunerRunner.schedule();

    final List<PruningStat> pruningStats = testSlashingProtectionPruner.getPruningStats();
    waitForPruningToFinish(pruningStats, 3);
    assertThat(
            pruningStats.stream()
                .allMatch(ps -> ps.getThread().getName().equals(PRUNING_THREAD_NAME)))
        .isTrue();
    final LocalDateTime firstPruningStartTime = pruningStats.get(0).getStartTime();
    assertThat(pruningStats.get(1).getStartTime())
        .isEqualToIgnoringNanos(firstPruningStartTime.plusSeconds(1));
    assertThat(pruningStats.get(2).getStartTime())
        .isEqualToIgnoringNanos(firstPruningStartTime.plusSeconds(2));
    assertThat(fetchAttestations(1)).hasSize(5);
    assertThat(fetchBlocks(1)).hasSize(5);
  }

  @Test
  void prunesValidatorsForScheduledRunHandlesErrors() {
    final SlashingProtectionParameters slashingProtectionParameters =
        new TestSlashingProtectionParameters(databaseUrl, USERNAME, PASSWORD, 5, 1, 1);
    final TestSlashingProtectionPruner testSlashingProtectionPruner =
        new TestSlashingProtectionPruner(pruningSlashingProtectionContext.getPruner());
    final DbPrunerRunner dbPrunerRunner =
        new DbPrunerRunner(
            slashingProtectionParameters, testSlashingProtectionPruner, scheduledExecutorService);

    dbPrunerRunner.schedule();

    final List<PruningStat> pruningStats = testSlashingProtectionPruner.getPruningStats();
    waitForPruningToFinish(pruningStats, 2);
    assertThat(
            pruningStats.stream()
                .allMatch(ps -> ps.getThread().getName().equals(PRUNING_THREAD_NAME)))
        .isTrue();
    final LocalDateTime firstPruningStartTime = pruningStats.get(0).getStartTime();
    assertThat(pruningStats.get(1).getStartTime())
        .isEqualToIgnoringNanos(firstPruningStartTime.plusSeconds(1));
    assertThat(fetchAttestations(1)).hasSize(5);
    assertThat(fetchBlocks(1)).hasSize(5);
  }

  private void waitForPruningToFinish(final List<PruningStat> pruningStats, final int pruningSize) {
    Awaitility.await()
        .ignoreExceptions()
        .atMost(30, TimeUnit.SECONDS)
        .untilAsserted(() -> assertThat(pruningStats).hasSize(pruningSize));
  }

  private static class TestSlashingProtectionPruner implements SlashingProtectionPruner {

    private final Runnable pruningRunner;
    private final List<PruningStat> pruningStats = new ArrayList<>();

    TestSlashingProtectionPruner(final SlashingProtectionPruner pruner) {
      this.pruningRunner = pruner::prune;
    }

    TestSlashingProtectionPruner(final Runnable runnable) {
      this.pruningRunner = runnable;
    }

    @Override
    public void prune() {
      final Thread currentThread = Thread.currentThread();
      final LocalDateTime currentTime = LocalDateTime.now(ZoneId.systemDefault());
      pruningStats.add(new PruningStat(currentThread, currentTime));
      pruningRunner.run();
    }

    List<PruningStat> getPruningStats() {
      return pruningStats;
    }
  }

  private static class PruningStat {
    private final Thread thread;
    private final LocalDateTime startTime;

    PruningStat(final Thread thread, final LocalDateTime startTime) {
      this.thread = thread;
      this.startTime = startTime;
    }

    Thread getThread() {
      return thread;
    }

    LocalDateTime getStartTime() {
      return startTime;
    }
  }
}
