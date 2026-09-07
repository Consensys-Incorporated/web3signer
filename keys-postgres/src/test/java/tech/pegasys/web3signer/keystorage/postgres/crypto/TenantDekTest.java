/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.Test;

class TenantDekTest {

  @Test
  void wipeZeroesKeyBytesWhenNoActiveLease() {
    final byte[] keyBytes = {1, 2, 3, 4};
    final TenantDek dek = new TenantDek(keyBytes);

    dek.markForWipeAndAttempt();

    assertThat(keyBytes).containsOnly(0);
  }

  @Test
  void leaseExposesTheUnderlyingBytesUntilClosed() {
    final byte[] keyBytes = {1, 2, 3, 4};
    final TenantDek dek = new TenantDek(keyBytes);

    try (final TenantDek.Lease lease = dek.acquireForRead()) {
      assertThat(lease.keyBytes()).isEqualTo(keyBytes);
    }
  }

  @Test
  void wipeIsDeferredWhileALeaseIsHeld() throws InterruptedException {
    final byte[] keyBytes = {1, 2, 3, 4};
    final TenantDek dek = new TenantDek(keyBytes);
    final CountDownLatch wipeAttempted = new CountDownLatch(1);
    final ExecutorService executor = Executors.newSingleThreadExecutor();

    try (final TenantDek.Lease lease = dek.acquireForRead()) {
      executor.submit(
          () -> {
            dek.markForWipeAndAttempt();
            wipeAttempted.countDown();
          });
      wipeAttempted.await();

      // the wipe attempt ran, but could not acquire the write lock while the lease is held
      assertThat(keyBytes).isNotEqualTo(new byte[] {0, 0, 0, 0});
      assertThat(lease.keyBytes()).isEqualTo(new byte[] {1, 2, 3, 4});
    }

    // closing the lease retries the wipe, which now succeeds
    await().atMost(Duration.ofSeconds(5)).untilAsserted(() -> assertThat(keyBytes).containsOnly(0));

    executor.shutdownNow();
  }

  @Test
  void newLeasesAreRejectedOncePendingWipe() {
    final TenantDek dek = new TenantDek(new byte[] {1, 2, 3, 4});
    dek.markForWipeAndAttempt();

    assertThatThrownBy(dek::acquireForRead).isInstanceOf(IllegalStateException.class);
  }
}
