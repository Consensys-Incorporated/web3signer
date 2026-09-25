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

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

class TenantDekCacheTest {

  @Test
  void resolverIsInvokedOnceThenCachedForSameTenantAndVersion() {
    final TenantDekCache cache = new TenantDekCache(Duration.ofMinutes(15));
    final AtomicInteger resolveCount = new AtomicInteger();

    final TenantDek first = cache.getOrLoad("tenant-a", 1, () -> resolve(resolveCount));
    final TenantDek second = cache.getOrLoad("tenant-a", 1, () -> resolve(resolveCount));

    assertThat(first).isSameAs(second);
    assertThat(resolveCount).hasValue(1);
  }

  @Test
  void differentTenantsResolveIndependently() {
    final TenantDekCache cache = new TenantDekCache(Duration.ofMinutes(15));
    final AtomicInteger resolveCount = new AtomicInteger();

    cache.getOrLoad("tenant-a", 1, () -> resolve(resolveCount));
    cache.getOrLoad("tenant-b", 1, () -> resolve(resolveCount));

    assertThat(resolveCount).hasValue(2);
  }

  @Test
  void dekVersionBumpForcesReResolution() {
    final TenantDekCache cache = new TenantDekCache(Duration.ofMinutes(15));
    final AtomicInteger resolveCount = new AtomicInteger();

    cache.getOrLoad("tenant-a", 1, () -> resolve(resolveCount));
    cache.getOrLoad("tenant-a", 2, () -> resolve(resolveCount));

    assertThat(resolveCount).hasValue(2);
  }

  @Test
  void closeWipesAllCachedDeks() {
    final TenantDekCache cache = new TenantDekCache(Duration.ofMinutes(15));
    final byte[] keyBytes = {1, 2, 3, 4};
    cache.getOrLoad("tenant-a", 1, () -> keyBytes);

    cache.close();

    assertThat(keyBytes).containsOnly(0);
  }

  private static byte[] resolve(final AtomicInteger resolveCount) {
    resolveCount.incrementAndGet();
    return new byte[] {1, 2, 3, 4};
  }
}
