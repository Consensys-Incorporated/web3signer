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

import java.time.Duration;
import java.util.function.Supplier;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;

/**
 * Caches resolved tenant DEKs for a configurable TTL, keyed by {@code (tenantId, dekVersion)} -
 * keying on the DEK version (rather than tenant alone) means a DEK rotation is automatically a
 * cache miss instead of silently serving a stale DEK for up to the remainder of the TTL window.
 *
 * <p>A cache hit means zero vault calls for that tenant on a subsequent load/reload within the TTL
 * window - this is the mechanism behind the sub-100ms tenant-scoped reload target.
 */
public final class TenantDekCache implements AutoCloseable {

  public record TenantDekKey(String tenantId, int dekVersion) {}

  private final Cache<TenantDekKey, TenantDek> cache;

  public TenantDekCache(final Duration ttl) {
    this.cache =
        Caffeine.newBuilder()
            .expireAfterWrite(ttl)
            .removalListener(
                (final TenantDekKey key, final TenantDek value, final RemovalCause cause) -> {
                  if (value != null) {
                    value.markForWipeAndAttempt();
                  }
                })
            .build();
  }

  /**
   * Returns the cached DEK for the given tenant/version, resolving (and caching) it via {@code
   * resolver} on a cache miss. Caffeine guarantees {@code resolver} runs at most once per key even
   * under concurrent callers.
   */
  public TenantDek getOrLoad(
      final String tenantId, final int dekVersion, final Supplier<byte[]> resolver) {
    return cache.get(new TenantDekKey(tenantId, dekVersion), key -> new TenantDek(resolver.get()));
  }

  @Override
  public void close() {
    cache.asMap().values().forEach(TenantDek::markForWipeAndAttempt);
    cache.invalidateAll();
  }
}
