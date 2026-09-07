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
package tech.pegasys.web3signer.keystorage.postgres;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.keystorage.postgres.crypto.AadCodec;
import tech.pegasys.web3signer.keystorage.postgres.crypto.AesGcmKeyCipher;
import tech.pegasys.web3signer.keystorage.postgres.crypto.TenantDek;
import tech.pegasys.web3signer.keystorage.postgres.crypto.TenantDekCache;
import tech.pegasys.web3signer.keystorage.postgres.kek.KekResolver;

import java.io.Closeable;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import javax.sql.DataSource;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

/**
 * Bulk-loads and decrypts every BLS key from the postgres keystore in a single streaming pass,
 * making exactly one vault call per distinct tenant encountered (via the long-lived {@link
 * TenantDekCache} shared across calls to {@link #loadAll()}).
 *
 * <p>Long-lived by design: construct once and reuse across startup and every {@code /reload} so the
 * DEK cache actually has a chance to serve cache hits across reload cycles - re-creating this class
 * per load would defeat the cache entirely.
 */
public final class PostgresBulkKeyLoader implements Closeable {

  private static final Logger LOG = LogManager.getLogger();

  private static final String QUERY =
      "SELECT t.id AS tenant_id, t.name AS tenant_name, t.vault_type, t.kek_key_id, "
          + "t.encrypted_dek, t.dek_version AS tenant_dek_version, "
          + "k.key_identifier, k.encrypted_bls_key, k.dek_version AS key_dek_version "
          + "FROM bls_signing_keys k JOIN tenants t ON t.id = k.tenant_id ORDER BY t.id";

  private final DataSource dataSource;
  private final Map<String, KekResolver> resolversByVaultType;
  private final TenantDekCache dekCache;
  private final int decryptionParallelism;

  private volatile int lastVaultCallCount;

  public PostgresBulkKeyLoader(
      final DataSource dataSource,
      final Map<String, KekResolver> resolversByVaultType,
      final Duration dekCacheTtl,
      final int decryptionParallelism) {
    this.dataSource = dataSource;
    this.resolversByVaultType = Map.copyOf(resolversByVaultType);
    this.dekCache = new TenantDekCache(dekCacheTtl);
    this.decryptionParallelism =
        Math.clamp(decryptionParallelism, 1, Runtime.getRuntime().availableProcessors());
  }

  /** The number of KEK vault calls made during the most recent {@link #loadAll()} invocation. */
  public int getLastVaultCallCount() {
    return lastVaultCallCount;
  }

  public MappedResults<DecryptedBlsKey> loadAll() {
    final Set<DecryptedBlsKey> results = ConcurrentHashMap.newKeySet();
    final AtomicInteger errorCount = new AtomicInteger();
    final AtomicInteger vaultCalls = new AtomicInteger();
    final ThreadLocal<AesGcmKeyCipher> cipherThreadLocal =
        ThreadLocal.withInitial(AesGcmKeyCipher::new);
    final ExecutorService decryptExecutor = newDecryptExecutor();

    try (final Connection connection = dataSource.getConnection()) {
      connection.setAutoCommit(false);
      try (final PreparedStatement statement =
          connection.prepareStatement(
              QUERY, ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_READ_ONLY)) {
        statement.setFetchSize(1000);
        try (final ResultSet resultSet = statement.executeQuery()) {
          processRows(
              resultSet, decryptExecutor, cipherThreadLocal, results, errorCount, vaultCalls);
        }
      }
      connection.commit();
    } catch (final SQLException e) {
      LOG.error("Unexpected error during Postgres bulk key scan", e);
      errorCount.incrementAndGet();
    } finally {
      shutdownGracefully(decryptExecutor);
    }

    this.lastVaultCallCount = vaultCalls.get();
    return MappedResults.newInstance(results, errorCount.intValue());
  }

  private void processRows(
      final ResultSet resultSet,
      final ExecutorService decryptExecutor,
      final ThreadLocal<AesGcmKeyCipher> cipherThreadLocal,
      final Set<DecryptedBlsKey> results,
      final AtomicInteger errorCount,
      final AtomicInteger vaultCalls)
      throws SQLException {
    final List<Future<?>> pendingDecrypts = new ArrayList<>();
    Integer currentTenantId = null;
    TenantRecord currentTenant = null;
    TenantDek currentDek = null;

    while (resultSet.next()) {
      final int tenantId = resultSet.getInt("tenant_id");
      if (currentTenantId == null || tenantId != currentTenantId) {
        currentTenantId = tenantId;
        currentTenant =
            new TenantRecord(
                tenantId,
                resultSet.getString("tenant_name"),
                resultSet.getString("vault_type"),
                resultSet.getString("kek_key_id"),
                Bytes.of(resultSet.getBytes("encrypted_dek")),
                resultSet.getInt("tenant_dek_version"));
        currentDek = tryResolveDek(currentTenant, vaultCalls);
      }

      final String keyIdentifier = resultSet.getString("key_identifier");
      final int keyDekVersion = resultSet.getInt("key_dek_version");
      final byte[] encryptedBlsKey = resultSet.getBytes("encrypted_bls_key");

      if (currentDek == null) {
        errorCount.incrementAndGet();
        continue;
      }
      if (keyDekVersion != currentTenant.dekVersion()) {
        errorCount.incrementAndGet();
        LOG.warn(
            "Key '{}' for tenant '{}' was encrypted under DEK version [{}] but the tenant's"
                + " current DEK version is [{}] - skipping; re-provisioning required",
            keyIdentifier,
            currentTenant.name(),
            keyDekVersion,
            currentTenant.dekVersion());
        continue;
      }

      final TenantRecord tenant = currentTenant;
      final TenantDek dekForRow = currentDek;
      pendingDecrypts.add(
          decryptExecutor.submit(
              () ->
                  decryptRow(
                      tenant,
                      keyIdentifier,
                      encryptedBlsKey,
                      dekForRow,
                      cipherThreadLocal,
                      results,
                      errorCount)));
    }

    awaitAll(pendingDecrypts, errorCount);
  }

  private TenantDek tryResolveDek(final TenantRecord tenant, final AtomicInteger vaultCalls) {
    final KekResolver resolver = resolversByVaultType.get(tenant.vaultType());
    if (resolver == null) {
      LOG.warn(
          "No KekResolver configured for vault type '{}' (tenant '{}')",
          tenant.vaultType(),
          tenant.name());
      return null;
    }
    try {
      return dekCache.getOrLoad(
          tenant.name(),
          tenant.dekVersion(),
          () -> {
            vaultCalls.incrementAndGet();
            return resolver.unwrapDek(tenant);
          });
    } catch (final RuntimeException e) {
      LOG.warn(
          "Failed to resolve DEK for tenant '{}': {}", tenant.name(), e.getClass().getSimpleName());
      return null;
    }
  }

  private void decryptRow(
      final TenantRecord tenant,
      final String keyIdentifier,
      final byte[] encryptedBlsKey,
      final TenantDek dek,
      final ThreadLocal<AesGcmKeyCipher> cipherThreadLocal,
      final Set<DecryptedBlsKey> results,
      final AtomicInteger errorCount) {
    final byte[] aad = AadCodec.forRow(tenant.name(), keyIdentifier, tenant.dekVersion());
    try (final TenantDek.Lease lease = dek.acquireForRead()) {
      final Bytes plaintext =
          Bytes.of(cipherThreadLocal.get().decrypt(lease.keyBytes(), encryptedBlsKey, aad));
      results.add(new DecryptedBlsKey(keyIdentifier, plaintext));
    } catch (final GeneralSecurityException | IllegalStateException e) {
      errorCount.incrementAndGet();
      LOG.warn(
          "Failed to decrypt BLS key for tenant '{}', key '{}': {}",
          tenant.name(),
          keyIdentifier,
          e.getClass().getSimpleName());
    }
  }

  private void awaitAll(final List<Future<?>> futures, final AtomicInteger errorCount) {
    for (final Future<?> future : futures) {
      try {
        future.get();
      } catch (final InterruptedException _) {
        Thread.currentThread().interrupt();
        errorCount.incrementAndGet();
      } catch (final ExecutionException e) {
        errorCount.incrementAndGet();
        LOG.warn(
            "Unexpected error while decrypting a key: {}",
            e.getCause() != null
                ? e.getCause().getClass().getSimpleName()
                : e.getClass().getSimpleName());
      }
    }
  }

  private ExecutorService newDecryptExecutor() {
    return Executors.newFixedThreadPool(
        decryptionParallelism,
        runnable -> {
          final Thread thread = new Thread(runnable, "postgres-keystore-decrypt");
          thread.setDaemon(true);
          return thread;
        });
  }

  private void shutdownGracefully(final ExecutorService executorService) {
    executorService.shutdown();
    try {
      if (!executorService.awaitTermination(30, TimeUnit.SECONDS)) {
        executorService.shutdownNow();
      }
    } catch (final InterruptedException _) {
      Thread.currentThread().interrupt();
      executorService.shutdownNow();
    }
  }

  @Override
  public void close() {
    dekCache.close();
    if (dataSource instanceof final Closeable closeableDataSource) {
      try {
        closeableDataSource.close();
      } catch (final IOException e) {
        LOG.warn("Error closing Postgres keystore datasource", e);
      }
    }
  }
}
