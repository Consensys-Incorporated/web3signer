/*
 * Copyright 2020 ConsenSys AG.
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
package tech.pegasys.web3signer.signing.config;

import tech.pegasys.web3signer.keystorage.azure.AzureKeyVault;
import tech.pegasys.web3signer.keystorage.azure.AzureOverrides;

import java.io.Closeable;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;

/**
 * Builds {@link AzureKeyVault} instances, caching one per distinct credentials/vault/behaviour
 * combination. Building one is expensive (AAD login + new HTTP connection pool), and this is called
 * once per loaded key/secret, so identical calls reuse the cached instance instead.
 *
 * <p>Cached instances hold no closeable resources, so eviction/{@link #close()} just drop
 * references.
 */
public class AzureKeyVaultFactory implements Closeable {
  private static final int CLIENT_CACHE_SIZE = 10;

  private final AtomicReference<ExecutorService> executorServiceCache = new AtomicReference<>();
  private final LoadingCache<AzureKeyVaultKey, AzureKeyVault> vaultCache =
      CacheBuilder.newBuilder()
          .maximumSize(CLIENT_CACHE_SIZE)
          .build(
              new CacheLoader<>() {
                @Override
                public AzureKeyVault load(final AzureKeyVaultKey key) {
                  return buildAzureKeyVault(key);
                }
              });

  public AzureKeyVault createAzureKeyVault(final AzureKeyVaultParameters azureKeyVaultParameters) {
    return createAzureKeyVault(
        azureKeyVaultParameters.getClientId(),
        azureKeyVaultParameters.getClientSecret(),
        azureKeyVaultParameters.getKeyVaultName(),
        azureKeyVaultParameters.getTenantId(),
        azureKeyVaultParameters.getAuthenticationMode(),
        azureKeyVaultParameters.getTimeout(),
        azureKeyVaultParameters.getAzureOverrides());
  }

  public AzureKeyVault createAzureKeyVault(
      final String clientId,
      final String clientSecret,
      final String keyVaultName,
      final String tenantId,
      final AzureAuthenticationMode mode,
      final long httpClientTimeout,
      final AzureOverrides azureOverrides) {
    final AzureKeyVaultKey key =
        new AzureKeyVaultKey(
            clientId,
            clientSecret,
            keyVaultName,
            tenantId,
            mode,
            httpClientTimeout,
            azureOverrides);
    // Safe: the loader only throws unchecked exceptions.
    return vaultCache.getUnchecked(key);
  }

  private AzureKeyVault buildAzureKeyVault(final AzureKeyVaultKey key) {
    return switch (key.mode()) {
      case USER_ASSIGNED_MANAGED_IDENTITY ->
          AzureKeyVault.createUsingManagedIdentity(
              Optional.of(key.clientId()),
              key.keyVaultName(),
              key.httpClientTimeout(),
              key.azureOverrides());
      case SYSTEM_ASSIGNED_MANAGED_IDENTITY ->
          AzureKeyVault.createUsingManagedIdentity(
              Optional.empty(), key.keyVaultName(), key.httpClientTimeout(), key.azureOverrides());
      case CLIENT_SECRET ->
          AzureKeyVault.createUsingClientSecretCredentials(
              key.clientId(),
              key.clientSecret(),
              key.tenantId(),
              key.keyVaultName(),
              getOrCreateExecutor(),
              key.httpClientTimeout(),
              key.azureOverrides());
    };
  }

  private ExecutorService getOrCreateExecutor() {
    return executorServiceCache.updateAndGet(
        e ->
            Objects.requireNonNullElseGet(
                e, () -> Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors())));
  }

  @Override
  public void close() {
    vaultCache.invalidateAll();

    final ExecutorService executorService = executorServiceCache.get();
    if (executorService != null) {
      executorService.shutdownNow();
      executorServiceCache.set(null);
    }
  }

  @VisibleForTesting
  protected AtomicReference<ExecutorService> getExecutorServiceCache() {
    return executorServiceCache;
  }

  @VisibleForTesting
  protected LoadingCache<AzureKeyVaultKey, AzureKeyVault> getVaultCache() {
    return vaultCache;
  }

  /** Identifies a cached {@link AzureKeyVault} by every input that affects how it is built. */
  @VisibleForTesting
  record AzureKeyVaultKey(
      String clientId,
      String clientSecret,
      String keyVaultName,
      String tenantId,
      AzureAuthenticationMode mode,
      long httpClientTimeout,
      AzureOverrides azureOverrides) {

    @Override
    public String toString() {
      return "AzureKeyVaultKey["
          + "clientId="
          + clientId
          + ", clientSecret="
          + (clientSecret != null ? "***" : "null")
          + ", keyVaultName="
          + keyVaultName
          + ", tenantId="
          + tenantId
          + ", mode="
          + mode
          + ", httpClientTimeout="
          + httpClientTimeout
          + ", azureOverrides="
          + azureOverrides
          + ']';
    }
  }
}
