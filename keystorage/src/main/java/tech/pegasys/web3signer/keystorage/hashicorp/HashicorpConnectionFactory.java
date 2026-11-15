/*
 * Copyright 2023 ConsenSys AG.
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
package tech.pegasys.web3signer.keystorage.hashicorp;

import tech.pegasys.web3signer.keystorage.hashicorp.config.ConnectionParameters;
import tech.pegasys.web3signer.keystorage.hashicorp.config.TlsOptions;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Factory for Hashicorp connections. Uses Java's HttpClient implementation. Caches one HttpClient
 * per vault URI and client settings, so connections with different TLS trust never share a client.
 */
public class HashicorpConnectionFactory implements AutoCloseable {

  private static final Logger LOG = LogManager.getLogger();
  private final Map<ClientKey, HttpClient> httpClientMap = new ConcurrentHashMap<>();
  private final AtomicBoolean closed = new AtomicBoolean(false);

  public HashicorpConnectionFactory() {}

  public HashicorpConnection create(final ConnectionParameters connectionParameters) {
    ensureNotClosed();
    final HttpClient httpClient = getHttpClient(connectionParameters);
    return new HashicorpConnection(httpClient, connectionParameters);
  }

  private HttpClient getHttpClient(ConnectionParameters connectionParameters) {
    ensureNotClosed();
    return httpClientMap.computeIfAbsent(
        ClientKey.of(connectionParameters),
        _key -> {
          // Double-check after acquiring the lock for creation
          if (closed.get()) {
            throw new HashicorpException("ConnectionFactory is closed");
          }

          final HttpClient.Builder httpClientBuilder =
              HttpClient.newBuilder()
                  .followRedirects(HttpClient.Redirect.NORMAL)
                  .version(connectionParameters.getHttpProtocolVersion())
                  .connectTimeout(Duration.ofMillis(connectionParameters.getTimeoutMilliseconds()));
          try {
            if (connectionParameters.getTlsOptions().isPresent()) {
              LOG.debug("Connection to hashicorp vault using TLS.");
              httpClientBuilder.sslContext(
                  getCustomSSLContext(connectionParameters.getTlsOptions().get()));
            }
            LOG.debug("Creating new HttpClient for URI: {}", connectionParameters.getVaultURI());
            return httpClientBuilder.build();
          } catch (final Exception e) {
            throw new HashicorpException("Unable to initialise connection to hashicorp vault.", e);
          }
        });
  }

  private void ensureNotClosed() {
    if (closed.get()) {
      throw new HashicorpException("HashicorpConnectionFactory is closed");
    }
  }

  private SSLContext getCustomSSLContext(final TlsOptions tlsOptions)
      throws GeneralSecurityException, IOException {

    validateTlsTrustStoreOptions(tlsOptions);

    if (tlsOptions.getTrustStoreType().isEmpty()) {
      return SSLContext.getDefault();
    }

    // Hashicorp vault support TLSv1.3 by default, hence we default to TLSv1.3 being more secure.
    final SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
    sslContext.init(
        null,
        TrustManagerFactoryProvider.getTrustManagerFactory(tlsOptions).getTrustManagers(),
        null);
    return sslContext;
  }

  private void validateTlsTrustStoreOptions(final TlsOptions tlsOptions) {
    if (tlsOptions.getTrustStoreType().isEmpty()) {
      return;
    }

    final TrustStoreType trustStoreType = tlsOptions.getTrustStoreType().get();

    if (tlsOptions.getTrustStorePath() == null) {
      throw new HashicorpException(
          String.format(
              "To use a %s trust store for TLS connections, " + "the trustStore path must be set",
              trustStoreType.name()));
    }

    if (tlsOptions.getTrustStorePassword() == null && trustStoreType.isPasswordRequired()) {
      throw new HashicorpException(
          String.format(
              "To use a %s trust store for TLS connections, "
                  + "the trustStore password must be set",
              trustStoreType.name()));
    }
  }

  @Override
  public void close() {
    // Prevent multiple close attempts
    if (!closed.compareAndSet(false, true)) {
      LOG.debug("HashicorpConnectionFactory already closed");
      return;
    }

    LOG.debug(
        "Closing HashicorpConnectionFactory with {} active connections", httpClientMap.size());

    // Drain all entries atomically to local collection
    final List<Map.Entry<ClientKey, HttpClient>> entries = new ArrayList<>();
    httpClientMap
        .entrySet()
        .removeIf(
            entry -> {
              entries.add(entry);
              return true;
            });

    // Close all clients outside the concurrent map
    for (Map.Entry<ClientKey, HttpClient> entry : entries) {
      try {
        LOG.trace("Closing HttpClient for URI: {}", entry.getKey().vaultUri());
        entry.getValue().close();
      } catch (Exception e) {
        LOG.warn("Failed to close HttpClient for URI: {}", entry.getKey().vaultUri(), e);
      }
    }
  }

  private record ClientKey(
      URI vaultUri,
      Optional<TlsOptions> tlsOptions,
      HttpClient.Version httpProtocolVersion,
      long timeoutMilliseconds) {
    static ClientKey of(final ConnectionParameters parameters) {
      return new ClientKey(
          parameters.getVaultURI(),
          parameters.getTlsOptions(),
          parameters.getHttpProtocolVersion(),
          parameters.getTimeoutMilliseconds());
    }
  }
}
