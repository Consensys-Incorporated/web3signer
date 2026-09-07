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
package tech.pegasys.web3signer.keystorage.azure;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.keystorage.common.SecretValueMapperUtil;

import java.io.InputStream;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import javax.net.ssl.TrustManagerFactory;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.ResourceNotFoundException;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.core.http.rest.PagedIterable;
import com.azure.core.util.HttpClientOptions;
import com.azure.identity.ClientSecretCredentialBuilder;
import com.azure.identity.ManagedIdentityCredentialBuilder;
import com.azure.security.keyvault.keys.KeyClient;
import com.azure.security.keyvault.keys.KeyClientBuilder;
import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import com.azure.security.keyvault.keys.models.KeyProperties;
import com.azure.security.keyvault.keys.models.KeyVaultKey;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.azure.security.keyvault.secrets.models.SecretProperties;
import com.google.common.annotations.VisibleForTesting;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;

public class AzureKeyVault {

  private static final Logger LOG = LogManager.getLogger();
  private final TokenCredential tokenCredential;
  private final SecretClient secretClient;
  private final KeyClient keyClient;
  private final HttpClient httpClient;
  private final boolean endpointOverridden;

  public static AzureKeyVault createUsingClientSecretCredentials(
      final String clientId,
      final String clientSecret,
      final String tenantId,
      final String vaultName,
      final ExecutorService executorService,
      final long timeout,
      final AzureOverrides azureOverrides) {
    final String vaultUrl = resolveVaultUrl(vaultName, azureOverrides);
    // Shared by the credential (MSAL token requests) and the vault clients below: Azure Identity
    // otherwise builds its own separate default HTTP client (its own connection pool/event
    // loop) for the token request if none is supplied, independent of the one used for the
    // vault calls.
    final HttpClient httpClient =
        buildHttpClient(timeout, azureOverrides.trustCertificateOverride());
    final ClientSecretCredentialBuilder credentialBuilder =
        new ClientSecretCredentialBuilder()
            .clientId(clientId)
            .clientSecret(clientSecret)
            .tenantId(tenantId)
            .executorService(executorService)
            .httpClient(httpClient);
    azureOverrides
        .authorityHostOverride()
        .ifPresent(
            uri -> {
              credentialBuilder.authorityHost(uri.toString());
              credentialBuilder.disableInstanceDiscovery();
            });
    return new AzureKeyVault(
        credentialBuilder.build(),
        vaultUrl,
        httpClient,
        azureOverrides.endpointOverride().isPresent());
  }

  public static AzureKeyVault createUsingManagedIdentity(
      final Optional<String> clientId,
      final String vaultName,
      final long timeout,
      final AzureOverrides azureOverrides) {
    final ManagedIdentityCredentialBuilder managedIdentityCredentialBuilder =
        new ManagedIdentityCredentialBuilder();
    clientId.ifPresent(managedIdentityCredentialBuilder::clientId);
    return new AzureKeyVault(
        managedIdentityCredentialBuilder.build(),
        resolveVaultUrl(vaultName, azureOverrides),
        buildHttpClient(timeout, azureOverrides.trustCertificateOverride()),
        azureOverrides.endpointOverride().isPresent());
  }

  private static String resolveVaultUrl(
      final String vaultName, final AzureOverrides azureOverrides) {
    return azureOverrides
        .endpointOverride()
        .map(URI::toString)
        .orElseGet(() -> constructAzureKeyVaultUrl(vaultName));
  }

  /**
   * The platform default trust store is used unless a trust certificate override is configured.
   * Building the client via a raw {@code SslContextBuilder} (rather than relying on ambient {@code
   * javax.net.ssl.trustStore} JVM properties) is required because the Netty transport used here
   * prefers its own BoringSSL (netty-tcnative) engine when available, which does not consult those
   * properties.
   */
  private static HttpClient buildHttpClient(
      final long timeoutSeconds, final Optional<Path> trustCertificateOverride) {
    if (trustCertificateOverride.isEmpty()) {
      return HttpClient.createDefault(
          new HttpClientOptions().setResponseTimeout(Duration.ofSeconds(timeoutSeconds)));
    }

    final Path certificatePath = trustCertificateOverride.get();
    try {
      final X509Certificate certificate;
      try (InputStream in = Files.newInputStream(certificatePath)) {
        certificate =
            (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
      }
      final KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
      trustStore.load(null, null);
      trustStore.setCertificateEntry("azure-trust-override", certificate);
      final TrustManagerFactory trustManagerFactory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      trustManagerFactory.init(trustStore);

      final SslContext sslContext =
          SslContextBuilder.forClient().trustManager(trustManagerFactory).build();
      final reactor.netty.http.client.HttpClient reactorHttpClient =
          reactor.netty.http.client.HttpClient.create()
              .secure(spec -> spec.sslContext(sslContext))
              .responseTimeout(Duration.ofSeconds(timeoutSeconds));
      return new NettyAsyncHttpClientBuilder(reactorHttpClient).build();
    } catch (final Exception e) {
      throw new IllegalStateException(
          "Unable to build Azure HTTP client trusting " + certificatePath, e);
    }
  }

  private AzureKeyVault(
      final TokenCredential tokenCredential,
      final String vaultUrl,
      final HttpClient httpClient,
      final boolean endpointOverridden) {
    this.tokenCredential = tokenCredential;
    this.httpClient = httpClient;
    this.endpointOverridden = endpointOverridden;

    final SecretClientBuilder secretClientBuilder =
        new SecretClientBuilder()
            .httpClient(httpClient)
            .vaultUrl(vaultUrl)
            .credential(tokenCredential);
    final KeyClientBuilder keyClientBuilder =
        new KeyClientBuilder()
            .httpClient(httpClient)
            .vaultUrl(vaultUrl)
            .credential(tokenCredential);
    if (endpointOverridden) {
      secretClientBuilder.disableChallengeResourceVerification();
      keyClientBuilder.disableChallengeResourceVerification();
    }
    secretClient = secretClientBuilder.buildClient();
    keyClient = keyClientBuilder.buildClient();
  }

  public Optional<String> fetchSecret(final String secretName) {
    try {
      return Optional.of(secretClient.getSecret(secretName).getValue());
    } catch (final ResourceNotFoundException e) {
      return Optional.empty();
    }
  }

  public CryptographyClient fetchKey(final String keyName, final String keyVersion) {
    final KeyVaultKey key = keyClient.getKey(keyName, keyVersion);
    final String keyId = key.getId();

    final CryptographyClientBuilder cryptographyClientBuilder =
        new CryptographyClientBuilder()
            .httpClient(httpClient)
            .credential(tokenCredential)
            .keyIdentifier(keyId);
    if (endpointOverridden) {
      cryptographyClientBuilder.disableChallengeResourceVerification();
    }
    return cryptographyClientBuilder.buildClient();
  }

  public static String constructAzureKeyVaultUrl(final String keyVaultName) {
    return String.format("https://%s.vault.azure.net", keyVaultName);
  }

  /**
   * Fetch multiple secrets from Azure. Apply mapper function to transform the secret values.
   *
   * @param mapper The mapper function to transform secret values to type R.
   * @param tags Map of tags. Only secrets which contains all the tags entries are processed.
   * @return Mapped results containing the converted secrets and error count.
   * @param <R> The result type of mapper function.
   */
  public <R> MappedResults<R> mapSecrets(
      final BiFunction<String, String, R> mapper, final Map<String, String> tags) {
    final Set<R> result = ConcurrentHashMap.newKeySet();
    final AtomicInteger errorCount = new AtomicInteger(0);
    try {
      final PagedIterable<SecretProperties> secretsPagedIterable =
          secretClient.listPropertiesOfSecrets();

      secretsPagedIterable
          .streamByPage()
          .forEach(
              keyPage ->
                  keyPage.getValue().parallelStream()
                      .filter(secretProperties -> secretPropertiesPredicate(tags, secretProperties))
                      .forEach(
                          sp -> {
                            try {
                              final KeyVaultSecret secret = secretClient.getSecret(sp.getName());
                              final MappedResults<R> multiResult =
                                  SecretValueMapperUtil.mapSecretValue(
                                      mapper, sp.getName(), secret.getValue());
                              result.addAll(multiResult.getValues());
                              errorCount.addAndGet(multiResult.getErrorCount());
                            } catch (final Exception e) {
                              LOG.warn(
                                  "Failed to map secret '{}' to requested object type.",
                                  sp.getName());
                              errorCount.incrementAndGet();
                            }
                          }));

    } catch (final Exception e) {
      LOG.error("Unexpected error during Azure map-secrets", e);
      errorCount.incrementAndGet();
    }
    return MappedResults.newInstance(result, errorCount.intValue());
  }

  /**
   * Fetch multiple "Keys" objects from Azure Key Vault. Apply mapper function to transform the key
   * properties.
   *
   * @param mapper Mapper function to transform Azure KeyProperties to type R
   * @param tags Map of tags. Only keys which contains all the tags entries are processed.
   * @return Mapped results containing the converted keys and error count.
   * @param <R> The result type of mapper function.
   */
  public <R> MappedResults<R> mapKeyProperties(
      final Function<KeyProperties, R> mapper, final Map<String, String> tags) {
    final Set<R> result = ConcurrentHashMap.newKeySet();
    final AtomicInteger errorCount = new AtomicInteger(0);
    try {
      keyClient
          .listPropertiesOfKeys()
          .streamByPage()
          .forEach(
              keyPage ->
                  keyPage.getValue().parallelStream()
                      .filter(keyProperties -> keyPropertiesPredicate(tags, keyProperties))
                      .forEach(
                          kp -> {
                            try {
                              final R value = mapper.apply(kp);
                              result.add(value);
                            } catch (final Exception e) {
                              LOG.warn(
                                  "Failed to map keyProperties '{}' to requested object type.",
                                  kp.getName());
                              errorCount.incrementAndGet();
                            }
                          }));
    } catch (final Exception e) {
      LOG.error("Unexpected error during Azure mapKeyProperties", e);
      errorCount.incrementAndGet();
    }

    return MappedResults.newInstance(result, errorCount.intValue());
  }

  /**
   * Fetch all "Key" Objects from the Azure Key Vault. Useful for testing purposes.
   *
   * @return List of Azure Keys containing key name, public key hex and map of tags.
   */
  @VisibleForTesting
  public List<AzureKey> getAzureKeys() {
    final PagedIterable<KeyProperties> keysPagedIterable = keyClient.listPropertiesOfKeys();

    return keysPagedIterable
        .streamByPage()
        .flatMap(
            keyPage ->
                keyPage.getValue().stream()
                    .map(
                        kp -> {
                          final var cryptoClient = fetchKey(kp.getName(), kp.getVersion());
                          final var jsonWebKey = cryptoClient.getKey().getKey();
                          final var rawPublicKey =
                              Bytes.concatenate(
                                  Bytes.wrap(jsonWebKey.getX()), Bytes.wrap(jsonWebKey.getY()));
                          return new AzureKey(
                              kp.getName(), rawPublicKey.toHexString(), kp.getTags());
                        }))
        .toList();
  }

  /**
   * Fetch all "Secret" objects from the Azure Key Vault. Useful for testing purposes.
   *
   * @return List of Azure Secrets containing name of secrets, set of values and map of tags.
   */
  @VisibleForTesting
  public List<AzureSecret> getAzureSecrets() {
    final PagedIterable<SecretProperties> secretsPagedIterable =
        secretClient.listPropertiesOfSecrets();

    return secretsPagedIterable
        .streamByPage()
        .flatMap(
            keyPage ->
                keyPage.getValue().stream()
                    .map(
                        sp -> {
                          var secretName = sp.getName();
                          var secretValue = secretClient.getSecret(secretName).getValue();
                          var secretValueSet = splitSecretValues(secretValue);
                          return new AzureSecret(secretName, secretValueSet, sp.getTags());
                        }))
        .toList();
  }

  private static Set<String> splitSecretValues(final String secretValue) {
    if (secretValue == null || secretValue.isEmpty()) {
      return Set.of();
    }

    return Arrays.stream(secretValue.split("\\r?\\n"))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .collect(Collectors.toCollection(LinkedHashSet::new));
  }

  private static boolean isEmptyTags(final Map<String, String> tags) {
    return tags == null || tags.isEmpty();
  }

  private static boolean secretPropertiesPredicate(
      final Map<String, String> tags, final SecretProperties secretProperties) {
    if (isEmptyTags(tags))
      return true; // we don't want to filter if user-supplied tags map is empty

    return secretProperties.getTags() != null // return false if remote secret doesn't have any tags
        && secretProperties.getTags().entrySet().containsAll(tags.entrySet());
  }

  private static boolean keyPropertiesPredicate(
      final Map<String, String> tags, final KeyProperties keyProperties) {
    if (isEmptyTags(tags))
      return true; // we don't want to filter if user-supplied tags map is empty

    return keyProperties.getTags() != null // return false if remote secret doesn't have any tags
        && keyProperties.getTags().entrySet().containsAll(tags.entrySet());
  }

  @VisibleForTesting
  public record AzureSecret(String name, Set<String> values, Map<String, String> tags) {}

  @VisibleForTesting
  public record AzureKey(String name, String publicKeyHex, Map<String, String> tags) {}
}
