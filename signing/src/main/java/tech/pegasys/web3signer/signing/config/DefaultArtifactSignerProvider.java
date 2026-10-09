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

import static tech.pegasys.web3signer.signing.KeyType.BLS;
import static tech.pegasys.web3signer.signing.KeyType.SECP256K1;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.bulkloading.BlsKeystoreBulkLoader;
import tech.pegasys.web3signer.signing.bulkloading.SecpV3KeystoresBulkLoader;

import java.io.File;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Default implementation of {@link ArtifactSignerProvider} that loads signers and proxy signers.
 *
 * <p>This class is optimized for read-heavy workloads where signing operations vastly outnumber
 * reload operations. It uses a volatile reference with immutable map swap pattern to provide:
 *
 * <ul>
 *   <li><b>Lock-free reads:</b> {@code getSigner()}, {@code getProxySigner()}, and other read
 *       operations perform a single volatile read with no synchronization overhead.
 *   <li><b>Atomic snapshots:</b> Readers see either the complete old state or the complete new
 *       state, never a mix of both during reload operations.
 *   <li><b>Memory efficiency:</b> Immutable maps have lower overhead compared to concurrent
 *       collections, and old maps become eligible for garbage collection immediately after swap.
 * </ul>
 *
 * <p>Write operations ({@code load()}, {@code addSigner()}, {@code removeSigner()}, {@code
 * addProxySigner()}) are serialized through a single-threaded executor to ensure consistency. These
 * operations use copy-on-write semantics, building a new immutable map and atomically swapping the
 * volatile reference.
 *
 * <p>Thread safety guarantees:
 *
 * <ul>
 *   <li>All read operations are thread-safe and can be called concurrently from multiple Vert.x
 *       event loop threads.
 *   <li>Write operations are serialized and thread-safe.
 *   <li>Reads during writes will see either the complete old state or the complete new state.
 * </ul>
 *
 * @see ArtifactSignerProvider
 */
public class DefaultArtifactSignerProvider implements ArtifactSignerProvider {

  private static final Logger LOG = LogManager.getLogger();

  // MappedResults = Collection + Error count
  private final Supplier<MappedResults<ArtifactSigner>> artifactSignerResultsSupplier;
  private final Optional<BiConsumer<Set<String>, Set<String>>> postLoadingCallback;
  private final Optional<KeystoresParameters> commitBoostKeystoresParameters;

  // Volatile references to immutable maps - readers see atomic snapshots
  private volatile SignerState state = new SignerState(Map.of(), Map.of());

  private record SignerState(
      Map<String, ArtifactSigner> signers, Map<String, Set<ArtifactSigner>> proxySigners) {}

  private final ExecutorService executorService =
      Executors.newSingleThreadExecutor(
          r -> {
            final Thread thread = new Thread(r, "artifact-signer-loader");
            thread.setDaemon(true);
            return thread;
          });

  public DefaultArtifactSignerProvider(
      final Supplier<MappedResults<ArtifactSigner>> artifactSignerResultsSupplier,
      final Optional<BiConsumer<Set<String>, Set<String>>> postLoadingCallback,
      final Optional<KeystoresParameters> commitBoostKeystoresParameters) {
    this.artifactSignerResultsSupplier = artifactSignerResultsSupplier;
    this.postLoadingCallback = postLoadingCallback;
    this.commitBoostKeystoresParameters = commitBoostKeystoresParameters;
  }

  /**
   * Loads or reloads all signers and proxy signers from configured sources.
   *
   * <p>This operation is executed asynchronously on a single-threaded executor to ensure
   * serialization with other write operations. The loading process:
   *
   * <ol>
   *   <li>Invokes the {@code artifactSignerResultsSupplier} to load signers from all configured
   *       sources (encrypted keystores, AWS KMS, Azure Key Vault, GCP Secret Manager, HashiCorp
   *       Vault, etc.), capturing both successfully loaded signers and error counts
   *   <li>Builds a new immutable signers map from successfully loaded signers, handling duplicate
   *       keys by keeping the first signer and logging a warning
   *   <li>If commit boost parameters are enabled, loads proxy signers for each consensus public key
   *   <li>Atomically swaps the volatile references to the new immutable maps
   *   <li>Invokes the optional post-loading callback (e.g., for slashing protection registration)
   * </ol>
   *
   * <p>The atomic swap ensures that concurrent readers see either the complete old state or the
   * complete new state, never a mix. This is critical for maintaining consistency during signing
   * operations while a reload is in progress.
   *
   * <p><b>Error Handling:</b> Individual signer loading failures are counted but do not prevent
   * loading of other valid signers. Signers missing from an errored load are retained, so a
   * transient failure cannot remove them from slashing protection; the next error-free load drops
   * keys that are genuinely gone. Errors are counted, not attributed to a source or file, so while
   * any load error persists (even a single malformed file in the same directory) a key removed from
   * its source stays loaded; use the key manager delete API to remove a key immediately.
   *
   * <p>This method is typically invoked:
   *
   * <ul>
   *   <li>At application startup to perform initial loading of signers
   *   <li>Via the {@code /reload} API endpoint to refresh signers without restarting the
   *       application
   * </ul>
   *
   * <p><b>Note:</b> Loading can be a time-consuming operation, especially when loading from remote
   * vaults or decrypting many keystores. The returned {@link Future} completes when all signers
   * have been processed (both successful and failed) and the state swap has occurred.
   *
   * @return a {@link Future} containing the number of signer configurations that failed to load (0
   *     indicates all signers loaded successfully)
   */
  @Override
  public Future<Long> load() {
    return executorService.submit(
        () -> {
          final SignerState currentState = this.state;
          LOG.debug("Signer keys pre-loaded in memory {}", currentState.signers.size());

          // Get MappedResults - includes error count
          final MappedResults<ArtifactSigner> results = artifactSignerResultsSupplier.get();
          final long errorCount = results.getErrorCount();

          // Build new signers map from successful results
          final Map<String, ArtifactSigner> newSigners =
              results.getValues().stream()
                  .collect(
                      Collectors.toMap(
                          ArtifactSigner::getIdentifier,
                          Function.identity(),
                          (signer1, signer2) -> {
                            LOG.warn(
                                "Duplicate key found while loading: {}", signer1.getIdentifier());
                            return signer1;
                          },
                          HashMap::new));

          // A source failure (unreadable keystore dir/password file, vault outage, ...) returns an
          // error count and only the keys it managed to load. Retain previously loaded signers
          // missing from an errored load instead of reporting them as removed, which would disable
          // them in slashing protection permanently.
          if (errorCount > 0) {
            final Map<String, ArtifactSigner> retainedSigners = new HashMap<>();
            currentState.signers.forEach(
                (identifier, signer) -> {
                  if (!newSigners.containsKey(identifier)) {
                    retainedSigners.put(identifier, signer);
                  }
                });
            if (!retainedSigners.isEmpty()) {
              LOG.warn(
                  "Signer loading reported {} error(s); retaining {} previously loaded signer(s)"
                      + " that could not be re-loaded",
                  errorCount,
                  retainedSigners.size());
              newSigners.putAll(retainedSigners);
            }
          }

          // Build new proxy signers map
          final Map<String, Set<ArtifactSigner>> newProxySigners = new HashMap<>();

          commitBoostKeystoresParameters
              .filter(KeystoresParameters::isEnabled)
              .ifPresent(
                  keystoreParameter -> {
                    newSigners
                        .keySet()
                        .forEach(
                            consensusPubKey -> {
                              LOG.trace("Loading proxy signers for '{}' ...", consensusPubKey);
                              final Set<ArtifactSigner> proxies = new HashSet<>();

                              loadProxySignersInto(
                                  proxies,
                                  keystoreParameter,
                                  consensusPubKey,
                                  SECP256K1.name(),
                                  SecpV3KeystoresBulkLoader::loadECDSAProxyKeystores);

                              loadProxySignersInto(
                                  proxies,
                                  keystoreParameter,
                                  consensusPubKey,
                                  BLS.name(),
                                  BlsKeystoreBulkLoader::loadKeystoresUsingPasswordFile);

                              if (!proxies.isEmpty()) {
                                newProxySigners.put(consensusPubKey, Set.copyOf(proxies));
                              }
                            });
                  });

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads
          state = new SignerState(Map.copyOf(newSigners), Map.copyOf(newProxySigners));

          // Compute delta and invoke callback only when callback is configured
          postLoadingCallback.ifPresent(
              callback -> {
                final Set<String> addedKeys = new HashSet<>(state.signers.keySet());
                addedKeys.removeAll(currentState.signers.keySet());

                final Set<String> removedKeys = new HashSet<>(currentState.signers.keySet());
                removedKeys.removeAll(state.signers.keySet());

                callback.accept(addedKeys, removedKeys);
              });

          LOG.info("Total signers (keys) currently loaded in memory: {}", state.signers.size());
          return errorCount;
        });
  }

  @Override
  public Optional<ArtifactSigner> getSigner(final String identifier) {
    final SignerState currentState = this.state;
    // Single volatile read - no locking
    final Optional<ArtifactSigner> result =
        Optional.ofNullable(currentState.signers.get(identifier));
    if (result.isEmpty()) {
      LOG.debug("No signer was loaded matching identifier '{}'", identifier);
    }
    return result;
  }

  @Override
  public Optional<ArtifactSigner> getProxySigner(final String proxyPubKey) {
    // Single volatile read, then stream over immutable collections
    final SignerState currentState = this.state;
    return currentState.proxySigners.values().stream()
        .flatMap(Set::stream)
        .filter(signer -> signer.getIdentifier().equals(proxyPubKey))
        .findFirst();
  }

  @Override
  public Set<String> availableIdentifiers() {
    // signers is already immutable, keySet() returns immutable view
    final SignerState currentState = this.state;
    return currentState.signers.keySet();
  }

  @Override
  public Map<KeyType, Set<String>> getProxyIdentifiers(final String consensusPubKey) {
    // Pure read - no writes!
    final SignerState currentState = this.state;
    final Set<ArtifactSigner> proxies =
        currentState.proxySigners.getOrDefault(consensusPubKey, Set.of());

    if (proxies.isEmpty()) {
      return Map.of();
    }

    return proxies.stream()
        .collect(
            Collectors.groupingBy(
                ArtifactSigner::getKeyType,
                Collectors.mapping(ArtifactSigner::getIdentifier, Collectors.toUnmodifiableSet())));
  }

  @Override
  public Future<Void> addSigner(final ArtifactSigner signer) {
    return executorService.submit(
        () -> {
          final SignerState currentState = this.state;

          final Map<String, ArtifactSigner> newSigners = new HashMap<>(currentState.signers);
          final ArtifactSigner existing = newSigners.put(signer.getIdentifier(), signer);
          if (existing != null) {
            LOG.warn("Replaced existing signer for identifier '{}'", signer.getIdentifier());
          }

          final Map<String, Set<ArtifactSigner>> newProxySigners =
              new HashMap<>(currentState.proxySigners);
          newProxySigners.putIfAbsent(signer.getIdentifier(), Set.of());

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads
          state = new SignerState(Map.copyOf(newSigners), Map.copyOf(newProxySigners));
          LOG.info("Loaded new signer for identifier '{}'", signer.getIdentifier());
          return null;
        });
  }

  @Override
  public Future<Void> removeSigner(final String identifier) {
    return executorService.submit(
        () -> {
          final SignerState currentState = this.state;

          final Map<String, ArtifactSigner> newSigners = new HashMap<>(currentState.signers);
          newSigners.remove(identifier);
          final Map<String, Set<ArtifactSigner>> newProxySigners =
              new HashMap<>(currentState.proxySigners);
          newProxySigners.remove(identifier);

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads
          this.state = new SignerState(Map.copyOf(newSigners), Map.copyOf(newProxySigners));

          LOG.info("Removed signer with identifier '{}'", identifier);
          return null;
        });
  }

  /**
   * Adds a proxy signer associated with a consensus public key.
   *
   * <p>This operation is executed asynchronously on a single-threaded executor to ensure
   * serialization with other write operations. The method uses copy-on-write semantics:
   *
   * <ol>
   *   <li>Creates a mutable copy of the current proxy signers map
   *   <li>Adds the new proxy signer to the set for the given consensus public key
   *   <li>Atomically swaps the volatile reference to the new immutable map
   * </ol>
   *
   * <p>Concurrent readers will see either the state before or after the addition, never an
   * intermediate state.
   *
   * @param signerToAdd the proxy signer to add
   * @param consensusPubKey the consensus public key to associate with the proxy signer
   * @return a {@link Future} that completes when the proxy signer has been added
   */
  @Override
  public Future<Void> addProxySigner(
      final ArtifactSigner signerToAdd, final String consensusPubKey) {
    return executorService.submit(
        () -> {
          final SignerState currentState = this.state;

          final Map<String, Set<ArtifactSigner>> newProxySigners =
              new HashMap<>(currentState.proxySigners);
          final Set<ArtifactSigner> existingProxies =
              newProxySigners.getOrDefault(consensusPubKey, Set.of());
          final Set<ArtifactSigner> updatedProxies = new HashSet<>(existingProxies);
          updatedProxies.add(signerToAdd);
          newProxySigners.put(consensusPubKey, Set.copyOf(updatedProxies));

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads
          this.state = new SignerState(currentState.signers, Map.copyOf(newProxySigners));

          LOG.info(
              "Loaded new proxy signer {} for consensus public key '{}'",
              signerToAdd.getIdentifier(),
              consensusPubKey);
          return null;
        });
  }

  @Override
  public void close() {
    // Immediate shutdown is appropriate here since if the app is shutting down,
    // there's no need to wait for a potentially long-running load operation
    executorService.shutdownNow();
  }

  private static boolean canReadFromDirectory(final Path path) {
    final File file = path.toFile();
    return file.canRead() && file.isDirectory();
  }

  /**
   * Loads proxy signers from a keystore directory into the target set.
   *
   * <p>This static utility method attempts to load proxy signers for a specific consensus public
   * key and key type from the configured keystores path. The directory structure expected is:
   *
   * <pre>
   * {keystoresPath}/{consensusPubKey}/{keyType}/
   * </pre>
   *
   * <p>For example, for a consensus key {@code 0x1234...} with BLS proxy signers:
   *
   * <pre>
   * /path/to/keystores/0x1234.../BLS/
   * </pre>
   *
   * <p>If the directory exists and is readable, the loader function is invoked to bulk load all
   * keystores from that directory using the configured password file. If the directory does not
   * exist or is not readable, no action is taken.
   *
   * @param targetSet the mutable set to add loaded proxy signers into
   * @param keystoreParameter the keystore configuration containing paths and password file location
   * @param consensusPubKey the consensus public key for which to load proxy signers
   * @param keyType the type of keys to load (e.g., "BLS" or "SECP256K1")
   * @param loaderFunction the bulk loading function that reads keystores from a directory using a
   *     password file and returns the loaded signers
   */
  private static void loadProxySignersInto(
      final Set<ArtifactSigner> targetSet,
      final KeystoresParameters keystoreParameter,
      final String consensusPubKey,
      final String keyType,
      final BiFunction<Path, Path, MappedResults<ArtifactSigner>> loaderFunction) {

    final Path identifierPath = keystoreParameter.getKeystoresPath().resolve(consensusPubKey);
    final Path proxyDir = identifierPath.resolve(keyType);

    if (canReadFromDirectory(proxyDir)) {
      final MappedResults<ArtifactSigner> signersResult =
          loaderFunction.apply(proxyDir, keystoreParameter.getKeystoresPasswordFile());
      targetSet.addAll(signersResult.getValues());
    }
  }
}
