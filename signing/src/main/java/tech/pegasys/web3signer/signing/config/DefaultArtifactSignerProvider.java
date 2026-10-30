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

import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.ArtifactSignerProvider;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.bulkloading.BlsKeystoreBulkLoader;
import tech.pegasys.web3signer.signing.bulkloading.SecpV3KeystoresBulkLoader;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.BiConsumer;
import java.util.function.BiFunction;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import com.google.common.base.Suppliers;
import com.google.common.collect.Sets;
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

  private final Supplier<List<SignerSourceResult>> artifactSignerResultsSupplier;
  private final Optional<BiConsumer<Set<String>, Set<String>>> postLoadingCallback;
  private final Optional<KeystoresParameters> commitBoostKeystoresParameters;

  // Volatile references to immutable maps - readers see atomic snapshots
  private volatile SignerState state = new SignerState(Map.of(), Map.of(), Map.of(), Map.of());

  private record SignerState(
      Map<String, ArtifactSigner> signers,
      Map<String, Set<ArtifactSigner>> proxySigners,
      Map<String, Provenance> provenance,
      Map<String, Provenance> proxyProvenance) {}

  /** Source of keys imported without a key config file; no load removes them. */
  private static final String IN_MEMORY_SOURCE = "key manager API (in memory)";

  private static final Provenance IN_MEMORY = new Provenance(IN_MEMORY_SOURCE, null);

  /**
   * Where a signer was loaded from. A key defined by several files has one entry per file, chained
   * through {@code next}. A key imported without a file has the single place {@link #IN_MEMORY},
   * which every load keeps. Entries of keys removed via {@link #removeSigner} stay until the next
   * {@link #load()}; retention only looks at loaded keys.
   *
   * @param source loader source; the proxy keystore directory for proxy signers
   * @param file source file, {@code null} for vaults and in-memory keys
   * @param next another file the same key was loaded from, or {@code null}
   */
  private record Provenance(String source, String file, Provenance next) {

    private Provenance(final String source, final String file) {
      this(source, file, null);
    }

    /** Adds the places of {@code other} that {@code first} does not list yet. */
    private static Provenance merge(final Provenance first, final Provenance other) {
      Provenance merged = first;
      for (Provenance place = other; place != null; place = place.next) {
        if (!first.lists(place)) {
          merged = new Provenance(place.source, place.file, merged);
        }
      }
      return merged;
    }

    private boolean lists(final Provenance other) {
      for (Provenance place = this; place != null; place = place.next) {
        if (place.source.equals(other.source) && Objects.equals(place.file, other.file)) {
          return true;
        }
      }
      return false;
    }
  }

  private final ExecutorService executorService =
      Executors.newSingleThreadExecutor(
          r -> {
            final Thread thread = new Thread(r, "artifact-signer-loader");
            thread.setDaemon(true);
            return thread;
          });

  public DefaultArtifactSignerProvider(
      final Supplier<List<SignerSourceResult>> artifactSignerResultsSupplier,
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
   *   <li>If commit boost parameters are enabled, loads proxy signers for each consensus public
   *       key, keeping those whose directory or file failed to load
   *   <li>Atomically swaps the volatile references to the new immutable maps, unless interrupted
   *   <li>Invokes the optional post-loading callback (e.g., for slashing protection registration)
   * </ol>
   *
   * <p>The atomic swap ensures that concurrent readers see either the complete old state or the
   * complete new state, never a mix. This is critical for maintaining consistency during signing
   * operations while a reload is in progress.
   *
   * <p><b>Error Handling:</b> Individual signer loading failures (e.g., malformed keystores,
   * invalid keys) are counted but do not prevent the loading of other valid signers. Successfully
   * loaded signers are made available even if some configurations fail. The returned error count
   * allows callers to detect partial failures. A missing signer is kept if its source or one of its
   * files failed to load; otherwise it is removed.
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

          // per-source results, with failed files and error counts
          final List<SignerSourceResult> results = artifactSignerResultsSupplier.get();
          final long errorCount = results.stream().mapToLong(SignerSourceResult::errorCount).sum();

          // build the new signers map and record where each signer came from
          final Map<String, ArtifactSigner> newSigners = new HashMap<>();
          final Map<String, Provenance> newProvenance = new HashMap<>();
          for (final SignerSourceResult result : results) {
            for (final SignerSourceResult.LoadedSigner loaded : result.signers()) {
              final String identifier = loaded.signer().getIdentifier();
              if (newSigners.putIfAbsent(identifier, loaded.signer()) != null) {
                LOG.warn("Duplicate key found while loading: {}", identifier);
              }
              newProvenance.merge(
                  identifier,
                  new Provenance(result.source(), loaded.file().orElse(null)),
                  Provenance::merge);
            }
          }

          retainSignersOfFailedSources(
              currentState, Failures.of(results), newSigners, newProvenance);

          // Build new proxy signers map
          final Map<String, Set<ArtifactSigner>> newProxySigners = new HashMap<>();
          final Map<String, Provenance> newProxyProvenance = new HashMap<>();
          commitBoostKeystoresParameters
              .filter(KeystoresParameters::isEnabled)
              .ifPresent(
                  keystoreParameter ->
                      loadProxySigners(
                          keystoreParameter,
                          currentState,
                          newSigners.keySet(),
                          newProxySigners,
                          newProxyProvenance));

          // an interrupted load (shutdown) may miss keys that were not deleted: publish nothing
          if (Thread.currentThread().isInterrupted()) {
            LOG.warn("Signer loading was interrupted; keeping the currently loaded signers");
            throw new CancellationException("Signer loading was interrupted");
          }

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads
          state =
              new SignerState(
                  Map.copyOf(newSigners),
                  Map.copyOf(newProxySigners),
                  Map.copyOf(newProvenance),
                  Map.copyOf(newProxyProvenance));

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
  public Future<Void> addSigner(final ArtifactSigner signer, final Optional<Path> keyConfigFile) {
    return executorService.submit(
        () -> {
          final SignerState currentState = this.state;
          final String identifier = signer.getIdentifier();

          final Map<String, ArtifactSigner> newSigners = new HashMap<>(currentState.signers);
          final ArtifactSigner existing = newSigners.put(identifier, signer);
          if (existing != null) {
            LOG.warn("Replaced existing signer for identifier '{}'", identifier);
          }

          final Map<String, Set<ArtifactSigner>> newProxySigners =
              new HashMap<>(currentState.proxySigners);
          newProxySigners.putIfAbsent(identifier, Set.of());

          // the signer comes from its key config file, as if loaded by the key config source, or
          // from memory only, which no load removes
          final Map<String, Provenance> newProvenance = new HashMap<>(currentState.provenance);
          newProvenance.put(
              identifier,
              keyConfigFile
                  .map(
                      file -> new Provenance(SignerLoader.SOURCE_NAME, SignerLoader.fileName(file)))
                  .orElse(IN_MEMORY));

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads.
          state =
              new SignerState(
                  Map.copyOf(newSigners),
                  Map.copyOf(newProxySigners),
                  Map.copyOf(newProvenance),
                  currentState.proxyProvenance);
          LOG.info("Loaded new signer for identifier '{}'", identifier);
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
          // threads. Provenance is left in place (see Provenance).
          this.state =
              new SignerState(
                  Map.copyOf(newSigners),
                  Map.copyOf(newProxySigners),
                  currentState.provenance,
                  currentState.proxyProvenance);

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
   * intermediate state. The proxy signer is attributed to its keystore file, as if loaded from its
   * proxy directory.
   *
   * @param signerToAdd the proxy signer to add
   * @param consensusPubKey the consensus public key to associate with the proxy signer
   * @param keystoreFile the proxy keystore file written for the proxy signer
   * @return a {@link Future} that completes when the proxy signer has been added
   */
  @Override
  public Future<Void> addProxySigner(
      final ArtifactSigner signerToAdd, final String consensusPubKey, final Path keystoreFile) {
    return executorService.submit(
        () -> {
          final SignerState currentState = this.state;
          final String identifier = signerToAdd.getIdentifier();

          final Map<String, Set<ArtifactSigner>> newProxySigners =
              new HashMap<>(currentState.proxySigners);
          final Set<ArtifactSigner> existingProxies =
              newProxySigners.getOrDefault(consensusPubKey, Set.of());
          final Set<ArtifactSigner> updatedProxies = new HashSet<>(existingProxies);
          updatedProxies.add(signerToAdd);
          newProxySigners.put(consensusPubKey, Set.copyOf(updatedProxies));

          // the same names the proxy loader reports: the proxy directory under the configured
          // keystores path, and the file in it
          final Path proxyDir =
              commitBoostKeystoresParameters
                  .map(KeystoresParameters::getKeystoresPath)
                  .map(
                      path ->
                          path.resolve(consensusPubKey).resolve(signerToAdd.getKeyType().name()))
                  .orElse(keystoreFile.getParent());
          final Map<String, Provenance> newProxyProvenance =
              new HashMap<>(currentState.proxyProvenance);
          newProxyProvenance.put(
              identifier,
              new Provenance(
                  proxyDir.toString(), proxyDir.resolve(keystoreFile.getFileName()).toString()));

          // Atomically publish new immutable state - Map.copyOf() ensures readers never see
          // intermediate modifications, volatile write guarantees immediate visibility across
          // threads
          this.state =
              new SignerState(
                  currentState.signers,
                  Map.copyOf(newProxySigners),
                  currentState.provenance,
                  Map.copyOf(newProxyProvenance));

          LOG.info(
              "Loaded new proxy signer {} for consensus public key '{}'",
              identifier,
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

  /**
   * Loads the proxy signers of every consensus public key from the commit boost keystores path. The
   * directory structure expected is:
   *
   * <pre>
   * {keystoresPath}/{consensusPubKey}/{keyType}/
   * </pre>
   *
   * <p>A missing proxy signer is kept if its directory (unreadable directory or password file) or
   * its file failed to load; a missing or empty directory has no proxy signers. A missing keystores
   * path has no proxy signers; one that cannot be read keeps them all. The password file is read at
   * most once.
   */
  private static void loadProxySigners(
      final KeystoresParameters keystoreParameter,
      final SignerState currentState,
      final Set<String> consensusPubKeys,
      final Map<String, Set<ArtifactSigner>> newProxySigners,
      final Map<String, Provenance> newProxyProvenance) {
    final Path keystoresPath = keystoreParameter.getKeystoresPath();
    final boolean hadProxies =
        currentState.proxySigners.values().stream().anyMatch(proxies -> !proxies.isEmpty());
    if (Files.notExists(keystoresPath)) {
      if (hadProxies) {
        LOG.warn("Proxy keystores path {} does not exist; removing proxy keys", keystoresPath);
      }
      return;
    }
    if (!Files.isDirectory(keystoresPath) || !Files.isReadable(keystoresPath)) {
      if (hadProxies) {
        LOG.error(
            "Unable to read proxy keystores path {}; keeping previously loaded proxy keys",
            keystoresPath);
        retainAllProxySigners(currentState, consensusPubKeys, newProxySigners, newProxyProvenance);
      }
      return;
    }

    final Supplier<Optional<String>> password =
        Suppliers.memoize(() -> readProxyPassword(keystoreParameter.getKeystoresPasswordFile()));
    int retainedCount = 0;

    for (final String consensusPubKey : consensusPubKeys) {
      LOG.trace("Loading proxy signers for '{}' ...", consensusPubKey);
      final List<SignerSourceResult> dirResults = new ArrayList<>(2);
      loadProxyDir(
              keystoresPath,
              consensusPubKey,
              SECP256K1,
              password,
              SecpV3KeystoresBulkLoader::loadECDSAProxyKeystores)
          .ifPresent(dirResults::add);
      loadProxyDir(
              keystoresPath,
              consensusPubKey,
              BLS,
              password,
              BlsKeystoreBulkLoader::loadKeystoresUsingPassword)
          .ifPresent(dirResults::add);

      final Map<String, ArtifactSigner> proxies = new HashMap<>();
      for (final SignerSourceResult result : dirResults) {
        for (final SignerSourceResult.LoadedSigner loaded : result.signers()) {
          final String identifier = loaded.signer().getIdentifier();
          proxies.putIfAbsent(identifier, loaded.signer());
          newProxyProvenance.merge(
              identifier,
              new Provenance(result.source(), loaded.file().orElse(null)),
              Provenance::merge);
        }
      }

      final Failures dirFailures = Failures.of(dirResults);
      for (final ArtifactSigner previous :
          currentState.proxySigners.getOrDefault(consensusPubKey, Set.of())) {
        final String identifier = previous.getIdentifier();
        final Provenance provenance = currentState.proxyProvenance.get(identifier);
        if (proxies.containsKey(identifier)) {
          if (!dirFailures.isEmpty()) {
            newProxyProvenance.computeIfPresent(
                identifier, (id, places) -> withKeptPlaces(places, provenance, dirFailures));
          }
          continue;
        }
        final Provenance kept = keptPlaces(provenance, dirFailures);
        if (kept == null) {
          continue;
        }
        proxies.put(identifier, previous);
        newProxyProvenance.merge(identifier, kept, Provenance::merge);
        retainedCount++;
      }

      if (!proxies.isEmpty()) {
        newProxySigners.put(consensusPubKey, Set.copyOf(proxies.values()));
      }
    }

    if (retainedCount > 0) {
      LOG.warn(
          "Retained {} previously loaded proxy key(s) whose directory or file failed to load",
          retainedCount);
    }
  }

  private static void retainAllProxySigners(
      final SignerState currentState,
      final Set<String> consensusPubKeys,
      final Map<String, Set<ArtifactSigner>> newProxySigners,
      final Map<String, Provenance> newProxyProvenance) {
    int retainedCount = 0;
    for (final String consensusPubKey : consensusPubKeys) {
      final Set<ArtifactSigner> previousProxies =
          currentState.proxySigners.getOrDefault(consensusPubKey, Set.of());
      if (!previousProxies.isEmpty()) {
        newProxySigners.put(consensusPubKey, previousProxies);
        previousProxies.forEach(
            proxy -> copyProvenance(currentState, proxy.getIdentifier(), newProxyProvenance));
        retainedCount += previousProxies.size();
      }
    }
    if (retainedCount > 0) {
      LOG.warn("Retained {} previously loaded proxy key(s)", retainedCount);
    }
  }

  private static void copyProvenance(
      final SignerState currentState,
      final String identifier,
      final Map<String, Provenance> newProxyProvenance) {
    final Provenance provenance = currentState.proxyProvenance.get(identifier);
    if (provenance != null) {
      // the same proxy key may also be loaded for another consensus key
      newProxyProvenance.merge(identifier, provenance, Provenance::merge);
    }
  }

  private static Optional<String> readProxyPassword(final Path passwordFile) {
    try {
      return Optional.of(Files.readString(passwordFile));
    } catch (final IOException e) {
      LOG.error(
          "Unable to read proxy keystores password file; keeping previously loaded proxy keys", e);
      return Optional.empty();
    }
  }

  /**
   * Loads the proxy keystores of one consensus key and key type, as a source named after the
   * directory. Empty only if the directory is known not to exist.
   */
  private static Optional<SignerSourceResult> loadProxyDir(
      final Path keystoresPath,
      final String consensusPubKey,
      final KeyType keyType,
      final Supplier<Optional<String>> password,
      final BiFunction<Path, String, SignerSourceResult> loaderFunction) {
    final Path proxyDir = keystoresPath.resolve(consensusPubKey).resolve(keyType.name());
    // not Files.exists: it is also false when existence cannot be determined
    if (Files.notExists(proxyDir)) {
      return Optional.empty();
    }
    final String source = proxyDir.toString();
    if (password.get().isEmpty()) {
      return Optional.of(SignerSourceResult.sourceFailure(source));
    }
    final SignerSourceResult result = loaderFunction.apply(proxyDir, password.get().get());
    return Optional.of(
        new SignerSourceResult(
            source,
            result.signers(),
            result.failedFiles(),
            result.errorCount(),
            result.sourceFailed()));
  }

  /**
   * Keeps previously loaded signers that are missing because their source or file failed to load,
   * so a failure is not reported as a removal (and does not disable them in slashing protection).
   * Only the failed places are kept. A signer that still loads keeps its previous failed places.
   * Signers imported in memory only are always kept.
   */
  private static void retainSignersOfFailedSources(
      final SignerState currentState,
      final Failures failures,
      final Map<String, ArtifactSigner> newSigners,
      final Map<String, Provenance> newProvenance) {
    int retainedCount = 0;
    for (final Map.Entry<String, ArtifactSigner> previous : currentState.signers.entrySet()) {
      final String identifier = previous.getKey();
      final Provenance provenance = currentState.provenance.get(identifier);
      if (newSigners.containsKey(identifier)) {
        if (provenance != null && (!failures.isEmpty() || provenance.lists(IN_MEMORY))) {
          newProvenance.computeIfPresent(
              identifier, (id, places) -> withKeptPlaces(places, provenance, failures));
        }
        continue;
      }
      final Provenance kept = keptPlaces(provenance, failures);
      if (kept == null) {
        continue;
      }
      newSigners.put(identifier, previous.getValue());
      newProvenance.put(identifier, kept);
      if (kept.next() != null || !kept.source().equals(IN_MEMORY_SOURCE)) {
        retainedCount++;
      }
    }

    if (retainedCount > 0) {
      LOG.warn(
          "Retained {} previously loaded key(s) whose source or file failed to load; they are removed once their source or file loads without them",
          retainedCount);
    }
  }

  /**
   * The places to keep in this load: those that failed, and the in-memory place. {@code null} if
   * none; {@code places} itself if it is a single kept place.
   */
  private static Provenance keptPlaces(final Provenance places, final Failures failures) {
    if (places == null) {
      return null;
    }
    if (places.next() == null) {
      return isKept(places, failures) ? places : null;
    }
    if (failures.isEmpty() && !places.lists(IN_MEMORY)) {
      return null;
    }
    Provenance kept = null;
    for (Provenance place = places; place != null; place = place.next()) {
      if (isKept(place, failures)) {
        kept = new Provenance(place.source(), place.file(), kept);
      }
    }
    return kept;
  }

  private static boolean isKept(final Provenance place, final Failures failures) {
    return place.source().equals(IN_MEMORY_SOURCE) || failures.failed(place);
  }

  /** Adds a loaded key's previous places that are kept in this load. */
  private static Provenance withKeptPlaces(
      final Provenance places, final Provenance previous, final Failures failures) {
    final Provenance kept = keptPlaces(previous, failures);
    return kept == null ? places : Provenance.merge(places, kept);
  }

  /**
   * What failed in one load: whole sources, and individual files by source. Built once per load, so
   * checking a place is a hash lookup instead of a scan of the results.
   */
  private record Failures(Set<String> failedSources, Map<String, Set<String>> failedFiles) {
    private static final Failures NONE = new Failures(Set.of(), Map.of());

    private static Failures of(final List<SignerSourceResult> results) {
      final Set<String> failedSources = new HashSet<>();
      final Map<String, Set<String>> failedFiles = new HashMap<>();
      for (final SignerSourceResult result : results) {
        if (result.sourceFailed()) {
          failedSources.add(result.source());
        } else if (!result.failedFiles().isEmpty()) {
          failedFiles.merge(result.source(), result.failedFiles(), Sets::union);
        }
      }
      if (failedSources.isEmpty() && failedFiles.isEmpty()) {
        return NONE;
      }
      return new Failures(failedSources, failedFiles);
    }

    private boolean isEmpty() {
      return failedSources.isEmpty() && failedFiles.isEmpty();
    }

    private boolean failed(final Provenance place) {
      if (failedSources.contains(place.source())) {
        return true;
      }
      final Set<String> files = failedFiles.get(place.source());
      return files != null && place.file() != null && files.contains(place.file());
    }
  }
}
