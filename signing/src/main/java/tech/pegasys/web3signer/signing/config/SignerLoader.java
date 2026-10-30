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

import tech.pegasys.web3signer.common.config.SignerLoaderConfig;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.config.SignerSourceResult.LoadedSigner;
import tech.pegasys.web3signer.signing.config.metadata.SigningMetadata;
import tech.pegasys.web3signer.signing.config.metadata.SigningMetadataException;
import tech.pegasys.web3signer.signing.config.metadata.parser.SignerParser;

import java.io.Closeable;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.Sets;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * The SignerLoader loads metadata files and converts them to ArtifactSigners using a smart caching
 * mechanism. This class maintains a cache of loaded signers and automatically handles file
 * additions and deletions. It leverages Java virtual threads for efficient parallel processing of
 * large file sets.
 *
 * <p>Processing strategies:
 *
 * <ul>
 *   <li>Sequential: For small batches (below sequential threshold, default 100 files)
 *   <li>Parallel with virtual threads: For larger batches, processed in configurable batch sizes
 * </ul>
 *
 * <p>This class implements {@link Closeable} for proper resource management. The {@link #close()}
 * method is idempotent as required by the Closeable contract.
 *
 * <p>This class is thread-safe and uses volatile references with immutable maps for lock-free
 * reads. All write operations are atomic through copy-on-write semantics.
 */
public class SignerLoader implements Closeable {
  private static final Logger LOG = LogManager.getLogger();
  private static final Set<String> CONFIG_FILE_EXTENSIONS = Set.of("yaml", "yml");
  static final String SOURCE_NAME = "key config files";

  /** The name under which a key config file is reported in {@link SignerSourceResult}. */
  static String fileName(final Path file) {
    return file.toAbsolutePath().normalize().toString();
  }

  private volatile Map<String, CachedSignerData> cachedArtifactSigners = Collections.emptyMap();
  private final AtomicBoolean closed = new AtomicBoolean(false);

  /** Holds cached signer data along with file metadata for cache invalidation. */
  private record CachedSignerData(
      String filePath, FileTime lastModifiedTime, Set<ArtifactSigner> signers) {}

  /**
   * Result of loading signers from configuration files.
   *
   * @param loadedSigners map of file paths to their loaded artifact signers
   * @param failedPaths files present but failed to load; one error each
   * @param unprocessedPaths files not processed because loading stopped (loader closed, thread
   *     interrupted, task cancelled); not errors, but not deleted either
   */
  @VisibleForTesting
  record LoadResult(
      Map<String, Set<ArtifactSigner>> loadedSigners,
      Set<String> failedPaths,
      Set<String> unprocessedPaths) {
    private static final LoadResult EMPTY = new LoadResult(Map.of(), Set.of(), Set.of());

    static LoadResult loaded(final String path, final Set<ArtifactSigner> signers) {
      return new LoadResult(Map.of(path, signers), Set.of(), Set.of());
    }

    static LoadResult failed(final String path) {
      return new LoadResult(Map.of(), Set.of(path), Set.of());
    }

    static LoadResult unprocessed(final String path) {
      return new LoadResult(Map.of(), Set.of(), Set.of(path));
    }

    int errorCount() {
      return failedPaths.size();
    }
  }

  /** Accumulates file results; not thread-safe. */
  private static final class LoadResultBuilder {
    private final Map<String, Set<ArtifactSigner>> loadedSigners = new HashMap<>();
    private final Set<String> failedPaths = new HashSet<>();
    private final Set<String> unprocessedPaths = new HashSet<>();

    void add(final LoadResult result) {
      loadedSigners.putAll(result.loadedSigners());
      failedPaths.addAll(result.failedPaths());
      unprocessedPaths.addAll(result.unprocessedPaths());
    }

    void addFailed(final String path) {
      failedPaths.add(path);
    }

    void addUnprocessed(final String path) {
      unprocessedPaths.add(path);
    }

    LoadResult build() {
      return new LoadResult(loadedSigners, failedPaths, unprocessedPaths);
    }
  }

  private final SignerLoaderConfig config;
  private final ExecutorService virtualThreadExecutor;

  public SignerLoader(final SignerLoaderConfig config) {
    this.config = config;
    this.virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor();
  }

  /**
   * Load ArtifactSigners for metadata files. This method maintains a cache of loaded signers and
   * intelligently handles file changes:
   *
   * <ul>
   *   <li>New files are processed and added to cache
   *   <li>Modified files (based on last modified time) are reprocessed
   *   <li>Deleted files are removed from cache
   *   <li>Unchanged files remain in cache without reprocessing
   * </ul>
   *
   * @param signerParser An implementation of SignerParser to parse the metadata files
   * @return the loaded signers with their files, the failed files and the error count
   * @throws IllegalStateException if this SignerLoader has been closed
   */
  public SignerSourceResult load(final SignerParser signerParser) {
    if (closed.get()) {
      throw new IllegalStateException("SignerLoader instance has been closed");
    }
    LOG.info("Loading signer configuration metadata files from {}", config.configsDirectory());
    final Instant loadStartTime = Instant.now();

    // Get all metadata file paths from the config directory
    final Map<String, FileTime> availableFilesWithTime;
    try {
      availableFilesWithTime = getMetadataConfigFilesWithTime();
    } catch (final IOException e) {
      LOG.error("Unable to access the supplied key directory", e);
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    // Get new cache by removing entries that doesn't exist or has modified time
    final Map<String, CachedSignerData> newCache = getNewCacheMap(availableFilesWithTime);

    // Find files to process (new + modified)
    final Set<String> newFilesToProcess =
        getNewFilesToProcess(availableFilesWithTime.keySet(), newCache.keySet());
    LOG.info(
        "Processing {} metadata files. Cached paths: {}",
        newFilesToProcess.size(),
        newCache.size());

    // load new signers
    final LoadResult loadResult = loadNewSigners(newFilesToProcess, signerParser);

    // Add newly loaded signers to cache with their modification times
    loadResult.loadedSigners.forEach(
        (pathStr, signers) -> {
          FileTime modTime = availableFilesWithTime.get(pathStr);
          if (modTime == null) {
            LOG.warn("No modification time found for {}, using current time", pathStr);
            modTime = FileTime.from(Instant.now());
          }
          newCache.put(pathStr, new CachedSignerData(pathStr, modTime, signers));
          LOG.trace("Added {} signers from {}", signers.size(), pathStr);
        });

    // Update the volatile reference with the new immutable map
    cachedArtifactSigners = Map.copyOf(newCache);

    // one entry per file, so that a key defined by several files is kept while any of them fails;
    // unprocessed files are kept like failed ones but are not errors
    final SignerSourceResult result =
        new SignerSourceResult(
            SOURCE_NAME,
            cachedArtifactSigners.values().stream()
                .flatMap(
                    cached ->
                        cached.signers().stream()
                            .map(
                                signer -> new LoadedSigner(signer, Optional.of(cached.filePath()))))
                .toList(),
            Sets.union(loadResult.failedPaths(), loadResult.unprocessedPaths()),
            loadResult.errorCount(),
            false);

    LOG.info(
        "Total Artifact Signers loaded via configuration files: {}\nTotal Paths cached: {}, Error count: {}, Not processed: {}\nTime Taken: {}.",
        result.signers().size(),
        cachedArtifactSigners.size(),
        loadResult.errorCount(),
        loadResult.unprocessedPaths().size(),
        calculateTimeTaken(loadStartTime).orElse("unknown duration"));

    return result;
  }

  /**
   * Identifies files that need to be processed by computing the set difference between available
   * files and unchanged cached files. The result includes both new files (never cached) and
   * modified files (cached but with different timestamps).
   *
   * @param availableFiles all files currently present in the directory
   * @param unchangedCachedFiles files in cache that haven't been modified
   * @return set of file paths that need to be processed (new + modified files)
   */
  private Set<String> getNewFilesToProcess(
      final Set<String> availableFiles, final Set<String> unchangedCachedFiles) {
    final Set<String> filesToProcess = new HashSet<>(availableFiles);
    filesToProcess.removeAll(unchangedCachedFiles);

    // filesToProcess now contains:
    // 1. New files (were never in cache)
    // 2. Modified files (were in cache but have different timestamp)
    return filesToProcess;
  }

  /**
   * Creates a new cache map containing only files that still exist on the filesystem and haven't
   * been modified since last cached. Files are retained in cache only if:
   *
   * <ol>
   *   <li>They still exist in the filesystem
   *   <li>Their last modified time hasn't changed
   * </ol>
   *
   * Modified or deleted files are excluded from the returned cache and will be reprocessed or
   * removed respectively.
   *
   * @param currentFilesWithTime map of current file paths to their last modified times
   * @return new cache map containing only unchanged files
   */
  private Map<String, CachedSignerData> getNewCacheMap(
      final Map<String, FileTime> currentFilesWithTime) {

    final Map<String, CachedSignerData> currentCacheSnapshot = Map.copyOf(cachedArtifactSigners);
    final Map<String, CachedSignerData> newCache = new HashMap<>();

    // Iterate cached files
    for (Map.Entry<String, CachedSignerData> entry : currentCacheSnapshot.entrySet()) {
      final String filePath = entry.getKey();
      final CachedSignerData cachedData = entry.getValue();

      // only add the files which are there on file system and modified time not changed
      if (currentFilesWithTime.containsKey(filePath)) {
        final FileTime currentModTime = currentFilesWithTime.get(filePath);

        // Keep in cache only if unchanged
        if (currentModTime.compareTo(cachedData.lastModifiedTime()) == 0) {
          newCache.put(filePath, cachedData);
        } else {
          LOG.trace("File modified, will reprocess: {}", filePath);
        }
      } else {
        LOG.trace("File deleted: {}", filePath);
      }
    }

    return newCache; // Contains ONLY unchanged cached files
  }

  /**
   * Loads new signers from the specified files using the appropriate processing strategy based on
   * file count and configuration.
   *
   * @param newFilesToProcess files that need to be loaded
   * @param signerParser parser to convert file content to signers
   * @return pair of loaded signers map and error count
   */
  @VisibleForTesting
  LoadResult loadNewSigners(final Set<String> newFilesToProcess, final SignerParser signerParser) {

    final AtomicLong configFilesHandled = new AtomicLong(0);
    final int totalFiles = newFilesToProcess.size();

    if (totalFiles == 0) {
      return LoadResult.EMPTY;
    }

    // Sequential processing for small batches or when parallel is disabled
    if (!config.parallelProcess() || totalFiles < config.sequentialThreshold()) {
      LOG.info("Processing {} files sequentially", totalFiles);
      return processSequentially(newFilesToProcess, signerParser, configFilesHandled, totalFiles);
    }

    // Parallel processing with batches
    LOG.info("Processing {} files in parallel with batch size {}", totalFiles, config.batchSize());
    return processInBatches(newFilesToProcess, signerParser, configFilesHandled, totalFiles);
  }

  /**
   * Processes files in parallel using virtual threads, subdivided into batches. Stops before the
   * next batch if the loader is closed or the thread is interrupted; files of batches not started
   * are reported as unprocessed.
   *
   * @param filesToProcess set of file paths to process
   * @param signerParser parser for converting file content
   * @param configFilesHandled atomic counter for progress tracking
   * @param totalFiles total number of files for progress reporting
   * @return LoadResult with all loaded signers, failed and unprocessed files
   */
  @VisibleForTesting
  LoadResult processInBatches(
      final Set<String> filesToProcess,
      final SignerParser signerParser,
      final AtomicLong configFilesHandled,
      final int totalFiles) {

    final LoadResultBuilder results = new LoadResultBuilder();
    final List<String> fileList = new ArrayList<>(filesToProcess);
    int handledFiles = 0;

    while (handledFiles < fileList.size()) {
      if (closed.get()) {
        LOG.warn("SignerLoader closed during batch processing");
        break;
      }
      if (Thread.currentThread().isInterrupted()) {
        LOG.warn("Batch processing interrupted, returning partial results");
        break;
      }
      final int batchStart = handledFiles;
      final int batchEnd = Math.min(batchStart + config.batchSize(), fileList.size());
      final List<String> batch = fileList.subList(batchStart, batchEnd);

      if (totalFiles > config.batchSize()) {
        LOG.info("Processing batch {}-{} of {} files", batchStart + 1, batchEnd, totalFiles);
      }

      // Submit all tasks in this batch; the executor rejects tasks once the loader is closed
      final List<Future<LoadResult>> futures = new ArrayList<>(batch.size());
      try {
        for (String pathStr : batch) {
          futures.add(
              virtualThreadExecutor.submit(
                  () -> processFile(pathStr, signerParser, configFilesHandled, totalFiles)));
        }
      } catch (final RejectedExecutionException e) {
        LOG.warn("SignerLoader closed during batch processing");
      }

      results.add(collectBatchResults(futures, batch.subList(0, futures.size())));
      handledFiles = batchStart + futures.size();
      if (futures.size() < batch.size()) {
        break;
      }
    }

    // not processed, not deleted: report them so that their previously loaded signers are kept
    fileList.subList(handledFiles, fileList.size()).forEach(results::addUnprocessed);
    return results.build();
  }

  /**
   * Collects results from a batch of futures, applying individual timeout to each task.
   *
   * <p>If interrupted while waiting for a future, this method restores the thread's interrupt
   * status, keeps the results of the tasks that already completed, cancels the others and reports
   * their files as unprocessed.
   *
   * @param futures list of submitted futures to collect results from
   * @param batch corresponding file paths
   * @return LoadResult with the loaded signers, failed and unprocessed files of the batch
   */
  @VisibleForTesting
  LoadResult collectBatchResults(final List<Future<LoadResult>> futures, final List<String> batch) {
    final LoadResultBuilder results = new LoadResultBuilder();

    for (int i = 0; i < futures.size(); i++) {
      final Future<LoadResult> future = futures.get(i);
      final String filePath = batch.get(i);

      try {
        results.add(future.get(config.taskTimeoutSeconds(), TimeUnit.SECONDS));
      } catch (final TimeoutException e) {
        LOG.error("Task timed out after {} seconds: {}", config.taskTimeoutSeconds(), filePath);
        future.cancel(true);
        results.addFailed(filePath);
      } catch (final InterruptedException e) {
        Thread.currentThread().interrupt();
        LOG.warn("Interrupted while collecting batch results");
        collectCompletedAndCancelRest(futures, batch, i, results);
        break;
      } catch (final ExecutionException e) {
        LOG.warn("Task execution failed: {}", filePath, e);
        results.addFailed(filePath);
      } catch (final CancellationException e) {
        LOG.warn("Task was canceled: {}", filePath);
        results.addUnprocessed(filePath);
      }
    }
    return results.build();
  }

  /** Keeps the results of the tasks from the given index that completed; cancels the others. */
  private static void collectCompletedAndCancelRest(
      final List<Future<LoadResult>> futures,
      final List<String> batch,
      final int startIndex,
      final LoadResultBuilder results) {
    for (int j = startIndex; j < futures.size(); j++) {
      final Future<LoadResult> future = futures.get(j);
      switch (future.state()) {
        case SUCCESS -> results.add(future.resultNow());
        case FAILED -> results.addFailed(batch.get(j));
        default -> {
          future.cancel(true);
          results.addUnprocessed(batch.get(j));
        }
      }
    }
  }

  /**
   * Processes files sequentially without parallelization. Used for small batches or when parallel
   * processing is disabled.
   *
   * @param newFilesToProcess files to process
   * @param signerParser parser for converting metadata to signers
   * @param configFilesHandled counter for processed files
   * @param totalFiles total number of files for progress reporting
   * @return LoadResult with loaded signers and error count
   */
  @VisibleForTesting
  LoadResult processSequentially(
      final Set<String> newFilesToProcess,
      final SignerParser signerParser,
      final AtomicLong configFilesHandled,
      final int totalFiles) {

    final LoadResultBuilder results = new LoadResultBuilder();
    for (String pathStr : newFilesToProcess) {
      results.add(processFile(pathStr, signerParser, configFilesHandled, totalFiles));
    }
    return results.build();
  }

  /**
   * Processes a single metadata file and converts it to ArtifactSigners.
   *
   * <p>This method handles the complete lifecycle of processing a signer configuration file:
   *
   * <ol>
   *   <li><b>File Reading (IO-bound):</b> Reads the file content from disk using NIO operations
   *   <li><b>Metadata Parsing (Mixed IO/CPU):</b> Parses the YAML/YML content into SigningMetadata
   *       objects
   *   <li><b>Signer Creation (CPU-bound):</b> Performs decryption and creates ArtifactSigner
   *       instances
   * </ol>
   *
   * <p>The method includes comprehensive error handling and thread interruption checks at strategic
   * points to ensure responsive cancellation when running in virtual threads. Interruption checks
   * are placed:
   *
   * <ul>
   *   <li>Before starting any work (early exit optimization)
   *   <li>After IO operations (NIO channels may be affected by interruption)
   *   <li>Before CPU-intensive decryption operations (which can take up to a minute)
   * </ul>
   *
   * <p><b>Thread Safety:</b> This method is thread-safe and can be called concurrently from
   * multiple virtual threads. The shared counters use atomic operations for thread-safe updates.
   *
   * <p><b>Error Handling:</b> All errors are logged with appropriate detail levels and reported as
   * a failed file; an interrupted file is reported as unprocessed. Exceptions are not propagated,
   * allowing batch processing to continue with other files.
   *
   * @param pathStr absolute normalized path to the metadata file to process
   * @param signerParser parser implementation for converting metadata to ArtifactSigners
   * @param configFilesHandled atomic counter tracking total files processed (for progress
   *     reporting)
   * @param totalFiles total number of files being processed in this batch (for progress
   *     calculation)
   * @return the file's immutable set of ArtifactSigners, or the file as failed or unprocessed
   * @implNote The returned Set of ArtifactSigners is made immutable using {@code Set.copyOf()} to
   *     ensure thread safety when cached. The decryption step (Step 3) is the most time-consuming
   *     operation and may involve HSM operations, encrypted key material decryption, or remote key
   *     vault access.
   */
  @VisibleForTesting
  LoadResult processFile(
      final String pathStr,
      final SignerParser signerParser,
      final AtomicLong configFilesHandled,
      final int totalFiles) {
    // interrupted files are reported as unprocessed, not deleted; check before starting
    if (Thread.currentThread().isInterrupted()) {
      LOG.debug("File processing interrupted before start: {}", pathStr);
      return LoadResult.unprocessed(pathStr);
    }

    reportProgress(configFilesHandled, totalFiles);

    try {
      // Step 1: File reading (IO-bound)
      final Path filePath = Path.of(pathStr);
      final String content = Files.readString(filePath, StandardCharsets.UTF_8);

      // Check interruption after IO operation
      if (Thread.currentThread().isInterrupted()) {
        LOG.debug("File processing interrupted after reading: {}", pathStr);
        return LoadResult.unprocessed(pathStr);
      }

      // Step 2: Parse metadata (mixed IO/CPU)
      final List<SigningMetadata> signingMetadata;
      try {
        signingMetadata = signerParser.readSigningMetadata(content);
      } catch (final SigningMetadataException e) {
        LOG.error(
            "Error parsing metadata file {} to signing metadata: {}",
            pathStr,
            ExceptionUtils.getRootCauseMessage(e));
        return LoadResult.failed(pathStr);
      }

      // Check interruption before expensive decryption operation
      if (Thread.currentThread().isInterrupted()) {
        LOG.debug("File processing interrupted before decryption: {}", pathStr);
        return LoadResult.unprocessed(pathStr);
      }

      // Step 3: Decryption and conversion (CPU-bound, can take up to a minute)
      final Set<ArtifactSigner> artifactSigners;
      try {
        artifactSigners = Set.copyOf(signerParser.parse(signingMetadata));
      } catch (final SigningMetadataException e) {
        LOG.error(
            "Error converting signing metadata to Artifact Signer for file {}: {}",
            pathStr,
            ExceptionUtils.getRootCauseMessage(e));
        return LoadResult.failed(pathStr);
      }

      LOG.trace("Successfully processed file {} with {} signers", pathStr, artifactSigners.size());
      return LoadResult.loaded(pathStr, artifactSigners);
    } catch (final IOException e) {
      // Check if IOException was caused by interruption
      if (Thread.currentThread().isInterrupted()) {
        LOG.debug("File processing interrupted during IO: {}", pathStr);
        return LoadResult.unprocessed(pathStr);
      }
      LOG.error("Error reading metadata config file: {}", pathStr, e);
      return LoadResult.failed(pathStr);
    } catch (final Exception e) {
      // Check if exception is due to thread interruption (timeout/cancellation)
      if (Thread.currentThread().isInterrupted()
          || e instanceof InterruptedException
          || (e.getCause() != null && e.getCause() instanceof InterruptedException)) {
        LOG.debug("File processing cancelled: {}", pathStr);
        return LoadResult.unprocessed(pathStr);
      }
      LOG.error("Unexpected error processing file: {}", pathStr, e);
      return LoadResult.failed(pathStr);
    }
  }

  /**
   * Reports processing progress at dynamic intervals based on total file count. Ensures
   * approximately 100 progress reports regardless of file count, with a minimum interval of 10
   * files.
   *
   * @param processed atomic counter of processed files
   * @param total total number of files being processed
   */
  private void reportProgress(final AtomicLong processed, final int total) {
    long count = processed.incrementAndGet();
    // Report ~100 times max, or every 10 files minimum
    int interval = Math.max(10, total / 100);
    if (count % interval == 0 || count == total) {
      final int percentage = (int) Math.round((count * 100.0) / total);
      LOG.info("Processed {}/{} files ({}%)", count, total, percentage);
    }
  }

  /**
   * Closes this SignerLoader and releases resources. This method is idempotent - calling it
   * multiple times has no additional effect.
   *
   * @throws IOException if an I/O error occurs during shutdown
   */
  @Override
  public void close() throws IOException {
    if (!closed.compareAndSet(false, true)) {
      return;
    }

    if (virtualThreadExecutor != null) {
      virtualThreadExecutor.shutdown();
      try {
        if (!virtualThreadExecutor.awaitTermination(5, TimeUnit.MINUTES)) {
          LOG.warn("Executor did not terminate in 5 minutes, forcing shutdown");
          virtualThreadExecutor.shutdownNow();
        }
      } catch (InterruptedException e) {
        LOG.error("Interrupted while waiting for executor shutdown", e);
        virtualThreadExecutor.shutdownNow();
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted during close", e);
      }
    }

    // Clear cache to release memory - AFTER executor is shut down
    cachedArtifactSigners = Collections.emptyMap();
  }

  /**
   * Get all metadata config file paths with their last modified times from the directory.
   *
   * @return A map of normalized path strings to their last modified times
   * @throws IOException If there is an error reading the config directory
   */
  private Map<String, FileTime> getMetadataConfigFilesWithTime() throws IOException {
    if (!Files.exists(config.configsDirectory())) {
      throw new FileNotFoundException("Config directory does not exist");
    }

    if (!Files.isDirectory(config.configsDirectory())) {
      throw new IOException("Path is not a directory: " + config.configsDirectory());
    }

    try (final Stream<Path> fileStream = Files.list(config.configsDirectory())) {
      return fileStream
          .filter(SignerLoader::validFileExtension)
          .collect(
              Collectors.toMap(
                  SignerLoader::fileName,
                  path -> {
                    try {
                      return Files.getLastModifiedTime(path);
                    } catch (IOException e) {
                      LOG.warn("Could not get last modified time for {}, using current time", path);
                      return FileTime.from(Instant.now());
                    }
                  }));
    }
  }

  @VisibleForTesting
  static Optional<String> calculateTimeTaken(final Instant start) {
    final Instant now = Instant.now();
    final long timeTaken = Duration.between(start, now).toMillis();
    if (timeTaken < 0) {
      LOG.warn("System Clock returned time in past. Start: {}, Now: {}.", start, now);
      return Optional.empty();
    }
    return Optional.of(DurationFormatUtils.formatDurationHMS(timeTaken));
  }

  /**
   * Validates if a file has an acceptable extension for processing. Filters out hidden files and
   * only accepts .yaml and .yml extensions.
   *
   * @param filename path to validate
   * @return true if file should be processed, false otherwise
   */
  private static boolean validFileExtension(final Path filename) {
    final boolean isHidden = filename.toFile().isHidden();
    final String extension = FilenameUtils.getExtension(filename.toString());
    return !isHidden && CONFIG_FILE_EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT));
  }
}
