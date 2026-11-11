/*
 * Copyright 2026 Consensys Incorporated.
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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.config.SignerSourceResult;
import tech.pegasys.web3signer.signing.config.SignerSourceResult.LoadedSigner;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.function.Function;

/** Loads keystore files in parallel; reports each signer's file and the files that failed. */
final class KeystoreFilesLoader {

  private KeystoreFilesLoader() {}

  /**
   * Outcome of loading one keystore file.
   *
   * @param signer the loaded signer, {@code null} if the file failed
   * @param claimedKey for a failed file, the unverified key it claims to hold, or {@code null}
   */
  record FileResult(ArtifactSigner signer, String claimedKey) {
    private static final FileResult FAILED = new FileResult(null, null);

    static FileResult loaded(final ArtifactSigner signer) {
      return new FileResult(signer, null);
    }

    static FileResult failed() {
      return FAILED;
    }

    static FileResult failedClaiming(final String claimedKey) {
      return claimedKey == null ? FAILED : new FileResult(null, claimedKey);
    }
  }

  /**
   * @param loadFile loads one keystore file. Must not throw, so that one file cannot fail the whole
   *     load.
   */
  static SignerSourceResult load(
      final String source,
      final List<Path> keystoreFiles,
      final Function<Path, FileResult> loadFile) {
    final ConcurrentLinkedQueue<LoadedSigner> signers = new ConcurrentLinkedQueue<>();
    final Set<String> failedFiles = ConcurrentHashMap.newKeySet();
    final Map<String, String> failedFileKeys = new ConcurrentHashMap<>();

    keystoreFiles.parallelStream()
        .forEach(
            keystoreFile -> {
              final FileResult result = loadFile.apply(keystoreFile);
              final String file = keystoreFile.toString();
              if (result.signer() != null) {
                signers.add(new LoadedSigner(result.signer(), Optional.of(file)));
              } else {
                failedFiles.add(file);
                if (result.claimedKey() != null) {
                  failedFileKeys.put(file, result.claimedKey());
                }
              }
            });

    return new SignerSourceResult(
        source, List.copyOf(signers), failedFiles, failedFiles.size(), false, failedFileKeys);
  }
}
