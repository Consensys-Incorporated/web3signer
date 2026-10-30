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
package tech.pegasys.web3signer.signing.config;

import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Signers loaded from one source (key config directory, keystore directory or vault), with the
 * files that failed and whether the source failed as a whole. {@link DefaultArtifactSignerProvider}
 * uses them to tell a deleted key from one that failed to load.
 *
 * @param source name of the source, unique among the sources of one provider
 * @param signers loaded signers with their file; a key defined by several files appears once per
 *     file
 * @param failedFiles files that are present but failed to load
 * @param errorCount number of errors in this source
 * @param sourceFailed failure not attributable to a file (unlistable directory, unreadable shared
 *     password file, any vault error)
 */
public record SignerSourceResult(
    String source,
    List<LoadedSigner> signers,
    Set<String> failedFiles,
    int errorCount,
    boolean sourceFailed) {

  /** A loaded signer and its file; the file is empty for vaults. */
  public record LoadedSigner(ArtifactSigner signer, Optional<String> file) {}

  public SignerSourceResult {
    signers = List.copyOf(signers);
    failedFiles = Set.copyOf(failedFiles);
  }

  /** The whole source failed before any file could be loaded. */
  public static SignerSourceResult sourceFailure(final String source) {
    return new SignerSourceResult(source, List.of(), Set.of(), 1, true);
  }

  /** Vault loaders cannot attribute errors to secrets, so any error fails the whole source. */
  public static SignerSourceResult fromVault(
      final String source, final MappedResults<ArtifactSigner> results) {
    return new SignerSourceResult(
        source,
        results.getValues().stream()
            .map(signer -> new LoadedSigner(signer, Optional.empty()))
            .toList(),
        Set.of(),
        results.getErrorCount(),
        results.getErrorCount() > 0);
  }

  public List<ArtifactSigner> artifactSigners() {
    return signers.stream().map(LoadedSigner::signer).toList();
  }
}
