/*
 * Copyright 2022 ConsenSys AG.
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
package tech.pegasys.web3signer.signing;

import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import org.apache.tuweni.bytes.Bytes;

/// Default `ValidatorManager` implementation that supports both file-backed and in-memory-only
/// validator management.
///
/// When a `KeystoreFileManager` is supplied, validators are persisted to disk before being
/// activated in memory, so they survive a restart. When no file manager is supplied (i.e.
/// `skipKeystoreStorage` is enabled), validators exist only in memory and are lost when Web3Signer
/// stops.
///
/// In both modes the in-memory state is always the source of truth for active signing: additions
/// register the signer in memory _after_ a successful file write (if applicable), and deletions
/// remove the signer from memory _before_ deleting any files.
public class DefaultValidatorManager implements ValidatorManager {
  private final ArtifactSignerProvider signerProvider;
  private final Optional<KeystoreFileManager> keystoreFileManager;

  /// Creates a new `DefaultValidatorManager`.
  ///
  /// @param signerProvider the registry used to activate and deactivate signers in memory
  /// @param keystoreFileManager when present, keystore files are written on import and deleted on
  ///   removal; when empty, the manager operates in in-memory-only mode and imported validators are
  ///   **not** persisted across restarts
  public DefaultValidatorManager(
      final ArtifactSignerProvider signerProvider,
      final Optional<KeystoreFileManager> keystoreFileManager) {
    this.signerProvider = signerProvider;
    this.keystoreFileManager = keystoreFileManager;
  }

  @Override
  public void deleteValidator(final Bytes publicKey) {
    try {
      // Remove active key from memory first, will stop any further signing with this key
      signerProvider.removeSigner(publicKey.toHexString()).get();
      // Then, delete the corresponding keystore files
      if (keystoreFileManager.isPresent()) {
        final boolean filesDeleted =
            keystoreFileManager.get().deleteKeystoreFiles(publicKey.toHexString());
        if (!filesDeleted) {
          throw new IllegalStateException(
              "Unable to delete keystore files for '"
                  + publicKey
                  + "': files missing, unreadable, or pubkey mismatch — check logs for details");
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Unable to delete validator", e);
    } catch (IOException | ExecutionException e) {
      throw new IllegalStateException("Unable to delete validator", e);
    }
  }

  @Override
  public void addValidator(
      final BlsArtifactSigner signer, final KeystoreFileRecord keystoreFileRecord) {
    try {
      // write keystore to file - allows to bail out in case of failure
      if (keystoreFileManager.isPresent()) {
        keystoreFileManager.get().createKeystoreFiles(keystoreFileRecord);
      }
      // Then, add it in memory to make it available for signing ...
      signerProvider.addSigner(signer).get();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IllegalStateException("Unable to add validator", e);
    } catch (ExecutionException | IOException e) {
      throw new IllegalStateException("Unable to add validator", e);
    }
  }
}
