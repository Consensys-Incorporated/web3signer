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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.config.SignerSourceResult;
import tech.pegasys.web3signer.signing.config.metadata.SignerOrigin;
import tech.pegasys.web3signer.signing.secp256k1.util.JsonFilesUtil;
import tech.pegasys.web3signer.signing.util.IdentifierUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Bulk-loads BLS keystores; reports each signer's file and the files that failed. */
public class BlsKeystoreBulkLoader {
  private static final Logger LOG = LogManager.getLogger();
  private static final String SOURCE_NAME = "bls keystores";

  public static SignerSourceResult loadKeystoresUsingPasswordDir(
      final Path keystoresDirectory, final Path passwordsDirectory) {
    final PasswordReader passwordReader;
    try {
      passwordReader = PasswordReader.fromDirectory(passwordsDirectory);
    } catch (final IOException e) {
      LOG.error("Unable to read keystore password directory", e);
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    final List<Path> keystoreFiles;
    try {
      keystoreFiles = JsonFilesUtil.loadJsonExtPaths(keystoresDirectory);
    } catch (final IOException e) {
      LOG.error("Error reading keystore files", e);
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    return KeystoreFilesLoader.load(
        SOURCE_NAME,
        keystoreFiles,
        keystoreFile -> createSignerForKeystore(keystoreFile, passwordReader));
  }

  public static SignerSourceResult loadKeystoresUsingPasswordFile(
      final Path keystoresDirectory, final Path passwordFile) {
    final String password;
    try {
      password = Files.readString(passwordFile);
    } catch (final IOException e) {
      LOG.error("Unable to read password file", e);
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    return loadKeystoresUsingPassword(keystoresDirectory, password);
  }

  /** Loads every keystore with an already read password (proxy keystores). */
  public static SignerSourceResult loadKeystoresUsingPassword(
      final Path keystoresDirectory, final String password) {
    final List<Path> keystoreFiles;
    try {
      keystoreFiles = JsonFilesUtil.loadJsonExtPaths(keystoresDirectory);
    } catch (final IOException e) {
      LOG.error("Error reading keystore files", e);
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    return KeystoreFilesLoader.load(
        SOURCE_NAME,
        keystoreFiles,
        keystoreFile -> createSignerForKeystore(keystoreFile, ignored -> password));
  }

  /**
   * A keystore whose password file cannot be read reports the pubkey in its JSON, which a renamed
   * keystore still holds. The pubkey is unverified: decryption has not run, so nothing contradicts
   * it. A keystore that fails at or after decryption claims nothing.
   */
  private static KeystoreFilesLoader.FileResult createSignerForKeystore(
      final Path keystoreFile, final PasswordReader passwordReader) {
    LOG.debug("Loading keystore {}", keystoreFile);
    try {
      final KeyStoreData keyStoreData = KeyStoreLoader.loadFromFile(keystoreFile.toUri());
      final String fileNameWithoutExt =
          FilenameUtils.removeExtension(keystoreFile.getFileName().toString());
      final String password;
      try {
        password = passwordReader.readPassword(fileNameWithoutExt + ".txt");
      } catch (final IOException e) {
        LOG.error("Password of keystore {} could not be read", keystoreFile, e);
        return KeystoreFilesLoader.FileResult.failedClaiming(claimedKey(keyStoreData));
      }
      final BLSKeyPair keyPair = KeyStore.decrypt(password, keyStoreData);
      return KeystoreFilesLoader.FileResult.loaded(
          new BlsArtifactSigner(keyPair, SignerOrigin.FILE_KEYSTORE));
    } catch (final RuntimeException e) {
      LOG.error("Keystore could not be loaded {}", keystoreFile, e);
      return KeystoreFilesLoader.FileResult.failed();
    }
  }

  private static String claimedKey(final KeyStoreData keyStoreData) {
    return keyStoreData.pubkey() == null
        ? null
        : IdentifierUtils.normaliseIdentifier(keyStoreData.pubkey().toHexString());
  }
}
