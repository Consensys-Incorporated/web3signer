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
package tech.pegasys.web3signer.signing.bulkloading;

import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.EthSecpArtifactSigner;
import tech.pegasys.web3signer.signing.K256ArtifactSigner;
import tech.pegasys.web3signer.signing.config.SignerSourceResult;
import tech.pegasys.web3signer.signing.config.SignerSourceResult.LoadedSigner;
import tech.pegasys.web3signer.signing.secp256k1.filebased.CredentialSigner;
import tech.pegasys.web3signer.signing.secp256k1.util.JsonFilesUtil;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.crypto.exception.CipherException;

/** Bulk-loads SECP256K1 v3 keystores; reports each signer's file and the files that failed. */
public class SecpV3KeystoresBulkLoader {
  private static final Logger LOG = LogManager.getLogger();
  private static final String SOURCE_NAME = "v3 keystores";

  /**
   * Bulk-load Ethereum compatible SECP Artifact Signers from encrypted v3 keystores.
   *
   * @param keystoresPath Path to the directory containing the v3 keystores
   * @param pwrdFileOrDirPath Path to the password file or directory containing the passwords for
   *     the v3 keystores
   * @return the loaded signers with their files, and the failed files
   */
  public static SignerSourceResult loadV3KeystoresUsingPasswordFileOrDir(
      final Path keystoresPath, final Path pwrdFileOrDirPath) {
    if (!Files.exists(pwrdFileOrDirPath)) {
      LOG.error("Password file or directory doesn't exist.");
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    final PasswordReader passwordReader;
    if (Files.isDirectory(pwrdFileOrDirPath)) {
      passwordReader = passwordFile -> Files.readString(pwrdFileOrDirPath.resolve(passwordFile));
    } else if (Files.isRegularFile(pwrdFileOrDirPath)) {
      try {
        final String password = Files.readString(pwrdFileOrDirPath);
        passwordReader = passwordFile -> password;
      } catch (final IOException e) {
        LOG.error("Unable to read password file.", e);
        return SignerSourceResult.sourceFailure(SOURCE_NAME);
      }
    } else {
      LOG.error(
          "Password path is neither a regular file nor a directory; check the keystores password file or directory in the configuration.");
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    return loadV3Keystores(keystoresPath, passwordReader, true);
  }

  /**
   * Bulk-load generic SECP Artifact Signers from encrypted v3 keystores that can be used by Commit
   * Boost API. It uses compressed public key as identifier and apply SHA256 digest on the message
   * before signing.
   *
   * @param keystoresPath Path to the directory containing the v3 keystores
   * @param password the password of every keystore in the directory
   * @return the loaded signers with their files, and the failed files
   */
  public static SignerSourceResult loadECDSAProxyKeystores(
      final Path keystoresPath, final String password) {
    return loadV3Keystores(keystoresPath, passwordFile -> password, false);
  }

  private static SignerSourceResult loadV3Keystores(
      final Path keystoresPath,
      final PasswordReader passwordReader,
      final boolean ethereumSECPCompatible) {
    final List<Path> keystoresFiles;
    try {
      keystoresFiles = JsonFilesUtil.loadJsonExtPaths(keystoresPath);
    } catch (final IOException e) {
      LOG.error("Error listing v3 keystores paths {}", keystoresPath);
      return SignerSourceResult.sourceFailure(SOURCE_NAME);
    }

    final ConcurrentLinkedQueue<LoadedSigner> signers = new ConcurrentLinkedQueue<>();
    final Set<String> failedFiles = ConcurrentHashMap.newKeySet();

    keystoresFiles.parallelStream()
        .forEach(
            keystoreFile -> {
              final Optional<ArtifactSigner> signer =
                  createSecpArtifactSigner(keystoreFile, passwordReader, ethereumSECPCompatible);
              if (signer.isPresent()) {
                signers.add(new LoadedSigner(signer.get(), Optional.of(keystoreFile.toString())));
              } else {
                failedFiles.add(keystoreFile.toString());
              }
            });

    return new SignerSourceResult(
        SOURCE_NAME, List.copyOf(signers), failedFiles, failedFiles.size(), false);
  }

  private static Optional<ArtifactSigner> createSecpArtifactSigner(
      final Path v3KeystorePath,
      final PasswordReader passwordReader,
      final boolean ethereumSECPCompatible) {
    try {
      final String fileNameWithoutExt =
          FilenameUtils.removeExtension(v3KeystorePath.getFileName().toString());

      final String password = passwordReader.readPassword(fileNameWithoutExt + ".txt");

      final Credentials credentials =
          WalletUtils.loadCredentials(password, v3KeystorePath.toFile());
      final ArtifactSigner artifactSigner =
          ethereumSECPCompatible
              ? new EthSecpArtifactSigner(new CredentialSigner(credentials))
              : new K256ArtifactSigner(credentials.getEcKeyPair());

      return Optional.of(artifactSigner);
    } catch (final IOException | CipherException | RuntimeException e) {
      LOG.error("Error loading v3 keystore {}", v3KeystorePath, e);
      return Optional.empty();
    }
  }
}
