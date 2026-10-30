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

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.KeyStoreValidationException;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.signing.config.metadata.FileKeyStoreMetadata;
import tech.pegasys.web3signer.signing.config.metadata.SigningMetadata;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class KeystoreFileManager {

  private static final Logger LOG = LogManager.getLogger();

  private final Path keystorePath;
  private final YAMLMapper yamlMapper;

  public KeystoreFileManager(final Path keystorePath, final YAMLMapper yamlMapper) {
    this.keystorePath = keystorePath;
    this.yamlMapper = yamlMapper;
  }

  /**
   * Keystore API uses pubkey.yaml format to write metadata file.
   *
   * @param pubkey Pubkey to use as filename (without .yaml extension)
   * @return true if files are deleted successfully, false because metadata/keystore/password files
   *     do not exist.
   * @throws IOException In case of IO Exception while reading files
   */
  public boolean deleteKeystoreFiles(final String pubkey) throws IOException {
    final Optional<KeystoreFiles> keystoreFiles = findKeystoreConfigFiles(pubkey);
    if (keystoreFiles.isEmpty()) {
      return false;
    }

    final KeystoreFiles files = keystoreFiles.get();
    if (!filesExists(files)) {
      LOG.debug("Unable to delete keystore files because they don't exist");
      return false;
    }

    // before deletion, decrypt and make sure that keystore is correct one
    final KeyStoreData keyStoreData;
    final BLSKeyPair blsKeyPair;
    try {
      keyStoreData = KeyStoreLoader.loadFromFile(files.keystoreFile.toUri());
      blsKeyPair =
          KeyStore.decrypt(
              Files.readString(files.passwordFile, StandardCharsets.UTF_8), keyStoreData);
    } catch (KeyStoreValidationException e) {
      LOG.warn(
          "Unable to verify keystore for '{}', files will not be deleted: {}",
          pubkey,
          e.getMessage());
      return false;
    }
    if (!blsKeyPair.getPublicKey().toHexString().equals(pubkey)) {
      LOG.warn(
          "Unable to delete keystore files because provided pub key doesn't match with decrypted pub key");
      return false;
    }

    var metadataFileDeleted = Files.deleteIfExists(files.yamlFile());
    var keystoreFileDeleted = Files.deleteIfExists(files.keystoreFile());
    var passwordFileDeleted = Files.deleteIfExists(files.passwordFile());

    return metadataFileDeleted && keystoreFileDeleted && passwordFileDeleted;
  }

  private static boolean filesExists(final KeystoreFiles files) {
    return files.keystoreFile().toFile().exists() && files.passwordFile().toFile().exists();
  }

  /**
   * Create Keystore metadata, json and password files.
   *
   * @param fileRecord KeystoreFileRecord with keystore file data
   * @return the metadata (key config) yaml file
   * @throws IOException In case file write operations fail
   */
  public Path createKeystoreFiles(final KeystoreFileRecord fileRecord) throws IOException {
    final Path metadataYamlFile = keystorePath.resolve(fileRecord.metadataFileName());
    final Path keystoreJsonFile = keystorePath.resolve(fileRecord.keystoreFileName());
    final Path keystorePasswordFile = keystorePath.resolve(fileRecord.passwordFileName());

    final FileKeyStoreMetadata data =
        new FileKeyStoreMetadata(keystoreJsonFile, keystorePasswordFile, KeyType.BLS);
    try {
      // keystore metadata yaml file
      createYamlFile(metadataYamlFile, data);
      // keystore data json file
      Files.writeString(keystoreJsonFile, fileRecord.json(), StandardCharsets.UTF_8);
      // password file
      Files.writeString(keystorePasswordFile, fileRecord.password(), StandardCharsets.UTF_8);
      return metadataYamlFile;
    } catch (final IOException e) {
      deleteFile(metadataYamlFile);
      deleteFile(keystoreJsonFile);
      deleteFile(keystorePasswordFile);

      throw e;
    }
  }

  private Optional<KeystoreFiles> findKeystoreConfigFiles(final String pubkey) {
    final Path yamlFile = keystorePath.resolve(pubkey + ".yaml");
    if (!Files.exists(yamlFile)) {
      LOG.debug("Cannot read metadata file because it doesn't exist {}", yamlFile);
      return Optional.empty();
    }
    try {
      final String fileContent = Files.readString(yamlFile, StandardCharsets.UTF_8);
      final SigningMetadata metaDataInfo = yamlMapper.readValue(fileContent, SigningMetadata.class);
      if (metaDataInfo.getKeyType() == KeyType.BLS
          && metaDataInfo instanceof FileKeyStoreMetadata info) {
        return Optional.of(
            new KeystoreFiles(yamlFile, info.getKeystoreFile(), info.getKeystorePasswordFile()));
      } else {
        LOG.debug("Metadata file type is incorrect {}", yamlFile);
      }
    } catch (final Exception e) {
      LOG.error("Unexpected error reading metadata file: {}", yamlFile, e);
    }
    return Optional.empty();
  }

  private void createYamlFile(final Path filePath, final FileKeyStoreMetadata signingMetadata)
      throws IOException {
    final String yamlContent = yamlMapper.writeValueAsString(signingMetadata);
    Files.writeString(filePath, yamlContent);
  }

  private static void deleteFile(final Path file) {
    try {
      Files.deleteIfExists(file);
    } catch (final IOException e) {
      LOG.warn("Unable to delete file due to {}", e.getMessage());
    }
  }

  private record KeystoreFiles(Path yamlFile, Path keystoreFile, Path passwordFile) {}
}
