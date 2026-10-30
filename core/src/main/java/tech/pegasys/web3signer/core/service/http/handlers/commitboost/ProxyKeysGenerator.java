/*
 * Copyright 2024 ConsenSys AG.
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
package tech.pegasys.web3signer.core.service.http.handlers.commitboost;

import static tech.pegasys.web3signer.bls.keystore.model.Pbkdf2PseudoRandomFunction.HMAC_SHA256;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.model.CipherFunction;
import tech.pegasys.web3signer.bls.keystore.model.CipherParam;
import tech.pegasys.web3signer.bls.keystore.model.CipherSpec;
import tech.pegasys.web3signer.bls.keystore.model.KdfParam;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.web3signer.core.service.http.SigningObjectMapperFactory;
import tech.pegasys.web3signer.signing.ArtifactSigner;
import tech.pegasys.web3signer.signing.BlsArtifactSigner;
import tech.pegasys.web3signer.signing.K256ArtifactSigner;
import tech.pegasys.web3signer.signing.KeyType;
import tech.pegasys.web3signer.signing.config.KeystoresParameters;
import tech.pegasys.web3signer.signing.config.metadata.SignerOrigin;
import tech.pegasys.web3signer.signing.secp256k1.EthPublicKeyUtils;
import tech.pegasys.web3signer.signing.util.SecureRandomProvider;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes48;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Wallet;
import org.web3j.crypto.WalletFile;
import org.web3j.crypto.exception.CipherException;

/** Generate BLS and SECP256K1 proxy keys for Commit Boost API */
public class ProxyKeysGenerator {
  private static final Logger LOG = LogManager.getLogger();
  private static final ObjectMapper JSON_MAPPER = SigningObjectMapperFactory.createObjectMapper();
  private final KeystoresParameters commitBoostParameters;

  /** A generated proxy key and the encrypted keystore file written for it. */
  public record GeneratedProxyKey(ArtifactSigner signer, Path keystoreFile) {}

  public ProxyKeysGenerator(final KeystoresParameters commitBoostParameters) {
    this.commitBoostParameters = commitBoostParameters;
  }

  /**
   * Generate a random K256 proxy key and encrypted keystore for the given consensus public key
   *
   * @param consensusPubKey the public key of the consensus signer for which the proxy key is being
   *     generated
   * @return a K256ArtifactSigner representing the generated proxy key, and its keystore file
   */
  public GeneratedProxyKey generateECProxyKey(final String consensusPubKey) {
    final ECKeyPair ecKeyPair = ECKeyPair.create(EthPublicKeyUtils.generateK256KeyPair());
    final Path ecWalletFile = createECWalletFile(ecKeyPair, consensusPubKey);
    LOG.debug(
        "Created proxy EC wallet file {} for consensus key: {}", ecWalletFile, consensusPubKey);
    return new GeneratedProxyKey(new K256ArtifactSigner(ecKeyPair), ecWalletFile);
  }

  /**
   * Generate a random BLS proxy key and encrypted keystore for the given consensus public key
   *
   * @param consensusPubKey the public key of the consensus signer for which the proxy key is being
   *     generated
   * @return a BlsArtifactSigner representing the generated proxy key, and its keystore file
   */
  public GeneratedProxyKey generateBLSProxyKey(final String consensusPubKey) {
    final BLSKeyPair blsKeyPair = BLSKeyPair.random(SecureRandomProvider.getSecureRandom());
    final Path blsKeystoreFile = createBLSKeystoreFile(blsKeyPair, consensusPubKey);
    LOG.debug(
        "Created proxy BLS keystore file {} for consensus key: {}",
        blsKeystoreFile,
        consensusPubKey);
    return new GeneratedProxyKey(
        new BlsArtifactSigner(blsKeyPair, SignerOrigin.FILE_KEYSTORE), blsKeystoreFile);
  }

  private Path createBLSKeystoreFile(final BLSKeyPair keyPair, final String consensusPubKey) {
    final Bytes salt = Bytes.random(32, SecureRandomProvider.getSecureRandom());
    final CipherParam cipherParam =
        new CipherParam(Bytes.random(16, SecureRandomProvider.getSecureRandom()));
    final int counter = 65536; // 2^16
    final KdfParam kdfParam = new Pbkdf2Param(32, counter, HMAC_SHA256, salt);
    final CipherSpec cipher = new CipherSpec(CipherFunction.AES_128_CTR, cipherParam);
    final Bytes48 publicKey = keyPair.getPublicKey().toBytesCompressed();
    final String password = readFile(commitBoostParameters.getKeystoresPasswordFile());
    final KeyStoreData keyStoreData = KeyStore.encrypt(keyPair, password, "", kdfParam, cipher);
    try {
      final Path keystoreDir =
          createSubDirectories(
              commitBoostParameters.getKeystoresPath(), consensusPubKey, KeyType.BLS);
      final Path keystoreFile = keystoreDir.resolve(publicKey + ".json");
      KeyStoreLoader.saveToFile(keystoreFile, keyStoreData);
      return keystoreFile;
    } catch (final IOException e) {
      throw new UncheckedIOException("Unable to create keystore file", e);
    }
  }

  private Path createECWalletFile(final ECKeyPair ecKeyPair, final String consensusPubKey) {
    final String password = readFile(commitBoostParameters.getKeystoresPasswordFile());
    final Path keystoreDir =
        createSubDirectories(
            commitBoostParameters.getKeystoresPath(), consensusPubKey, KeyType.SECP256K1);

    final String compressedPubHex =
        EthPublicKeyUtils.toHexStringCompressed(
            EthPublicKeyUtils.web3JPublicKeyToECPublicKey(ecKeyPair.getPublicKey()));

    final Path keystoreFile = keystoreDir.resolve(compressedPubHex + ".json");
    try {
      final WalletFile walletFile = Wallet.createStandard(password, ecKeyPair);
      JSON_MAPPER.writeValue(keystoreFile.toFile(), walletFile);
      return keystoreFile;
    } catch (final CipherException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static String readFile(final Path file) {
    try {
      return Files.readString(file, StandardCharsets.UTF_8);
    } catch (final IOException e) {
      throw new UncheckedIOException("Unable to read file", e);
    }
  }

  private static Path createSubDirectories(
      final Path parentDirectory, final String directoryName, final KeyType keyType) {
    final Path subDirectory = parentDirectory.resolve(directoryName).resolve(keyType.name());
    try {
      Files.createDirectories(subDirectory);
    } catch (final IOException e) {
      throw new UncheckedIOException("Unable to create directory: " + subDirectory, e);
    }
    return subDirectory;
  }
}
