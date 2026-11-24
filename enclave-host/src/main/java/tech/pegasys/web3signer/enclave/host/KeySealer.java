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
package tech.pegasys.web3signer.enclave.host;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.KeyStoreValidationException;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;

/**
 * Seals BLS keys into a {@link KeyBundle}: each secret is AES-256-GCM encrypted under a fresh data
 * key from the {@link KeyReleaseBroker}, with its public key as additional data. Runs on the
 * operator's machine; never prints or logs a secret.
 */
public final class KeySealer {
  private static final Logger LOG = LogManager.getLogger(KeySealer.class);
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final SecureRandom RANDOM = new SecureRandom();

  private KeySealer() {}

  /**
   * Where the keys come from. Null fields are unused.
   *
   * @param keystoresPath directory of EIP-2335 keystores ({@code *.json})
   * @param keystoresPasswordFile one password for every keystore
   * @param keystoresPasswordsPath directory with {@code <keystore name>.txt} password files
   * @param rawKeysFile one hex secret per line
   */
  public record Sources(
      Path keystoresPath,
      Path keystoresPasswordFile,
      Path keystoresPasswordsPath,
      Path rawKeysFile) {}

  /**
   * Outcome of sealing.
   *
   * @param keyCount number of sealed keys
   * @param keyId the key that wraps the data key: the KMS key ARN, or {@code dev}
   */
  public record Result(int keyCount, String keyId) {}

  /** Collects key pairs from keystores and a raw keys file. Fails on zero keys and duplicates. */
  public static List<BLSKeyPair> collect(final Sources sources) {
    final List<BLSKeyPair> keys = new ArrayList<>();
    if (sources.keystoresPath() != null) {
      keys.addAll(fromKeystores(sources));
    }
    if (sources.rawKeysFile() != null) {
      keys.addAll(fromRawKeysFile(sources.rawKeysFile()));
    }
    if (keys.isEmpty()) {
      throw new EnclaveHostException("No keys to seal");
    }
    final Set<Bytes> publicKeys = new HashSet<>();
    for (final BLSKeyPair key : keys) {
      if (!publicKeys.add(key.getPublicKey().toBytesCompressed())) {
        throw new EnclaveHostException(
            "Duplicate public key " + key.getPublicKey().toBytesCompressed().toHexString());
      }
    }
    return keys;
  }

  private static List<BLSKeyPair> fromKeystores(final Sources sources) {
    if ((sources.keystoresPasswordFile() == null) == (sources.keystoresPasswordsPath() == null)) {
      throw new EnclaveHostException(
          "Keystores need exactly one of a password file or a passwords directory");
    }
    final List<Path> files;
    try (Stream<Path> listing = Files.list(sources.keystoresPath())) {
      files =
          listing
              .filter(Files::isRegularFile)
              .filter(p -> p.getFileName().toString().toLowerCase(Locale.ROOT).endsWith(".json"))
              .sorted()
              .toList();
    } catch (final IOException e) {
      throw new EnclaveHostException(
          "Cannot read keystores directory " + sources.keystoresPath(), e);
    }
    final List<BLSKeyPair> keys = new ArrayList<>();
    for (final Path file : files) {
      if (!looksLikeKeystore(file)) {
        LOG.warn("Skipping {}: not an EIP-2335 keystore (no crypto section)", file);
        continue;
      }
      final String name = file.getFileName().toString();
      final Path passwordFile =
          sources.keystoresPasswordFile() != null
              ? sources.keystoresPasswordFile()
              : sources
                  .keystoresPasswordsPath()
                  .resolve(name.substring(0, name.length() - ".json".length()) + ".txt");
      try {
        final String password = Files.readString(passwordFile);
        keys.add(KeyStore.decrypt(password, KeyStoreLoader.loadFromFile(file.toUri())));
      } catch (final IOException e) {
        throw new EnclaveHostException("Cannot read password file " + passwordFile, e);
      } catch (final KeyStoreValidationException e) {
        throw new EnclaveHostException("Keystore " + file + " could not be decrypted", e);
      }
    }
    return keys;
  }

  /**
   * Whether {@code file} is a JSON object with a {@code crypto} section, as every EIP-2335 keystore
   * is. Other valid JSON (such as staking-deposit-cli {@code deposit_data-*.json}) is skipped;
   * malformed JSON fails, so a damaged keystore is never dropped silently.
   */
  private static boolean looksLikeKeystore(final Path file) {
    try {
      final JsonNode root = JSON.readTree(file.toFile());
      return root != null && root.isObject() && root.has("crypto");
    } catch (final IOException e) {
      throw new EnclaveHostException("Cannot parse " + file + " as JSON", e);
    }
  }

  private static List<BLSKeyPair> fromRawKeysFile(final Path file) {
    final List<String> lines;
    try {
      lines = Files.readAllLines(file);
    } catch (final IOException e) {
      throw new EnclaveHostException("Cannot read raw keys file " + file, e);
    }
    final List<BLSKeyPair> keys = new ArrayList<>();
    for (int i = 0; i < lines.size(); i++) {
      final String line = lines.get(i).trim();
      if (line.isEmpty()) {
        continue;
      }
      try {
        keys.add(new BLSKeyPair(BLSSecretKey.fromBytes(Bytes32.fromHexString(line))));
      } catch (final RuntimeException e) {
        // the exception message could carry the secret: report the line number only
        throw new EnclaveHostException("Raw keys file line " + (i + 1) + " is not a valid secret");
      }
    }
    return keys;
  }

  /** Seals {@code keys} under a new data key. The plaintext data key is zeroed before returning. */
  public static KeyBundle seal(final List<BLSKeyPair> keys, final KeyReleaseBroker broker) {
    try (KeyReleaseBroker.DataKey dataKey = broker.newDataKey()) {
      final SecretKeySpec aes = new SecretKeySpec(dataKey.plaintext(), "AES");
      final List<SealedKey> sealed = new ArrayList<>(keys.size());
      for (final BLSKeyPair key : keys) {
        final byte[] publicKey = key.getPublicKey().toBytesCompressed().toArray();
        final byte[] secret = key.getSecretKey().toBytes().toArray();
        final byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        try {
          final Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
          gcm.init(Cipher.ENCRYPT_MODE, aes, new GCMParameterSpec(128, nonce));
          gcm.updateAAD(publicKey);
          sealed.add(new SealedKey(publicKey, nonce, gcm.doFinal(secret)));
        } catch (final GeneralSecurityException e) {
          throw new EnclaveHostException("Sealing failed", e);
        } finally {
          java.util.Arrays.fill(secret, (byte) 0);
        }
      }
      return new KeyBundle(KeyBundle.VERSION, dataKey.dek(), sealed);
    }
  }

  /** Collects, seals and writes the bundle to {@code output}. */
  public static Result sealToFile(
      final Sources sources, final KeyReleaseBroker broker, final Path output) {
    final KeyBundle bundle = seal(collect(sources), broker);
    try {
      KeyBundleIo.write(bundle, output);
    } catch (final IOException e) {
      throw new EnclaveHostException("Cannot write bundle " + output, e);
    }
    return new Result(bundle.keys().size(), bundle.dek().keyId());
  }
}
