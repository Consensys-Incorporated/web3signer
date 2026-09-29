/*
 * Copyright 2025 ConsenSys AG.
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
package tech.pegasys.web3signer.bls.keystore;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSecretKey;
import tech.pegasys.web3signer.bls.keystore.model.CipherFunction;
import tech.pegasys.web3signer.bls.keystore.model.CipherParam;
import tech.pegasys.web3signer.bls.keystore.model.CipherSpec;
import tech.pegasys.web3signer.bls.keystore.model.KdfParam;
import tech.pegasys.web3signer.bls.keystore.model.KeyStoreData;
import tech.pegasys.web3signer.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.web3signer.bls.keystore.model.Pbkdf2PseudoRandomFunction;
import tech.pegasys.web3signer.bls.keystore.model.SCryptParam;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import com.google.common.io.Resources;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class KeyStoreTest {
  private static final int DKLEN = 32;
  private static final int ITERATIVE_COUNT = 262144;
  private static final int MEMORY_CPU_COST = 262144;
  private static final int PARALLELIZATION = 1;
  private static final int BLOCKSIZE = 8;

  private static final String PASSWORD =
      "\uD835\uDD31\uD835\uDD22\uD835\uDD30\uD835\uDD31\uD835\uDD2D\uD835\uDD1E\uD835\uDD30\uD835\uDD30\uD835\uDD34\uD835\uDD2C\uD835\uDD2F\uD835\uDD21\uD83D\uDD11";
  private static final Bytes32 BLS_PRIVATE_KEY =
      Bytes32.fromHexString("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
  private static final BLSKeyPair BLS_KEY_PAIR =
      new BLSKeyPair(BLSSecretKey.fromBytes(BLS_PRIVATE_KEY));
  private static final Bytes BLS_PUB_KEY =
      Bytes.fromHexString(
          "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07");
  private static final Bytes32 SALT =
      Bytes32.fromHexString("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3");
  private static final CipherParam AES_IV_PARAM =
      new CipherParam(Bytes.fromHexString("264daa3f303d7259501c93d997d84fe6"));

  private static final String SCRYPT_KEYSTORE_RESOURCE = "scryptTestVector.json";
  private static final String SCRYPT_EXTRA_FIELD_KEYSTORE_RESOURCE =
      "scryptExtraFieldTestVector.json";

  private static final String PBKDF2_KEYSTORE_RESOURCE = "pbkdf2TestVector.json";
  private static final String MISSING_SECTION_KEYSTORE_RESOURCE =
      "missingKdfSectionTestVector.json";
  private static final String UNSUPPORTED_VERSION_JSON_RESOURCE = "v3TestVector.json";
  private static final String UNSUPPORTED_CHECKSUM_FUNCTION_JSON =
      "unsupportedChecksumFunction.json";
  private static final String UNSUPPORTED_CIPHER_FUNCTION_JSON = "unsupportedCipherFunction.json";
  private static final String UNSUPPORTED_KDF_FUNCTION_JSON = "unsupportedKdfFunction.json";
  private static final String UNSUPPORTED_PBKDF2_PRF_FUNCTION_JSON = "unsupportedPBKDF2Prf.json";
  private static final String UNSUPPORTED_DKLEN_FUNCTION_JSON = "unsupportedDkLen.json";
  private static final CipherSpec CIPHER_SPEC =
      new CipherSpec(CipherFunction.AES_128_CTR, AES_IV_PARAM);

  private static final String MISSING_CRYPTO = "missingCrypto.json";
  private static final String MISSING_VERSION = "missingVersion.json";

  public static Stream<Arguments> encryptWithKdfAndCipherArguments() {
    // KdfParam, expected checksum, expected encrypted cipher message
    return Stream.of(
        Arguments.of(
            new SCryptParam(DKLEN, MEMORY_CPU_COST, PARALLELIZATION, BLOCKSIZE, SALT),
            Bytes.fromHexString("d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"),
            Bytes.fromHexString(
                "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f")),
        Arguments.of(
            new Pbkdf2Param(DKLEN, ITERATIVE_COUNT, Pbkdf2PseudoRandomFunction.HMAC_SHA256, SALT),
            Bytes.fromHexString("8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"),
            Bytes.fromHexString(
                "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad")));
  }

  public static Stream<Arguments> resourceLoaderErrorConditions() {
    return Stream.of(
        Arguments.of(
            Named.of("Invalid json", MISSING_SECTION_KEYSTORE_RESOURCE),
            "Invalid KeyStore: Missing property 'params' for external type id 'function'"),
        Arguments.of(
            Named.of("Unsupported version", UNSUPPORTED_VERSION_JSON_RESOURCE),
            "KeyStore version not supported: 3"),
        Arguments.of(
            Named.of("Unsupported checksum fn", UNSUPPORTED_CHECKSUM_FUNCTION_JSON),
            "Checksum function [sha128] is not supported."),
        Arguments.of(
            Named.of("Unsupported cipher fn", UNSUPPORTED_CIPHER_FUNCTION_JSON),
            "Cipher function [aes-256-ctr] is not supported."),
        Arguments.of(
            Named.of("Unsupported kdf fn", UNSUPPORTED_KDF_FUNCTION_JSON),
            "Kdf function [pbkdf3] is not supported."),
        Arguments.of(
            Named.of("Unsupported pbkdf2 fn", UNSUPPORTED_PBKDF2_PRF_FUNCTION_JSON),
            "PBKDF2 pseudorandom function (prf) [hmac-sha512] is not supported."),
        Arguments.of(
            Named.of("Unsupported dklen fn", UNSUPPORTED_DKLEN_FUNCTION_JSON),
            "Generated key length parameter dklen must be >= 32."),

        // required attributes
        Arguments.of(
            Named.of("Missing crypto", MISSING_CRYPTO),
            "Invalid KeyStore: Missing 'crypto' property"),
        Arguments.of(
            Named.of("Missing version", MISSING_VERSION),
            "Invalid KeyStore: Missing 'version' property"));
  }

  @ParameterizedTest(name = "{index} - Load And Decrypt Keystore with {0}")
  @ValueSource(
      strings = {
        SCRYPT_KEYSTORE_RESOURCE,
        PBKDF2_KEYSTORE_RESOURCE,
        SCRYPT_EXTRA_FIELD_KEYSTORE_RESOURCE
      })
  void loadAndDecryptKeystore(final String resourcePath) {
    final KeyStoreData keyStoreData = loadKeyStoreFromResource(resourcePath);
    final BLSKeyPair decryptedBlsPrivateKey = KeyStore.decrypt(PASSWORD, keyStoreData);
    assertThat(decryptedBlsPrivateKey.getSecretKey().toBytes()).isEqualTo(BLS_PRIVATE_KEY);
  }

  @ParameterizedTest(name = "{index} - Invalid Password with {0}")
  @ValueSource(strings = {SCRYPT_KEYSTORE_RESOURCE, PBKDF2_KEYSTORE_RESOURCE})
  void invalidPasswordRaiseError(final String resourcePath) {
    final KeyStoreData keyStoreData = loadKeyStoreFromResource(resourcePath);
    assertThat(KeyStore.validatePassword("invalidpassword", keyStoreData)).isFalse();
  }

  @Test
  void shouldLoadKeystoreDataFromStringInput() throws IOException {
    assertThat(loadKeystoreFromString(SCRYPT_KEYSTORE_RESOURCE))
        .isNotNull()
        .extracting(KeyStoreData::pubkey)
        .isEqualTo(BLS_PUB_KEY);
  }

  @ParameterizedTest(name = "{index} - Encrypt with KdfParam {0}")
  @MethodSource("encryptWithKdfAndCipherArguments")
  void encryptWithKdfAndCipherFunction(
      final KdfParam kdfParam, final Bytes expectedChecksum, final Bytes encryptedCipherMessage) {
    final KeyStoreData keyStoreData =
        KeyStore.encrypt(BLS_KEY_PAIR, PASSWORD, "", kdfParam, CIPHER_SPEC);
    assertThat(keyStoreData.crypto().checksum().message()).isEqualTo(expectedChecksum);
    assertThat(keyStoreData.crypto().cipher().message()).isEqualTo(encryptedCipherMessage);
    assertThat(keyStoreData.version()).isEqualTo(KeyStoreData.KEYSTORE_VERSION);
    assertThat(keyStoreData.pubkey()).isEqualTo(BLS_PUB_KEY);
    assertThat(keyStoreData.uuid()).isNotNull();
  }

  @ParameterizedTest(name = "{index} - Encrypt and Reload with KdfParam {0}")
  @MethodSource("encryptWithKdfAndCipherArguments")
  void encryptAndReload(
      final KdfParam kdfParam,
      final Bytes expectedChecksum,
      final Bytes encryptedCipherMessage,
      @TempDir final Path tempDir)
      throws IOException {

    final KeyStoreData keyStoreData =
        KeyStore.encrypt(BLS_KEY_PAIR, PASSWORD, "", kdfParam, CIPHER_SPEC);
    final Path tempKeyStoreFile = Files.createTempFile(tempDir, "keystore", ".json");
    assertThatCode(() -> KeyStoreLoader.saveToFile(tempKeyStoreFile, keyStoreData))
        .doesNotThrowAnyException();

    // reload it back
    final KeyStoreData loadedKeyStore = KeyStoreLoader.loadFromFile(tempKeyStoreFile.toUri());
    assertThat(loadedKeyStore.uuid()).isEqualByComparingTo(keyStoreData.uuid());
    assertThat(loadedKeyStore.crypto().checksum().message()).isEqualTo(expectedChecksum);
    assertThat(loadedKeyStore.crypto().cipher().message()).isEqualTo(encryptedCipherMessage);
  }

  @ParameterizedTest(name = "{0} should result in an error")
  @MethodSource("resourceLoaderErrorConditions")
  void shouldErrorLoadingFromFile(final String resource, final String messageStartsWith) {
    assertThatExceptionOfType(RuntimeException.class)
        .isThrownBy(() -> loadKeyStoreFromResource(resource))
        .withMessageStartingWith(messageStartsWith);
  }

  @ParameterizedTest(name = "{0} should result in an error")
  @MethodSource("resourceLoaderErrorConditions")
  void shouldErrorLoadingFromString(final String resource, final String messageStartsWith) {
    assertThatExceptionOfType(KeyStoreValidationException.class)
        .isThrownBy(() -> loadKeystoreFromString(resource))
        .withMessageStartingWith(messageStartsWith);
  }

  @Test
  void loadingNonExistentKeyStoreFileThrowsError(@TempDir final Path tempDir) {
    final Path keyStoreFile = tempDir.resolve("nonexistent.json");
    assertThatExceptionOfType(KeyStoreValidationException.class)
        .isThrownBy(() -> KeyStoreLoader.loadFromFile(keyStoreFile.toUri()))
        .withMessageStartingWith("Failed to read keystore file:")
        .withMessageEndingWith(keyStoreFile.getFileName().toString());
  }

  @Test
  void decryptSucceedsWhenPubkeyIsAbsent() {
    final KeyStoreData withoutPubkey =
        new KeyStoreData(
            KeyStore.encrypt(
                    BLS_KEY_PAIR,
                    PASSWORD,
                    "",
                    new SCryptParam(DKLEN, MEMORY_CPU_COST, PARALLELIZATION, BLOCKSIZE, SALT),
                    CIPHER_SPEC)
                .crypto(),
            null,
            "");
    final BLSKeyPair result = KeyStore.decrypt(PASSWORD, withoutPubkey);
    assertThat(result.getSecretKey().toBytes()).isEqualTo(BLS_PRIVATE_KEY);
  }

  @Test
  void decryptThrowsExceptionWhenPubkeyMismatches() {
    final BLSKeyPair otherPair =
        new BLSKeyPair(
            BLSSecretKey.fromBytes(
                Bytes32.fromHexString(
                    "0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26e")));
    final KeyStoreData tampered =
        new KeyStoreData(
            KeyStore.encrypt(
                    BLS_KEY_PAIR,
                    PASSWORD,
                    "",
                    new SCryptParam(DKLEN, MEMORY_CPU_COST, PARALLELIZATION, BLOCKSIZE, SALT),
                    CIPHER_SPEC)
                .crypto(),
            otherPair.getPublicKey().toBytesCompressed(),
            "");
    assertThatExceptionOfType(KeyStoreValidationException.class)
        .isThrownBy(() -> KeyStore.decrypt(PASSWORD, tampered))
        .withMessage("Keystore pubkey does not match decrypted key");
  }

  private KeyStoreData loadKeyStoreFromResource(final String resourcePath) {
    final URL resource = Resources.getResource(KeyStoreTest.class, resourcePath);
    try {
      return KeyStoreLoader.loadFromFile(resource.toURI());
    } catch (URISyntaxException e) {
      throw new RuntimeException(e);
    }
  }

  private KeyStoreData loadKeystoreFromString(final String resourceFileName) throws IOException {
    final String keystoreString =
        Resources.toString(
            Resources.getResource(KeyStoreTest.class, resourceFileName), StandardCharsets.UTF_8);
    return KeyStoreLoader.loadFromString(keystoreString);
  }
}
