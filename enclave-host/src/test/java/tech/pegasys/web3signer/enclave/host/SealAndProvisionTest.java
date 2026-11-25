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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static tech.pegasys.web3signer.bls.keystore.model.Pbkdf2PseudoRandomFunction.HMAC_SHA256;

import tech.pegasys.teku.bls.BLS;
import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.teku.bls.BLSSignature;
import tech.pegasys.web3signer.bls.keystore.KeyStore;
import tech.pegasys.web3signer.bls.keystore.KeyStoreLoader;
import tech.pegasys.web3signer.bls.keystore.model.CipherFunction;
import tech.pegasys.web3signer.bls.keystore.model.CipherParam;
import tech.pegasys.web3signer.bls.keystore.model.CipherSpec;
import tech.pegasys.web3signer.bls.keystore.model.Pbkdf2Param;
import tech.pegasys.web3signer.enclave.client.EnclaveClient;
import tech.pegasys.web3signer.enclave.host.aws.AwsKmsKeyReleaseBroker;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Protocol;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SealAndProvisionTest {
  private static final KeyProvisioner.Options OPTIONS =
      new KeyProvisioner.Options(5, EnclaveClient.DEFAULT_PROVISIONING_TIMEOUT, true, null);
  private static final SecureRandom RANDOM = new SecureRandom();

  @TempDir Path dir;
  private InProcessEnclaveSigner signer;
  private EnclaveClient client;

  @BeforeEach
  void start() {
    signer = new InProcessEnclaveSigner();
    client = EnclaveClient.create(signer.address(), new EnclaveClient.Options(1, 30_000));
  }

  @AfterEach
  void stop() {
    client.close();
    signer.close();
  }

  private static byte[] masterKey() {
    final byte[] key = new byte[32];
    RANDOM.nextBytes(key);
    return key;
  }

  private static void writeKeystore(
      final Path directory, final String name, final BLSKeyPair key, final String password)
      throws IOException {
    final Pbkdf2Param kdf = new Pbkdf2Param(32, 2, HMAC_SHA256, Bytes.random(32));
    final CipherSpec cipher =
        new CipherSpec(CipherFunction.AES_128_CTR, new CipherParam(Bytes.random(16)));
    Files.writeString(
        directory.resolve(name + ".json"),
        KeyStoreLoader.toJson(KeyStore.encrypt(key, password, "", kdf, cipher)));
  }

  private void assertSignable(final List<BLSKeyPair> keys) {
    final Bytes root = Bytes.random(32);
    for (final BLSKeyPair key : keys) {
      final byte[] signature =
          client.sign(key.getPublicKey().toBytesCompressed().toArrayUnsafe(), root.toArrayUnsafe());
      assertThat(
              BLS.verify(
                  key.getPublicKey(),
                  root,
                  BLSSignature.fromBytesCompressed(Bytes.wrap(signature))))
          .isTrue();
    }
  }

  private KeyProvisioner.Result sealAndProvision(final KeySealer.Sources sources)
      throws IOException {
    final Path bundleFile = dir.resolve("keys.bundle.json");
    final byte[] master = masterKey();
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(master)) {
      final KeySealer.Result sealed = KeySealer.sealToFile(sources, broker, bundleFile);
      assertThat(sealed.keyId()).isEqualTo("dev");
    }
    final String json = Files.readString(bundleFile);
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(master)) {
      return KeyProvisioner.provision(KeyBundleIo.fromJson(json), broker, client, OPTIONS);
    }
  }

  @Test
  void sealsKeystoresWithAPasswordFile() throws IOException {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    final List<BLSKeyPair> keys = EnclaveTestKeys.randomKeys(3);
    for (int i = 0; i < keys.size(); i++) {
      writeKeystore(keystores, "key" + i, keys.get(i), "secret password");
    }
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "secret password");
    final KeyProvisioner.Result result =
        sealAndProvision(new KeySealer.Sources(keystores, passwordFile, null, null));
    assertThat(result.load()).isEqualTo(new LoadResult(3, 0, 0));
    assertThat(result.enclaveKeyCount()).isEqualTo(3);
    assertSignable(keys);
  }

  @Test
  void sealsKeystoresWithAPasswordDirectoryAndRawKeys() throws IOException {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    final Path passwords = Files.createDirectory(dir.resolve("passwords"));
    final List<BLSKeyPair> keys = EnclaveTestKeys.randomKeys(4);
    for (int i = 0; i < 2; i++) {
      writeKeystore(keystores, "key" + i, keys.get(i), "password " + i);
      Files.writeString(passwords.resolve("key" + i + ".txt"), "password " + i);
    }
    final Path raw =
        Files.writeString(
            dir.resolve("raw.txt"),
            keys.get(2).getSecretKey().toBytes().toHexString()
                + "\n\n"
                + keys.get(3).getSecretKey().toBytes().toUnprefixedHexString()
                + "\n");
    final KeyProvisioner.Result result =
        sealAndProvision(new KeySealer.Sources(keystores, null, passwords, raw));
    assertThat(result.load()).isEqualTo(new LoadResult(4, 0, 0));
    assertSignable(keys);
  }

  @Test
  void sealingFailsOnAWrongPassword() throws IOException {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    writeKeystore(keystores, "key", EnclaveTestKeys.randomKeys(1).get(0), "right");
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "wrong");
    assertThatThrownBy(
            () ->
                KeySealer.readKeyPairs(new KeySealer.Sources(keystores, passwordFile, null, null)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageContaining("could not be decrypted");
  }

  @Test
  void sealingSkipsJsonFilesThatAreNotKeystores() throws IOException {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    final BLSKeyPair key = EnclaveTestKeys.randomKeys(1).get(0);
    writeKeystore(keystores, "keystore-m_12381_3600_0_0_0", key, "secret password");
    Files.writeString(
        keystores.resolve("deposit_data-1700000000.json"), "[{\"pubkey\":\"ab\",\"amount\":1}]");
    // A trailing newline is harmless: EIP-2335 strips control codes from passwords.
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "secret password\n");
    final List<BLSKeyPair> collected =
        KeySealer.readKeyPairs(new KeySealer.Sources(keystores, passwordFile, null, null));
    assertThat(collected).containsExactly(key);
  }

  @Test
  void sealingFailsOnMalformedJson() throws IOException {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    Files.writeString(keystores.resolve("key.json"), "{\"crypto\": ");
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "x");
    assertThatThrownBy(
            () ->
                KeySealer.readKeyPairs(new KeySealer.Sources(keystores, passwordFile, null, null)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageContaining("Cannot parse");
  }

  @Test
  void provisioningAnEmptyBundleFailsBeforeContactingTheEnclave() {
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(masterKey())) {
      final KeyBundle empty = KeySealer.seal(List.of(), broker);
      assertThatThrownBy(() -> KeyProvisioner.provision(empty, broker, client, OPTIONS))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessageContaining("no keys");
    }
    assertThat(client.status().keyCount()).isZero();
  }

  @Test
  void sealingFailsOnADuplicateKey() throws IOException {
    final String secret =
        EnclaveTestKeys.randomKeys(1).get(0).getSecretKey().toBytes().toHexString();
    final Path raw = Files.writeString(dir.resolve("raw.txt"), secret + "\n" + secret + "\n");
    assertThatThrownBy(() -> KeySealer.readKeyPairs(new KeySealer.Sources(null, null, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageContaining("Duplicate");
  }

  @Test
  void sealingFailsOnEmptyInput() throws IOException {
    final Path raw = Files.writeString(dir.resolve("raw.txt"), "\n\n");
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "x");
    assertThatThrownBy(
            () -> KeySealer.readKeyPairs(new KeySealer.Sources(keystores, passwordFile, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageContaining("No keys");
  }

  @Test
  void sealingAnInvalidRawSecretDoesNotPrintIt() throws IOException {
    final Path raw = Files.writeString(dir.resolve("raw.txt"), "0x1234zz\n");
    assertThatThrownBy(() -> KeySealer.readKeyPairs(new KeySealer.Sources(null, null, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessage(
            "Raw keys file line 1 is not a valid secret: expected 64 hex characters, not zero and"
                + " below the curve order")
        .hasMessageNotContaining("1234");
  }

  @Test
  void provisioningTwiceReportsDuplicates() {
    final List<BLSKeyPair> keys = EnclaveTestKeys.randomKeys(5);
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(masterKey())) {
      final KeyBundle bundle = KeySealer.seal(keys, broker);
      assertThat(KeyProvisioner.provision(bundle, broker, client, OPTIONS).load())
          .isEqualTo(new LoadResult(5, 0, 0));
      final KeyProvisioner.Result again = KeyProvisioner.provision(bundle, broker, client, OPTIONS);
      assertThat(again.load()).isEqualTo(new LoadResult(0, 5, 0));
      assertThat(again.enclaveKeyCount()).isEqualTo(5);
    }
  }

  @Test
  void provisioningWithAnotherDataKeyRejectsEveryEntryAndFails() {
    final List<BLSKeyPair> keys = EnclaveTestKeys.randomKeys(3);
    try (DevKeyReleaseBroker first = new DevKeyReleaseBroker(masterKey());
        DevKeyReleaseBroker second = new DevKeyReleaseBroker(masterKey())) {
      final KeyBundle sealed = KeySealer.seal(keys, first);
      final KeyBundle otherDek = KeySealer.seal(EnclaveTestKeys.randomKeys(1), second);
      final KeyBundle mixed = new KeyBundle(otherDek.dek(), sealed.keys());
      assertThatThrownBy(() -> KeyProvisioner.provision(mixed, second, client, OPTIONS))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessageContaining("data key does not match")
          .hasMessageContaining("3 rejected of 3");
      assertThatThrownBy(() -> KeyProvisioner.provision(sealed, second, client, OPTIONS))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining("does not open");
    }
    assertThat(client.status().keyCount()).isZero();
  }

  @Test
  void bundleProviderMustMatchTheBroker() {
    final AwsKmsKeyReleaseBroker aws =
        new AwsKmsKeyReleaseBroker(
            org.mockito.Mockito.mock(software.amazon.awssdk.services.kms.KmsClient.class), "k");
    try (DevKeyReleaseBroker dev = new DevKeyReleaseBroker(masterKey())) {
      final KeyBundle bundle = KeySealer.seal(EnclaveTestKeys.randomKeys(1), dev);
      assertThatThrownBy(() -> KeyProvisioner.provision(bundle, aws, client, OPTIONS))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessage("The bundle was sealed with provider dev, but the aws-kms broker was given");
    }
  }

  @Test
  void enclavePlatformMustMatchTheBroker() {
    final software.amazon.awssdk.services.kms.KmsClient kms =
        org.mockito.Mockito.mock(software.amazon.awssdk.services.kms.KmsClient.class);
    final AwsKmsKeyReleaseBroker aws = new AwsKmsKeyReleaseBroker(kms, "k");
    try (DevKeyReleaseBroker dev = new DevKeyReleaseBroker(masterKey())) {
      final KeyBundle sealed = KeySealer.seal(EnclaveTestKeys.randomKeys(1), dev);
      final KeyBundle awsBundle =
          new KeyBundle(
              new KeyBundle.Dek(KeyBundle.Dek.PROVIDER_AWS_KMS, "k", Map.of(), new byte[] {1}),
              sealed.keys());
      assertThatThrownBy(() -> KeyProvisioner.provision(awsBundle, aws, client, OPTIONS))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessage(
              "The aws-kms broker releases data keys only to an enclave on platform aws-nitro,"
                  + " but the enclave runs dev");
    }
    org.mockito.Mockito.verifyNoInteractions(kms);
  }

  @Test
  void provisioningGivesUpWhenNothingListens() {
    final EnclaveClient nowhere =
        EnclaveClient.create(
            tech.pegasys.web3signer.enclave.transport.EnclaveAddress.parseConnect(
                "tcp:127.0.0.1:1"),
            new EnclaveClient.Options(1, 1000));
    try (DevKeyReleaseBroker dev = new DevKeyReleaseBroker(masterKey());
        nowhere) {
      final KeyBundle bundle = KeySealer.seal(EnclaveTestKeys.randomKeys(1), dev);
      assertThatThrownBy(
              () ->
                  KeyProvisioner.provision(
                      bundle,
                      dev,
                      nowhere,
                      new KeyProvisioner.Options(
                          0, EnclaveClient.DEFAULT_PROVISIONING_TIMEOUT, true, null)))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessageContaining("connection failed");
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "0x01",
        "0x111111111111111111111111111111111111111111111111111111111111",
        "0x",
        "0x0000000000000000000000000000000000000000000000000000000000000000"
      })
  void sealingRefusesARawSecretThatIsShortOrZero(final String line) throws IOException {
    final Path raw = Files.writeString(dir.resolve("raw.txt"), line + "\n");
    assertThatThrownBy(() -> KeySealer.readKeyPairs(new KeySealer.Sources(null, null, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageStartingWith("Raw keys file line 1 is not a valid secret");
  }

  @Test
  void provisioningFailsAsIncompleteWhenSomeEntriesAreRejected() {
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(masterKey())) {
      final KeyBundle sealed = KeySealer.seal(EnclaveTestKeys.randomKeys(3), broker);
      final SealedKey first = sealed.keys().get(0);
      final byte[] damaged = first.ciphertext().clone();
      damaged[0] ^= 1;
      final KeyBundle bundle =
          new KeyBundle(
              sealed.dek(),
              List.of(
                  new SealedKey(first.publicKey(), first.nonce(), damaged),
                  sealed.keys().get(1),
                  sealed.keys().get(2)));
      assertThatThrownBy(() -> KeyProvisioner.provision(bundle, broker, client, OPTIONS))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessage("Provisioning incomplete: 2 loaded, 0 duplicates, 1 rejected of 3");
    }
    assertThat(client.status().keyCount()).isEqualTo(2);
  }

  @Test
  void evidenceTypeMustMatchTheBroker() {
    try (TestBroker broker = new TestBroker(new DevKeyReleaseBroker(masterKey()))) {
      broker.evidenceType = Protocol.EVIDENCE_AWS_NITRO;
      final KeyBundle bundle = KeySealer.seal(EnclaveTestKeys.randomKeys(1), broker);
      assertThatThrownBy(() -> KeyProvisioner.provision(bundle, broker, client, OPTIONS))
          .isInstanceOf(EnclaveHostException.class)
          .hasMessage("The dev broker accepts evidence type 1, but the enclave produced type 0");
      assertThat(broker.releases).isZero();
    }
  }

  @Test
  void failedKeyPolicyCheckStopsBeforeTheRelease() {
    try (TestBroker broker = new TestBroker(new DevKeyReleaseBroker(masterKey()))) {
      broker.policyFailure = new IllegalStateException("policy too open");
      final KeyBundle bundle = KeySealer.seal(EnclaveTestKeys.randomKeys(1), broker);
      assertThatThrownBy(() -> KeyProvisioner.provision(bundle, broker, client, OPTIONS))
          .isSameAs(broker.policyFailure);
      assertThat(broker.releases).isZero();
    }
    assertThat(client.status().keyCount()).isZero();
  }

  @Test
  void devMasterKeyFileIgnoresSurroundingWhitespace() throws IOException {
    final Path file =
        Files.writeString(dir.resolve("master.hex"), "\n  " + "ab".repeat(32) + " \n");
    try (DevKeyReleaseBroker broker = DevKeyReleaseBroker.fromFile(file)) {
      final KeyBundle bundle = KeySealer.seal(EnclaveTestKeys.randomKeys(1), broker);
      assertThat(KeyProvisioner.provision(bundle, broker, client, OPTIONS).load().loaded())
          .isEqualTo(1);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"", "abab", "0xabababababababababababababababababababababababababababababababab"})
  void devMasterKeyFileMustHold64HexCharacters(final String content) throws IOException {
    final Path file = Files.writeString(dir.resolve("master.hex"), content);
    assertThatThrownBy(() -> DevKeyReleaseBroker.fromFile(file))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The dev master key file must hold 64 hex characters");
  }

  @Test
  void devMasterKeyFileRefusesCharactersThatAreNotHex() throws IOException {
    final Path file = Files.writeString(dir.resolve("master.hex"), "zz".repeat(32));
    assertThatThrownBy(() -> DevKeyReleaseBroker.fromFile(file))
        .isInstanceOf(IllegalArgumentException.class);
  }

  /**
   * Writes a keystore that decrypts to {@code secret} with a valid checksum, bypassing the checks
   * {@code KeyStore.encrypt} makes, so that sealing sees a secret no BLS key pair could hold.
   */
  private static void writeKeystoreWithSecret(
      final Path directory, final String name, final byte[] secret, final String password)
      throws Exception {
    final Bytes salt = Bytes.random(32);
    final Bytes decryptionKey =
        new Pbkdf2Param(32, 2, HMAC_SHA256, salt)
            .generateDecryptionKey(Bytes.wrap(password.getBytes(StandardCharsets.UTF_8)));
    final byte[] iv = Bytes.random(16).toArray();
    final Cipher ctr = Cipher.getInstance("AES/CTR/NoPadding");
    ctr.init(
        Cipher.ENCRYPT_MODE,
        new SecretKeySpec(decryptionKey.slice(0, 16).toArray(), "AES"),
        new IvParameterSpec(iv));
    final byte[] message = ctr.doFinal(secret);
    final byte[] checksum =
        MessageDigest.getInstance("SHA-256")
            .digest(Bytes.concatenate(decryptionKey.slice(16, 16), Bytes.wrap(message)).toArray());
    final HexFormat hex = HexFormat.of();
    Files.writeString(
        directory.resolve(name + ".json"),
        "{\"crypto\":{\"kdf\":{\"function\":\"pbkdf2\",\"params\":{\"dklen\":32,\"c\":2,"
            + "\"prf\":\"hmac-sha256\",\"salt\":\""
            + hex.formatHex(salt.toArray())
            + "\"},\"message\":\"\"},\"checksum\":{\"function\":\"sha256\",\"params\":{},"
            + "\"message\":\""
            + hex.formatHex(checksum)
            + "\"},\"cipher\":{\"function\":\"aes-128-ctr\",\"params\":{\"iv\":\""
            + hex.formatHex(iv)
            + "\"},\"message\":\""
            + hex.formatHex(message)
            + "\"}},\"path\":\"\",\"uuid\":\"9f75a3fa-1e5a-49f9-be3d-f5a19779c6fa\","
            + "\"version\":4}");
  }

  @Test
  void sealingRefusesAKeystoreHoldingTheZeroSecret() throws Exception {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    writeKeystoreWithSecret(keystores, "zero", new byte[32], "pw");
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "pw");
    assertThatThrownBy(
            () ->
                KeySealer.readKeyPairs(new KeySealer.Sources(keystores, passwordFile, null, null)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessage("Keystore " + keystores.resolve("zero.json") + " holds the zero secret");
  }

  @ParameterizedTest
  @ValueSource(ints = {31, 32})
  void sealingRefusesAKeystoreWithAnInvalidSecretWithoutPrintingIt(final int length)
      throws Exception {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    final byte[] secret = new byte[length];
    java.util.Arrays.fill(secret, (byte) 0xff);
    writeKeystoreWithSecret(keystores, "bad", secret, "pw");
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "pw");
    assertThatThrownBy(
            () ->
                KeySealer.readKeyPairs(new KeySealer.Sources(keystores, passwordFile, null, null)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessage(
            "Keystore " + keystores.resolve("bad.json") + " does not hold a valid BLS secret")
        .hasNoCause()
        .hasMessageNotContaining("ffff");
  }

  /** Delegates to a real broker, with overrides for the checks under test. */
  private static final class TestBroker implements KeyReleaseBroker {
    private final KeyReleaseBroker delegate;
    private Integer evidenceType;
    private RuntimeException policyFailure;
    private int releases;

    TestBroker(final KeyReleaseBroker delegate) {
      this.delegate = delegate;
    }

    @Override
    public String provider() {
      return delegate.provider();
    }

    @Override
    public int expectedPlatform() {
      return delegate.expectedPlatform();
    }

    @Override
    public int expectedEvidenceType() {
      return evidenceType != null ? evidenceType : delegate.expectedEvidenceType();
    }

    @Override
    public DataKey newDataKey() {
      return delegate.newDataKey();
    }

    @Override
    public byte[] release(final KeyBundle.Dek dek, final Evidence evidence) {
      releases++;
      return delegate.release(dek, evidence);
    }

    @Override
    public void assertEvidenceRequired(final KeyBundle.Dek dek) {
      if (policyFailure != null) {
        throw policyFailure;
      }
      delegate.assertEvidenceRequired(dek);
    }

    @Override
    public void close() {
      delegate.close();
    }
  }
}
