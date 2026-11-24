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
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.signer.InProcessEnclaveSigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;
import java.util.Map;

import org.apache.tuweni.bytes.Bytes;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
            () -> KeySealer.collect(new KeySealer.Sources(keystores, passwordFile, null, null)))
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
        KeySealer.collect(new KeySealer.Sources(keystores, passwordFile, null, null));
    assertThat(collected).containsExactly(key);
  }

  @Test
  void sealingFailsOnMalformedJson() throws IOException {
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    Files.writeString(keystores.resolve("key.json"), "{\"crypto\": ");
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "x");
    assertThatThrownBy(
            () -> KeySealer.collect(new KeySealer.Sources(keystores, passwordFile, null, null)))
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
    assertThatThrownBy(() -> KeySealer.collect(new KeySealer.Sources(null, null, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageContaining("Duplicate");
  }

  @Test
  void sealingFailsOnEmptyInput() throws IOException {
    final Path raw = Files.writeString(dir.resolve("raw.txt"), "\n\n");
    final Path keystores = Files.createDirectory(dir.resolve("keystores"));
    final Path passwordFile = Files.writeString(dir.resolve("password.txt"), "x");
    assertThatThrownBy(
            () -> KeySealer.collect(new KeySealer.Sources(keystores, passwordFile, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessageContaining("No keys");
  }

  @Test
  void sealingAnInvalidRawSecretDoesNotPrintIt() throws IOException {
    final Path raw = Files.writeString(dir.resolve("raw.txt"), "0x1234zz\n");
    assertThatThrownBy(() -> KeySealer.collect(new KeySealer.Sources(null, null, null, raw)))
        .isInstanceOf(EnclaveHostException.class)
        .hasMessage("Raw keys file line 1 is not a valid secret");
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
      final KeyBundle mixed = new KeyBundle(1, otherDek.dek(), sealed.keys());
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
              1,
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
}
