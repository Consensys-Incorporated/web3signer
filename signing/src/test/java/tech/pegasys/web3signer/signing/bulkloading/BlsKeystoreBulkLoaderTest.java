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

import static org.assertj.core.api.Assertions.assertThat;

import tech.pegasys.teku.bls.BLSKeyPair;
import tech.pegasys.web3signer.BLSTestUtil;
import tech.pegasys.web3signer.KeystoreUtil;
import tech.pegasys.web3signer.keystorage.common.MappedResults;
import tech.pegasys.web3signer.signing.ArtifactSigner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BlsKeystoreBulkLoaderTest {

  private static final BLSKeyPair KEY_PAIR_1 = BLSTestUtil.randomKeyPair(0);
  private static final BLSKeyPair KEY_PAIR_2 = BLSTestUtil.randomKeyPair(1);
  private static final String KEYSTORE_PASSWORD_1 = "password1";
  private static final String KEYSTORE_PASSWORD_2 = "password2";

  @Test
  void loadingEmptyKeystoreDirReturnsNoSigners(
      final @TempDir Path keystoreDir, final @TempDir Path passwordDir) {
    MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordDir(keystoreDir, passwordDir);
    assertThat(result.getValues()).isEmpty();
    assertThat(result.getErrorCount()).isEqualTo(0);
  }

  @Test
  void loadsMultipleKeystores(final @TempDir Path keystoreDir, final @TempDir Path passwordDir) {
    KeystoreUtil.createKeystore(KEY_PAIR_1, keystoreDir, passwordDir, "password1");
    KeystoreUtil.createKeystore(KEY_PAIR_2, keystoreDir, passwordDir, KEYSTORE_PASSWORD_2);
    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordDir(keystoreDir, passwordDir);
    final Collection<ArtifactSigner> signers = result.getValues();

    assertThat(signers).hasSize(2);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_1);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_2);

    assertThat(result.getErrorCount()).isEqualTo(0);
  }

  @Test
  void loadsMultipleKeystoresUsingSinglePasswordFile(final @TempDir Path tempDir)
      throws IOException {
    final Path keystoreDir = tempDir.resolve("keystores");
    Files.createDirectory(keystoreDir);
    KeystoreUtil.createKeystoreFile(KEY_PAIR_1, keystoreDir, KEYSTORE_PASSWORD_1);
    KeystoreUtil.createKeystoreFile(KEY_PAIR_2, keystoreDir, KEYSTORE_PASSWORD_1);
    final Path passwordFile = tempDir.resolve("password.txt");
    Files.writeString(passwordFile, KEYSTORE_PASSWORD_1);

    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordFile(keystoreDir, passwordFile);
    final Collection<ArtifactSigner> signers = result.getValues();
    assertThat(signers).hasSize(2);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_1);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_2);

    assertThat(result.getErrorCount()).isEqualTo(0);
  }

  @Test
  void ignoresNonJsonFiles(final @TempDir Path keystoreDir, final @TempDir Path passwordDir)
      throws IOException {
    KeystoreUtil.createKeystore(KEY_PAIR_1, keystoreDir, passwordDir, KEYSTORE_PASSWORD_1);
    KeystoreUtil.createKeystore(KEY_PAIR_2, keystoreDir, passwordDir, KEYSTORE_PASSWORD_2);

    // rename keypair 0 so it now ignored
    final Path sourcePath = keystoreDir.resolve(KEY_PAIR_1.getPublicKey() + ".json");
    final Path targetPath = keystoreDir.resolve(KEY_PAIR_1.getPublicKey() + ".ignored");
    Files.move(sourcePath, targetPath);

    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordDir(keystoreDir, passwordDir);
    final Collection<ArtifactSigner> signers = result.getValues();
    assertThat(signers).hasSize(1);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_2);

    assertThat(result.getErrorCount()).isEqualTo(0);
  }

  @Test
  void keystoreWithoutPasswordCausesErrorCountAndRemainingKeystoresAreLoaded(
      final @TempDir Path keystoreDir, final @TempDir Path passwordDir) {
    KeystoreUtil.createKeystoreFile(KEY_PAIR_1, keystoreDir, KEYSTORE_PASSWORD_1);
    KeystoreUtil.createKeystore(KEY_PAIR_2, keystoreDir, passwordDir, KEYSTORE_PASSWORD_2);

    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordDir(keystoreDir, passwordDir);
    final Collection<ArtifactSigner> signers = result.getValues();
    assertThat(signers).hasSize(1);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_2);

    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void invalidKeystoreIsIgnoredAndRemainingKeystoresAreLoaded(
      final @TempDir Path keystoreDir, final @TempDir Path passwordDir) throws IOException {
    Files.writeString(keystoreDir.resolve(KEY_PAIR_1.getPublicKey() + ".json"), "{}");
    KeystoreUtil.createKeystorePasswordFile(KEY_PAIR_1, passwordDir, KEYSTORE_PASSWORD_1);
    KeystoreUtil.createKeystore(KEY_PAIR_2, keystoreDir, passwordDir, KEYSTORE_PASSWORD_2);

    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordDir(keystoreDir, passwordDir);
    final Collection<ArtifactSigner> signers = result.getValues();
    assertThat(signers).hasSize(1);
    assertThatSignerHasPublicKey(signers, KEY_PAIR_2);

    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void invalidKeystoreDirectoryReturnsErrorCount(
      final @TempDir Path keystoreDir, final @TempDir Path passwordDir) {
    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordDir(
            keystoreDir.resolve("invalidKeystorePath"), passwordDir);
    assertThat(result.getValues()).isEmpty();
    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  @Test
  void invalidKeystorePasswordFileReturnsErrorCount(final @TempDir Path tempDir)
      throws IOException {
    final Path keystoreDir = tempDir.resolve("keystores");
    Files.createDirectory(keystoreDir);

    final MappedResults<ArtifactSigner> result =
        BlsKeystoreBulkLoader.loadKeystoresUsingPasswordFile(
            keystoreDir, tempDir.resolve("invalidPasswordFilePath"));
    assertThat(result.getValues()).isEmpty();
    assertThat(result.getErrorCount()).isEqualTo(1);
  }

  private void assertThatSignerHasPublicKey(
      final Collection<ArtifactSigner> signers, final BLSKeyPair keyPair0) {
    assertThat(signers).anyMatch(s -> s.getIdentifier().equals(keyPair0.getPublicKey().toString()));
  }
}
