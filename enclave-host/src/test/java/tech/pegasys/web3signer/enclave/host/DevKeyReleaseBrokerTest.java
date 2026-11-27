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

import tech.pegasys.web3signer.enclave.host.KeyReleaseBroker.DataKey;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;

import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DevKeyReleaseBrokerTest {
  private static KeyPair releaseKey;

  @TempDir Path dir;

  @BeforeAll
  static void generateReleaseKey() throws Exception {
    final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    releaseKey = generator.generateKeyPair();
  }

  private static byte[] masterKey(final int fill) {
    final byte[] key = new byte[32];
    Arrays.fill(key, (byte) fill);
    return key;
  }

  private static Evidence devEvidence() {
    final byte[] spki = releaseKey.getPublic().getEncoded();
    return new Evidence(Protocol.EVIDENCE_DEV, spki, spki);
  }

  /** Opens a release envelope the way the enclave does, with the release key's private half. */
  private static byte[] open(final byte[] envelope) throws Exception {
    final RecipientInformation recipient =
        new CMSEnvelopedData(envelope).getRecipientInfos().getRecipients().iterator().next();
    return recipient.getContent(new JceKeyTransEnvelopedRecipient(releaseKey.getPrivate()));
  }

  @Test
  void releasesTheDataKeyToTheReleaseKey() throws Exception {
    try (DevKeyReleaseBroker broker = new DevKeyReleaseBroker(masterKey(1));
        DataKey dataKey = broker.newDataKey()) {
      final byte[] expected = dataKey.plaintext().clone();

      assertThat(expected).hasSize(Protocol.DEK_SIZE);
      assertThat(dataKey.dek().provider()).isEqualTo(KeyBundle.Dek.PROVIDER_DEV);
      assertThat(open(broker.release(dataKey.dek(), devEvidence()))).isEqualTo(expected);
    }
  }

  @Test
  void anotherMasterKeyCannotReleaseTheDataKey() {
    try (DevKeyReleaseBroker first = new DevKeyReleaseBroker(masterKey(1));
        DevKeyReleaseBroker second = new DevKeyReleaseBroker(masterKey(2));
        DataKey dataKey = first.newDataKey()) {
      assertThatThrownBy(() -> second.release(dataKey.dek(), devEvidence()))
          .isInstanceOf(IllegalStateException.class)
          .hasMessage("The dev master key does not open this bundle's data key");
    }
  }

  @Test
  void masterKeyFileIgnoresSurroundingWhitespace() throws Exception {
    final Path file =
        Files.writeString(dir.resolve("master.hex"), "\n  " + "ab".repeat(32) + " \n");
    try (DevKeyReleaseBroker fromFile = DevKeyReleaseBroker.fromFile(file);
        DevKeyReleaseBroker same = new DevKeyReleaseBroker(masterKey(0xab));
        DataKey dataKey = fromFile.newDataKey()) {
      final byte[] expected = dataKey.plaintext().clone();
      assertThat(open(same.release(dataKey.dek(), devEvidence()))).isEqualTo(expected);
    }
  }

  @ParameterizedTest
  @ValueSource(
      strings = {"", "abab", "0xabababababababababababababababababababababababababababababababab"})
  void masterKeyFileMustHold64HexCharacters(final String content) throws IOException {
    final Path file = Files.writeString(dir.resolve("master.hex"), content);
    assertThatThrownBy(() -> DevKeyReleaseBroker.fromFile(file))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The dev master key file must hold 64 hex characters");
  }

  @Test
  void masterKeyFileRefusesCharactersThatAreNotHex() throws IOException {
    final Path file = Files.writeString(dir.resolve("master.hex"), "zz".repeat(32));
    assertThatThrownBy(() -> DevKeyReleaseBroker.fromFile(file))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void masterKeyMustBe32Bytes() {
    assertThatThrownBy(() -> new DevKeyReleaseBroker(new byte[31]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("The dev master key must be 32 bytes");
  }
}
