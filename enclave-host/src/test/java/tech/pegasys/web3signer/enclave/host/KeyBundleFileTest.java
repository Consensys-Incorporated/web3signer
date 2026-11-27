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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class KeyBundleFileTest {

  private static byte[] filled(final int size, final int value) {
    final byte[] bytes = new byte[size];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  private static final KeyBundle BUNDLE =
      new KeyBundle(
          new KeyBundle.Dek(
              KeyBundle.Dek.PROVIDER_AWS_KMS,
              "arn:aws:kms:us-east-1:111122223333:key/0b9c",
              Map.of("purpose", "web3signer-enclave-bls-keys"),
              filled(20, 7)),
          List.of(
              new SealedKey(filled(48, 1), filled(12, 2), filled(48, 3)),
              new SealedKey(filled(48, 4), filled(12, 5), filled(48, 6))));

  @Test
  void roundTripsThroughJsonAndFiles(@TempDir final Path dir) throws Exception {
    final String json = KeyBundleFile.toJson(BUNDLE);
    assertThat(json)
        .contains("\"provider\" : \"aws-kms\"")
        .contains("\"wrapped\" : \"BwcHBwcHBwcHBwcHBwcHBwcHBwc=\"")
        .contains("\"pubkey\" : \"0x" + "01".repeat(48) + "\"")
        .contains("\"nonce\" : \"0x" + "02".repeat(12) + "\"");
    final KeyBundle parsed = KeyBundleFile.fromJson(json);
    assertThat(parsed.keys())
        .usingRecursiveFieldByFieldElementComparator()
        .isEqualTo(BUNDLE.keys());
    assertThat(parsed.dek()).isEqualTo(BUNDLE.dek());

    final Path file = dir.resolve("keys.bundle.json");
    KeyBundleFile.write(BUNDLE, file);
    assertThat(KeyBundleFile.read(file).keys())
        .usingRecursiveFieldByFieldElementComparator()
        .isEqualTo(BUNDLE.keys());
    assertThat(dir.toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void writeReplacesAnExistingBundle(@TempDir final Path dir) throws Exception {
    final Path file = dir.resolve("keys.bundle.json");
    Files.writeString(file, "old");
    KeyBundleFile.write(BUNDLE, file);
    assertThat(Files.readString(file)).isEqualTo(KeyBundleFile.toJson(BUNDLE));
    assertThat(dir.toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void newBundleGetsTheDefaultPermissions(@TempDir final Path dir) throws Exception {
    assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
    final Path file = dir.resolve("keys.bundle.json");
    KeyBundleFile.write(BUNDLE, file);
    final Path reference = Files.createFile(dir.resolve("reference"));
    assertThat(Files.getPosixFilePermissions(file))
        .isEqualTo(Files.getPosixFilePermissions(reference));
  }

  @ParameterizedTest
  @ValueSource(strings = {"rw-r-----", "rw-rw-r--", "r--r--r--"})
  void replacedBundleKeepsItsPermissions(final String permissions, @TempDir final Path dir)
      throws Exception {
    assumeTrue(dir.getFileSystem().supportedFileAttributeViews().contains("posix"));
    final Path file = Files.writeString(dir.resolve("keys.bundle.json"), "old");
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString(permissions));
    KeyBundleFile.write(BUNDLE, file);
    assertThat(PosixFilePermissions.toString(Files.getPosixFilePermissions(file)))
        .isEqualTo(permissions);
    assertThat(KeyBundleFile.read(file).dek()).isEqualTo(BUNDLE.dek());
    assertThat(dir.toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void writeFollowsASymlinkAndKeepsIt(@TempDir final Path dir) throws Exception {
    final Path real = Files.createDirectory(dir.resolve("real")).resolve("keys.bundle.json");
    Files.writeString(real, "old");
    final Path link =
        createSymlinkOrSkip(dir.resolve("link.json"), Path.of("real/keys.bundle.json"));
    KeyBundleFile.write(BUNDLE, link);
    assertThat(Files.isSymbolicLink(link)).isTrue();
    assertThat(Files.readString(real)).isEqualTo(KeyBundleFile.toJson(BUNDLE));
    assertThat(real.getParent().toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void writeCreatesTheFileADanglingSymlinkPointsTo(@TempDir final Path dir) throws Exception {
    final Path real = dir.resolve("keys.bundle.json");
    final Path link = createSymlinkOrSkip(dir.resolve("link.json"), real);
    KeyBundleFile.write(BUNDLE, link);
    assertThat(Files.isSymbolicLink(link)).isTrue();
    assertThat(KeyBundleFile.read(real).dek()).isEqualTo(BUNDLE.dek());
  }

  @Test
  void writeRefusesASymlinkLoop(@TempDir final Path dir) throws Exception {
    final Path a = dir.resolve("a");
    createSymlinkOrSkip(a, dir.resolve("b"));
    createSymlinkOrSkip(dir.resolve("b"), a);
    assertThatThrownBy(() -> KeyBundleFile.write(BUNDLE, a))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("Too many levels of symbolic links");
  }

  private static Path createSymlinkOrSkip(final Path link, final Path target) {
    try {
      return Files.createSymbolicLink(link, target);
    } catch (final IOException | UnsupportedOperationException e) {
      assumeTrue(false, "symbolic links not supported: " + e);
      return link;
    }
  }

  @Test
  void encryptionContextIsWrittenSorted() {
    final KeyBundle bundle =
        new KeyBundle(
            new KeyBundle.Dek(
                KeyBundle.Dek.PROVIDER_AWS_KMS,
                "arn:aws:kms:us-east-1:111122223333:key/0b9c",
                Map.of("d", "4", "b", "2", "e", "5", "a", "1", "c", "3"),
                filled(20, 7)),
            List.of());
    final String json = KeyBundleFile.toJson(bundle).replaceAll("\\s+", "");
    assertThat(json)
        .contains(
            "\"encryptionContext\":{\"a\":\"1\",\"b\":\"2\",\"c\":\"3\",\"d\":\"4\",\"e\":\"5\"}");
  }

  @Test
  void unknownVersionIsRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("\"version\" : 1", "\"version\" : 2");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("version");
  }

  @Test
  void malformedEntriesAreRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("0x" + "02".repeat(12), "0x0202");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("nonce");
  }

  static Stream<String> badPubkeys() {
    return Stream.of(
        "01".repeat(48),
        "0X" + "01".repeat(48),
        "0x" + "AB".repeat(48),
        "0x" + "01".repeat(47),
        "0x" + "01".repeat(47) + "0",
        "0x" + "zz".repeat(48));
  }

  @ParameterizedTest
  @MethodSource("badPubkeys")
  void hexFieldsMustBeWrittenAsWeWriteThem(final String pubkey) {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("0x" + "01".repeat(48), pubkey);
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field pubkey must be 0x followed by 96 lowercase hex digits");
  }

  @Test
  void missingDekFieldIsRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("\"provider\" : \"aws-kms\",", "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field missing: provider");
  }

  @Test
  void missingWrappedKeyIsRefused() {
    final String json =
        KeyBundleFile.toJson(BUNDLE)
            .replace(",\n    \"wrapped\" : \"BwcHBwcHBwcHBwcHBwcHBwcHBwc=\"", "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field missing: wrapped");
  }

  @Test
  void unknownFieldsAreIgnored() {
    final String json =
        KeyBundleFile.toJson(BUNDLE)
            .replaceFirst("\\{", "{ \"comment\" : \"x\",")
            .replace("\"provider\"", "\"extra\" : 1, \"provider\"");
    assertThat(KeyBundleFile.fromJson(json).dek()).isEqualTo(BUNDLE.dek());
  }

  @Test
  void wrappedKeyThatIsNotBase64NamesTheField() {
    final String json =
        KeyBundleFile.toJson(BUNDLE).replace("BwcHBwcHBwcHBwcHBwcHBwcHBwc=", "Bw!HBwc=");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field is not base64: wrapped");
  }

  @Test
  void missingKeysAreRefused() {
    final String json =
        "{\"version\":1,\"dek\":{\"provider\":\"dev\",\"keyId\":\"dev\","
            + "\"encryptionContext\":{},\"wrapped\":\"AQID\"}}";
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field missing: keys");
  }

  private static final String KEY =
      "{\"pubkey\":\"0x"
          + "01".repeat(48)
          + "\",\"nonce\":\"0x"
          + "02".repeat(12)
          + "\",\"ciphertext\":\"0x"
          + "03".repeat(48)
          + "\"}";

  private static String bundle(
      final String version, final String dek, final String keys, final String after) {
    return "{\"version\":" + version + ",\"dek\":" + dek + ",\"keys\":[" + keys + "]}" + after;
  }

  private static String dek(final String provider, final String context, final String wrapped) {
    return "{\"provider\":"
        + provider
        + ",\"keyId\":\"dev\",\"encryptionContext\":"
        + context
        + ",\"wrapped\":\""
        + wrapped
        + "\"}";
  }

  @Test
  void strictBaselineIsAccepted() {
    final KeyBundle parsed =
        KeyBundleFile.fromJson(bundle("1", dek("\"dev\"", "{\"a\":\"b\"}", "AQID"), KEY, ""));
    assertThat(parsed.dek().encryptionContext()).isEqualTo(Map.of("a", "b"));
    assertThat(parsed.keys()).hasSize(1);
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource(
      delimiter = '|',
      value = {
        "version as a string | \"1\" | \"dev\" | {} | AQID | Unsupported key bundle version",
        "version true | true | \"dev\" | {} | AQID | Unsupported key bundle version",
        "version 1.9 | 1.9 | \"dev\" | {} | AQID | Unsupported key bundle version",
        "unknown provider | 1 | \"bogus\" | {} | AQID | Unknown key bundle provider: bogus",
        "empty wrapped key | 1 | \"dev\" | {} | '' | The wrapped data key is empty",
        "context as an array | 1 | \"dev\" | [\"a\"] | AQID"
            + " | Key bundle field missing: encryptionContext",
        "context as a string | 1 | \"dev\" | \"a\" | AQID"
            + " | Key bundle field missing: encryptionContext",
        "context object value | 1 | \"dev\" | {\"a\":{}} | AQID"
            + " | Key bundle encryption context value is not a string: a",
        "context number value | 1 | \"dev\" | {\"a\":12} | AQID"
            + " | Key bundle encryption context value is not a string: a",
      })
  void looseFieldsAreRefused(
      final String name,
      final String version,
      final String provider,
      final String context,
      final String wrapped,
      final String message) {
    final String json = bundle(version, dek(provider, context, wrapped), KEY, "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(message);
  }

  @Test
  void missingEncryptionContextIsRefused() {
    final String json =
        KeyBundleFile.toJson(BUNDLE).replaceAll("\"encryptionContext\" : \\{[^}]*},", "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field missing: encryptionContext");
  }

  @Test
  void missingDekIsRefused() {
    assertThatThrownBy(() -> KeyBundleFile.fromJson(bundle("1", "\"dev\"", KEY, "")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle field missing: dek");
  }

  @Test
  void duplicateFieldsAreRefused() {
    final String json = bundle("1", dek("\"aws-kms\",\"provider\":\"dev\"", "{}", "AQID"), KEY, "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle is not valid JSON");
  }

  @Test
  void trailingContentIsRefused() {
    final String json = bundle("1", dek("\"dev\"", "{}", "AQID"), KEY, " {");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle is not valid JSON");
  }

  @Test
  void duplicatePublicKeysAreRefused() {
    final String json = bundle("1", dek("\"dev\"", "{}", "AQID"), KEY + "," + KEY, "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle holds public key 0x" + "01".repeat(48) + " more than once");
  }
}
