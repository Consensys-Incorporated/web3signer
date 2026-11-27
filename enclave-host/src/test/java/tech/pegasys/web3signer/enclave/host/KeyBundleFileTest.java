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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
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
  void roundTripsThroughJsonAndFiles(@TempDir final Path dir) throws Exception {
    final String json = KeyBundleFile.toJson(BUNDLE);
    assertThat(json)
        .contains("\"provider\" : \"aws-kms\"")
        .contains("\"wrapped\" : \"0x" + "07".repeat(20) + "\"")
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
    KeyBundleFile.write(new KeyBundle(BUNDLE.dek(), List.of(BUNDLE.keys().getFirst())), file);
    KeyBundleFile.write(BUNDLE, file);
    final KeyBundle read = KeyBundleFile.read(file);
    assertThat(read.dek()).isEqualTo(BUNDLE.dek());
    assertThat(read.keys()).usingRecursiveFieldByFieldElementComparator().isEqualTo(BUNDLE.keys());
    assertThat(dir.toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void failedWriteLeavesTheTargetAndNoTempFile(@TempDir final Path dir) throws Exception {
    // a non-empty directory cannot be renamed over
    final Path target = Files.createDirectory(dir.resolve("keys.bundle.json"));
    Files.writeString(target.resolve("inside"), "kept");
    assertThatThrownBy(() -> KeyBundleFile.write(BUNDLE, target)).isInstanceOf(IOException.class);
    assertThat(Files.readString(target.resolve("inside"))).isEqualTo("kept");
    assertThat(dir.toFile().list()).containsExactly("keys.bundle.json");
  }

  @Test
  void everyTruncatedBundleIsRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE);
    for (int length = 0; length < json.length(); length++) {
      final String partial = json.substring(0, length);
      assertThatThrownBy(() -> KeyBundleFile.fromJson(partial))
          .as("truncated to %d chars", length)
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  @Test
  void writeToARelativePath(@TempDir final Path dir) throws Exception {
    final Path file = Path.of("").toAbsolutePath().relativize(dir.resolve("keys.bundle.json"));
    KeyBundleFile.write(BUNDLE, file);
    assertThat(KeyBundleFile.read(file).keys()).hasSize(2);
  }

  @Test
  void readNamesTheFileWhenItsContentIsInvalid(@TempDir final Path dir) throws Exception {
    final Path file = Files.writeString(dir.resolve("keys.bundle.json"), "[]");
    assertThatThrownBy(() -> KeyBundleFile.read(file))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(file + ": Key bundle is not a JSON object");
  }

  @Test
  void readNamesTheFileWhenItIsNotUtf8(@TempDir final Path dir) throws Exception {
    final Path file = Files.write(dir.resolve("keys.bundle.json"), new byte[] {'{', (byte) 0xff});
    assertThatThrownBy(() -> KeyBundleFile.read(file))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage(file + ": Key bundle is not valid UTF-8");
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
  void unknownVersionIsRefusedBeforeItsFieldsAreRead() {
    final String json = "{\"version\":2,\"dataKey\":{}}";
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unsupported key bundle version: 2");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "   ", "null", "[]", "\"x\"", "1"})
  void bundleThatIsNotAnObjectIsRefused(final String json) {
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle is not a JSON object");
  }

  @Test
  void missingVersionIsRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("\"version\" : 1,", "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Unsupported key bundle version: none");
  }

  @Test
  void malformedEntriesAreRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("0x" + "05".repeat(12), "0x0505");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle is not valid at `keys.1`: Sealed key has wrong field sizes");
  }

  static Stream<Arguments> badPubkeys() {
    return Stream.of(
        Arguments.of("0X" + "01".repeat(48), "Illegal character 'X' found at index 1"),
        Arguments.of("0x" + "01".repeat(47) + "0", "Invalid odd-length hex"),
        Arguments.of("0x" + "zz".repeat(48), "Illegal character 'z' found at index 0"));
  }

  @ParameterizedTest
  @MethodSource("badPubkeys")
  void badHexIsRefused(final String pubkey, final String reason) {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("0x" + "01".repeat(48), pubkey);
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `keys.0.pubkey`: " + reason);
  }

  @ParameterizedTest
  @ValueSource(strings = {"0x", ""})
  void hexIsReadLikeTheRestOfWeb3signer(final String prefix) {
    // tuweni, as elsewhere: the 0x is optional and either case is read
    final String json =
        KeyBundleFile.toJson(BUNDLE).replace("0x" + "04".repeat(48), prefix + "0A".repeat(48));
    assertThat(KeyBundleFile.fromJson(json).keys().get(1).pubKey()).containsOnly(0x0a);
  }

  @Test
  void missingDekFieldIsRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("\"provider\" : \"aws-kms\",", "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(
            "Key bundle is not valid at `dek.provider`: Missing creator property 'provider'");
  }

  @Test
  void missingWrappedKeyIsRefused() {
    final String json =
        KeyBundleFile.toJson(BUNDLE)
            .replace(",\n    \"wrapped\" : \"0x" + "07".repeat(20) + "\"", "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(
            "Key bundle is not valid at `dek.wrapped`: Missing creator property 'wrapped'");
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
  void wrappedKeyThatIsNotHexIsRefused() {
    final String json = KeyBundleFile.toJson(BUNDLE).replace("0x" + "07".repeat(20), "0x07zz");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `dek.wrapped`: Illegal character 'z'");
  }

  @Test
  void badHexNamesTheKeyAndField() {
    final String json =
        KeyBundleFile.toJson(BUNDLE).replace("0x" + "05".repeat(12), "0x" + "zz".repeat(12));
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `keys.1.nonce`: Illegal character 'z'");
  }

  @Test
  void wrappedKeyAsAnArrayOfNumbersIsRefused() {
    final String json =
        KeyBundleFile.toJson(BUNDLE).replace("\"0x" + "07".repeat(20) + "\"", "[1, 2, 3]");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(
            "Key bundle is not valid at `dek.wrapped`: Cannot deserialize value of type `java.lang.String` from Array value");
  }

  @Test
  void nullKeyEntryIsRefused() {
    final String json =
        "{\"version\":1,\"dek\":{\"provider\":\"dev\",\"keyId\":\"dev\","
            + "\"encryptionContext\":{},\"wrapped\":\"0x010203\"},\"keys\":[null]}";
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(
            "Key bundle is not valid at `keys.0`: Invalid `null` value encountered");
  }

  @Test
  void missingKeysAreRefused() {
    final String json =
        "{\"version\":1,\"dek\":{\"provider\":\"dev\",\"keyId\":\"dev\","
            + "\"encryptionContext\":{},\"wrapped\":\"0x010203\"}}";
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(
            "Key bundle is not valid at `keys`: Missing creator property 'keys'");
  }

  @Test
  void strictBaselineIsAccepted() {
    final KeyBundle parsed =
        KeyBundleFile.fromJson(bundle("1", dek("\"dev\"", "{\"a\":\"b\"}", "0x010203"), KEY, ""));
    assertThat(parsed.dek().encryptionContext()).isEqualTo(Map.of("a", "b"));
    assertThat(parsed.keys()).hasSize(1);
  }

  @ParameterizedTest(name = "{0}")
  @CsvSource(
      delimiter = '|',
      value = {
        "version as a string | \"1\" | \"dev\" | {} | 0x010203 | Unsupported key bundle version: \"1\"",
        "version true | true | \"dev\" | {} | 0x010203 | Unsupported key bundle version: true",
        "version 1.9 | 1.9 | \"dev\" | {} | 0x010203 | Unsupported key bundle version: 1.9",
        "version 1.0 | 1.0 | \"dev\" | {} | 0x010203 | Unsupported key bundle version: 1.0",
        "version null | null | \"dev\" | {} | 0x010203 | Unsupported key bundle version: null",
        "provider null | 1 | null | {} | 0x010203"
            + " | Key bundle is not valid at `dek.provider`: Invalid `null` value encountered",
        "unknown provider | 1 | \"bogus\" | {} | 0x010203 | Unknown key bundle provider: bogus",
        "empty wrapped key | 1 | \"dev\" | {} | '' | The wrapped data key is empty",
        "context as an array | 1 | \"dev\" | [\"a\"] | 0x010203"
            + " | Key bundle is not valid at `dek.encryptionContext`: Cannot deserialize value of type `java.util.LinkedHashMap",
        "context as a string | 1 | \"dev\" | \"a\" | 0x010203"
            + " | Key bundle is not valid at `dek.encryptionContext`: Cannot construct instance of `java.util.LinkedHashMap`",
        "context object value | 1 | \"dev\" | {\"a\":{}} | 0x010203"
            + " | Key bundle is not valid at `dek.encryptionContext.a`: Cannot deserialize value of type `java.lang.String`",
        "context number value | 1 | \"dev\" | {\"a\":12} | 0x010203"
            + " | Key bundle is not valid at `dek.encryptionContext.a`: Cannot coerce Integer value (12) to `java.lang.String`",
        "context null value | 1 | \"dev\" | {\"a\":null} | 0x010203"
            + " | Key bundle is not valid at `dek.encryptionContext.a`: Invalid `null` value encountered for property \"encryptionContext\"",
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
        .hasMessageStartingWith(
            "Key bundle is not valid at `dek.encryptionContext`: Missing creator property 'encryptionContext'");
  }

  @Test
  void dekThatIsNotAnObjectIsRefused() {
    assertThatThrownBy(() -> KeyBundleFile.fromJson(bundle("1", "\"dev\"", KEY, "")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `dek`: Cannot construct instance");
  }

  @Test
  void missingDekIsRefused() {
    assertThatThrownBy(() -> KeyBundleFile.fromJson("{\"version\":1,\"keys\":[]}"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `dek`: Missing creator property 'dek'");
  }

  @Test
  void nullDekIsRefused() {
    assertThatThrownBy(() -> KeyBundleFile.fromJson(bundle("1", "null", KEY, "")))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `dek`: Invalid `null` value");
  }

  @Test
  void nullKeysAreRefused() {
    final String json =
        "{\"version\":1,\"dek\":" + dek("\"dev\"", "{}", "0x010203") + ",\"keys\":null}";
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at `keys`: Invalid `null` value");
  }

  @Test
  void duplicateFieldsAreRefused() {
    final String json =
        bundle("1", dek("\"aws-kms\",\"provider\":\"dev\"", "{}", "0x010203"), KEY, "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith(
            "Key bundle is not valid at line 1, column 53: Duplicate field 'provider'");
  }

  @Test
  void trailingContentIsRefused() {
    final String json = bundle("1", dek("\"dev\"", "{}", "0x010203"), KEY, " {");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageStartingWith("Key bundle is not valid at line 1, column 370: Trailing token");
  }

  @Test
  void duplicatePublicKeysAreRefused() {
    final String json = bundle("1", dek("\"dev\"", "{}", "0x010203"), KEY + "," + KEY, "");
    assertThatThrownBy(() -> KeyBundleFile.fromJson(json))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessage("Key bundle holds public key 0x" + "01".repeat(48) + " more than once");
  }
}
