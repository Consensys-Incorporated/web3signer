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

import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Protocol;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** The key bundle file: its JSON format, and reading and writing it on disk. */
public final class KeyBundleFile {
  /** Bundle file format version. */
  public static final int VERSION = 1;

  // refuse anything we would not have written ourselves
  private static final ObjectMapper MAPPER =
      JsonMapper.builder()
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .build();
  private static final HexFormat HEX = HexFormat.of();

  private KeyBundleFile() {}

  public static String toJson(final KeyBundle bundle) {
    final ObjectNode root = MAPPER.createObjectNode();
    root.put("version", VERSION);
    final ObjectNode dek = root.putObject("dek");
    dek.put("provider", bundle.dek().provider());
    dek.put("keyId", bundle.dek().keyId());
    final ObjectNode context = dek.putObject("encryptionContext");
    // sorted, so that the same bundle is always written the same way
    new TreeMap<>(bundle.dek().encryptionContext()).forEach(context::put);
    dek.put("wrapped", Base64.getEncoder().encodeToString(bundle.dek().wrapped()));
    final ArrayNode keys = root.putArray("keys");
    for (final SealedKey key : bundle.keys()) {
      keys.addObject()
          .put("pubkey", "0x" + HEX.formatHex(key.pubKey()))
          .put("nonce", "0x" + HEX.formatHex(key.nonce()))
          .put("ciphertext", "0x" + HEX.formatHex(key.ciphertext()));
    }
    try {
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    } catch (final IOException e) {
      throw new IllegalStateException("Cannot serialise key bundle", e);
    }
  }

  /**
   * Reads a bundle written by {@link #toJson}. Refuses malformed or ambiguous input; unknown fields
   * are ignored.
   */
  public static KeyBundle fromJson(final String json) {
    final JsonNode root;
    try {
      root = MAPPER.readTree(json);
    } catch (final IOException e) {
      throw new IllegalArgumentException("Key bundle is not valid JSON", e);
    }
    if (!root.isObject()) {
      throw new IllegalArgumentException("Key bundle must be a JSON object");
    }
    final JsonNode version = root.path("version");
    if (!version.isInt() || version.intValue() != VERSION) {
      throw new IllegalArgumentException("Unsupported key bundle version: " + version);
    }
    final JsonNode dek = object(root, "dek");
    final JsonNode keys = root.path("keys");
    if (!keys.isArray()) {
      throw new IllegalArgumentException("Key bundle field missing: keys");
    }
    final List<SealedKey> sealed = keys.valueStream().map(KeyBundleFile::sealedKey).toList();
    // the constructors refuse an unknown provider, an empty wrapped key and duplicate pubkeys
    return new KeyBundle(
        new KeyBundle.Dek(
            text(dek, "provider"), text(dek, "keyId"), context(dek), base64(dek, "wrapped")),
        sealed);
  }

  private static SealedKey sealedKey(final JsonNode key) {
    return new SealedKey(
        hex(key, "pubkey", Protocol.PUBLIC_KEY_SIZE),
        hex(key, "nonce", Protocol.SEALED_NONCE_SIZE),
        hex(key, "ciphertext", Protocol.SEALED_CIPHERTEXT_SIZE));
  }

  private static Map<String, String> context(final JsonNode dek) {
    final Map<String, String> context = new HashMap<>();
    for (final Map.Entry<String, JsonNode> entry : object(dek, "encryptionContext").properties()) {
      if (!entry.getValue().isTextual()) {
        throw new IllegalArgumentException(
            "Key bundle encryption context value is not a string: " + entry.getKey());
      }
      context.put(entry.getKey(), entry.getValue().textValue());
    }
    return context;
  }

  private static JsonNode object(final JsonNode node, final String field) {
    final JsonNode value = node.get(field);
    if (value == null || !value.isObject()) {
      throw new IllegalArgumentException("Key bundle field missing: " + field);
    }
    return value;
  }

  private static String text(final JsonNode node, final String field) {
    final JsonNode value = node.get(field);
    if (value == null || !value.isTextual()) {
      throw new IllegalArgumentException("Key bundle field missing: " + field);
    }
    return value.asText();
  }

  private static byte[] base64(final JsonNode node, final String field) {
    final String value = text(node, field);
    try {
      return Base64.getDecoder().decode(value);
    } catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException("Key bundle field is not base64: " + field, e);
    }
  }

  /** Exactly as {@link #toJson} writes it: {@code 0x} and lowercase hex of {@code size} bytes. */
  private static byte[] hex(final JsonNode node, final String field, final int size) {
    final String value = text(node, field);
    final String digits = value.startsWith("0x") ? value.substring(2) : "";
    if (digits.length() != 2 * size || !digits.chars().allMatch(KeyBundleFile::isLowerHex)) {
      throw new IllegalArgumentException(
          "Key bundle field "
              + field
              + " must be 0x followed by "
              + 2 * size
              + " lowercase hex digits");
    }
    return HEX.parseHex(digits);
  }

  private static boolean isLowerHex(final int c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
  }

  public static KeyBundle read(final Path file) throws IOException {
    return fromJson(Files.readString(file));
  }

  /**
   * Writes to a temporary file in the same directory, flushes it to disk, then moves it into place
   * atomically, so a crash leaves either the old bundle or the new one. A bundle that is replaced
   * keeps its permissions; a new one gets the default for new files. A symlink is followed, and
   * stays in place.
   */
  public static void write(final KeyBundle bundle, final Path file) throws IOException {
    final Path target = followLinks(file.toAbsolutePath());
    final Path directory = target.getParent();
    // not Files.createTempFile, which makes the file readable by its owner only
    final Path temp =
        Files.createFile(directory.resolve(".keys-bundle-" + UUID.randomUUID() + ".tmp"));
    try {
      try (FileOutputStream out = new FileOutputStream(temp.toFile())) {
        out.write(toJson(bundle).getBytes(StandardCharsets.UTF_8));
        out.getFD().sync();
      }
      keepPermissions(target, temp);
      Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      syncDirectory(directory);
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  /** Where {@code path} points, even when that file doesn't exist yet. */
  private static Path followLinks(final Path path) throws IOException {
    Path current = path;
    for (int hops = 0; Files.isSymbolicLink(current); hops++) {
      if (hops == 40) {
        throw new IOException("Too many levels of symbolic links: " + path);
      }
      current = current.resolveSibling(Files.readSymbolicLink(current));
    }
    return current;
  }

  /** After writing, so that a read-only bundle can still be replaced. */
  private static void keepPermissions(final Path target, final Path temp) throws IOException {
    if (Files.exists(target)
        && target.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Files.setPosixFilePermissions(temp, Files.getPosixFilePermissions(target));
    }
  }

  /** Makes the rename durable, as far as the platform allows. Windows can't open a directory. */
  private static void syncDirectory(final Path directory) {
    try (FileChannel channel = FileChannel.open(directory)) {
      channel.force(true);
    } catch (final IOException e) {
      // best effort: the bundle is already in place
    }
  }
}
