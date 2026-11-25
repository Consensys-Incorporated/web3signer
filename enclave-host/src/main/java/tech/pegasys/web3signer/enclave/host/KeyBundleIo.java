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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Reads and writes {@link KeyBundle} as JSON. */
public final class KeyBundleIo {
  /** Bundle file format version. */
  public static final int VERSION = 1;

  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final HexFormat HEX = HexFormat.of();

  private KeyBundleIo() {}

  public static String toJson(final KeyBundle bundle) {
    final ObjectNode root = MAPPER.createObjectNode();
    root.put("version", VERSION);
    final ObjectNode dek = root.putObject("dek");
    dek.put("provider", bundle.dek().provider());
    dek.put("keyId", bundle.dek().keyId());
    final ObjectNode context = dek.putObject("encryptionContext");
    bundle.dek().encryptionContext().forEach(context::put);
    dek.put("wrapped", Base64.getEncoder().encodeToString(bundle.dek().wrapped()));
    final ArrayNode keys = root.putArray("keys");
    for (final SealedKey key : bundle.keys()) {
      keys.addObject()
          .put("pubkey", "0x" + HEX.formatHex(key.publicKey()))
          .put("nonce", "0x" + HEX.formatHex(key.nonce()))
          .put("ciphertext", "0x" + HEX.formatHex(key.ciphertext()));
    }
    try {
      return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(root);
    } catch (final IOException e) {
      throw new IllegalStateException("Cannot serialise key bundle", e);
    }
  }

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
    if (root.path("version").asInt(-1) != VERSION) {
      throw new IllegalArgumentException("Unsupported key bundle version: " + root.path("version"));
    }
    final JsonNode dek = root.path("dek");
    final Map<String, String> context =
        dek.path("encryptionContext")
            .propertyStream()
            .collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().asText()));
    final JsonNode keys = root.path("keys");
    if (!keys.isArray()) {
      throw new IllegalArgumentException("Key bundle field missing: keys");
    }
    final List<SealedKey> sealed =
        keys.valueStream()
            .map(
                key ->
                    new SealedKey(
                        hex(key, "pubkey", Protocol.PUBLIC_KEY_SIZE),
                        hex(key, "nonce", Protocol.SEALED_NONCE_SIZE),
                        hex(key, "ciphertext", Protocol.SEALED_CIPHERTEXT_SIZE)))
            .toList();
    return new KeyBundle(
        new KeyBundle.Dek(
            text(dek, "provider"), text(dek, "keyId"), context, base64(dek, "wrapped")),
        sealed);
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

  private static byte[] hex(final JsonNode node, final String field, final int size) {
    String value = text(node, field);
    if (value.startsWith("0x") || value.startsWith("0X")) {
      value = value.substring(2);
    }
    final byte[] bytes;
    try {
      bytes = HEX.parseHex(value);
    } catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException("Key bundle field is not hex: " + field, e);
    }
    if (bytes.length != size) {
      throw new IllegalArgumentException(
          "Key bundle field " + field + " must be " + size + " bytes");
    }
    return bytes;
  }

  public static KeyBundle read(final Path file) throws IOException {
    return fromJson(Files.readString(file));
  }

  /** Writes to a temporary file in the same directory, then moves it into place atomically. */
  public static void write(final KeyBundle bundle, final Path file) throws IOException {
    final Path target = file.toAbsolutePath();
    final Path temp = Files.createTempFile(target.getParent(), ".keys-bundle", ".tmp");
    try {
      Files.writeString(temp, toJson(bundle));
      Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } finally {
      Files.deleteIfExists(temp);
    }
  }
}
