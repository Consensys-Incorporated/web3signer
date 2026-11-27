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

import java.io.Closeable;
import java.io.IOException;
import java.nio.charset.CharacterCodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.type.LogicalType;
import org.apache.tuweni.bytes.Bytes;

/** The key bundle file: its JSON format, and reading and writing it on disk. */
public final class KeyBundleFile {
  /** Bundle file format version. */
  public static final int VERSION = 1;

  // strict about structure: no duplicate, missing or null fields or entries, no type coercion,
  // nothing after it
  private static final ObjectMapper MAPPER =
      JsonMapper.builder()
          .defaultSetterInfo(JsonSetter.Value.construct(Nulls.FAIL, Nulls.FAIL))
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
          .enable(SerializationFeature.INDENT_OUTPUT)
          .withCoercionConfig(
              LogicalType.Textual,
              c -> {
                c.setCoercion(CoercionInputShape.Integer, CoercionAction.Fail);
                c.setCoercion(CoercionInputShape.Float, CoercionAction.Fail);
                c.setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail);
              })
          .build();

  private record FileJson(int version, DekJson dek, List<KeyJson> keys) {}

  private record DekJson(
      String provider, String keyId, Map<String, String> encryptionContext, String wrapped) {
    static DekJson of(final KeyBundle.Dek dek) {
      return new DekJson(dek.provider(), dek.keyId(), dek.encryptionContext(), hex(dek.wrapped()));
    }

    /** {@link KeyBundle.Dek} checks the values. */
    KeyBundle.Dek toDek() {
      return new KeyBundle.Dek(provider, keyId, encryptionContext, unhex("dek.wrapped", wrapped));
    }
  }

  private record KeyJson(String pubkey, String nonce, String ciphertext) {
    static KeyJson of(final SealedKey key) {
      return new KeyJson(hex(key.pubKey()), hex(key.nonce()), hex(key.ciphertext()));
    }

    /** {@link SealedKey} checks the sizes. */
    SealedKey toSealedKey(final String path) {
      final byte[] pubKey = unhex(path + ".pubkey", pubkey);
      final byte[] nonceBytes = unhex(path + ".nonce", nonce);
      final byte[] ciphertextBytes = unhex(path + ".ciphertext", ciphertext);
      try {
        return new SealedKey(pubKey, nonceBytes, ciphertextBytes);
      } catch (final IllegalArgumentException e) {
        throw invalidAt(path, e);
      }
    }
  }

  private KeyBundleFile() {}

  public static String toJson(final KeyBundle bundle) {
    try {
      return MAPPER.writeValueAsString(
          new FileJson(
              VERSION, DekJson.of(bundle.dek()), bundle.keys().stream().map(KeyJson::of).toList()));
    } catch (final IOException e) {
      throw new IllegalStateException("Cannot serialise key bundle", e);
    }
  }

  /**
   * Reads a bundle written by {@link #toJson}. Refuses malformed or ambiguous input; unknown fields
   * are ignored.
   */
  public static KeyBundle fromJson(final String json) {
    final FileJson file;
    try {
      // through a tree, whose duplicate field check needs no jackson-core feature
      final JsonNode tree = MAPPER.readTree(json);
      if (tree.isMissingNode() || tree.isNull()) {
        throw new IllegalArgumentException("Key bundle is empty");
      }
      if (!tree.isObject()) {
        throw new IllegalArgumentException("Key bundle is not a JSON object");
      }
      // first and exactly, so a later format is refused by its version whatever else changed
      final JsonNode version = tree.path("version");
      if (!version.isInt() || version.intValue() != VERSION) {
        throw new IllegalArgumentException(
            "Unsupported key bundle version: " + (version.isMissingNode() ? "none" : version));
      }
      file = MAPPER.treeToValue(tree, FileJson.class);
    } catch (final JsonProcessingException e) {
      throw invalid(e);
    }
    return new KeyBundle(
        file.dek().toDek(),
        IntStream.range(0, file.keys().size())
            .mapToObj(i -> file.keys().get(i).toSealedKey("keys." + i))
            .toList());
  }

  private static IllegalArgumentException invalid(final JsonProcessingException e) {
    return new IllegalArgumentException(
        "Key bundle is not valid" + where(e) + ": " + e.getOriginalMessage(), e);
  }

  /** The field, as mapping runs on a tree and has no line to report; else the line and column. */
  private static String where(final JsonProcessingException e) {
    if (e instanceof JsonMappingException mapping && !mapping.getPath().isEmpty()) {
      return mapping.getPath().stream()
          .map(r -> r.getFieldName() != null ? r.getFieldName() : String.valueOf(r.getIndex()))
          .collect(Collectors.joining(".", " at `", "`"));
    }
    final JsonLocation location = e.getLocation();
    return location != null && location.getLineNr() > 0
        ? " at line " + location.getLineNr() + ", column " + location.getColumnNr()
        : "";
  }

  private static String hex(final byte[] bytes) {
    return Bytes.wrap(bytes).toHexString();
  }

  private static byte[] unhex(final String path, final String value) {
    try {
      return Bytes.fromHexString(value).toArray();
    } catch (final IllegalArgumentException e) {
      throw invalidAt(path, e);
    }
  }

  private static IllegalArgumentException invalidAt(
      final String path, final IllegalArgumentException e) {
    return new IllegalArgumentException(
        "Key bundle is not valid at `" + path + "`: " + e.getMessage(), e);
  }

  /** As {@link #fromJson}, with the file named in any error about its content. */
  public static KeyBundle read(final Path file) throws IOException {
    try {
      return fromJson(Files.readString(file));
    } catch (final CharacterCodingException e) {
      throw new IllegalArgumentException(file + ": Key bundle is not valid UTF-8", e);
    } catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException(file + ": " + e.getMessage(), e);
    }
  }

  /** Writes a new bundle file. Never replaces an existing one. */
  public static void write(final KeyBundle bundle, final Path file) throws IOException {
    // written and synced beside it first, so a crash never leaves a partial bundle in its place
    final Path temp = file.resolveSibling(file.getFileName() + ".tmp-" + UUID.randomUUID());
    // as a resource, so a failed delete is added to a write error rather than hiding it
    try (Closeable deleteTemp = () -> Files.deleteIfExists(temp)) {
      Files.writeString(
          temp, toJson(bundle), StandardOpenOption.CREATE_NEW, StandardOpenOption.SYNC);
      // a hard link refuses an existing file in one step, unlike move's check then rename
      Files.createLink(file, temp);
    } catch (final UnsupportedOperationException e) {
      throw new IOException(
          "Cannot write key bundle " + file + ": hard links are not supported", e);
    }
  }
}
