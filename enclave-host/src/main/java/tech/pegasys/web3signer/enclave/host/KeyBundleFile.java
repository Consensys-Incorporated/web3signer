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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.cfg.CoercionAction;
import com.fasterxml.jackson.databind.cfg.CoercionInputShape;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.type.LogicalType;
import org.apache.tuweni.bytes.Bytes;

/** The key bundle file: its JSON format, and reading and writing it on disk. */
public final class KeyBundleFile {
  /** Bundle file format version. */
  public static final int VERSION = 1;

  // as strict as the format: no duplicate or missing fields, no type coercion, nothing after it
  private static final ObjectMapper MAPPER =
      JsonMapper.builder()
          .enable(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY)
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .enable(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES)
          .enable(DeserializationFeature.FAIL_ON_NULL_CREATOR_PROPERTIES)
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .disable(DeserializationFeature.ACCEPT_FLOAT_AS_INT)
          .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
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

  private record FileJson(int version, KeyBundle.Dek dek, List<KeyJson> keys) {}

  private record KeyJson(String pubkey, String nonce, String ciphertext) {
    static KeyJson of(final SealedKey key) {
      return new KeyJson(hex(key.pubKey()), hex(key.nonce()), hex(key.ciphertext()));
    }

    /** {@link SealedKey} checks the sizes. */
    SealedKey toSealedKey() {
      return new SealedKey(unhex(pubkey), unhex(nonce), unhex(ciphertext));
    }
  }

  private KeyBundleFile() {}

  public static String toJson(final KeyBundle bundle) {
    try {
      return MAPPER.writeValueAsString(
          new FileJson(VERSION, bundle.dek(), bundle.keys().stream().map(KeyJson::of).toList()));
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
      file = MAPPER.treeToValue(MAPPER.readTree(json), FileJson.class);
    } catch (final ValueInstantiationException e) {
      // KeyBundle.Dek refused the values
      throw e.getCause() instanceof IllegalArgumentException cause ? cause : invalid(e);
    } catch (final IOException e) {
      throw invalid(e);
    }
    if (file == null) {
      throw new IllegalArgumentException("Key bundle is empty");
    }
    if (file.version() != VERSION) {
      throw new IllegalArgumentException("Unsupported key bundle version: " + file.version());
    }
    return new KeyBundle(file.dek(), file.keys().stream().map(KeyJson::toSealedKey).toList());
  }

  /** Keeps the first line: the rest is Jackson's location and internal class names. */
  private static IllegalArgumentException invalid(final IOException e) {
    return new IllegalArgumentException(
        "Key bundle is not valid: " + e.getMessage().lines().findFirst().orElse(""), e);
  }

  private static String hex(final byte[] bytes) {
    return Bytes.wrap(bytes).toHexString();
  }

  private static byte[] unhex(final String value) {
    return Bytes.fromHexString(value).toArray();
  }

  public static KeyBundle read(final Path file) throws IOException {
    return fromJson(Files.readString(file));
  }

  /** Writes a new bundle file. Never replaces one: it may be the only copy of the sealed keys. */
  public static void write(final KeyBundle bundle, final Path file) throws IOException {
    Files.writeString(file, toJson(bundle), StandardOpenOption.CREATE_NEW);
  }
}
