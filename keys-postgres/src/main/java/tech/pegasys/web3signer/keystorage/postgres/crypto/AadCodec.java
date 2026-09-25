/*
 * Copyright 2026 Consensys Software Inc.
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
package tech.pegasys.web3signer.keystorage.postgres.crypto;

import java.io.ByteArrayOutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/**
 * Builds the Additional Authenticated Data (AAD) that every AES-GCM ciphertext in the postgres
 * keystore is bound to, so a ciphertext copied or moved between rows fails decryption instead of
 * silently succeeding under the wrong identity.
 *
 * <p>Encoding is length-prefixed fields (4-byte big-endian length + UTF-8 bytes), never
 * delimited/concatenated strings, so that e.g. tenant="A", key="BC" cannot collide with
 * tenant="AB", key="C". This encoding is a contract shared with the provisioning/write side - see
 * designs/postgres-bulk-key-loading.md.
 */
public final class AadCodec {

  private AadCodec() {}

  public static byte[] forRow(
      final String tenantId, final String keyIdentifier, final int dekVersion) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeLengthPrefixed(out, tenantId);
    writeLengthPrefixed(out, keyIdentifier);
    writeInt(out, dekVersion);
    return out.toByteArray();
  }

  public static byte[] forTenant(final String tenantId, final int dekVersion) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    writeLengthPrefixed(out, tenantId);
    writeInt(out, dekVersion);
    return out.toByteArray();
  }

  private static void writeLengthPrefixed(final ByteArrayOutputStream out, final String value) {
    final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
    writeInt(out, bytes.length);
    out.writeBytes(bytes);
  }

  private static void writeInt(final ByteArrayOutputStream out, final int value) {
    try {
      out.write(
          new byte[] {
            (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value
          });
    } catch (final java.io.IOException e) {
      // ByteArrayOutputStream never throws IOException on write
      throw new UncheckedIOException(e);
    }
  }
}
