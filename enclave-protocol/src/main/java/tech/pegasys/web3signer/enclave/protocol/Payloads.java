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
package tech.pegasys.web3signer.enclave.protocol;

import static tech.pegasys.web3signer.enclave.protocol.Frames.getInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getUnsignedInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.getUnsignedShort;
import static tech.pegasys.web3signer.enclave.protocol.Frames.putInt;
import static tech.pegasys.web3signer.enclave.protocol.Frames.putShort;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.BOOT_ID_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_LOAD_KEYS;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_MESSAGE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_NONCE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.MAX_PUBLIC_KEYS_PAGE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.OK;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.PUBLIC_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SEALED_CIPHERTEXT_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SEALED_KEY_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SEALED_NONCE_SIZE;
import static tech.pegasys.web3signer.enclave.protocol.Protocol.SIGNATURE_SIZE;

import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/** Payload layouts of the protocol operations: requests and responses. */
public final class Payloads {
  private Payloads() {}

  /** One page of {@code GET_PUBLIC_KEYS}. */
  public record PublicKeysPage(long total, List<byte[]> publicKeys) {}

  // ------------------------------------------------------------------ requests

  public static byte[] statusRequest() {
    return new byte[0];
  }

  public static byte[] getPublicKeysRequest(final int offset, final int limit) {
    if (offset < 0 || limit < 1 || limit > MAX_PUBLIC_KEYS_PAGE) {
      throw new IllegalArgumentException("Invalid page: offset " + offset + ", limit " + limit);
    }
    final byte[] payload = new byte[8];
    putInt(payload, 0, offset);
    putInt(payload, 4, limit);
    return payload;
  }

  /** Size of a {@code SIGN} request payload for a message of {@code messageSize} bytes. */
  public static int signRequestSize(final int messageSize) {
    return PUBLIC_KEY_SIZE + 2 + messageSize;
  }

  /** Writes a {@code SIGN} request payload at {@code offset}. */
  public static void putSignRequest(
      final byte[] buffer, final int offset, final byte[] publicKey, final byte[] message) {
    checkSign(publicKey, message);
    System.arraycopy(publicKey, 0, buffer, offset, PUBLIC_KEY_SIZE);
    putShort(buffer, offset + PUBLIC_KEY_SIZE, message.length);
    System.arraycopy(message, 0, buffer, offset + PUBLIC_KEY_SIZE + 2, message.length);
  }

  public static byte[] signRequest(final byte[] publicKey, final byte[] message) {
    checkSign(publicKey, message);
    final byte[] payload = new byte[signRequestSize(message.length)];
    putSignRequest(payload, 0, publicKey, message);
    return payload;
  }

  static void checkSign(final byte[] publicKey, final byte[] message) {
    if (publicKey.length != PUBLIC_KEY_SIZE) {
      throw new IllegalArgumentException("Public key must be 48 bytes");
    }
    if (message.length > MAX_MESSAGE_SIZE) {
      throw new IllegalArgumentException("Message longer than " + MAX_MESSAGE_SIZE + " bytes");
    }
  }

  public static byte[] attestRequest(final byte[] nonce) {
    if (nonce.length > MAX_NONCE_SIZE) {
      throw new IllegalArgumentException("Nonce longer than " + MAX_NONCE_SIZE + " bytes");
    }
    final byte[] payload = new byte[1 + nonce.length];
    payload[0] = (byte) nonce.length;
    System.arraycopy(nonce, 0, payload, 1, nonce.length);
    return payload;
  }

  public static byte[] unwrapDekRequest(final int format, final byte[] blob) {
    if (blob.length > Protocol.MAX_PAYLOAD_SIZE - 5) {
      throw new IllegalArgumentException("Release blob too large");
    }
    final byte[] payload = new byte[5 + blob.length];
    payload[0] = (byte) format;
    putInt(payload, 1, blob.length);
    System.arraycopy(blob, 0, payload, 5, blob.length);
    return payload;
  }

  public static byte[] loadKeysRequest(final List<SealedKey> keys) {
    if (keys.isEmpty() || keys.size() > MAX_LOAD_KEYS) {
      throw new IllegalArgumentException("LOAD_KEYS takes 1 to " + MAX_LOAD_KEYS + " entries");
    }
    final byte[] payload = new byte[4 + keys.size() * SEALED_KEY_SIZE];
    putInt(payload, 0, keys.size());
    int at = 4;
    for (final SealedKey key : keys) {
      System.arraycopy(key.publicKey(), 0, payload, at, PUBLIC_KEY_SIZE);
      System.arraycopy(key.nonce(), 0, payload, at + PUBLIC_KEY_SIZE, SEALED_NONCE_SIZE);
      System.arraycopy(
          key.ciphertext(),
          0,
          payload,
          at + PUBLIC_KEY_SIZE + SEALED_NONCE_SIZE,
          SEALED_CIPHERTEXT_SIZE);
      at += SEALED_KEY_SIZE;
    }
    return payload;
  }

  // ------------------------------------------------------------------ responses, encoding

  /** A response payload with a status other than OK: the status byte and nothing else. */
  public static byte[] errorResponse(final int status) {
    return new byte[] {(byte) status};
  }

  public static byte[] statusResponse(
      final int platform,
      final int cpus,
      final long keyCount,
      final byte[] bootId,
      final String version) {
    final byte[] versionBytes = truncatedUtf8(version, 255);
    final byte[] payload = new byte[1 + 2 + 1 + 2 + 4 + BOOT_ID_SIZE + 1 + versionBytes.length];
    payload[0] = OK;
    putShort(payload, 1, Protocol.VERSION);
    payload[3] = (byte) platform;
    putShort(payload, 4, Math.min(cpus, 0xffff));
    putInt(payload, 6, (int) keyCount);
    System.arraycopy(bootId, 0, payload, 10, BOOT_ID_SIZE);
    payload[26] = (byte) versionBytes.length;
    System.arraycopy(versionBytes, 0, payload, 27, versionBytes.length);
    return payload;
  }

  private static byte[] truncatedUtf8(final String value, final int maxBytes) {
    String s = value;
    byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
    while (bytes.length > maxBytes) {
      s = s.substring(0, s.length() - 1);
      bytes = s.getBytes(StandardCharsets.UTF_8);
    }
    return bytes;
  }

  public static byte[] attestResponse(final byte[] document) {
    final byte[] payload = new byte[5 + document.length];
    payload[0] = OK;
    putInt(payload, 1, document.length);
    System.arraycopy(document, 0, payload, 5, document.length);
    return payload;
  }

  public static byte[] unwrapDekResponse() {
    return new byte[] {OK};
  }

  public static byte[] loadKeysResponse(final LoadResult result) {
    final byte[] payload = new byte[13];
    payload[0] = OK;
    putInt(payload, 1, (int) result.loaded());
    putInt(payload, 5, (int) result.duplicates());
    putInt(payload, 9, (int) result.rejected());
    return payload;
  }

  // ------------------------------------------------------------------ responses, decoding

  /**
   * Checks the type and status of a response.
   *
   * @throws EnclaveUnavailableException when the type does not answer {@code opcode}
   * @throws EnclaveException when the status is not OK
   */
  public static void requireOk(final Frame response, final int opcode) {
    if (response.type() != (opcode | Protocol.RESPONSE_FLAG)) {
      throw new EnclaveUnavailableException(
          "Unexpected response type 0x" + Integer.toHexString(response.type()));
    }
    final int status = response.status();
    if (status != OK) {
      throw new EnclaveException(status, "Enclave signer refused opcode 0x" + hex(opcode));
    }
  }

  public static EnclaveStatus decodeStatus(final byte[] payload) {
    require(payload.length >= 27, "STATUS");
    final int versionLength = payload[26] & 0xff;
    require(payload.length == 27 + versionLength, "STATUS");
    return new EnclaveStatus(
        getUnsignedShort(payload, 1),
        payload[3] & 0xff,
        getUnsignedShort(payload, 4),
        getUnsignedInt(payload, 6),
        HexFormat.of().formatHex(payload, 10, 10 + BOOT_ID_SIZE),
        printable(new String(payload, 27, versionLength, StandardCharsets.UTF_8)));
  }

  /** The version comes from the peer and ends up in logs: control characters become '?'. */
  private static String printable(final String value) {
    return value.replaceAll("[\\r\\n\\p{Cntrl}]", "?");
  }

  public static PublicKeysPage decodePublicKeys(final byte[] payload) {
    require(payload.length >= 9, "GET_PUBLIC_KEYS");
    final long total = getUnsignedInt(payload, 1);
    final int count = getInt(payload, 5);
    require(
        count >= 0
            && count <= MAX_PUBLIC_KEYS_PAGE
            && payload.length == 9 + count * PUBLIC_KEY_SIZE,
        "GET_PUBLIC_KEYS");
    final List<byte[]> keys = new ArrayList<>(count);
    for (int i = 0; i < count; i++) {
      final int at = 9 + i * PUBLIC_KEY_SIZE;
      keys.add(Arrays.copyOfRange(payload, at, at + PUBLIC_KEY_SIZE));
    }
    return new PublicKeysPage(total, keys);
  }

  public static byte[] decodeSignature(final byte[] payload) {
    require(payload.length == 1 + SIGNATURE_SIZE, "SIGN");
    return Arrays.copyOfRange(payload, 1, 1 + SIGNATURE_SIZE);
  }

  public static byte[] decodeAttestation(final byte[] payload) {
    require(payload.length >= 5, "ATTEST");
    final long length = getUnsignedInt(payload, 1);
    require(payload.length == 5 + length, "ATTEST");
    return Arrays.copyOfRange(payload, 5, payload.length);
  }

  public static void decodeUnwrapDek(final byte[] payload) {
    require(payload.length == 1, "UNWRAP_DEK");
  }

  public static LoadResult decodeLoadKeys(final byte[] payload) {
    require(payload.length == 13, "LOAD_KEYS");
    return new LoadResult(
        getUnsignedInt(payload, 1), getUnsignedInt(payload, 5), getUnsignedInt(payload, 9));
  }

  private static void require(final boolean condition, final String operation) {
    if (!condition) {
      throw new EnclaveUnavailableException("Malformed " + operation + " response");
    }
  }

  private static String hex(final int value) {
    return Integer.toHexString(value);
  }
}
