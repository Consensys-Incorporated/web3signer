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
package tech.pegasys.web3signer.enclave.signer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The few CBOR shapes the Nitro Security Module interface needs: map headers, text strings, byte
 * strings and null. Encodes the attestation request and decodes its response.
 */
final class NsmCbor {
  private static final int MAJOR_BYTES = 0x40;
  private static final int MAJOR_TEXT = 0x60;
  private static final int MAJOR_MAP = 0xa0;
  private static final int NULL = 0xf6;

  private NsmCbor() {}

  /** The NSM answered with an error, or the response is not in the expected form. */
  static final class NsmException extends Exception {
    private static final long serialVersionUID = 1L;

    NsmException(final String message) {
      super(message);
    }
  }

  /**
   * {@code {"Attestation": {"user_data": u, "nonce": n, "public_key": k}}}, keys in that order; a
   * null argument is encoded as CBOR null.
   */
  static byte[] attestationRequest(
      final byte[] userData, final byte[] nonce, final byte[] publicKey) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(MAJOR_MAP | 1);
    text(out, "Attestation");
    out.write(MAJOR_MAP | 3);
    text(out, "user_data");
    bytesOrNull(out, userData);
    text(out, "nonce");
    bytesOrNull(out, nonce);
    text(out, "public_key");
    bytesOrNull(out, publicKey);
    return out.toByteArray();
  }

  private static void text(final ByteArrayOutputStream out, final String value) {
    final byte[] bytes = value.getBytes(StandardCharsets.US_ASCII);
    header(out, MAJOR_TEXT, bytes.length);
    out.writeBytes(bytes);
  }

  private static void bytesOrNull(final ByteArrayOutputStream out, final byte[] value) {
    if (value == null) {
      out.write(NULL);
      return;
    }
    header(out, MAJOR_BYTES, value.length);
    out.writeBytes(value);
  }

  private static void header(final ByteArrayOutputStream out, final int major, final int length) {
    if (length < 24) {
      out.write(major | length);
    } else if (length < 0x100) {
      out.write(major | 24);
      out.write(length);
    } else if (length < 0x10000) {
      out.write(major | 25);
      out.write(length >>> 8);
      out.write(length);
    } else {
      out.write(major | 26);
      out.write(length >>> 24);
      out.write(length >>> 16);
      out.write(length >>> 8);
      out.write(length);
    }
  }

  /**
   * Returns the document of {@code {"Attestation": {"document": <bytes>}}}. Throws with the error
   * name for {@code {"Error": <text>}}.
   */
  static byte[] attestationDocument(final byte[] response) throws NsmException {
    final Reader reader = new Reader(response);
    if (reader.mapSize() != 1) {
      throw new NsmException("unexpected NSM response");
    }
    final String kind = reader.text();
    if (kind.equals("Error")) {
      throw new NsmException("NSM error " + reader.text());
    }
    if (!kind.equals("Attestation") || reader.mapSize() != 1 || !reader.text().equals("document")) {
      throw new NsmException("unexpected NSM response");
    }
    final byte[] document = reader.bytes();
    if (reader.position != response.length) {
      throw new NsmException("unexpected NSM response");
    }
    return document;
  }

  private static final class Reader {
    private final byte[] data;
    private int position;

    Reader(final byte[] data) {
      this.data = data;
    }

    private int next() throws NsmException {
      if (position >= data.length) {
        throw new NsmException("truncated NSM response");
      }
      return data[position++] & 0xff;
    }

    /** Reads a header of the given major type and returns its length argument. */
    private int length(final int major) throws NsmException {
      final int head = next();
      if ((head & 0xe0) != major) {
        throw new NsmException("unexpected NSM response");
      }
      final int info = head & 0x1f;
      if (info < 24) {
        return info;
      }
      final int size =
          switch (info) {
            case 24 -> 1;
            case 25 -> 2;
            case 26 -> 4;
            default -> throw new NsmException("unsupported CBOR length in NSM response");
          };
      long value = 0;
      for (int i = 0; i < size; i++) {
        value = (value << 8) | next();
      }
      if (value > data.length - position) {
        throw new NsmException("truncated NSM response");
      }
      return (int) value;
    }

    int mapSize() throws NsmException {
      final int head = next();
      if ((head & 0xe0) != MAJOR_MAP || (head & 0x1f) >= 24) {
        throw new NsmException("unexpected NSM response");
      }
      return head & 0x1f;
    }

    String text() throws NsmException {
      final int length = length(MAJOR_TEXT);
      final String value = new String(data, position, length, StandardCharsets.UTF_8);
      position += length;
      return value;
    }

    byte[] bytes() throws NsmException {
      final int length = length(MAJOR_BYTES);
      final byte[] value = Arrays.copyOfRange(data, position, position + length);
      position += length;
      return value;
    }
  }
}
