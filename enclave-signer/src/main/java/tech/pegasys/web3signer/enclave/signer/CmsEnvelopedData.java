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
import java.util.Arrays;

/**
 * The fields of a CMS EnvelopedData as AWS KMS returns it for a recipient: one
 * KeyTransRecipientInfo with RSAES-OAEP and AES-256-CBC content. A JDK-only BER reader.
 *
 * <p>Reader rules: definite and indefinite lengths at every level, indefinite only on constructed
 * tags; no tag number above 30, no length-of-length above 4, no nesting deeper than 8, no element
 * running past its parent, no bytes after the ContentInfo.
 */
final class CmsEnvelopedData {
  private static final int MAX_DEPTH = 8;
  private static final int SEQUENCE = 0x30;
  private static final int SET = 0x31;
  private static final int INTEGER = 0x02;
  private static final int OCTET_STRING = 0x04;
  private static final int OID = 0x06;
  private static final int CONTEXT_0_CONSTRUCTED = 0xa0;
  private static final int CONTEXT_0_PRIMITIVE = 0x80;

  private static final byte[] OID_ENVELOPED_DATA = hex("2a864886f70d010703");
  private static final byte[] OID_DATA = hex("2a864886f70d010701");
  private static final byte[] OID_RSAES_OAEP = hex("2a864886f70d010107");
  private static final byte[] OID_AES256_CBC = hex("60864801650304012a");

  private final byte[] encryptedKey;
  private final byte[] iv;
  private final byte[] encryptedContent;

  private CmsEnvelopedData(
      final byte[] encryptedKey, final byte[] iv, final byte[] encryptedContent) {
    this.encryptedKey = encryptedKey;
    this.iv = iv;
    this.encryptedContent = encryptedContent;
  }

  byte[] encryptedKey() {
    return encryptedKey;
  }

  byte[] iv() {
    return iv;
  }

  byte[] encryptedContent() {
    return encryptedContent;
  }

  /** The envelope does not have the expected structure. */
  static final class FormatException extends Exception {
    private static final long serialVersionUID = 1L;

    FormatException(final String message) {
      super(message);
    }
  }

  /** One BER element: tag, content range and the offset after it. */
  private record Node(int tag, int start, int end, int next) {}

  static CmsEnvelopedData parse(final byte[] b) throws FormatException {
    final Node contentInfo = expect(b, 0, b.length, 0, SEQUENCE);
    if (contentInfo.next != b.length) {
      throw new FormatException("bytes after ContentInfo");
    }
    final Node contentType = expect(b, contentInfo.start, contentInfo.end, 1, OID);
    expectOid(b, contentType, OID_ENVELOPED_DATA);
    final Node explicit = expect(b, contentType.next, contentInfo.end, 1, CONTEXT_0_CONSTRUCTED);
    final Node envelopedData = expect(b, explicit.start, explicit.end, 2, SEQUENCE);

    final Node version = expect(b, envelopedData.start, envelopedData.end, 3, INTEGER);
    Node recipientInfos = read(b, version.next, envelopedData.end, 3);
    if (recipientInfos.tag == CONTEXT_0_CONSTRUCTED) { // originatorInfo, skipped
      recipientInfos = read(b, recipientInfos.next, envelopedData.end, 3);
    }
    if (recipientInfos.tag != SET) {
      throw new FormatException("recipientInfos");
    }
    final Node recipient = expect(b, recipientInfos.start, recipientInfos.end, 4, SEQUENCE);
    if (recipient.next != recipientInfos.end) {
      throw new FormatException("exactly one recipient expected");
    }
    final Node recipientVersion = expect(b, recipient.start, recipient.end, 5, INTEGER);
    final Node rid = read(b, recipientVersion.next, recipient.end, 5);
    final Node keyAlgorithm = expect(b, rid.next, recipient.end, 5, SEQUENCE);
    expectOid(b, expect(b, keyAlgorithm.start, keyAlgorithm.end, 6, OID), OID_RSAES_OAEP);
    final Node encryptedKey = expect(b, keyAlgorithm.next, recipient.end, 5, OCTET_STRING);

    final Node contentInfoNode = expect(b, recipientInfos.next, envelopedData.end, 3, SEQUENCE);
    final Node dataType = expect(b, contentInfoNode.start, contentInfoNode.end, 4, OID);
    expectOid(b, dataType, OID_DATA);
    final Node algorithm = expect(b, dataType.next, contentInfoNode.end, 4, SEQUENCE);
    final Node algorithmOid = expect(b, algorithm.start, algorithm.end, 5, OID);
    expectOid(b, algorithmOid, OID_AES256_CBC);
    final Node iv = expect(b, algorithmOid.next, algorithm.end, 5, OCTET_STRING);
    if (iv.end - iv.start != 16) {
      throw new FormatException("iv must be 16 bytes");
    }

    final Node content = read(b, algorithm.next, contentInfoNode.end, 4);
    final ByteArrayOutputStream ciphertext = new ByteArrayOutputStream();
    if (content.tag == CONTEXT_0_PRIMITIVE) {
      ciphertext.write(b, content.start, content.end - content.start);
    } else if (content.tag == CONTEXT_0_CONSTRUCTED) {
      for (int at = content.start; at < content.end; ) {
        final Node chunk = expect(b, at, content.end, 5, OCTET_STRING);
        ciphertext.write(b, chunk.start, chunk.end - chunk.start);
        at = chunk.next;
      }
    } else {
      throw new FormatException("encryptedContent");
    }
    return new CmsEnvelopedData(
        Arrays.copyOfRange(b, encryptedKey.start, encryptedKey.end),
        Arrays.copyOfRange(b, iv.start, iv.end),
        ciphertext.toByteArray());
  }

  private static Node read(final byte[] b, final int at, final int limit, final int depth)
      throws FormatException {
    if (depth > MAX_DEPTH) {
      throw new FormatException("nesting too deep");
    }
    if (at < 0 || limit > b.length || at + 2 > limit) {
      throw new FormatException("truncated");
    }
    final int tag = b[at] & 0xff;
    if ((tag & 0x1f) == 0x1f) {
      throw new FormatException("tag number above 30");
    }
    final int first = b[at + 1] & 0xff;
    int position = at + 2;
    if (first == 0x80) {
      if ((tag & 0x20) == 0) {
        throw new FormatException("indefinite length on a primitive");
      }
      int child = position;
      while (true) {
        if (child + 2 > limit) {
          throw new FormatException("missing end-of-contents");
        }
        if (b[child] == 0 && b[child + 1] == 0) {
          break;
        }
        child = read(b, child, limit, depth + 1).next;
      }
      return new Node(tag, position, child, child + 2);
    }
    final int length;
    if (first < 0x80) {
      length = first;
    } else {
      final int count = first & 0x7f;
      if (count > 4 || position + count > limit) {
        throw new FormatException("length");
      }
      long value = 0;
      for (int i = 0; i < count; i++) {
        value = (value << 8) | (b[position++] & 0xff);
      }
      if (value > Integer.MAX_VALUE) {
        throw new FormatException("length");
      }
      length = (int) value;
    }
    if (length > limit - position) {
      throw new FormatException("element runs past its parent");
    }
    return new Node(tag, position, position + length, position + length);
  }

  private static Node expect(
      final byte[] b, final int at, final int limit, final int depth, final int tag)
      throws FormatException {
    final Node node = read(b, at, limit, depth);
    if (node.tag != tag) {
      throw new FormatException("unexpected tag");
    }
    return node;
  }

  private static void expectOid(final byte[] b, final Node node, final byte[] oid)
      throws FormatException {
    if (!Arrays.equals(b, node.start, node.end, oid, 0, oid.length)) {
      throw new FormatException("unexpected object identifier");
    }
  }

  private static byte[] hex(final String value) {
    return java.util.HexFormat.of().parseHex(value);
  }
}
