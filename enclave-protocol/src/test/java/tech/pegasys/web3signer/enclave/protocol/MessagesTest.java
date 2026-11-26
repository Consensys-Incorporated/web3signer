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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.web3signer.enclave.protocol.Frames.Frame;
import tech.pegasys.web3signer.enclave.protocol.Messages.Evidence;
import tech.pegasys.web3signer.enclave.protocol.Messages.KeyLoadCounts;
import tech.pegasys.web3signer.enclave.protocol.Messages.PublicKeysRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.SealedKey;
import tech.pegasys.web3signer.enclave.protocol.Messages.UnwrapDekRequest;
import tech.pegasys.web3signer.enclave.transport.Connection;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

class MessagesTest {
  private static final byte[] BOOT_ID = new byte[16];

  private static void putUint32(final byte[] body, final int at, final long value) {
    ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN).putInt(at, (int) value);
  }

  /** A connection that serves fixed bytes and records what is written to it. */
  private static final class BytesConnection implements Connection {
    private final byte[] data;
    private final ByteArrayOutputStream written = new ByteArrayOutputStream();
    private int position;

    BytesConnection(final byte[] data) {
      this.data = data;
    }

    @Override
    public int read(final byte[] buffer, final int offset, final int length) {
      if (position == data.length) {
        return -1;
      }
      final int n = Math.min(length, data.length - position);
      System.arraycopy(data, position, buffer, offset, n);
      position += n;
      return n;
    }

    @Override
    public void write(final byte[] buffer, final int offset, final int length) {
      written.write(buffer, offset, length);
    }

    @Override
    public void close() {}
  }

  private static byte[] frame(final int requestId, final int kind, final byte[] body)
      throws IOException {
    final BytesConnection connection = new BytesConnection(new byte[0]);
    Frames.write(connection, new Frame(requestId, kind, body));
    return connection.written.toByteArray();
  }

  private static Frame read(final byte[] bytes) throws IOException {
    return Frames.readResponse(new BytesConnection(bytes));
  }

  private static SealedKey sealedKey() {
    return new SealedKey(new byte[48], new byte[12], new byte[48]);
  }

  // ------------------------------------------------------------------ frames

  @Test
  void frameHeaderIsLittleEndianLengthRequestIdAndKind() throws IOException {
    final byte[] frame = frame(0x01020304, Protocol.SIGN, new byte[] {9, 8});
    assertThat(HexFormat.of().formatHex(frame)).isEqualTo("02000000" + "04030201" + "03" + "0908");
    final Frame read = read(frame);
    assertThat(read.requestId()).isEqualTo(0x01020304);
    assertThat(read.kind()).isEqualTo(Protocol.SIGN);
    assertThat(read.body()).containsExactly(9, 8);
  }

  @Test
  void aBodyOfExactlyTheLimitIsWrittenAndRead() throws IOException {
    final byte[] body = new byte[Protocol.MAX_BODY_SIZE];
    body[body.length - 1] = 7;
    assertThat(read(frame(1, Protocol.OK, body)).body()).isEqualTo(body);
  }

  @Test
  void aBodyAboveTheLimitIsRejectedBeforeItIsRead() {
    final byte[] header = new byte[Frames.HEADER_SIZE];
    putUint32(header, 0, Protocol.MAX_BODY_SIZE + 1L);
    assertThatThrownBy(() -> read(header))
        .isInstanceOf(IOException.class)
        .hasMessageContaining("out of range");
    putUint32(header, 0, 0xFFFF_FFFFL);
    assertThatThrownBy(() -> read(header)).isInstanceOf(IOException.class);
    assertThatThrownBy(() -> frame(1, Protocol.SIGN, new byte[Protocol.MAX_BODY_SIZE + 1]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private static final int[] OPCODES = {
    Protocol.STATUS,
    Protocol.GET_PUBLIC_KEYS,
    Protocol.SIGN,
    Protocol.GET_EVIDENCE,
    Protocol.UNWRAP_DEK,
    Protocol.LOAD_KEYS
  };

  @Test
  void requestLimitsAreTheLargestEncodedRequests() {
    assertThat(Messages.encodeStatusRequest())
        .hasSize(Protocol.maxRequestBodySize(Protocol.STATUS));
    assertThat(Messages.encodePublicKeysRequest(new PublicKeysRequest(0, 1)))
        .hasSize(Protocol.maxRequestBodySize(Protocol.GET_PUBLIC_KEYS));
    assertThat(
            Messages.encodeSignRequest(
                new Messages.SignRequest(
                    new byte[Protocol.PUBLIC_KEY_SIZE], new byte[Protocol.SIGNING_ROOT_SIZE])))
        .hasSize(Protocol.maxRequestBodySize(Protocol.SIGN));
    assertThat(Messages.encodeNonce(new byte[Protocol.MAX_NONCE_SIZE]))
        .hasSize(Protocol.maxRequestBodySize(Protocol.GET_EVIDENCE));
    assertThat(
            Messages.encodeUnwrapDekRequest(
                new UnwrapDekRequest(Protocol.BLOB_FORMAT_CMS, new byte[Protocol.MAX_BLOB_SIZE])))
        .hasSize(Protocol.maxRequestBodySize(Protocol.UNWRAP_DEK));
    assertThat(Messages.encodeSealedKeys(Collections.nCopies(Protocol.MAX_LOAD_KEYS, sealedKey())))
        .hasSize(Protocol.maxRequestBodySize(Protocol.LOAD_KEYS));
  }

  @Test
  void aRequestAtItsLimitIsReadAndOneByteOverIsRefusedBeforeItsBody() throws IOException {
    for (final int opcode : OPCODES) {
      final int max = Protocol.maxRequestBodySize(opcode);
      final byte[] body = new byte[max];
      assertThat(Frames.readRequest(new BytesConnection(frame(1, opcode, body))).body())
          .isEqualTo(body);

      final byte[] header = Arrays.copyOf(frame(1, opcode, new byte[0]), Frames.HEADER_SIZE);
      putUint32(header, 0, max + 1L);
      assertThatThrownBy(() -> Frames.readRequest(new BytesConnection(header)))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("out of range for " + Protocol.opcodeName(opcode));
    }
  }

  @Test
  void anUnknownOpcodesBodyIsDiscardedAndTheNextRequestIsRead() throws IOException {
    final byte[] unknown = frame(1, 0x7f, new byte[Protocol.MAX_BODY_SIZE]);
    final byte[] status = frame(2, Protocol.STATUS, new byte[0]);
    final byte[] stream = Arrays.copyOf(unknown, unknown.length + status.length);
    System.arraycopy(status, 0, stream, unknown.length, status.length);
    final BytesConnection connection = new BytesConnection(stream);

    final Frame first = Frames.readRequest(connection);
    assertThat(first.requestId()).isEqualTo(1);
    assertThat(first.kind()).isEqualTo(0x7f);
    assertThat(first.body()).isEmpty();
    final Frame second = Frames.readRequest(connection);
    assertThat(second.requestId()).isEqualTo(2);
    assertThat(second.kind()).isEqualTo(Protocol.STATUS);
  }

  @Test
  void resultCodesHaveNames() {
    assertThat(Protocol.resultName(Protocol.KEY_LIMIT_REACHED)).isEqualTo("KEY_LIMIT_REACHED");
    assertThat(Protocol.resultName(Protocol.EVIDENCE_FAILED)).isEqualTo("EVIDENCE_FAILED");
    assertThat(Protocol.resultName(200)).isEqualTo("RESULT_200");
  }

  @Test
  void aKindThatDoesNotFitAByteIsNotSent() {
    assertThatThrownBy(() -> frame(1, 256, new byte[0]))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("kind out of range");
    assertThatThrownBy(() -> frame(1, -1, new byte[0]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void aStreamThatEndsInsideAFrameIsAnError() throws IOException {
    final byte[] frame = frame(1, Protocol.OK, new byte[10]);
    assertThatThrownBy(() -> read(Arrays.copyOf(frame, Frames.HEADER_SIZE - 1)))
        .isInstanceOf(EOFException.class);
    assertThatThrownBy(() -> read(Arrays.copyOf(frame, frame.length - 1)))
        .isInstanceOf(EOFException.class);
  }

  // ------------------------------------------------------------------ SSZ offsets

  /** A valid two-field body: Evidence{type, release_key, evidence}; offsets at 1 and 5. */
  private static byte[] evidence() {
    return Messages.encodeEvidence(new Evidence(1, new byte[] {1, 2}, new byte[] {3, 4, 5}));
  }

  @Test
  void firstOffsetMustBeTheSizeOfTheFixedPart() {
    for (final long offset : new long[] {4, 10}) {
      final byte[] body = evidence();
      putUint32(body, 1, offset);
      assertThatThrownBy(() -> Messages.decodeEvidence(body)).hasMessageContaining("first offset");
    }
  }

  @Test
  void firstOffsetBeforeOrPastTheFixedPartIsMalformed() {
    // STATUS has 24 fixed bytes before its offset, so these gaps are whole multiples of 4
    for (final long offset : new long[] {0, 0xFFFF_FFF8L}) {
      final byte[] body = Messages.encodeStatus(0, 1, 0, BOOT_ID, "v1");
      putUint32(body, 24, offset);
      assertThatThrownBy(() -> Messages.decodeStatus(body))
          .isInstanceOf(IOException.class)
          .hasMessageContaining("first offset");
    }
  }

  @Test
  void offsetsMustNotDecrease() {
    final byte[] body = evidence();
    putUint32(body, 5, 8);
    assertThatThrownBy(() -> Messages.decodeEvidence(body)).hasMessageContaining("decrease");
  }

  @Test
  void offsetsMustNotPointPastTheEnd() {
    final byte[] body = evidence();
    putUint32(body, 5, body.length + 1);
    assertThatThrownBy(() -> Messages.decodeEvidence(body)).hasMessageContaining("past the end");
    putUint32(body, 5, 0xFFFF_FFFFL);
    assertThatThrownBy(() -> Messages.decodeEvidence(body)).hasMessageContaining("past the end");
  }

  @Test
  void bodyShorterThanTheFixedPartIsMalformed() {
    assertThatThrownBy(() -> Messages.decodeEvidence(new byte[4]))
        .hasMessageContaining("shorter than its fixed part");
    assertThatThrownBy(() -> Messages.decodeStatus(new byte[] {1, 0, 0, 0, 0, 0, 0}))
        .hasMessageContaining("shorter than its fixed part");
  }

  @Test
  void keyLoadCountsMustAccountForEveryEntry() throws IOException {
    final byte[] result = Messages.encodeKeyLoadCounts(new KeyLoadCounts(1, 2, 3));
    assertThat(Messages.decodeKeyLoadCounts(result, 6)).isEqualTo(new KeyLoadCounts(1, 2, 3));
    assertThatThrownBy(() -> Messages.decodeKeyLoadCounts(result, 7))
        .isInstanceOf(IOException.class)
        .hasMessage("Malformed LOAD_KEYS response: counts add up to 6, expected 7");
    assertThatThrownBy(() -> Messages.decodeKeyLoadCounts(result, 5))
        .hasMessageContaining("counts add up to 6, expected 5");
  }

  @Test
  void fixedSizeBodiesMustHaveExactlyTheirSize() throws IOException {
    final byte[] result = Messages.encodeKeyLoadCounts(new KeyLoadCounts(1, 2, 3));
    assertThatThrownBy(() -> Messages.decodeKeyLoadCounts(Arrays.copyOf(result, 13), 6))
        .hasMessageContaining("trailing bytes");
    assertThatThrownBy(() -> Messages.decodeKeyLoadCounts(Arrays.copyOf(result, 11), 6))
        .isInstanceOf(IOException.class);
    assertThatThrownBy(() -> Messages.decodeSignature(new byte[95]))
        .isInstanceOf(IOException.class);
    assertThatThrownBy(() -> Messages.decodeSignature(new byte[97]))
        .isInstanceOf(IOException.class);
    final byte[] page = Messages.encodePublicKeysRequest(new PublicKeysRequest(0, 1));
    assertThatThrownBy(() -> Messages.decodePublicKeysRequest(Arrays.copyOf(page, 9)))
        .hasMessageContaining("trailing bytes");
    assertThatThrownBy(() -> Messages.decodeStatusRequest(new byte[1]))
        .hasMessageContaining("not empty");
  }

  @Test
  void writerRejectsValuesOutsideTheirType() {
    assertThatThrownBy(
            () -> Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(256, new byte[1])))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("uint8 out of range");
    assertThatThrownBy(() -> Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(-1, new byte[1])))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Messages.encodeKeyLoadCounts(new KeyLoadCounts(-1, 0, 0)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("uint32 out of range");
    assertThatThrownBy(() -> Messages.encodeKeyLoadCounts(new KeyLoadCounts(1L << 32, 0, 0)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("uint32 out of range");
    assertThatThrownBy(() -> Messages.encodeSignature(new byte[95]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void fixedFieldsMustComeBeforeVariableOnes() {
    assertThatThrownBy(
            () -> Ssz.writeContainer().byteList(new byte[1], 10).vector(new byte[4], 4).toBytes())
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  void aBodyWithMoreOrFewerVariableFieldsThanTheMessageIsMalformed() {
    // UNWRAP_DEK has one byte list: two offsets claim two
    final byte[] two =
        Ssz.writeContainer().uint8(1).byteList(new byte[1], 10).byteList(new byte[1], 10).toBytes();
    assertThatThrownBy(() -> Messages.decodeUnwrapDekRequest(two))
        .hasMessageContaining("has 2 byte lists, expected 1");
    final byte[] one = Ssz.writeContainer().uint8(1).byteList(new byte[1], 10).toBytes();
    assertThatThrownBy(() -> Messages.decodeEvidence(one))
        .hasMessageContaining("has 1 byte lists, expected at least 2");
  }

  // ------------------------------------------------------------------ message limits

  @Test
  void publicKeysWhoseBytesAreNotWholeKeysAreMalformed() {
    final byte[] body = Messages.encodePublicKeys(List.of(new byte[48], new byte[48]));
    assertThatThrownBy(() -> Messages.decodePublicKeys(Arrays.copyOf(body, body.length - 1)))
        .hasMessageContaining("shorter than its fixed part");
  }

  @Test
  void publicKeysPageAboveTheLimitIsMalformed() {
    final byte[] body = new byte[(Protocol.MAX_PUBLIC_KEYS_PAGE + 1) * 48];
    assertThatThrownBy(() -> Messages.decodePublicKeys(body)).hasMessageContaining("longer than");
    final List<byte[]> keys = Collections.nCopies(Protocol.MAX_PUBLIC_KEYS_PAGE + 1, new byte[48]);
    assertThatThrownBy(() -> Messages.encodePublicKeys(keys))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void pageRequestLimitMustBeInRange() {
    for (final long limit : new long[] {0, Protocol.MAX_PUBLIC_KEYS_PAGE + 1L}) {
      final byte[] body = new byte[8];
      putUint32(body, 4, limit);
      assertThatThrownBy(() -> Messages.decodePublicKeysRequest(body))
          .hasMessageContaining("limit");
    }
    assertThatThrownBy(() -> Messages.encodePublicKeysRequest(new PublicKeysRequest(0, 0)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Messages.encodePublicKeysRequest(new PublicKeysRequest(1L << 32, 1)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void loadKeysTakesOneToMaxEntries() throws IOException {
    assertThatThrownBy(() -> Messages.encodeSealedKeys(List.of()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                Messages.encodeSealedKeys(
                    Collections.nCopies(Protocol.MAX_LOAD_KEYS + 1, sealedKey())))
        .isInstanceOf(IllegalArgumentException.class);

    final byte[] max =
        Messages.encodeSealedKeys(Collections.nCopies(Protocol.MAX_LOAD_KEYS, sealedKey()));
    assertThat(Messages.decodeSealedKeys(max)).hasSize(Protocol.MAX_LOAD_KEYS);

    assertThatThrownBy(() -> Messages.decodeSealedKeys(new byte[0]))
        .hasMessageContaining("no entries");

    final byte[] tooMany = Arrays.copyOf(max, max.length + Protocol.SEALED_KEY_SIZE);
    assertThatThrownBy(() -> Messages.decodeSealedKeys(tooMany))
        .hasMessageContaining("longer than");

    final byte[] partial = Arrays.copyOf(max, max.length - 1);
    assertThatThrownBy(() -> Messages.decodeSealedKeys(partial))
        .hasMessageContaining("shorter than its fixed part");
  }

  @Test
  void nonceRespectsItsLimit() throws IOException {
    final byte[] nonce = new byte[Protocol.MAX_NONCE_SIZE];
    assertThat(Messages.decodeNonce(Messages.encodeNonce(nonce))).isEqualTo(nonce);
    assertThatThrownBy(() -> Messages.encodeNonce(new byte[Protocol.MAX_NONCE_SIZE + 1]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Messages.decodeNonce(new byte[Protocol.MAX_NONCE_SIZE + 1]))
        .hasMessageContaining("longer than 64");
  }

  @Test
  void releaseKeyAndEvidenceRespectTheirLimits() throws IOException {
    final byte[] releaseKey = new byte[Protocol.MAX_RELEASE_KEY_SIZE];
    final byte[] evidence = new byte[Protocol.MAX_EVIDENCE_SIZE];
    final Evidence decoded =
        Messages.decodeEvidence(Messages.encodeEvidence(new Evidence(1, releaseKey, evidence)));
    assertThat(decoded.releaseKey()).hasSize(Protocol.MAX_RELEASE_KEY_SIZE);
    assertThat(decoded.evidence()).hasSize(Protocol.MAX_EVIDENCE_SIZE);

    final byte[] longKey = new byte[Protocol.MAX_RELEASE_KEY_SIZE + 1];
    final byte[] longEvidence = new byte[Protocol.MAX_EVIDENCE_SIZE + 1];
    assertThatThrownBy(() -> Messages.encodeEvidence(new Evidence(1, longKey, evidence)))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Messages.encodeEvidence(new Evidence(1, releaseKey, longEvidence)))
        .isInstanceOf(IllegalArgumentException.class);

    final int unlimited = Protocol.MAX_BODY_SIZE;
    final byte[] withLongKey =
        Ssz.writeContainer()
            .uint8(1)
            .byteList(longKey, unlimited)
            .byteList(evidence, unlimited)
            .toBytes();
    assertThatThrownBy(() -> Messages.decodeEvidence(withLongKey))
        .hasMessageContaining("longer than " + Protocol.MAX_RELEASE_KEY_SIZE);
    final byte[] withLongEvidence =
        Ssz.writeContainer()
            .uint8(1)
            .byteList(releaseKey, unlimited)
            .byteList(longEvidence, unlimited)
            .toBytes();
    assertThatThrownBy(() -> Messages.decodeEvidence(withLongEvidence))
        .hasMessageContaining("longer than " + Protocol.MAX_EVIDENCE_SIZE);
  }

  @Test
  void blobRespectsItsLimit() throws IOException {
    final byte[] blob = new byte[Protocol.MAX_BLOB_SIZE];
    assertThat(
            Messages.decodeUnwrapDekRequest(
                    Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(1, blob)))
                .blob())
        .hasSize(Protocol.MAX_BLOB_SIZE);
    final byte[] longBlob = new byte[Protocol.MAX_BLOB_SIZE + 1];
    assertThatThrownBy(() -> Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(1, longBlob)))
        .isInstanceOf(IllegalArgumentException.class);
    final byte[] body =
        Ssz.writeContainer().uint8(1).byteList(longBlob, Protocol.MAX_BODY_SIZE).toBytes();
    assertThatThrownBy(() -> Messages.decodeUnwrapDekRequest(body))
        .hasMessageContaining("longer than " + Protocol.MAX_BLOB_SIZE);
  }

  @Test
  void versionRespectsItsLimit() throws IOException {
    final byte[] status = Messages.encodeStatus(0, 1, 0, BOOT_ID, "v".repeat(300));
    assertThat(Messages.decodeStatus(status).version()).hasSize(Protocol.MAX_VERSION_SIZE);
    final byte[] longVersion =
        Ssz.writeContainer()
            .uint8(Protocol.VERSION)
            .uint8(0)
            .uint16(1)
            .uint32(0)
            .vector(BOOT_ID, 16)
            .byteList(new byte[Protocol.MAX_VERSION_SIZE + 1], 1000)
            .toBytes();
    assertThatThrownBy(() -> Messages.decodeStatus(longVersion))
        .hasMessageContaining("longer than " + Protocol.MAX_VERSION_SIZE);
  }

  @Test
  void errorMessageRespectsItsLimit() {
    assertThat(Messages.encodeErrorMessage("x".repeat(300))).hasSize(256);
    assertThatThrownBy(() -> Messages.decodeErrorMessage(new byte[257]))
        .isInstanceOf(IOException.class);
  }

  // ------------------------------------------------------------------ text and versions

  @Test
  void textFromThePeerIsPrintableAscii() throws IOException {
    final byte[] status = Messages.encodeStatus(0, 1, 0, BOOT_ID, "v1\nfake-log-line\u00e9");
    assertThat(Messages.decodeStatus(status).version()).isEqualTo("v1?fake-log-line?");

    final byte[] raw = Messages.encodeStatus(0, 1, 0, BOOT_ID, "ab");
    raw[raw.length - 1] = (byte) 0xC3;
    assertThat(Messages.decodeStatus(raw).version()).isEqualTo("a?");

    assertThat(Messages.decodeErrorMessage(new byte[] {'o', 'k', 0x1b, '['})).isEqualTo("ok?[");
  }

  @Test
  void anotherProtocolVersionIsReportedBeforeTheRestOfTheStatusIsRead() {
    // a v2 STATUS may have another layout: only the version must be readable
    final byte[] body = new byte[] {2};
    assertThatThrownBy(() -> Messages.decodeStatus(body))
        .isInstanceOfSatisfying(
            UnsupportedProtocolVersionException.class, e -> assertThat(e.version()).isEqualTo(2));
  }
}
