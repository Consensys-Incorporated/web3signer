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
import tech.pegasys.web3signer.enclave.protocol.Messages.LoadResult;
import tech.pegasys.web3signer.enclave.protocol.Messages.PageRequest;
import tech.pegasys.web3signer.enclave.protocol.Messages.PublicKeysPage;
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

  private static void putUint64(final byte[] body, final int at, final long value) {
    ByteBuffer.wrap(body).order(ByteOrder.LITTLE_ENDIAN).putLong(at, value);
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
    return Frames.read(new BytesConnection(bytes));
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
  void offsetsMustNotDecrease() {
    final byte[] body = evidence();
    putUint32(body, 5, 8);
    assertThatThrownBy(() -> Messages.decodeEvidence(body)).hasMessageContaining("decreasing");
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
    assertThatThrownBy(() -> Messages.decodeStatus(new byte[7]))
        .hasMessageContaining("shorter than its fixed part");
  }

  @Test
  void fixedSizeBodiesMustHaveExactlyTheirSize() throws IOException {
    final byte[] result = Messages.encodeLoadResult(new LoadResult(1, 2, 3));
    assertThatThrownBy(() -> Messages.decodeLoadResult(Arrays.copyOf(result, 25)))
        .hasMessageContaining("trailing bytes");
    assertThatThrownBy(() -> Messages.decodeLoadResult(Arrays.copyOf(result, 23)))
        .isInstanceOf(IOException.class);
    assertThatThrownBy(() -> Messages.decodeSignature(new byte[95]))
        .isInstanceOf(IOException.class);
    assertThatThrownBy(() -> Messages.decodeSignature(new byte[97]))
        .isInstanceOf(IOException.class);
    final byte[] page = Messages.encodePageRequest(new PageRequest(0, 1));
    assertThatThrownBy(() -> Messages.decodePageRequest(Arrays.copyOf(page, 17)))
        .hasMessageContaining("trailing bytes");
    assertThatThrownBy(() -> Messages.decodeStatusRequest(new byte[1]))
        .hasMessageContaining("not empty");
  }

  @Test
  void uint64AboveLongMaxIsMalformed() {
    final byte[] result = Messages.encodeLoadResult(new LoadResult(1, 2, 3));
    putUint64(result, 0, -1L);
    assertThatThrownBy(() -> Messages.decodeLoadResult(result)).hasMessageContaining("2^63");
  }

  @Test
  void writerRejectsValuesOutsideTheirType() {
    assertThatThrownBy(
            () -> Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(256, new byte[1])))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("uint8 out of range");
    assertThatThrownBy(() -> Messages.encodeUnwrapDekRequest(new UnwrapDekRequest(-1, new byte[1])))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Messages.encodeLoadResult(new LoadResult(-1, 0, 0)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("uint64 out of range");
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
    // GET_EVIDENCE's nonce is the only field: two offsets claim two
    final byte[] two =
        Ssz.writeContainer().byteList(new byte[1], 10).byteList(new byte[1], 10).toBytes();
    assertThatThrownBy(() -> Messages.decodeEvidenceRequest(two))
        .hasMessageContaining("has 2 variable fields, expected 1");
    final byte[] one = Ssz.writeContainer().uint8(1).byteList(new byte[1], 10).toBytes();
    assertThatThrownBy(() -> Messages.decodeEvidence(one))
        .hasMessageContaining("has 1 variable fields, expected at least 2");
  }

  // ------------------------------------------------------------------ message limits

  @Test
  void publicKeysWhoseBytesAreNotWholeKeysAreMalformed() {
    final byte[] body =
        Messages.encodePublicKeys(new PublicKeysPage(2, List.of(new byte[48], new byte[48])));
    assertThatThrownBy(() -> Messages.decodePublicKeys(Arrays.copyOf(body, body.length - 1)))
        .hasMessageContaining("shorter than its fixed part");
  }

  @Test
  void publicKeysPageAboveTheLimitIsMalformed() {
    final byte[] body = new byte[12 + (Protocol.MAX_PUBLIC_KEYS_PAGE + 1) * 48];
    putUint32(body, 8, 12);
    assertThatThrownBy(() -> Messages.decodePublicKeys(body)).hasMessageContaining("longer than");
    final List<byte[]> keys = Collections.nCopies(Protocol.MAX_PUBLIC_KEYS_PAGE + 1, new byte[48]);
    assertThatThrownBy(() -> Messages.encodePublicKeys(new PublicKeysPage(0, keys)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void pageRequestLimitMustBeInRange() {
    for (final long limit : new long[] {0, Protocol.MAX_PUBLIC_KEYS_PAGE + 1L}) {
      final byte[] body = new byte[16];
      putUint64(body, 8, limit);
      assertThatThrownBy(() -> Messages.decodePageRequest(body)).hasMessageContaining("limit");
    }
    assertThatThrownBy(() -> Messages.encodePageRequest(new PageRequest(0, 0)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void loadKeysTakesOneToMaxEntries() throws IOException {
    assertThatThrownBy(() -> Messages.encodeLoadKeysRequest(List.of()))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                Messages.encodeLoadKeysRequest(
                    Collections.nCopies(Protocol.MAX_LOAD_KEYS + 1, sealedKey())))
        .isInstanceOf(IllegalArgumentException.class);

    final byte[] max =
        Messages.encodeLoadKeysRequest(Collections.nCopies(Protocol.MAX_LOAD_KEYS, sealedKey()));
    assertThat(Messages.decodeLoadKeysRequest(max)).hasSize(Protocol.MAX_LOAD_KEYS);

    final byte[] empty = new byte[4];
    putUint32(empty, 0, 4);
    assertThatThrownBy(() -> Messages.decodeLoadKeysRequest(empty))
        .hasMessageContaining("no entries");

    final byte[] tooMany = Arrays.copyOf(max, max.length + Protocol.SEALED_KEY_SIZE);
    assertThatThrownBy(() -> Messages.decodeLoadKeysRequest(tooMany))
        .hasMessageContaining("longer than");

    final byte[] partial = Arrays.copyOf(max, max.length - 1);
    assertThatThrownBy(() -> Messages.decodeLoadKeysRequest(partial))
        .hasMessageContaining("shorter than its fixed part");
  }

  @Test
  void nonceRespectsItsLimit() throws IOException {
    final byte[] nonce = new byte[Protocol.MAX_NONCE_SIZE];
    assertThat(Messages.decodeEvidenceRequest(Messages.encodeEvidenceRequest(nonce)))
        .isEqualTo(nonce);
    assertThatThrownBy(() -> Messages.encodeEvidenceRequest(new byte[Protocol.MAX_NONCE_SIZE + 1]))
        .isInstanceOf(IllegalArgumentException.class);
    final byte[] tooLong = Ssz.writeContainer().byteList(new byte[65], 100).toBytes();
    assertThatThrownBy(() -> Messages.decodeEvidenceRequest(tooLong))
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
            .uint64(Protocol.VERSION)
            .uint8(0)
            .uint64(1)
            .uint64(0)
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
    final byte[] body = new byte[9];
    putUint64(body, 0, 2);
    assertThatThrownBy(() -> Messages.decodeStatus(body))
        .isInstanceOfSatisfying(
            UnsupportedProtocolVersionException.class, e -> assertThat(e.version()).isEqualTo(2));
  }
}
