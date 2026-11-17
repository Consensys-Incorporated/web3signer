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
import tech.pegasys.web3signer.enclave.protocol.Frames.FrameLengthException;

import java.io.IOException;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

import org.junit.jupiter.api.Test;

class FramesTest {
  private static final HexFormat HEX = HexFormat.of();

  private static byte[] filled(final int size, final int value) {
    final byte[] bytes = new byte[size];
    Arrays.fill(bytes, (byte) value);
    return bytes;
  }

  /** A connection that serves fixed bytes. */
  private static Connection bytes(final byte[] data) {
    return new Connection() {
      private int position;

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
      public void write(final byte[] buffer, final int offset, final int length) {}

      @Override
      public void close() {}
    };
  }

  @Test
  void frameHeaderLayout() throws IOException {
    final byte[] frame = Frames.encode(Protocol.STATUS, 0x01020304, new byte[0]);
    assertThat(HEX.formatHex(frame)).isEqualTo("00000005" + "01" + "01020304");
    final Frame decoded = Frames.read(bytes(frame));
    assertThat(decoded.type()).isEqualTo(Protocol.STATUS);
    assertThat(decoded.requestId()).isEqualTo(0x01020304);
    assertThat(decoded.payload()).isEmpty();
  }

  @Test
  void signFramesAre91And106Bytes() throws IOException {
    final byte[] publicKey = filled(48, 0xaa);
    final byte[] root = filled(32, 0xbb);
    final byte[] request = Frames.encode(Protocol.SIGN, 7, Payloads.signRequest(publicKey, root));
    assertThat(request).hasSize(91);
    assertThat(HEX.formatHex(request))
        .isEqualTo("00000057" + "03" + "00000007" + "aa".repeat(48) + "0020" + "bb".repeat(32));

    final byte[] payload = new byte[97];
    System.arraycopy(filled(96, 0xcc), 0, payload, 1, 96);
    final byte[] response = Frames.encode(Protocol.SIGN | 0x80, 7, payload);
    assertThat(response).hasSize(106);
    final Frame decoded = Frames.read(bytes(response));
    assertThat(decoded.type()).isEqualTo(0x83);
    Payloads.requireOk(decoded, Protocol.SIGN);
    assertThat(Payloads.decodeSignature(decoded.payload())).isEqualTo(filled(96, 0xcc));
  }

  @Test
  void statusLayout() {
    assertThat(Payloads.statusRequest()).isEmpty();
    final byte[] bootId = filled(16, 0x11);
    final byte[] payload =
        Payloads.statusResponse(Protocol.PLATFORM_AWS_NITRO, 2, 10_000, bootId, "1.0");
    assertThat(HEX.formatHex(payload))
        .isEqualTo("00" + "0001" + "01" + "0002" + "00002710" + "11".repeat(16) + "03" + "312e30");
    final EnclaveStatus status = Payloads.decodeStatus(payload);
    assertThat(status).isEqualTo(new EnclaveStatus(1, 1, 2, 10_000, "11".repeat(16), "1.0"));
    assertThat(status.platformName()).isEqualTo("aws-nitro");
  }

  @Test
  void peerVersionIsReducedToPrintableAscii() {
    final byte[] payload =
        Payloads.statusResponse(1, 2, 0, new byte[16], "1.0\r\nINFO forged line\u0007é");
    assertThat(Payloads.decodeStatus(payload).version()).isEqualTo("1.0??INFO forged line???");
  }

  @Test
  void getPublicKeysLayout() {
    assertThat(HEX.formatHex(Payloads.getPublicKeysRequest(5, 16384)))
        .isEqualTo("00000005" + "00004000");
    final byte[] payload =
        HEX.parseHex("00" + "00000003" + "00000002" + "01".repeat(48) + "02".repeat(48));
    final Payloads.PublicKeysPage page = Payloads.decodePublicKeys(payload);
    assertThat(page.total()).isEqualTo(3);
    assertThat(page.publicKeys()).containsExactly(filled(48, 1), filled(48, 2));
    assertThatThrownBy(() -> Payloads.getPublicKeysRequest(0, 16385))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Payloads.getPublicKeysRequest(0, 0))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void signAcceptsEmptyAndLongMessages() {
    assertThat(HEX.formatHex(Payloads.signRequest(filled(48, 1), new byte[0])))
        .isEqualTo("01".repeat(48) + "0000");
    assertThat(Payloads.signRequest(filled(48, 1), new byte[65535])).hasSize(48 + 2 + 65535);
    assertThatThrownBy(() -> Payloads.signRequest(filled(48, 1), new byte[65536]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> Payloads.signRequest(filled(47, 1), new byte[32]))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void attestLayout() {
    assertThat(HEX.formatHex(Payloads.attestRequest(HEX.parseHex("0102")))).isEqualTo("020102");
    assertThat(Payloads.attestRequest(new byte[0])).containsExactly(0);
    assertThatThrownBy(() -> Payloads.attestRequest(new byte[65]))
        .isInstanceOf(IllegalArgumentException.class);
    final byte[] response = Payloads.attestResponse(HEX.parseHex("d284"));
    assertThat(HEX.formatHex(response)).isEqualTo("00" + "00000002" + "d284");
    assertThat(Payloads.decodeAttestation(response)).isEqualTo(HEX.parseHex("d284"));
  }

  @Test
  void unwrapDekLayout() {
    assertThat(HEX.formatHex(Payloads.unwrapDekRequest(1, HEX.parseHex("308006"))))
        .isEqualTo("01" + "00000003" + "308006");
    assertThat(Payloads.unwrapDekResponse()).containsExactly(0);
  }

  @Test
  void loadKeysLayout() {
    final SealedKey key = new SealedKey(filled(48, 1), filled(12, 2), filled(48, 3));
    final byte[] request = Payloads.loadKeysRequest(List.of(key, key));
    assertThat(request).hasSize(4 + 2 * 108);
    assertThat(HEX.formatHex(request, 0, 4 + 108))
        .isEqualTo("00000002" + "01".repeat(48) + "02".repeat(12) + "03".repeat(48));
    final byte[] response = Payloads.loadKeysResponse(new LoadResult(1, 2, 3));
    assertThat(HEX.formatHex(response)).isEqualTo("00" + "00000001" + "00000002" + "00000003");
    assertThat(Payloads.decodeLoadKeys(response)).isEqualTo(new LoadResult(1, 2, 3));
    assertThatThrownBy(() -> Payloads.loadKeysRequest(List.of()))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void errorResponseCarriesOnlyTheStatus() throws IOException {
    final byte[] frame = Frames.encode(0x83, 9, Payloads.errorResponse(Protocol.UNKNOWN_KEY));
    assertThat(frame).hasSize(10);
    final Frame decoded = Frames.read(bytes(frame));
    assertThatThrownBy(() -> Payloads.requireOk(decoded, Protocol.SIGN))
        .isInstanceOfSatisfying(
            EnclaveException.class, e -> assertThat(e.status()).isEqualTo(Protocol.UNKNOWN_KEY));
    assertThatThrownBy(() -> Payloads.requireOk(decoded, Protocol.STATUS))
        .isInstanceOf(EnclaveUnavailableException.class);
  }

  @Test
  void lengthOutsideTheRangeIsRefused() {
    assertThatThrownBy(() -> Frames.read(bytes(HEX.parseHex("00000004" + "01000000"))))
        .isInstanceOf(FrameLengthException.class);
    assertThatThrownBy(() -> Frames.read(bytes(HEX.parseHex("00100001"))))
        .isInstanceOf(FrameLengthException.class);
    assertThatThrownBy(() -> Frames.read(bytes(HEX.parseHex("ffffffff"))))
        .isInstanceOf(FrameLengthException.class);
    assertThat(Frames.isValidLength(5)).isTrue();
    assertThat(Frames.isValidLength(1_048_576)).isTrue();
    assertThatThrownBy(() -> Frames.encode(Protocol.SIGN, 1, new byte[1_048_572]))
        .isInstanceOf(IllegalArgumentException.class);
    assertThat(Frames.encode(Protocol.SIGN, 1, new byte[1_048_571])).hasSize(4 + 1_048_576);
  }
}
