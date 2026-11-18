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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HexFormat;

import org.junit.jupiter.api.Test;

class NsmCborTest {
  private static final HexFormat HEX = HexFormat.of();

  @Test
  void encodesTheAwsTestRequest() {
    assertThat(
            HEX.formatHex(
                NsmCbor.attestationRequest(HEX.parseHex("0909"), null, HEX.parseHex("07"))))
        .isEqualTo(
            "a16b4174746573746174696f6ea369757365725f64617461420909656e6f6e6365f66a7075626c69635f6b65794107");
  }

  @Test
  void encodesTheRequestThisSignerSends() {
    assertThat(
            HEX.formatHex(
                NsmCbor.attestationRequest(null, HEX.parseHex("0102"), HEX.parseHex("07"))))
        .isEqualTo(
            "a16b4174746573746174696f6ea369757365725f64617461f6656e6f6e63654201026a7075626c69635f6b65794107");
  }

  @Test
  void encodesLongByteStrings() {
    final byte[] request = NsmCbor.attestationRequest(null, new byte[32], new byte[294]);
    // a 294-byte SPKI takes the two-byte length form: 0x59 0x01 0x26
    assertThat(HEX.formatHex(request)).contains("5820" + "00".repeat(32)).contains("590126");
    assertThat(request.length).isLessThan(0x1000);
  }

  @Test
  void decodesTheDocument() throws Exception {
    assertThat(
            NsmCbor.attestationDocument(
                HEX.parseHex("a16b4174746573746174696f6ea168646f63756d656e7442d284")))
        .isEqualTo(HEX.parseHex("d284"));
    final byte[] large = new byte[4790];
    final byte[] response =
        HEX.parseHex(
            "a16b4174746573746174696f6ea168646f63756d656e74" + "5912b6" + "00".repeat(4790));
    assertThat(NsmCbor.attestationDocument(response)).isEqualTo(large);
  }

  @Test
  void reportsTheErrorName() {
    assertThatThrownBy(
            () ->
                NsmCbor.attestationDocument(
                    HEX.parseHex("a1654572726f726c496e76616c6964496e646578")))
        .isInstanceOf(NsmCbor.NsmException.class)
        .hasMessage("NSM error InvalidIndex");
  }

  @Test
  void refusesMalformedResponses() {
    for (final String hex :
        new String[] {
          "",
          "a0",
          "a16b4174746573746174696f6ea168646f63756d656e7442d2",
          "a16b4174746573746174696f6ea168646f63756d656e7442d28400",
          "a16b4174746573746174696f6ea168646f63756d656e745bffffffffffffffff"
        }) {
      assertThatThrownBy(() -> NsmCbor.attestationDocument(HEX.parseHex(hex)))
          .isInstanceOf(NsmCbor.NsmException.class);
    }
  }
}
