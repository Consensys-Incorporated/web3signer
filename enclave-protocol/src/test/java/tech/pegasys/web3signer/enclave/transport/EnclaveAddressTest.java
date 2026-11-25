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
package tech.pegasys.web3signer.enclave.transport;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import tech.pegasys.web3signer.enclave.transport.EnclaveAddress.TcpAddress;
import tech.pegasys.web3signer.enclave.transport.EnclaveAddress.VsockAddress;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class EnclaveAddressTest {

  @Test
  void parsesConnectForms() {
    assertThat(EnclaveAddress.parseConnect("vsock:16:5000")).isEqualTo(new VsockAddress(16, 5000));
    assertThat(EnclaveAddress.parseConnect("vsock:3:4294967295"))
        .isEqualTo(new VsockAddress(3, 0xFFFF_FFFFL));
    assertThat(EnclaveAddress.parseConnect("vsock:4294967294:1"))
        .isEqualTo(new VsockAddress(0xFFFF_FFFEL, 1));
    assertThat(EnclaveAddress.parseConnect("tcp:127.0.0.1:5000"))
        .isEqualTo(new TcpAddress("127.0.0.1", 5000));
    assertThat(EnclaveAddress.parseConnect("tcp:enclave.local:1"))
        .isEqualTo(new TcpAddress("enclave.local", 1));
    assertThat(EnclaveAddress.parseConnect("tcp:[::1]:5000"))
        .isEqualTo(new TcpAddress("::1", 5000));
  }

  @Test
  void parsesListenForms() {
    assertThat(EnclaveAddress.parseListen("vsock:5000"))
        .isEqualTo(new VsockAddress(EnclaveAddress.VMADDR_CID_ANY, 5000));
    assertThat(EnclaveAddress.parseListen("vsock:4294967294"))
        .isEqualTo(new VsockAddress(EnclaveAddress.VMADDR_CID_ANY, 0xFFFF_FFFEL));
    assertThat(EnclaveAddress.parseListen("tcp:0.0.0.0:5000"))
        .isEqualTo(new TcpAddress("0.0.0.0", 5000));
    assertThat(EnclaveAddress.parseListen("tcp:127.0.0.1:0"))
        .isEqualTo(new TcpAddress("127.0.0.1", 0));
  }

  @Test
  void formatsBackToTheSameString() {
    for (final String value : new String[] {"vsock:16:5000", "tcp:127.0.0.1:5000", "tcp:[::1]:9"}) {
      assertThat(EnclaveAddress.parseConnect(value)).hasToString(value);
    }
    assertThat(EnclaveAddress.parseListen("vsock:5000")).hasToString("vsock:5000");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "vsock:",
        "vsock:16",
        "vsock:0:5000",
        "vsock:1:5000",
        "vsock:2:5000",
        "vsock:4294967295:5000",
        "vsock:16:",
        "vsock::5000",
        "vsock:x:5000",
        "vsock:-1:5000",
        "vsock:16:5000:1",
        "vsock:4294967296:5000",
        "tcp:",
        "tcp:host",
        "tcp::5000",
        "tcp:host:",
        "tcp:host:0",
        "tcp:host:65536",
        "tcp:host:+1",
        "tcp:host:\u0665\u0660\u0660\u0660",
        "vsock:16:\uff15\uff10\uff10\uff10",
        "udp:host:5000",
        "16:5000"
      })
  void rejectsInvalidConnectForms(final String value) {
    assertThatThrownBy(() -> EnclaveAddress.parseConnect(value))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "vsock:",
        "vsock:16:5000",
        "vsock:x",
        "vsock:4294967295",
        "tcp:5000",
        "tcp::5000",
        "tcp:h:70000"
      })
  void rejectsInvalidListenForms(final String value) {
    assertThatThrownBy(() -> EnclaveAddress.parseListen(value))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void rejectsNull() {
    assertThatThrownBy(() -> EnclaveAddress.parseConnect(null))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
