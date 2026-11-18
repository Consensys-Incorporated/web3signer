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
package tech.pegasys.web3signer.commandline;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.pegasys.web3signer.CmdlineHelpers.validBaseCommandOptions;

import tech.pegasys.web3signer.commandline.CommandlineParserTest.MockEth2SubCommand;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CommandlineParserEnclaveTest {
  private final StringWriter commandOutput = new StringWriter();
  private final StringWriter commandError = new StringWriter();
  private CommandlineParser parser;
  private MockEth2SubCommand eth2;

  @BeforeEach
  void setup() {
    parser =
        new CommandlineParser(
            new MockWeb3SignerBaseCommand(),
            new PrintWriter(commandOutput, true),
            new PrintWriter(commandError, true),
            Collections.emptyMap());
    eth2 = new MockEth2SubCommand();
    parser.registerSubCommands(eth2);
  }

  private int parse(final String eth2Options) {
    return parser.parseCommandLine(
        (validBaseCommandOptions() + "eth2 --slashing-protection-enabled=false " + eth2Options)
            .trim()
            .split(" "));
  }

  @Test
  void enclaveSignerIsDisabledByDefault() {
    assertThat(parse("")).isZero();
    assertThat(eth2.getEnclaveSignerParameters().isEnabled()).isFalse();
  }

  @Test
  void validOptionsAreParsed() {
    assertThat(
            parse(
                "--Xenclave-signer-enabled=true --Xenclave-signer-address=vsock:16:5000"
                    + " --Xenclave-signer-connections=2"
                    + " --Xenclave-signer-request-timeout-ms=500"))
        .isZero();
    final var parameters = eth2.getEnclaveSignerParameters();
    assertThat(parameters.isEnabled()).isTrue();
    assertThat(parameters.getAddress()).isEqualTo("vsock:16:5000");
    assertThat(parameters.getConnections()).isEqualTo(2);
    assertThat(parameters.getRequestTimeoutMillis()).isEqualTo(500);
  }

  @Test
  void defaultsApplyWhenOnlyTheAddressIsGiven() {
    assertThat(parse("--Xenclave-signer-enabled=true --Xenclave-signer-address=tcp:127.0.0.1:5000"))
        .isZero();
    final var parameters = eth2.getEnclaveSignerParameters();
    assertThat(parameters.getConnections()).isEqualTo(32);
    assertThat(parameters.getRequestTimeoutMillis()).isEqualTo(2000);
  }

  @Test
  void enabledWithoutAnAddressIsAnError() {
    assertThat(parse("--Xenclave-signer-enabled=true")).isNotZero();
    assertThat(commandError.toString())
        .contains("--Xenclave-signer-enabled=true requires --Xenclave-signer-address");
  }

  @ParameterizedTest
  @ValueSource(strings = {"vsock:16", "vsock:4294967295:5000", "tcp:host", "udp:host:1", "16:5000"})
  void anAddressThatDoesNotParseIsAnError(final String address) {
    assertThat(parse("--Xenclave-signer-enabled=true --Xenclave-signer-address=" + address))
        .isNotZero();
    assertThat(commandError.toString()).contains("Invalid enclave address");
  }

  @Test
  void fewerThanOneConnectionIsAnError() {
    assertThat(
            parse(
                "--Xenclave-signer-enabled=true --Xenclave-signer-address=vsock:16:5000"
                    + " --Xenclave-signer-connections=0"))
        .isNotZero();
    assertThat(commandError.toString())
        .contains("--Xenclave-signer-connections must be at least 1");
  }

  @Test
  void optionsAreHiddenFromHelpAndListedByXhelp() {
    parser.parseCommandLine("eth2", "--help");
    assertThat(commandOutput.toString()).doesNotContain("--Xenclave-signer");
    parser.parseCommandLine("eth2", "Xhelp");
    assertThat(commandOutput.toString())
        .contains("--Xenclave-signer-enabled")
        .contains("--Xenclave-signer-address")
        .contains("--Xenclave-signer-connections")
        .contains("--Xenclave-signer-request-timeout-ms");
  }

  @Test
  void sealForTheDevPlatformNeedsAMasterKey() {
    final int result =
        parser.parseCommandLine(
            "enclave", "seal", "--platform=dev", "--raw-keys-file=keys.txt", "--output=out.json");
    assertThat(result).isNotZero();
    assertThat(commandError.toString()).contains("--dev-master-key-file is required");
  }

  @Test
  void statusFailsWhenNothingListens() {
    final int result = parser.parseCommandLine("enclave", "status", "--address=tcp:127.0.0.1:1");
    assertThat(result).isEqualTo(1);
    assertThat(commandError.toString()).contains("Error:");
  }
}
