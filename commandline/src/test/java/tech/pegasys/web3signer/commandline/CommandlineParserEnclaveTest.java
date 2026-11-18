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

import tech.pegasys.web3signer.commandline.CommandlineParserTest.MockEth2SubCommand;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CommandlineParserEnclaveTest {
  private final StringWriter commandOutput = new StringWriter();
  private final StringWriter commandError = new StringWriter();
  private CommandlineParser parser;

  @BeforeEach
  void setup() {
    parser =
        new CommandlineParser(
            new MockWeb3SignerBaseCommand(),
            new PrintWriter(commandOutput, true),
            new PrintWriter(commandError, true),
            Collections.emptyMap());
    parser.registerSubCommands(new MockEth2SubCommand());
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
