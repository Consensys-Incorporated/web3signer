/*
 * Copyright 2020 ConsenSys AG.
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
import static tech.pegasys.web3signer.signing.config.KeystoresParameters.KEYSTORES_PASSWORDS_PATH;
import static tech.pegasys.web3signer.signing.config.KeystoresParameters.KEYSTORES_PASSWORD_FILE;
import static tech.pegasys.web3signer.signing.config.KeystoresParameters.KEYSTORES_PATH;

import tech.pegasys.web3signer.commandline.subcommands.Eth1SubCommand;
import tech.pegasys.web3signer.core.Runner;
import tech.pegasys.web3signer.core.config.TrustStoreOptions;
import tech.pegasys.web3signer.signing.config.KeystoresParameters;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class CommandlineParserEth1Test {
  private StringWriter commandOutput;
  private StringWriter commandError;
  private PrintWriter outputWriter;
  private PrintWriter errorWriter;
  private Web3SignerBaseCommand web3SignerBaseCommand;
  private Eth1SubCommand eth1SubCommand;
  private CommandlineParser parser;

  @BeforeEach
  void setup() {
    commandOutput = new StringWriter();
    commandError = new StringWriter();
    outputWriter = new PrintWriter(commandOutput, true);
    errorWriter = new PrintWriter(commandError, true);
    web3SignerBaseCommand = new MockWeb3SignerBaseCommand();
    eth1SubCommand = new MockEth1SubCommand();
    parser =
        new CommandlineParser(
            web3SignerBaseCommand, outputWriter, errorWriter, Collections.emptyMap());
    parser.registerSubCommands(eth1SubCommand);
  }

  @Test
  void v3KeystoreParametersAreParsedWithPasswordDir(
      @TempDir Path v3KeystorePath, @TempDir Path passwordDir) {
    List<String> params =
        List.of(
            KEYSTORES_PATH,
            v3KeystorePath.toString(),
            KEYSTORES_PASSWORDS_PATH,
            passwordDir.toString());

    String cmdline = validBaseCommandOptions();
    cmdline = cmdline + " eth1 --chain-id 1337 " + String.join(" ", params);
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));
    final KeystoresParameters keystoresParams = eth1SubCommand.getV3KeystoresBulkLoadParameters();

    assertThat(retCode).isZero();
    assertThat(keystoresParams.isEnabled()).isTrue();
    assertThat(keystoresParams.getKeystoresPasswordsPath()).isEqualTo(passwordDir);
    assertThat(keystoresParams.getKeystoresPasswordFile()).isNull();
  }

  @Test
  void v3KeystoreParametersAreParsedWithPasswordFile(
      @TempDir Path v3KeystorePath, @TempDir Path passwordDir) throws IOException {
    final Path passwordFile = passwordDir.resolve("pass.txt");
    Files.writeString(passwordFile, "test123");

    List<String> params =
        List.of(
            KEYSTORES_PATH,
            v3KeystorePath.toString(),
            KEYSTORES_PASSWORD_FILE,
            passwordFile.toString());

    final String cmdline =
        validBaseCommandOptions() + " eth1 --chain-id 1337 " + String.join(" ", params);
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));
    final KeystoresParameters keystoresParams = eth1SubCommand.getV3KeystoresBulkLoadParameters();

    assertThat(retCode).isZero();
    assertThat(keystoresParams.isEnabled()).isTrue();
    assertThat(keystoresParams.getKeystoresPasswordsPath()).isNull();
    assertThat(keystoresParams.getKeystoresPasswordFile()).isEqualTo(passwordFile);
  }

  @Test
  void v3KeystoreParametersAreNotEnabledWhenNotSpecified() {
    final String cmdline = validBaseCommandOptions() + " eth1 --chain-id 1337";
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));
    final KeystoresParameters keystoresParams = eth1SubCommand.getV3KeystoresBulkLoadParameters();

    assertThat(retCode).isZero();
    assertThat(keystoresParams.isEnabled()).isFalse();
    assertThat(keystoresParams.getKeystoresPasswordsPath()).isNull();
    assertThat(keystoresParams.getKeystoresPasswordFile()).isNull();
  }

  @Test
  void v3KeystoreParametersMissingPasswordOrDirCausesParsingError(@TempDir Path v3KeystorePath) {
    final List<String> params = List.of(KEYSTORES_PATH, v3KeystorePath.toString());
    final String cmdline =
        validBaseCommandOptions() + " eth1 --chain-id 1337 " + String.join(" ", params);
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));
    System.err.println(commandError);

    assertThat(retCode).isNotZero();
    final String expectedError =
        String.format(
            "Error parsing parameters: Either %s or %s must be specified",
            KEYSTORES_PASSWORD_FILE, KEYSTORES_PASSWORDS_PATH);
    assertThat(commandError.toString()).contains(expectedError);
  }

  @Test
  void v3KeystoreParametersBothPasswordOrDirCausesParsingError(
      @TempDir Path v3KeystorePath, @TempDir Path passwordDir) throws IOException {
    final Path passwordFile = passwordDir.resolve("pass.txt");
    Files.writeString(passwordFile, "test123");

    final List<String> params =
        List.of(
            KEYSTORES_PATH,
            v3KeystorePath.toString(),
            KEYSTORES_PASSWORD_FILE,
            passwordFile.toString(),
            KEYSTORES_PASSWORDS_PATH,
            passwordDir.toString());

    final String cmdline =
        validBaseCommandOptions() + " eth1 --chain-id 1337 " + String.join(" ", params);
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));

    assertThat(retCode).isNotZero();
    final String expectedError =
        String.format(
            "Error parsing parameters: Either %s or %s must be specified",
            KEYSTORES_PASSWORD_FILE, KEYSTORES_PASSWORDS_PATH);
    assertThat(commandError.toString()).contains(expectedError);
  }

  @Test
  void downstreamTrustStoreIsParsed() {
    final String cmdline =
        validBaseCommandOptions()
            + " eth1 --chain-id 1337 --downstream-http-tls-enabled"
            + " --downstream-http-tls-truststore-file=./truststore.p12"
            + " --downstream-http-tls-truststore-password-file=./truststore.pass";
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));

    assertThat(retCode).isZero();
    assertThat(eth1SubCommand.getClientTlsOptions().orElseThrow().getTrustStoreOptions())
        .contains(
            new TrustStoreOptions(
                Path.of("./truststore.p12"), Optional.of(Path.of("./truststore.pass"))));
  }

  @Test
  void downstreamTrustStoreWithoutPasswordFileIsParsed() {
    final String cmdline =
        validBaseCommandOptions()
            + " eth1 --chain-id 1337 --downstream-http-tls-enabled"
            + " --downstream-http-tls-truststore-file=./truststore.pem";
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));

    assertThat(retCode).isZero();
    assertThat(eth1SubCommand.getClientTlsOptions().orElseThrow().getTrustStoreOptions())
        .contains(new TrustStoreOptions(Path.of("./truststore.pem"), Optional.empty()));
  }

  @Test
  void downstreamTrustStorePasswordFileWithoutTrustStoreCausesParsingError() {
    final String cmdline =
        validBaseCommandOptions()
            + " eth1 --chain-id 1337 --downstream-http-tls-enabled"
            + " --downstream-http-tls-truststore-password-file=./truststore.pass";
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));

    assertThat(retCode).isNotZero();
    assertThat(commandError.toString())
        .contains(
            "Error parsing parameters: --downstream-http-tls-truststore-password-file requires --downstream-http-tls-truststore-file");
  }

  @ParameterizedTest
  @CsvSource(
      delimiter = '|',
      value = {
        "--downstream-http-tls-known-servers-file=./known_servers|--downstream-http-tls-truststore-file cannot be specified together with the deprecated --downstream-http-tls-known-servers-file",
        "--downstream-http-tls-ca-auth-enabled=false|--downstream-http-tls-ca-auth-enabled cannot be specified together with --downstream-http-tls-truststore-file",
        "--downstream-http-tls-ca-auth-enabled=true|--downstream-http-tls-ca-auth-enabled cannot be specified together with --downstream-http-tls-truststore-file"
      })
  void downstreamTrustStoreWithDeprecatedTrustOptionCausesParsingError(
      final String deprecatedOption, final String expectedError) {
    final String cmdline =
        validBaseCommandOptions()
            + " eth1 --chain-id 1337 --downstream-http-tls-enabled"
            + " --downstream-http-tls-truststore-file=./truststore.p12"
            + " --downstream-http-tls-truststore-password-file=./truststore.pass "
            + deprecatedOption;
    final int retCode = parser.parseCommandLine(cmdline.split("\\s+"));

    assertThat(retCode).isNotZero();
    assertThat(commandError.toString()).contains("Error parsing parameters: " + expectedError);
  }

  public static class MockEth1SubCommand extends Eth1SubCommand {
    @Override
    public Runner createRunner() {
      return new CommandlineParserTest.NoOpRunner(config);
    }
  }
}
