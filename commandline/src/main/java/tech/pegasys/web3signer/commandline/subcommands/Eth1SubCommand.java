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
package tech.pegasys.web3signer.commandline.subcommands;

import static tech.pegasys.web3signer.commandline.DefaultCommandValues.HOST_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.LONG_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.PATH_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.PORT_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.util.RequiredOptionsUtil.checkIfRequiredOptionsAreInitialized;
import static tech.pegasys.web3signer.signing.config.KeystoresParameters.KEYSTORES_PASSWORDS_PATH;
import static tech.pegasys.web3signer.signing.config.KeystoresParameters.KEYSTORES_PASSWORD_FILE;

import tech.pegasys.web3signer.commandline.PicoCliAwsKmsParameters;
import tech.pegasys.web3signer.commandline.PicoCliAzureKeyVaultParameters;
import tech.pegasys.web3signer.commandline.VersionProvider;
import tech.pegasys.web3signer.commandline.annotations.RequiredOption;
import tech.pegasys.web3signer.commandline.config.PicoV3KeystoresBulkloadParameters;
import tech.pegasys.web3signer.commandline.config.client.PicoCliClientTlsOptions;
import tech.pegasys.web3signer.core.Eth1Runner;
import tech.pegasys.web3signer.core.Runner;
import tech.pegasys.web3signer.core.config.Eth1Config;
import tech.pegasys.web3signer.core.config.client.ClientTlsOptions;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ChainIdProvider;
import tech.pegasys.web3signer.core.service.jsonrpc.handlers.signing.ConfigurationChainId;
import tech.pegasys.web3signer.signing.config.AwsVaultParameters;
import tech.pegasys.web3signer.signing.config.AzureKeyVaultParameters;
import tech.pegasys.web3signer.signing.config.KeystoresParameters;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.util.Optional;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;

@Command(
    name = Eth1SubCommand.COMMAND_NAME,
    description = "Handle Ethereum-1 SECP256k1 signing operations and public key reporting",
    subcommands = {HelpCommand.class, XHelpSubCommand.class},
    versionProvider = VersionProvider.class,
    mixinStandardHelpOptions = true,
    footer = "Unstable options are omitted from this help. Run 'web3signer eth1 -X' to list them.")
public class Eth1SubCommand extends ModeSubCommand implements Eth1Config {

  public static final String COMMAND_NAME = "eth1";

  @CommandLine.Spec private CommandLine.Model.CommandSpec spec; // injected by picocli

  @SuppressWarnings("FieldMayBeFinal")
  @RequiredOption
  @CommandLine.Option(
      names = {"--chain-id"},
      description = "The Chain Id that will be the intended recipient for signed transactions",
      paramLabel = LONG_FORMAT_HELP,
      arity = "1")
  private Long chainId;

  @SuppressWarnings("FieldMayBeFinal") // Because PicoCLI requires Strings to not be final.
  @CommandLine.Option(
      names = "--downstream-http-host",
      description =
          "The endpoint to which received requests are forwarded (default: ${DEFAULT-VALUE})",
      paramLabel = HOST_FORMAT_HELP,
      arity = "1")
  private String downstreamHttpHost = "127.0.0.1";

  @SuppressWarnings("FieldMayBeFinal") // Because PicoCLI requires Strings to not be final.
  @CommandLine.Option(
      names = "--downstream-http-port",
      description =
          "The endpoint to which received requests are forwarded (default: ${DEFAULT-VALUE})",
      paramLabel = PORT_FORMAT_HELP,
      arity = "1")
  private Integer downstreamHttpPort = 8545;

  private String downstreamHttpPath = "/";

  @CommandLine.Option(
      names = {"--downstream-http-path"},
      description = "The path to which received requests are forwarded (default: ${DEFAULT-VALUE})",
      defaultValue = "/",
      paramLabel = PATH_FORMAT_HELP,
      arity = "1")
  public void setDownstreamHttpPath(final String path) {
    try {
      final URI uri = new URI(path);
      if (!uri.getPath().equals(path)) {
        throw new CommandLine.ParameterException(
            spec.commandLine(), "Illegal characters detected in --downstream-http-path");
      }
    } catch (final URISyntaxException e) {
      throw new CommandLine.ParameterException(
          spec.commandLine(), "Illegal characters detected in --downstream-http-path");
    }
    this.downstreamHttpPath = path;
  }

  @SuppressWarnings("FieldMayBeFinal")
  @CommandLine.Option(
      names = {"--downstream-http-request-timeout"},
      description =
          "Timeout in milliseconds to wait for downstream request (default: ${DEFAULT-VALUE})",
      paramLabel = LONG_FORMAT_HELP,
      arity = "1")
  private long downstreamHttpRequestTimeout = Duration.ofSeconds(5).toMillis();

  @SuppressWarnings("FieldMayBeFinal") // Because PicoCLI requires Strings to not be final.
  @CommandLine.Option(
      names = {"--downstream-http-proxy-host"},
      description = "Hostname for proxy connect, no proxy if null (default: null)",
      paramLabel = HOST_FORMAT_HELP,
      arity = "1")
  private String httpProxyHost = null;

  @CommandLine.Option(
      names = {"--downstream-http-proxy-port"},
      paramLabel = PORT_FORMAT_HELP,
      description = "Port for proxy connect (default: 80)",
      arity = "1")
  private final Integer httpProxyPort = 80;

  @SuppressWarnings("FieldMayBeFinal") // Because PicoCLI requires Strings to not be final.
  @CommandLine.Option(
      names = {"--downstream-http-proxy-username"},
      paramLabel = "<username>",
      description =
          "Username for proxy connect, no authentication if null (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String httpProxyUsername = null;

  @SuppressWarnings("FieldMayBeFinal") // Because PicoCLI requires Strings to not be final.
  @CommandLine.Option(
      names = {"--downstream-http-proxy-password"},
      paramLabel = "<password>",
      description =
          "Password for proxy connect, no authentication if null (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String httpProxyPassword = null;

  private long awsKmsClientCacheSize = 1;

  @CommandLine.Mixin private PicoCliClientTlsOptions clientTlsOptions;

  @CommandLine.Mixin private PicoCliAzureKeyVaultParameters azureKeyVaultParameters;

  @CommandLine.Mixin private PicoV3KeystoresBulkloadParameters picoV3KeystoresBulkloadParameters;

  @CommandLine.Mixin private PicoCliAwsKmsParameters awsParameters;

  @Override
  public Runner createRunner() {
    return new Eth1Runner(config, this);
  }

  @Override
  public String getCommandName() {
    return COMMAND_NAME;
  }

  @Override
  protected void validateArgs() {
    checkIfRequiredOptionsAreInitialized(this);
    validateV3KeystoresBulkloadingParameters();
  }

  private void validateV3KeystoresBulkloadingParameters() {
    if (!picoV3KeystoresBulkloadParameters.isEnabled()) {
      return;
    }

    final boolean validOptionSelected =
        picoV3KeystoresBulkloadParameters.hasKeystoresPasswordFile()
            ^ picoV3KeystoresBulkloadParameters.hasKeystoresPasswordsPath();
    if (!validOptionSelected) {
      throw new CommandLine.ParameterException(
          spec.commandLine(),
          String.format(
              "Either %s or %s must be specified",
              KEYSTORES_PASSWORD_FILE, KEYSTORES_PASSWORDS_PATH));
    }
  }

  @Override
  public String getDownstreamHttpHost() {
    return downstreamHttpHost;
  }

  @Override
  public Integer getDownstreamHttpPort() {
    return downstreamHttpPort;
  }

  @Override
  public String getDownstreamHttpPath() {
    return downstreamHttpPath;
  }

  @Override
  public Duration getDownstreamHttpRequestTimeout() {
    return Duration.ofMillis(downstreamHttpRequestTimeout);
  }

  @Override
  public String getHttpProxyHost() {
    return httpProxyHost;
  }

  @Override
  public Integer getHttpProxyPort() {
    return httpProxyPort;
  }

  @Override
  public String getHttpProxyUsername() {
    return httpProxyUsername;
  }

  @Override
  public String getHttpProxyPassword() {
    return httpProxyPassword;
  }

  @Override
  public Optional<ClientTlsOptions> getClientTlsOptions() {
    return clientTlsOptions.isTlsEnabled() ? Optional.of(clientTlsOptions) : Optional.empty();
  }

  @Override
  public ChainIdProvider getChainId() {
    return new ConfigurationChainId(chainId);
  }

  @Override
  public AzureKeyVaultParameters getAzureKeyVaultConfig() {
    return azureKeyVaultParameters;
  }

  @Override
  public AwsVaultParameters getAwsVaultParameters() {
    return awsParameters;
  }

  @CommandLine.Option(
      names = {"--aws-kms-client-cache-size"},
      paramLabel = "<LONG>",
      defaultValue = "1",
      description =
          "AWS Kms Client cache size. Should be set based on different set of credentials and region (default: ${DEFAULT-VALUE})")
  public void setAwsKmsClientCacheSize(long awsKmsClientCacheSize) {
    if (awsKmsClientCacheSize < 1) {
      throw new CommandLine.ParameterException(
          spec.commandLine(), "--aws-kms-client-cache-size must be positive");
    }
    this.awsKmsClientCacheSize = awsKmsClientCacheSize;
  }

  @Override
  public long getAwsKmsClientCacheSize() {
    return awsKmsClientCacheSize;
  }

  @Override
  public KeystoresParameters getV3KeystoresBulkLoadParameters() {
    return picoV3KeystoresBulkloadParameters;
  }
}
