/*
 * Copyright 2019 ConsenSys AG.
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

import static tech.pegasys.web3signer.commandline.DefaultCommandValues.CONFIG_FILE_OPTION_NAME;

import tech.pegasys.web3signer.commandline.logging.LoggingConfigurator;
import tech.pegasys.web3signer.commandline.subcommands.ModeSubCommand;
import tech.pegasys.web3signer.commandline.valueprovider.CascadingDefaultProvider;
import tech.pegasys.web3signer.commandline.valueprovider.EnvironmentVariableDefaultProvider;
import tech.pegasys.web3signer.commandline.valueprovider.YamlConfigFileDefaultProvider;
import tech.pegasys.web3signer.common.ApplicationInfo;

import java.io.File;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.google.common.collect.Lists;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import picocli.CommandLine;
import picocli.CommandLine.Help.Ansi;
import picocli.CommandLine.IDefaultValueProvider;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

public class CommandlineParser {
  private static final Logger LOG = LogManager.getLogger("Web3SignerInit");

  private final Web3SignerBaseCommand baseCommand;
  private final PrintWriter outputWriter;
  private final PrintWriter errorWriter;
  private final Map<String, String> environment;

  private final List<ModeSubCommand> modes = Lists.newArrayList();

  public CommandlineParser(
      final Web3SignerBaseCommand baseCommand,
      final PrintWriter outputWriter,
      final PrintWriter errorWriter,
      final Map<String, String> environment) {
    this.baseCommand = baseCommand;
    this.outputWriter = outputWriter;
    this.errorWriter = errorWriter;
    this.environment = environment;
  }

  public void registerSubCommands(final ModeSubCommand... subCommands) {
    modes.addAll(Arrays.asList(subCommands));
  }

  public int parseCommandLine(final String... args) {
    final CommandLine commandLine = new CommandLine(baseCommand);

    // register subcommands first so that they can inherit subsequent settings
    for (final ModeSubCommand subcommand : modes) {
      commandLine.addSubcommand(subcommand.getCommandName(), subcommand);
    }

    commandLine.setCaseInsensitiveEnumValuesAllowed(true);
    commandLine.setOut(outputWriter);
    commandLine.setErr(errorWriter);
    commandLine.setExecutionExceptionHandler(this::handleExecutionException);
    commandLine.setParameterExceptionHandler(this::handleParseException);
    commandLine.setExecutionStrategy(this::executionStrategy);

    Optional<File> configFile = Optional.empty();
    try {
      final ParseResult pr = commandLine.parseArgs(args);
      if (pr.matchedOption(CONFIG_FILE_OPTION_NAME) != null) {
        configFile = Optional.ofNullable(pr.matchedOption(CONFIG_FILE_OPTION_NAME).getValue());
      }
    } catch (final ParameterException e) {
      // catch failures, which will be rethrown when commandline is run via execute().
    }
    commandLine.clearExecutionResults();
    commandLine.setDefaultValueProvider(defaultValueProvider(commandLine, configFile));
    return commandLine.execute(args);
  }

  private int executionStrategy(final ParseResult parseResult) {
    // initialize logging before execution
    if (System.getProperty("log4j.configurationFile") != null
        || System.getProperty("log4j2.configurationFile") != null) {
      LOG.debug("Using custom Log4j configuration file");
    } else {
      // Apply programmatic configuration
      LoggingConfigurator.configureLogging(
          baseCommand.getLogLevel(), baseCommand.getLoggingFormat(), outputWriter);
    }

    // Don't log startup message for any help/version requests
    if (!isHelpOrVersionRequested(parseResult)) {
      // App initialization information
      LOG.info("Starting Web3Signer version {}", ApplicationInfo.version());
      LOG.debug("Command line arguments: {}", String.join(" ", parseResult.originalArgs()));
    }

    // default execution strategy
    return new CommandLine.RunLast().execute(parseResult);
  }

  private boolean isHelpOrVersionRequested(final ParseResult parseResult) {
    // Walk through all subcommand levels to check if help or version is requested anywhere
    ParseResult current = parseResult;
    while (current != null) {
      if (current.isUsageHelpRequested()
          || current.isVersionHelpRequested()
          || current.commandSpec().helpCommand()) {
        return true;
      }
      current = current.hasSubcommand() ? current.subcommand() : null;
    }
    return false;
  }

  private IDefaultValueProvider defaultValueProvider(
      final CommandLine commandLine, final Optional<File> configFile) {
    if (configFile.isEmpty()) {
      return new EnvironmentVariableDefaultProvider(environment);
    }

    return new CascadingDefaultProvider(
        new EnvironmentVariableDefaultProvider(environment),
        new YamlConfigFileDefaultProvider(commandLine, configFile.get()));
  }

  private int handleParseException(final ParameterException ex, final String[] args) {
    errorWriter.println("Error parsing parameters: " + ex.getMessage());

    if (!(ex instanceof CommandLine.MutuallyExclusiveArgsException)
        && !CommandLine.UnmatchedArgumentException.printSuggestions(ex, outputWriter)) {
      ex.getCommandLine().usage(outputWriter, Ansi.AUTO);
    }

    return ex.getCommandLine().getCommandSpec().exitCodeOnInvalidInput();
  }

  private int handleExecutionException(
      final Exception ex,
      final CommandLine commandLine,
      final CommandLine.ParseResult parseResult) {
    errorWriter.println("Failed to initialize Web3Signer");
    errorWriter.println("Cause: " + ex.getMessage());

    if (LOG.isDebugEnabled()) {
      ex.printStackTrace(errorWriter);
    }

    return commandLine.getCommandSpec().exitCodeOnExecutionException();
  }
}
