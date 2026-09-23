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
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.FILE_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.HOST_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.INTEGER_FORMAT_HELP;
import static tech.pegasys.web3signer.commandline.DefaultCommandValues.PORT_FORMAT_HELP;
import static tech.pegasys.web3signer.common.Web3SignerMetricCategory.DEFAULT_METRIC_CATEGORIES;

import tech.pegasys.web3signer.commandline.config.AllowListHostsProperty;
import tech.pegasys.web3signer.commandline.config.PicoCliMetricsPushOptions;
import tech.pegasys.web3signer.commandline.config.PicoCliTlsServerOptions;
import tech.pegasys.web3signer.commandline.config.PicoCliTlsServerOptionsValidator;
import tech.pegasys.web3signer.commandline.convertor.MetricCategoryConverter;
import tech.pegasys.web3signer.commandline.logging.LoggingFormat;
import tech.pegasys.web3signer.commandline.subcommands.XHelpSubCommand;
import tech.pegasys.web3signer.common.Web3SignerMetricCategory;
import tech.pegasys.web3signer.common.config.SignerLoaderConfig;
import tech.pegasys.web3signer.core.config.BaseConfig;
import tech.pegasys.web3signer.core.config.MetricsPushOptions;
import tech.pegasys.web3signer.core.config.TlsOptions;

import java.io.File;
import java.net.InetAddress;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import com.google.common.base.MoreObjects;
import org.apache.logging.log4j.Level;
import org.hyperledger.besu.metrics.StandardMetricCategory;
import org.hyperledger.besu.plugin.services.metrics.MetricCategory;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

@SuppressWarnings("FieldCanBeLocal") // because Picocli injected fields report false positives
@Command(
    description =
        "This command runs the Web3Signer.\n"
            + "Documentation can be found at https://docs.web3signer.consensys.net .",
    abbreviateSynopsis = true,
    name = "web3signer",
    sortOptions = false,
    mixinStandardHelpOptions = true,
    versionProvider = VersionProvider.class,
    header = "Usage:",
    synopsisHeading = "%n",
    descriptionHeading = "%nDescription:%n%n",
    optionListHeading = "%nOptions:%n",
    footerHeading = "%n",
    subcommands = {HelpCommand.class, XHelpSubCommand.class},
    footer =
        "Unstable options are omitted from this help. Run 'web3signer -X' to list them.%n%n"
            + "Web3Signer is licensed under the Apache License 2.0")
public class Web3SignerBaseCommand implements BaseConfig, Runnable {
  private static final int VERTX_WORKER_POOL_SIZE_DEFAULT = 20;
  @Spec private CommandLine.Model.CommandSpec spec; // injected by picocli
  public static final String KEY_STORE_CONFIG_FILE_SIZE_OPTION_NAME =
      "--key-store-config-file-max-size";

  @SuppressWarnings("UnusedVariable")
  @CommandLine.Option(
      names = {CONFIG_FILE_OPTION_NAME},
      paramLabel = FILE_FORMAT_HELP,
      description = "Config file in yaml format (default: none)")
  private final File configFile = null;

  @Option(
      names = {"--data-path"},
      description = "The path to a directory to store temporary files",
      paramLabel = DefaultCommandValues.PATH_FORMAT_HELP,
      arity = "1")
  private Path dataPath;

  @Option(
      names = {"--key-config-path", "--key-store-path"},
      description = "The path to a directory storing yaml files defining available keys",
      paramLabel = DefaultCommandValues.PATH_FORMAT_HELP,
      arity = "1")
  private Path keyStorePath = Path.of("./");

  @Option(
      names = {KEY_STORE_CONFIG_FILE_SIZE_OPTION_NAME},
      description =
          "The key store configuration file size in bytes. Useful when loading a large number of configurations from "
              + "the same yaml file. Defaults to ${DEFAULT-VALUE} bytes.",
      paramLabel = "<NUMBER>",
      arity = "1")
  private int keystoreConfigFileMaxSize = 104_857_600;

  @Option(
      names = {"--logging", "-l"},
      paramLabel = "<LOG VERBOSITY LEVEL>",
      converter = LoggingLevelConverter.class,
      completionCandidates = LoggingLevelCompletionCandidates.class,
      description = "Logging verbosity levels: ${COMPLETION-CANDIDATES} (default: INFO)")
  private final Level logLevel = Level.INFO;

  @Option(
      names = {"--logging-format"},
      description = "Logging format: ${COMPLETION-CANDIDATES} (default: PLAIN)")
  private LoggingFormat loggingFormat = LoggingFormat.PLAIN;

  @SuppressWarnings("FieldMayBeFinal") // Because PicoCLI requires Strings to not be final.
  @Option(
      names = {"--http-listen-host"},
      description = "Host for HTTP to listen on (default: ${DEFAULT-VALUE})",
      paramLabel = HOST_FORMAT_HELP,
      arity = "1")
  private String httpListenHost = InetAddress.getLoopbackAddress().getHostAddress();

  @Option(
      names = {"--http-listen-port"},
      description = "Port for HTTP to listen on (default: ${DEFAULT-VALUE})",
      paramLabel = PORT_FORMAT_HELP,
      arity = "1")
  private final Integer httpListenPort = 9000;

  @Option(
      names = {"--http-host-allowlist"},
      paramLabel = "<hostname>[,<hostname>...]... or * or all",
      description =
          "Comma separated list of hostnames to allow for http access, or * to accept any host (default: ${DEFAULT-VALUE})",
      defaultValue = "localhost,127.0.0.1")
  private final AllowListHostsProperty httpHostAllowList = new AllowListHostsProperty();

  // A list of origins URLs that are accepted by the JsonRpcHttpServer (CORS)
  @Option(
      names = {"--http-cors-origins"},
      description = "Comma separated origin domain URLs for CORS validation (default: none)")
  private final CorsAllowedOriginsProperty httpCorsAllowedOrigins =
      new CorsAllowedOriginsProperty();

  @Option(
      names = {"--metrics-enabled"},
      description = "Set to start the metrics exporter (default: ${DEFAULT-VALUE})")
  private final Boolean metricsEnabled = false;

  @SuppressWarnings({"FieldCanBeFinal", "FieldMayBeFinal"}) // PicoCLI requires non-final Strings.
  @Option(
      names = {"--metrics-host"},
      paramLabel = HOST_FORMAT_HELP,
      description = "Host for the metrics exporter to listen on (default: ${DEFAULT-VALUE})",
      arity = "1")
  private String metricsHost = InetAddress.getLoopbackAddress().getHostAddress();

  @Option(
      names = {"--metrics-port"},
      paramLabel = PORT_FORMAT_HELP,
      description = "Port for the metrics exporter to listen on (default: ${DEFAULT-VALUE})",
      arity = "1")
  private final Integer metricsPort = 9001;

  @Option(
      names = {"--metrics-category", "--metrics-categories"},
      paramLabel = "<category name>",
      split = ",",
      arity = "1..*",
      description =
          "Comma separated list of categories to track metrics for (default: ${DEFAULT-VALUE}),",
      converter = Web3signerMetricCategoryConverter.class)
  private final Set<MetricCategory> metricCategories = DEFAULT_METRIC_CATEGORIES;

  @Option(
      names = {"--metrics-host-allowlist"},
      paramLabel = "<hostname>[,<hostname>...]... or * or all",
      description =
          "Comma separated list of hostnames to allow for metrics access, or * to accept any host (default: ${DEFAULT-VALUE})",
      defaultValue = "localhost,127.0.0.1")
  private final AllowListHostsProperty metricsHostAllowList = new AllowListHostsProperty();

  @CommandLine.Mixin private PicoCliMetricsPushOptions metricsPushOptions;

  @Option(
      names = {"--idle-connection-timeout-seconds"},
      paramLabel = "<timeout in seconds>",
      description =
          "Number of seconds after which an idle connection will be terminated (Default: ${DEFAULT-VALUE})",
      arity = "1")
  private int idleConnectionTimeoutSeconds = 30;

  @Option(
      names = {"--access-logs-enabled"},
      description = "Enable access logs (default: ${DEFAULT-VALUE})")
  private final Boolean accessLogsEnabled = false;

  @Option(
      names = "--vertx-worker-pool-size",
      description =
          "Configure the Vert.x worker pool size used for processing requests. (default: "
              + VERTX_WORKER_POOL_SIZE_DEFAULT
              + ")",
      paramLabel = INTEGER_FORMAT_HELP)
  private Integer vertxWorkerPoolSize = null;

  // Reload endpoint timeout (Vert.x Worker Executor)
  @CommandLine.Option(
      names = {"--reload-timeout"},
      description =
          "Maximum time allowed for the entire reload operation via /reload endpoint "
              + "(default: ${DEFAULT-VALUE} minutes). "
              + "Includes loading from all sources (file system, key vaults, etc.).",
      defaultValue = "30",
      paramLabel = "<MINUTES>",
      arity = "1")
  private long reloadTimeoutMinutes = 30;

  // SignerLoader timeout (per-file processing)
  @CommandLine.Option(
      names = {"--signer-load-timeout"},
      description =
          "Maximum time for processing each individual signer configuration file "
              + "(default: ${DEFAULT-VALUE} seconds). "
              + "Applies during parallel processing of files from the file system.",
      defaultValue = "60",
      paramLabel = "<SECONDS>",
      arity = "1")
  private int signerLoadTimeoutSeconds = 60;

  // SignerLoader batch configuration
  @CommandLine.Option(
      names = {"--signer-load-batch-size"},
      description =
          "Number of signer configuration files to process per batch during parallel loading "
              + "(default: ${DEFAULT-VALUE}). Minimum value is 100. "
              + "Reduce if hitting OS file descriptor limits.",
      defaultValue = "500",
      paramLabel = "<COUNT>",
      arity = "1")
  private int signerLoadBatchSize = 500;

  @CommandLine.Option(
      names = {"--signer-load-sequential-threshold"},
      description =
          "Minimum number of files required to use parallel processing "
              + "(default: ${DEFAULT-VALUE}). Minimum value is 1. "
              + "Files below this threshold are processed sequentially.",
      defaultValue = "100",
      paramLabel = "<COUNT>",
      arity = "1")
  private int signerLoadSequentialThreshold = 100;

  @CommandLine.Option(
      names = {"--signer-load-parallel"},
      description =
          "Enable parallel processing of signer configuration files "
              + "(default: ${DEFAULT-VALUE}). "
              + "Set to false for sequential processing.",
      defaultValue = "true",
      paramLabel = "<BOOLEAN>",
      arity = "1")
  private boolean signerLoadParallel = true;

  @CommandLine.Mixin private PicoCliTlsServerOptions picoCliTlsServerOptions;

  public Level getLogLevel() {
    return logLevel;
  }

  public LoggingFormat getLoggingFormat() {
    return loggingFormat;
  }

  @Override
  public String getHttpListenHost() {
    return httpListenHost;
  }

  @Override
  public Integer getHttpListenPort() {
    return httpListenPort;
  }

  @Override
  public AllowListHostsProperty getHttpHostAllowList() {
    return httpHostAllowList;
  }

  @Override
  public Collection<String> getCorsAllowedOrigins() {
    return httpCorsAllowedOrigins;
  }

  @Override
  public Path getDataPath() {
    return dataPath;
  }

  @Override
  public Path getKeyConfigPath() {
    return keyStorePath;
  }

  @Override
  public int getKeyStoreConfigFileMaxSize() {
    return keystoreConfigFileMaxSize;
  }

  @Override
  public Boolean isMetricsEnabled() {
    return metricsEnabled;
  }

  @Override
  public Integer getMetricsPort() {
    return metricsPort;
  }

  @Override
  public String getMetricsNetworkInterface() {
    return metricsHost;
  }

  @Override
  public Set<MetricCategory> getMetricCategories() {
    return metricCategories;
  }

  @Override
  public List<String> getMetricsHostAllowList() {
    return metricsHostAllowList;
  }

  @Override
  public Optional<MetricsPushOptions> getMetricsPushOptions() {
    if (metricsPushOptions.isMetricsPushEnabled()) {
      return Optional.of(metricsPushOptions);
    }
    return Optional.empty();
  }

  @Override
  public Optional<TlsOptions> getTlsOptions() {
    if (picoCliTlsServerOptions.getKeyStoreFile() != null
        && picoCliTlsServerOptions.getKeyStorePasswordFile() != null) {
      return Optional.of(picoCliTlsServerOptions);
    }
    return Optional.empty();
  }

  @Override
  public int getIdleConnectionTimeoutSeconds() {
    return idleConnectionTimeoutSeconds;
  }

  @Override
  public Boolean isAccessLogsEnabled() {
    return accessLogsEnabled;
  }

  @Override
  public int getVertxWorkerPoolSize() {
    if (vertxWorkerPoolSize != null) {
      return vertxWorkerPoolSize;
    }

    return VERTX_WORKER_POOL_SIZE_DEFAULT;
  }

  @Override
  public SignerLoaderConfig getSignerLoaderConfig() {
    return new SignerLoaderConfig(
        keyStorePath,
        signerLoadParallel,
        signerLoadBatchSize,
        signerLoadTimeoutSeconds,
        signerLoadSequentialThreshold);
  }

  @Override
  public long getReloadTimeoutMinutes() {
    return reloadTimeoutMinutes;
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("configFile", configFile)
        .add("dataPath", dataPath)
        .add("keyStorePath", keyStorePath)
        .add("logLevel", logLevel)
        .add("httpListenHost", httpListenHost)
        .add("httpListenPort", httpListenPort)
        .add("httpHostAllowList", httpHostAllowList)
        .add("corsAllowedOrigins", httpCorsAllowedOrigins)
        .add("metricsEnabled", metricsEnabled)
        .add("metricsHost", metricsHost)
        .add("metricsPort", metricsPort)
        .add("metricCategories", metricCategories)
        .add("metricsHostAllowList", metricsHostAllowList)
        .add("picoCliTlsServerOptions", picoCliTlsServerOptions)
        .add("idleConnectionTimeoutSeconds", idleConnectionTimeoutSeconds)
        .add("vertxWorkerPoolSize", vertxWorkerPoolSize)
        .add("signerLoaderConfig", getSignerLoaderConfig())
        .toString();
  }

  @Override
  public void run() {
    throw new ParameterException(spec.commandLine(), "Missing required subcommand");
  }

  @Override
  public void validateArgs() {
    if (keystoreConfigFileMaxSize <= 0) {
      throw new CommandLine.TypeConversionException(
          String.format(
              "Invalid value for option '%s': Expecting positive value.",
              KEY_STORE_CONFIG_FILE_SIZE_OPTION_NAME));
    }
    // custom validation for TLS options as we removed ArgGroups since they don't work with config
    // files
    final PicoCliTlsServerOptionsValidator picoCliTlsServerOptionsValidator =
        new PicoCliTlsServerOptionsValidator(spec, picoCliTlsServerOptions);
    picoCliTlsServerOptionsValidator.validate();

    if (isMetricsEnabled() && metricsPushOptions.isMetricsPushEnabled()) {
      throw new CommandLine.MutuallyExclusiveArgsException(
          spec.commandLine(),
          "--metrics-enabled option and --metrics-push-enabled option can't be used at the same "
              + "time.  Please refer to CLI reference for more details about this constraint.");
    }

    // reload endpoint handler timeout option validation
    if (reloadTimeoutMinutes < 1) {
      throw new CommandLine.ParameterException(
          spec.commandLine(), "--reload-timeout must be at least 1");
    }

    validateSignerLoaderConfigOptions();
  }

  private void validateSignerLoaderConfigOptions() {
    if (signerLoadTimeoutSeconds < 1) {
      throw new ParameterException(spec.commandLine(), "--signer-load-timeout must be at least 1");
    }

    if (signerLoadBatchSize < 100) {
      throw new ParameterException(
          spec.commandLine(), "--signer-load-batch-size must be at least 100");
    }

    if (signerLoadSequentialThreshold < 1) {
      throw new ParameterException(
          spec.commandLine(), "--signer-load-sequential-threshold must be at least 1");
    }
  }

  public static class Web3signerMetricCategoryConverter extends MetricCategoryConverter {

    public Web3signerMetricCategoryConverter() {
      addCategories(Web3SignerMetricCategory.class);
      addCategories(StandardMetricCategory.class);
    }
  }

  static class LoggingLevelConverter implements CommandLine.ITypeConverter<Level> {
    @Override
    public Level convert(final String value) {
      return Level.valueOf(value);
    }
  }

  static class LoggingLevelCompletionCandidates extends ArrayList<String> {
    LoggingLevelCompletionCandidates() {
      super(
          Arrays.stream(Level.values())
              .sorted(Comparator.comparingInt(Level::intLevel).reversed())
              .map(Level::name)
              .toList());
    }
  }
}
