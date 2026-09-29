/*
 * Copyright 2026 ConsenSys AG.
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
package tech.pegasys.web3signer.commandline.logging;

import java.io.PrintWriter;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.Layout;
import org.apache.logging.log4j.core.LifeCycle;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.WriterAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.Configurator;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilder;
import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory;
import org.apache.logging.log4j.core.config.builder.api.RootLoggerComponentBuilder;
import org.apache.logging.log4j.core.config.builder.impl.BuiltConfiguration;
import org.apache.logging.log4j.core.layout.PatternLayout;
import org.apache.logging.log4j.layout.template.json.JsonTemplateLayout;

public class LoggingConfigurator {
  private static final Logger LOG = LogManager.getLogger(LoggingConfigurator.class);

  private static final String DEFAULT_PATTERN =
      "%d{yyyy-MM-dd HH:mm:ss.SSSZZZ} | %t | %-5level | %c{1} | %msg%n";

  /**
   * Configure logging with the provided PrintWriter.
   *
   * @param logLevel the log level
   * @param format the logging format
   * @param writer the print writer for output
   */
  public static void configureLogging(
      final Level logLevel, final LoggingFormat format, final PrintWriter writer) {

    // Get current context and stop/remove existing appenders
    final LoggerContext context = LoggerContext.getContext(false);
    final Configuration oldConfig = context.getConfiguration();

    // Stop and remove all existing appenders
    oldConfig.getAppenders().values().forEach(LifeCycle::stop);
    oldConfig.getRootLogger().getAppenders().clear();

    // Build new configuration structure
    final ConfigurationBuilder<BuiltConfiguration> builder =
        ConfigurationBuilderFactory.newConfigurationBuilder();

    builder.setStatusLevel(Level.ERROR);
    builder.setConfigurationName("Web3SignerProgrammaticConfig");

    // Create root logger
    final RootLoggerComponentBuilder rootLogger = builder.newRootLogger(logLevel);
    builder.add(rootLogger);

    // Build the configuration
    final BuiltConfiguration config = builder.build();

    // Create layout based on format
    final Layout<?> layout = createLayout(config, format);

    // Create WriterAppender programmatically
    final WriterAppender appender =
        WriterAppender.newBuilder()
            .setName("WriterOutput")
            .setTarget(writer)
            .setLayout(layout)
            .setConfiguration(config)
            .build();

    appender.start();

    // Add appender to configuration
    config.addAppender(appender);
    config.getRootLogger().addAppender(appender, logLevel, null);

    // Apply configuration
    Configurator.reconfigure(config);

    LOG.debug("Logging configured: level={}, format={}", logLevel, format);
  }

  private static Layout<?> createLayout(final Configuration config, final LoggingFormat format) {
    if (format.isJson()) {
      return JsonTemplateLayout.newBuilder()
          .setConfiguration(config)
          .setEventTemplateUri(format.getEventTemplateUri())
          .build();
    } else {
      return PatternLayout.newBuilder()
          .setConfiguration(config)
          .setPattern(DEFAULT_PATTERN)
          .build();
    }
  }
}
